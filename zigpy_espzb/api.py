"""Espressif Zigbee NCP Serial Protocol API."""

from __future__ import annotations

import asyncio
import collections
import logging
import sys
from typing import Any, Callable

if sys.version_info[:2] < (3, 11):
    from async_timeout import timeout as asyncio_timeout  # pragma: no cover
else:
    from asyncio import timeout as asyncio_timeout  # pragma: no cover

from zigpy.config import CONF_DEVICE_PATH
import zigpy.types as t

from zigpy_espzb import commands
from zigpy_espzb.commands import (
    COMMAND_SCHEMA_TO_COMMAND_ID,
    COMMAND_SCHEMAS,
    CommandFrame,
    FrameType,
)
from zigpy_espzb.exception import APIException, CommandError
from zigpy_espzb.types import (
    Bytes,
    DeviceType,
    ExtendedAddrMode,
    FirmwareVersion,
    NetworkState,
    SecurityMode,
    ShiftedChannels,
    Status,
    TransmitOptions,
    TXStatus,
    addr_mode_with_eui64_to_addr_mode_address,
)
import zigpy_espzb.uart

LOGGER = logging.getLogger(__name__)

POLL_UNTIL_RUNNING_TIMEOUT = 10
COMMAND_TIMEOUT = 1.8
PROBE_TIMEOUT = 2
REQUEST_RETRY_DELAYS = (0.5, 1.0, 1.5, None)


class Znsp:
    """Espressif ZNSP API class."""

    def __init__(self, app: Callable, device_config: dict[str, Any]):
        """Init instance."""
        self._app = app

        # [seq][cmd_id] = [fut1, fut2, ...]
        self._awaiting = collections.defaultdict(lambda: collections.defaultdict(list))
        self._command_lock = asyncio.Lock()
        self._config = device_config
        self._network_state = NetworkState.OFFLINE

        self._data_poller_event = asyncio.Event()
        self._data_poller_event.set()
        self._data_poller_task: asyncio.Task | None = None

        self._seq = 0
        self._status = Status.SUCCESS
        self._firmware_version = FirmwareVersion(0)
        self._uart: zigpy_espzb.uart.Gateway | None = None

    @property
    def firmware_version(self) -> FirmwareVersion:
        """Return Device firmware version."""
        return self._firmware_version

    @property
    def network_state(self) -> NetworkState:
        """Return current network state."""
        return self._network_state

    async def connect(self) -> None:
        assert self._uart is None
        self._uart = await zigpy_espzb.uart.connect(self._config, self)

        # TODO: implement a firmware version command
        self._firmware_version = await self.system_firmware()
        self._network_state = await self.get_network_state()

    def connection_lost(self, exc: Exception) -> None:
        """Lost serial connection."""
        LOGGER.debug(
            "Serial %r connection lost unexpectedly: %r",
            self._config[CONF_DEVICE_PATH],
            exc,
        )

        if self._app is not None:
            self._app.connection_lost(exc)

    def close(self):
        self._app = None

        if self._data_poller_task is not None:
            self._data_poller_task.cancel()
            self._data_poller_task = None

        if self._uart is not None:
            self._uart.close()
            self._uart = None

    async def send_command(self, command: t.Struct, *, wait_for_response: bool = True):
        command_id = COMMAND_SCHEMA_TO_COMMAND_ID[type(command)]
        serialized_payload = command.serialize()

        command_frame = CommandFrame(
            version=0b0000,
            frame_type=FrameType.Request,
            reserved=0x00,
            command_id=command_id,
            seq=None,
            length=len(serialized_payload),
            payload=serialized_payload,
        )

        if self._uart is None:
            # connection was lost
            raise CommandError(Status.ERROR, "API is not running")

        async with self._command_lock:
            seq = self._seq

            LOGGER.debug("Sending %s (seq=%s)", command, seq)
            self._uart.send(command_frame.replace(seq=seq).serialize())

            self._seq = (self._seq % 255) + 1

            if not wait_for_response:
                LOGGER.debug("Not waiting for a response")
                return

            fut = asyncio.Future()
            self._awaiting[seq][command_id].append(fut)

            try:
                async with asyncio_timeout(COMMAND_TIMEOUT):
                    return await fut
            except asyncio.TimeoutError:
                LOGGER.debug("No response to '%s' command with seq %d", command, seq)
                raise
            finally:
                self._awaiting[seq][command_id].remove(fut)

    def data_received(self, data: bytes) -> None:
        command, _ = CommandFrame.deserialize(data)

        if command.command_id not in COMMAND_SCHEMAS:
            LOGGER.warning("Unknown command received: %s", command)
            return

        tx_schema, rx_schema, ind_schema = COMMAND_SCHEMAS[command.command_id]

        if command.frame_type == FrameType.Request:
            schema = tx_schema
        elif command.frame_type == FrameType.Response:
            schema = rx_schema
        elif command.frame_type == FrameType.Indicate:
            schema = ind_schema
        else:
            raise ValueError(f"Unknown frame type: {command}")

        # We won't implement requests for now
        assert command.frame_type != FrameType.Request

        if schema is None:
            return

        fut = None

        if command.frame_type == FrameType.Response:
            try:
                fut = self._awaiting[command.seq][command.command_id][0]
            except IndexError:
                LOGGER.warning(
                    "Received unexpected response %s%s", command.command_id, command
                )

        try:
            params, rest = schema.deserialize(command.payload)
        except Exception:
            LOGGER.warning("Failed to parse command %s", command, exc_info=True)

            if fut is not None and not fut.done():
                fut.set_exception(
                    APIException(f"Failed to deserialize command: {command}")
                )

            return

        if rest:
            LOGGER.debug("Unparsed data remains after frame: %s, %s", command, rest)

        LOGGER.debug(
            "Received %s %s (seq %d)",
            ("indication" if command.frame_type == FrameType.Indicate else "response"),
            params,
            command.seq,
        )

        exc = None
        status = getattr(params, "status", None)

        if status is not None and status != Status.SUCCESS:
            exc = CommandError(status, f"{command.command_id}, status: {status}")

        if fut is not None:
            try:
                if exc is None:
                    fut.set_result(params)
                else:
                    fut.set_exception(exc)
            except asyncio.InvalidStateError:
                LOGGER.warning(
                    "Duplicate or delayed response for 0x%02x sequence",
                    command.seq,
                )

            if exc is not None:
                return

        if handler := getattr(self, f"_handle_{command.command_id.name}", None):
            # Queue up the callback within the event loop
            asyncio.get_running_loop().call_soon(lambda: handler(**params.as_dict()))

    def _handle_aps_data_indication(
        self,
        network_state: NetworkState,
        dst_addr_mode: ExtendedAddrMode,
        dst_addr: t.EUI64,
        dst_ep: t.uint8_t,
        src_addr_mode: ExtendedAddrMode,
        src_addr: t.EUI64,
        src_ep: t.uint8_t,
        profile_id: t.uint16_t,
        cluster_id: t.uint16_t,
        indication_status: TXStatus,
        security_status: t.uint8_t,
        lqi: t.uint8_t,
        rx_time: t.uint32_t,
        asdu_length: t.uint32_t,
        asdu: Bytes,
    ):
        if network_state == NetworkState.INDICATION:
            self._app.packet_received(
                t.ZigbeePacket(
                    src=addr_mode_with_eui64_to_addr_mode_address(
                        src_addr_mode, src_addr
                    ),
                    src_ep=src_ep,
                    dst=addr_mode_with_eui64_to_addr_mode_address(
                        dst_addr_mode, dst_addr
                    ),
                    dst_ep=dst_ep,
                    tsn=None,
                    profile_id=profile_id,
                    cluster_id=cluster_id,
                    data=t.SerializableBytes(asdu),
                    lqi=lqi,
                    rssi=None,
                )
            )

    def _handle_network_state_changed(self, network_state: NetworkState) -> None:
        if network_state != self.network_state:
            LOGGER.debug(
                "Network network_state transition: %s -> %s",
                self.network_state.name,
                network_state.name,
            )

        self._network_state = network_state
        self._data_poller_event.set()

    def _handle_network_state(self, network_state: NetworkState) -> None:
        self._handle_network_state_changed(network_state=network_state)

    async def network_init(self) -> None:
        await self.send_command(commands.NetworkInitReq())

    async def get_channel_mask(self) -> t.Channels:
        rsp = await self.send_command(commands.PrimaryChannelMaskGetReq())
        return t.Channels.from_channel_list(tuple(rsp.channel_mask))

    async def set_channel_mask(self, channels: t.Channels) -> None:
        await self.send_command(
            commands.PrimaryChannelMaskSetReq(
                channel_mask=ShiftedChannels.from_channel_list(channels)
            )
        )

    async def set_channel(self, channel: int) -> None:
        await self.set_channel_mask(channels=t.Channels.from_channel_list([channel]))

    async def form_network(
        self,
        role: DeviceType = DeviceType.COORDINATOR,
        install_code_policy: bool = False,
        # For coordinators/routers
        max_children: t.uint8_t = 20,
        # For end devices
        ed_timeout: t.uint8_t = 0,
        keep_alive: t.uint32_t = 0,
    ) -> None:
        await self.send_command(
            commands.FormNetworkReq(
                role=role,
                install_code_policy=install_code_policy,
                max_children=max_children,
                ed_timeout=ed_timeout,
                keep_alive=keep_alive,
            )
        )

        # TODO: wait for the `form_network` indication as well?
        await asyncio.sleep(2)

    async def start(self, autostart: bool) -> Status:
        await self.send_command(commands.StartReq(autostart=autostart))

        # TODO: wait for the `form_network` indication as well?
        await asyncio.sleep(2)

    async def get_mac_address(self):
        rsp = await self.send_command(commands.LongAddrGetReq())

        return rsp.ieee

    async def set_mac_address(self, parameter: t.EUI64):
        await self.send_command(commands.LongAddrSetReq(ieee=parameter))

    async def get_nwk_address(self):
        rsp = await self.send_command(commands.ShortAddrGetReq())

        return rsp.short_addr

    async def set_nwk_address(self, parameter: t.uint16_t):
        await self.send_command(commands.ShortAddrSetReq(short_addr=parameter))

    async def get_nwk_panid(self):
        rsp = await self.send_command(commands.PanidGetReq())

        return rsp.panid

    async def set_nwk_panid(self, parameter: t.PanId):
        await self.send_command(commands.PanidSetReq(panid=parameter))

    async def get_nwk_extended_panid(self):
        rsp = await self.send_command(commands.ExtpanidGetReq())

        return rsp.ieee

    async def set_nwk_extended_panid(self, parameter: t.ExtendedPanId):
        await self.send_command(commands.ExtpanidSetReq(ieee=parameter))

    async def get_current_channel(self) -> int:
        rsp = await self.send_command(commands.CurrentChannelGetReq())

        return rsp.channel

    async def get_nwk_update_id(self):
        rsp = await self.send_command(commands.NwkUpdateIdGetReq())

        return rsp.nwk_update_id

    async def set_nwk_update_id(self, parameter: t.uint8_t):
        await self.send_command(commands.NwkUpdateIdSetReq(nwk_update_id=parameter))

    async def get_network_key(self):
        rsp = await self.send_command(commands.NetworkKeyGetReq())

        return rsp.nwk_key

    async def set_network_key(self, key: t.KeyData):
        await self.send_command(commands.NetworkKeySetReq(nwk_key=key))

    async def get_nwk_frame_counter(self):
        rsp = await self.send_command(commands.NwkFrameCounterGetReq())

        return rsp.nwk_frame_counter

    async def set_nwk_frame_counter(self, counter: t.uint32_t):
        await self.send_command(
            commands.NwkFrameCounterSetReq(nwk_frame_counter=counter)
        )

    async def get_trust_center_address(self):
        rsp = await self.send_command(commands.TrustCenterAddressGetReq())

        return rsp.trust_center_addr

    async def set_trust_center_address(self, addr: t.EUI64) -> None:
        await self.send_command(
            commands.TrustCenterAddressSetReq(trust_center_addr=addr)
        )

    async def get_link_key(self) -> Any:
        rsp = await self.send_command(commands.LinkKeyGetReq())

        return rsp.key

    async def set_link_key(self, key: t.KeyData):
        await self.send_command(commands.LinkKeySetReq(key=key))

    async def get_security_mode(self):
        rsp = await self.send_command(commands.SecurityModeGetReq())

        return rsp.security_mode

    async def set_security_mode(self, mode: SecurityMode):
        await self.send_command(commands.SecurityModeSetReq(security_mode=mode))

    async def add_endpoint(
        self,
        endpoint: t.uint8_t,
        profile: t.uint16_t,
        device_type: t.uint16_t,
        device_version: t.uint8_t,
        input_clusters: list[t.ClusterId],
        output_clusters: list[t.ClusterId],
    ):
        if profile == 0xC05E:
            return

        await self.send_command(
            commands.AddEndpointReq(
                endpoint=endpoint,
                profile_id=profile,
                device_id=device_type,
                app_flags=device_version,
                input_cluster_count=len(input_clusters),
                output_cluster_count=len(output_clusters),
                input_cluster_list=input_clusters,
                output_cluster_list=output_clusters,
            )
        )

    async def set_use_predefined_nwk_panid(self, use_predefined: t.Bool):
        await self.send_command(
            commands.UsePredefinedNwkPanidSetReq(
                predefined=use_predefined,
            )
        )

    async def set_permit_join(self, duration: t.uint8_t):
        await self.send_command(
            commands.PermitJoiningReq(
                duration=duration,
            )
        )

    async def get_network_role(self) -> DeviceType:
        rsp = await self.send_command(commands.NetworkRoleGetReq())
        return rsp.role

    async def set_network_role(self, role: DeviceType) -> None:
        await self.send_command(commands.NetworkRoleSetReq(role=role))

    async def aps_data_request(
        self,
        dst_addr: t.EUI64,
        dst_ep: t.uint8_t,
        src_addr: t.EUI64,
        src_ep: t.uint8_t,
        profile: t.uint16_t,
        addr_mode: t.AddrMode,
        cluster: t.uint16_t,
        sequence: t.uint16_t,
        options: TransmitOptions,
        radius: t.uint16_t,
        data: bytes,
    ):
        for delay in REQUEST_RETRY_DELAYS:
            try:
                await self.send_command(
                    commands.ApsDataRequestReq(
                        dst_addr=dst_addr,
                        dst_endpoint=dst_ep,
                        src_endpoint=src_ep,
                        address_mode=addr_mode,
                        profile_id=profile,
                        cluster_id=cluster,
                        tx_options=options,
                        use_alias=False,
                        alias_src_addr=src_addr,
                        alias_seq_num=sequence,
                        radius=radius,
                        asdu_length=len(data),
                        asdu=data,
                    )
                )
            except CommandError as ex:
                LOGGER.debug("'aps_data_request' failure: %s", ex)
                if delay is None or ex.status != Status.BUSY:
                    raise

                LOGGER.debug("retrying 'aps_data_request' in %ss", delay)
                await asyncio.sleep(delay)
            else:
                return

    async def get_network_state(self) -> NetworkState:
        rsp = await self.send_command(commands.NetworkStateReq())

        return rsp.network_state

    async def _poll_until_running(self):
        async with asyncio_timeout(POLL_UNTIL_RUNNING_TIMEOUT):
            while True:
                await asyncio.sleep(0.5)

                try:
                    LOGGER.debug("Polling firmware to see if it is running")
                    await self.system_firmware()
                    break
                except asyncio.TimeoutError:
                    pass

    async def reset(self) -> None:
        await self.send_command(commands.SystemResetReq(), wait_for_response=False)
        await self._poll_until_running()

    async def factory_reset(self):
        await self.send_command(commands.SystemFactoryReq(), wait_for_response=False)
        await self._poll_until_running()

    async def system_firmware(self):
        rsp = await self.send_command(commands.SystemFirmwareReq())

        return rsp.firmware_version

    async def system_model(self):
        rsp = await self.send_command(commands.SystemModelReq())

        return rsp.payload

    async def system_manufacturer(self):
        rsp = await self.send_command(commands.SystemManufacturerReq())

        return rsp.payload
