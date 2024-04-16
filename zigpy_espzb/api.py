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

from zigpy_espzb.commands import COMMAND_SCHEMAS, Command, CommandId, FrameType
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
    TXStatus,
    ZnspTransmitOptions,
    addr_mode_with_eui64_to_addr_mode_address,
)
import zigpy_espzb.uart

LOGGER = logging.getLogger(__name__)

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

    async def send_command(self, cmd, **kwargs):
        tx_schema, _, _ = COMMAND_SCHEMAS[cmd]

        params = tx_schema(**kwargs)
        serialized_payload = params.serialize()

        command = Command(
            version=0b0000,
            frame_type=FrameType.Request,
            reserved=0x00,
            command_id=cmd,
            seq=None,
            length=len(serialized_payload),
            payload=serialized_payload,
        )

        if self._uart is None:
            # connection was lost
            raise CommandError(Status.ERROR, "API is not running")

        async with self._command_lock:
            seq = self._seq

            LOGGER.debug("Sending %s (seq=%s)", params, seq)
            self._uart.send(command.replace(seq=seq).serialize())

            self._seq = (self._seq % 255) + 1

            fut = asyncio.Future()
            self._awaiting[seq][cmd].append(fut)

            try:
                async with asyncio_timeout(COMMAND_TIMEOUT):
                    return await fut
            except asyncio.TimeoutError:
                LOGGER.debug("No response to '%s' command with seq %d", cmd, seq)
                raise
            finally:
                self._awaiting[seq][cmd].remove(fut)

    def data_received(self, data: bytes) -> None:
        command, _ = Command.deserialize(data)

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

        status = None

        if hasattr(params, "status"):
            status = params.status

        exc = None

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
                    "Duplicate or delayed response for 0x:%02x sequence",
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
        await self.send_command(CommandId.network_init)

    async def get_channel_mask(self) -> t.Channels:
        rsp = await self.send_command(CommandId.primary_channel_mask_get)
        return t.Channels.from_channel_list(tuple(rsp.channel_mask))

    async def set_channel_mask(self, channels: t.Channels) -> None:
        await self.send_command(
            CommandId.primary_channel_mask_set,
            channel_mask=ShiftedChannels.from_channel_list(channels),
        )

    async def set_channel(self, channel: int) -> None:
        await self.send_command(CommandId.current_channel_set, channel=channel)

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
        rsp = await self.send_command(
            CommandId.form_network,
            role=role,
            install_code_policy=install_code_policy,
            max_children=max_children,
            ed_timeout=ed_timeout,
            keep_alive=keep_alive,
        )

        # TODO: wait for the `form_network` indication as well?
        await asyncio.sleep(2)

        return rsp.status

    async def leave_network(self) -> None:
        await self.send_command(CommandId.leave_network)

    async def start(self, autostart: bool) -> Status:
        rsp = await self.send_command(CommandId.start, autostart=t.uint8_t(autostart))

        # TODO: wait for the `form_network` indication as well?
        await asyncio.sleep(2)

        return rsp.status

    async def get_mac_address(self):
        rsp = await self.send_command(CommandId.long_addr_get)

        return rsp.ieee

    async def set_mac_address(self, parameter: t.EUI64):
        rsp = await self.send_command(CommandId.long_addr_set, ieee=parameter)

        return rsp.status

    async def get_nwk_address(self):
        rsp = await self.send_command(CommandId.short_addr_get)

        return rsp.short_addr

    async def set_nwk_address(self, parameter: t.uint16_t):
        rsp = await self.send_command(CommandId.short_addr_set, short_addr=parameter)

        return rsp.status

    async def get_nwk_panid(self):
        rsp = await self.send_command(CommandId.panid_get)

        return rsp.panid

    async def set_nwk_panid(self, parameter: t.PanId):
        rsp = await self.send_command(CommandId.panid_set, panid=parameter)

        return rsp.status

    async def get_nwk_extended_panid(self):
        rsp = await self.send_command(CommandId.extpanid_get)

        return rsp.ieee

    async def set_nwk_extended_panid(self, parameter: t.ExtendedPanId):
        rsp = await self.send_command(CommandId.extpanid_set, ieee=parameter)

        return rsp.status

    async def get_current_channel(self) -> int:
        rsp = await self.send_command(CommandId.current_channel_get)

        return rsp.channel

    async def get_nwk_update_id(self):
        rsp = await self.send_command(CommandId.nwk_update_id_get)

        return rsp.nwk_update_id

    async def set_nwk_update_id(self, parameter: t.uint8_t):
        rsp = await self.send_command(
            CommandId.nwk_update_id_set, nwk_update_id=parameter
        )

        return rsp.status

    async def get_network_key(self):
        rsp = await self.send_command(CommandId.network_key_get)

        return rsp.nwk_key

    async def set_network_key(self, key: t.KeyData):
        await self.send_command(CommandId.network_key_set, nwk_key=key)

    async def get_nwk_frame_counter(self):
        rsp = await self.send_command(CommandId.nwk_frame_counter_get)

        return rsp.nwk_frame_counter

    async def set_nwk_frame_counter(self, parameter: t.uint32_t):
        rsp = await self.send_command(
            CommandId.nwk_frame_counter_set,
            nwk_frame_counter=parameter,
        )

        return rsp.status

    async def get_trust_center_address(self):
        rsp = await self.send_command(CommandId.trust_center_address_get)

        return rsp.trust_center_addr

    async def set_trust_center_address(self, parameter: t.EUI64):
        rsp = await self.send_command(
            CommandId.trust_center_address_set, trust_center_addr=parameter
        )

        return rsp.status

    async def get_link_key(self) -> Any:
        rsp = await self.send_command(CommandId.link_key_get)

        return rsp.key

    async def set_link_key(self, key: t.KeyData):
        await self.send_command(CommandId.link_key_set, key=key)

    async def get_security_mode(self):
        rsp = await self.send_command(CommandId.security_mode_get)

        return rsp.security_mode

    async def set_security_mode(self, parameter: SecurityMode):
        rsp = await self.send_command(
            CommandId.security_mode_set, security_mode=parameter
        )

        return rsp.status

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
            return Status.SUCCESS

        rsp = await self.send_command(
            CommandId.add_endpoint,
            endpoint=endpoint,
            profile_id=profile,
            device_id=device_type,
            app_flags=device_version,
            input_cluster_count=len(input_clusters),
            output_cluster_count=len(output_clusters),
            input_cluster_list=input_clusters,
            output_cluster_list=output_clusters,
        )

        return rsp.status

    async def set_use_predefined_nwk_panid(self, parameter: t.Bool):
        rsp = await self.send_command(
            CommandId.use_predefined_nwk_panid_set,
            predefined=parameter,
        )

        return rsp.status

    async def set_permit_join(self, duration: t.uint8_t):
        rsp = await self.send_command(
            CommandId.permit_joining,
            duration=duration,
        )

        return rsp.status

    async def set_watchdog_ttl(self, parameter: t.uint16_t):
        rsp = await self.send_command(
            CommandId.watchdog_ttl_set,
            role=parameter,
        )

        return rsp.status

    async def get_network_role(self) -> DeviceType:
        rsp = await self.send_command(CommandId.network_role_get)
        return rsp.role

    async def set_network_role(self, role: DeviceType) -> None:
        rsp = await self.send_command(
            CommandId.network_role_set,
            role=role,
        )

        return rsp.status

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
        options: ZnspTransmitOptions,
        radius: t.uint16_t,
        data: bytes,
        relays: list[int] | None = None,
        extended_timeout: bool = False,
    ):
        for delay in REQUEST_RETRY_DELAYS:
            try:
                await self.send_command(
                    CommandId.aps_data_request,
                    dst_addr=dst_addr,
                    dst_endpoint=dst_ep,
                    src_endpoint=src_ep,
                    address_mode=addr_mode,
                    profile_id=profile,
                    cluster_id=cluster,
                    tx_options=options,
                    use_alias=False,
                    src_addr=src_addr,
                    sequence=sequence,
                    radius=radius,
                    asdu_length=len(data),
                    asdu=t.List(data),
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
        rsp = await self.send_command(CommandId.network_state)

        return rsp.network_state

    async def reset(self) -> None:
        # TODO: There is no reset command but we can trigger a crash if we form the
        # network twice

        LOGGER.debug("Resetting via crash...")

        for attempt in range(5):
            try:
                await self.form_network()
            except asyncio.TimeoutError:
                break
        else:
            raise RuntimeError("Failed to trigger a reset/crash")

        await asyncio.sleep(2)

        LOGGER.debug("Reset complete")
