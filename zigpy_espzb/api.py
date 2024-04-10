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

from zigpy_espzb.exception import APIException, CommandError
from zigpy_espzb.types import (
    Bytes,
    ExtendedAddrMode,
    ShiftedChannels,
    ZnspTransmitOptions,
    addr_mode_with_eui64_to_addr_mode_address,
    deserialize_dict,
)
import zigpy_espzb.uart

LOGGER = logging.getLogger(__name__)

COMMAND_TIMEOUT = 1.8
PROBE_TIMEOUT = 2
REQUEST_RETRY_DELAYS = (0.5, 1.0, 1.5, None)


class DeviceType(t.enum8):
    COORDINATOR = 0x00
    ROUTER = 0x01
    END_DEVICE = 0x02
    NONE = 0x03


class Status(t.enum8):
    SUCCESS = 0
    FAILURE = 1
    INVALID_VALUE = 2
    TIMEOUT = 3
    UNSUPPORTED = 4
    ERROR = 5
    NO_NETWORK = 6
    BUSY = 7


class FirmwareVersion(t.Struct, t.uint32_t):
    reserved: t.uint8_t
    patch: t.uint8_t
    minor: t.uint8_t
    major: t.uint8_t


class NetworkState(t.enum8):
    OFFLINE = 0
    JOINING = 1
    CONNECTED = 2
    LEAVING = 3
    CONFIRM = 4
    INDICATION = 5


class SecurityMode(t.enum8):
    NO_SECURITY = 0x00
    PRECONFIGURED_NETWORK_KEY = 0x01


class ZDPResponseHandling(t.bitmap16):
    NONE = 0x0000
    NodeDescRsp = 0x0001


class FormNetwork(t.Struct):
    role: DeviceType
    install_code_policy: t.Bool

    # For coordinators/routers
    max_children: t.uint8_t = t.StructField(
        requires=lambda f: f.role in (DeviceType.ROUTER, DeviceType.COORDINATOR)
    )

    # For end devices
    ed_timeout: t.uint8_t = t.StructField(
        requires=lambda f: f.role == DeviceType.END_DEVICE
    )
    keep_alive: t.uint32_t = t.StructField(
        requires=lambda f: f.role == DeviceType.END_DEVICE
    )


class CommandId(t.enum16):
    network_init = 0x0000
    start = 0x0001
    network_state = 0x0002
    stack_status_handler = 0x0003
    form_network = 0x0004
    permit_joining = 0x0005
    join_network = 0x0006
    leave_network = 0x0007
    start_scan = 0x0008
    scan_complete_handler = 0x0009
    stop_scan = 0x000A
    panid_get = 0x000B
    panid_set = 0x000C
    extpanid_get = 0x000D
    extpanid_set = 0x000E
    primary_channel_mask_get = 0x000F
    primary_channel_mask_set = 0x0010
    secondary_channel_mask_get = 0x0011
    secondary_channel_mask_set = 0x0012
    current_channel_get = 0x0013
    current_channel_set = 0x0014
    tx_power_get = 0x0015
    tx_power_set = 0x0016
    network_key_get = 0x0017
    network_key_set = 0x0018
    nwk_frame_counter_get = 0x0019
    nwk_frame_counter_set = 0x001A
    network_role_get = 0x001B
    network_role_set = 0x001C
    short_addr_get = 0x001D
    short_addr_set = 0x001E
    long_addr_get = 0x001F
    long_addr_set = 0x0020
    channel_masks_get = 0x0021
    channel_masks_set = 0x0022
    nwk_update_id_get = 0x0023
    nwk_update_id_set = 0x0024
    trust_center_address_get = 0x0025
    trust_center_address_set = 0x0026
    link_key_get = 0x0027
    link_key_set = 0x0028
    security_mode_get = 0x0029
    security_mode_set = 0x002A
    use_predefined_nwk_panid_set = 0x002B
    short_to_ieee = 0x002C
    ieee_to_short = 0x002D
    add_endpoint = 0x0100
    remove_endpoint = 0x0101
    attribute_read = 0x0102
    attribute_write = 0x0103
    attribute_report = 0x0104
    attribute_discover = 0x0105
    aps_read = 0x0106
    aps_write = 0x0107
    report_config = 0x0108
    bind_set = 0x0200
    unbind_set = 0x0201
    find_match = 0x0202
    aps_data_request = 0x0300
    aps_data_indication = 0x0301
    aps_data_confirm = 0x0302


class TXStatus(t.enum8):
    SUCCESS = 0x00

    @classmethod
    def _missing_(cls, value):
        chained = t.APSStatus(value)
        status = t.uint8_t.__new__(cls, chained.value)
        status._name_ = chained.name
        status._value_ = value
        return status


class FrameType(t.enum4):
    Request = 0
    Response = 1
    Indicate = 2


class Command(t.Struct):
    version: t.uint4_t
    frame_type: FrameType
    reserved: t.uint8_t

    command_id: CommandId
    seq: t.uint8_t
    length: t.uint16_t
    payload: Bytes


COMMAND_SCHEMAS = {
    CommandId.network_init: (
        {},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.start: (
        {
            "autostart": t.Bool,
        },
        {
            "status": Status,
        },
        {},
    ),
    CommandId.form_network: (
        {
            "form_nwk": FormNetwork,
        },
        {
            "status": Status,
        },
        {
            "extended_panid": t.EUI64,
            "panid": t.PanId,
            "channel": t.uint8_t,
        },
    ),
    CommandId.permit_joining: (
        {
            "duration": t.uint8_t,
        },
        {
            "status": Status,
        },
        {
            "duration": t.uint8_t,
        },
    ),
    CommandId.leave_network: (
        {},
        {
            "status": Status,
        },
        {
            "short_addr": t.NWK,
            "device_addr": t.EUI64,
            "rejoin": t.Bool,
        },
    ),
    CommandId.extpanid_get: (
        {},
        {"ieee": t.EUI64},
        {},
    ),
    CommandId.extpanid_set: (
        {"ieee": t.EUI64},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.panid_get: (
        {},
        {"panid": t.PanId},
        {},
    ),
    CommandId.panid_set: (
        {"panid": t.PanId},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.short_addr_get: (
        {},
        {"short_addr": t.NWK},
        {},
    ),
    CommandId.short_addr_set: (
        {"short_addr": t.NWK},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.long_addr_get: (
        {},
        {"ieee": t.EUI64},
        {},
    ),
    CommandId.long_addr_set: (
        {"ieee": t.EUI64},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.current_channel_get: (
        {},
        {"channel": t.uint8_t},
        {},
    ),
    CommandId.current_channel_set: (
        {"channel": t.uint8_t},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.primary_channel_mask_get: (
        {},
        {"channel_mask": ShiftedChannels},
        {},
    ),
    CommandId.primary_channel_mask_set: (
        {"channel_mask": ShiftedChannels},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.add_endpoint: (
        {
            "endpoint": t.uint8_t,
            "profile_id": t.uint16_t,
            "device_id": t.uint16_t,
            "app_flags": t.uint8_t,
            "input_cluster_count": t.uint8_t,
            "output_cluster_count": t.uint8_t,
            "input_cluster_list": t.List[t.uint16_t],
            "output_cluster_list": t.List[t.uint16_t],
        },
        {
            "status": Status,
        },
        {},
    ),
    CommandId.network_state: (
        {},
        {
            "network_state": NetworkState,
        },
        {},
    ),
    CommandId.stack_status_handler: (
        {},
        {
            "network_state": t.uint8_t,
        },
        {
            "network_state": t.uint8_t,
        },
    ),
    CommandId.aps_data_request: (
        {
            "dst_addr": t.EUI64,
            "dst_endpoint": t.uint8_t,
            "src_endpoint": t.uint8_t,
            "address_mode": t.uint8_t,
            "profile_id": t.uint16_t,
            "cluster_id": t.uint16_t,
            "tx_options": t.uint8_t,
            "use_alias": t.Bool,
            "src_addr": t.EUI64,
            "sequence": t.uint8_t,
            "radius": t.uint8_t,
            "asdu_length": t.uint32_t,
            "asdu": Bytes,
        },
        {
            "status": Status,
        },
        {},
    ),
    CommandId.aps_data_indication: (
        {},
        {
            "network_state": NetworkState,
            "dst_addr_mode": ExtendedAddrMode,
            "dst_addr": t.EUI64,
            "dst_ep": t.uint8_t,
            "src_addr_mode": ExtendedAddrMode,
            "src_addr": t.EUI64,
            "src_ep": t.uint8_t,
            "profile_id": t.uint16_t,
            "cluster_id": t.uint16_t,
            "indication_status": TXStatus,
            "security_status": t.uint8_t,
            "lqi": t.uint8_t,
            "rx_time": t.uint32_t,
            "asdu_length": t.uint32_t,
            "asdu": Bytes,
        },
        {
            "network_state": NetworkState,
            "dst_addr_mode": ExtendedAddrMode,
            "dst_addr": t.EUI64,
            "dst_ep": t.uint8_t,
            "src_addr_mode": ExtendedAddrMode,
            "src_addr": t.EUI64,
            "src_ep": t.uint8_t,
            "profile_id": t.uint16_t,
            "cluster_id": t.uint16_t,
            "indication_status": TXStatus,
            "security_status": t.uint8_t,
            "lqi": t.uint8_t,
            "rx_time": t.uint32_t,
            "asdu_length": t.uint32_t,
            "asdu": Bytes,
        },
    ),
    CommandId.aps_data_confirm: (
        {},
        {
            "network_state": NetworkState,
            "dst_addr_mode": ExtendedAddrMode,
            "dst_addr": t.EUI64,
            "dst_ep": t.uint8_t,
            "src_ep": t.uint8_t,
            "tx_time": t.uint32_t,
            "request_id": t.uint8_t,
            "confirm_status": TXStatus,
            "asdu_length": t.uint32_t,
            "asdu": Bytes,
        },
        {
            "network_state": NetworkState,
            "dst_addr_mode": ExtendedAddrMode,
            "dst_addr": t.EUI64,
            "dst_ep": t.uint8_t,
            "src_ep": t.uint8_t,
            "tx_time": t.uint32_t,
            "confirm_status": TXStatus,
            "asdu_length": t.uint32_t,
            "asdu": Bytes,
        },
    ),
    CommandId.network_key_get: (
        {},
        {"nwk_key": t.KeyData},
        {},
    ),
    CommandId.network_key_set: (
        {"nwk_key": t.KeyData},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.nwk_frame_counter_get: (
        {},
        {"nwk_frame_counter": t.uint32_t},
        {},
    ),
    CommandId.nwk_frame_counter_set: (
        {"nwk_frame_counter": t.uint32_t},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.network_role_get: (
        {},
        {"role": DeviceType},
        {},
    ),
    CommandId.network_role_set: (
        {"role": DeviceType},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.use_predefined_nwk_panid_set: (
        {"predefined": t.Bool},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.nwk_update_id_get: (
        {},
        {"nwk_update_id": t.uint8_t},
        {},
    ),
    CommandId.nwk_update_id_set: (
        {"nwk_update_id": t.uint8_t},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.trust_center_address_get: (
        {},
        {"trust_center_addr": t.EUI64},
        {},
    ),
    CommandId.trust_center_address_set: (
        {"trust_center_addr": t.EUI64},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.link_key_get: (
        {},
        {"ieee": t.EUI64, "key": t.KeyData},
        {},
    ),
    CommandId.link_key_set: (
        {"key": t.KeyData},
        {
            "status": Status,
        },
        {},
    ),
    CommandId.security_mode_get: (
        {},
        {"security_mode": SecurityMode},
        {},
    ),
    CommandId.security_mode_set: (
        {"security_mode": SecurityMode},
        {
            "status": Status,
        },
        {},
    ),
}


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
        payload = []
        tx_schema, _, _ = COMMAND_SCHEMAS[cmd]
        trailing_optional = False

        for name, param_type in tx_schema.items():
            if isinstance(param_type, int):
                if name not in kwargs:
                    # Default value
                    value = param_type.serialize()
                else:
                    value = type(param_type)(kwargs[name]).serialize()
            elif kwargs.get(name) is None:
                trailing_optional = True
                value = None
            elif not isinstance(kwargs[name], param_type):
                value = param_type(kwargs[name]).serialize()
            else:
                value = kwargs[name].serialize()

            if value is None:
                continue

            if trailing_optional:
                raise ValueError(
                    f"Command {cmd} with kwargs {kwargs}"
                    f" has non-trailing optional argument"
                )

            payload.append(value)

        serialized_payload = b"".join(payload)
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

            LOGGER.debug("Sending %s%s (seq=%s)", cmd, kwargs, seq)
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
            params, rest = deserialize_dict(command.payload, schema)
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
            "Received command %s%s (seq %d)", command.command_id, params, command.seq
        )

        status = Status.SUCCESS
        if "status" in params:
            status = params["status"]

        exc = None

        if status != Status.SUCCESS:
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
            asyncio.get_running_loop().call_soon(lambda: handler(**params))

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
        return t.Channels.from_channel_list(tuple(rsp["channel_mask"]))

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
            form_nwk=FormNetwork(
                role=role,
                install_code_policy=install_code_policy,
                max_children=max_children,
                ed_timeout=ed_timeout,
                keep_alive=keep_alive,
            ),
        )

        return rsp["status"]

    async def leave_network(self) -> None:
        await self.send_command(CommandId.leave_network)

    async def start(self, autostart: bool) -> Status:
        rsp = await self.send_command(CommandId.start, autostart=t.uint8_t(autostart))

        return rsp["status"]

    async def get_mac_address(self):
        rsp = await self.send_command(CommandId.long_addr_get)

        return rsp["ieee"]

    async def set_mac_address(self, parameter: t.EUI64):
        rsp = await self.send_command(CommandId.long_addr_set, ieee=parameter)

        return rsp["status"]

    async def get_nwk_address(self):
        rsp = await self.send_command(CommandId.short_addr_get)

        return rsp["short_addr"]

    async def set_nwk_address(self, parameter: t.uint16_t):
        rsp = await self.send_command(CommandId.short_addr_set, short_addr=parameter)

        return rsp["status"]

    async def get_nwk_panid(self):
        rsp = await self.send_command(CommandId.panid_get)

        return rsp["panid"]

    async def set_nwk_panid(self, parameter: t.PanId):
        rsp = await self.send_command(CommandId.panid_set, panid=parameter)

        return rsp["status"]

    async def get_nwk_extended_panid(self):
        rsp = await self.send_command(CommandId.extpanid_get)

        return rsp["ieee"]

    async def set_nwk_extended_panid(self, parameter: t.ExtendedPanId):
        rsp = await self.send_command(CommandId.extpanid_set, panid=parameter)

        return rsp["status"]

    async def get_current_channel(self) -> int:
        rsp = await self.send_command(CommandId.current_channel_get)

        return rsp["channel"]

    async def get_nwk_update_id(self):
        rsp = await self.send_command(CommandId.nwk_update_id_get)

        return rsp["nwk_update_id"]

    async def set_nwk_update_id(self, parameter: t.uint8_t):
        rsp = await self.send_command(
            CommandId.nwk_update_id_set, nwk_update_id=parameter
        )

        return rsp["status"]

    async def get_network_key(self):
        rsp = await self.send_command(CommandId.network_key_get)

        return rsp["nwk_key"]

    async def set_network_key(self, key: t.KeyData):
        await self.send_command(CommandId.network_key_set, nwk_key=key)

    async def get_nwk_frame_counter(self):
        rsp = await self.send_command(CommandId.nwk_frame_counter_get)

        return rsp["nwk_frame_counter"]

    async def set_nwk_frame_counter(self, parameter: t.uint32_t):
        rsp = await self.send_command(
            CommandId.nwk_frame_counter_set,
            nwk_frame_counter=parameter,
        )

        return rsp["status"]

    async def get_trust_center_address(self):
        rsp = await self.send_command(CommandId.trust_center_address_get)

        return rsp["trust_center_addr"]

    async def set_trust_center_address(self, parameter: t.EUI64):
        rsp = await self.send_command(
            CommandId.trust_center_address_set, trust_center_addr=parameter
        )

        return rsp["status"]

    async def get_link_key(self) -> Any:
        rsp = await self.send_command(CommandId.link_key_get)

        return rsp["key"]

    async def set_link_key(self, key: t.KeyData):
        await self.send_command(CommandId.link_key_set, key=key)

    async def get_security_mode(self):
        rsp = await self.send_command(CommandId.security_mode_get)

        return rsp["security_mode"]

    async def set_security_mode(self, parameter: SecurityMode):
        rsp = await self.send_command(
            CommandId.security_mode_set, security_mode=parameter
        )

        return rsp["status"]

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

        return rsp["status"]

    async def set_use_predefined_nwk_panid(self, parameter: t.Bool):
        rsp = await self.send_command(
            CommandId.use_predefined_nwk_panid_set,
            predefined=parameter,
        )

        return rsp["status"]

    async def set_permit_join(self, duration: t.uint8_t):
        rsp = await self.send_command(
            CommandId.permit_joining,
            duration=duration,
        )

        return rsp["status"]

    async def set_watchdog_ttl(self, parameter: t.uint16_t):
        rsp = await self.send_command(
            CommandId.watchdog_ttl_set,
            role=parameter,
        )

        return rsp["status"]

    async def get_network_role(self) -> DeviceType:
        rsp = await self.send_command(CommandId.network_role_get)
        return rsp["role"]

    async def set_network_role(self, role: DeviceType) -> None:
        rsp = await self.send_command(
            CommandId.network_role_set,
            role=role,
        )

        return rsp["status"]

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

        return rsp["network_state"]

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
