"""Espressif Zigbee NCP Serial Protocol API."""

from __future__ import annotations

import asyncio
import collections
import itertools
import logging
import sys
from typing import Any, Callable

if sys.version_info[:2] < (3, 11):
    from async_timeout import timeout as asyncio_timeout  # pragma: no cover
else:
    from asyncio import timeout as asyncio_timeout  # pragma: no cover

from zigpy.config import CONF_DEVICE_PATH
import zigpy.types as t
from zigpy.zdo.types import SimpleDescriptor

from zigpy_espzb.exception import APIException, CommandError, MismatchedResponseError
from zigpy_espzb.types import Bytes, DeviceAddrMode, ZnspTransmitOptions, list_replace
import zigpy_espzb.uart

LOGGER = logging.getLogger(__name__)

COMMAND_TIMEOUT = 1.8
PROBE_TIMEOUT = 2
REQUEST_RETRY_DELAYS = (0.5, 1.0, 1.5, None)

FRAME_LENGTH = object()
PAYLOAD_LENGTH = object()


class DeviceType(t.enum8):
    COORDINATOR = 0
    ROUTER = 1
    ED = 2


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
    CONFIRM = (4,)
    INDICATION = (5,)


class DeviceState(t.Struct):
    network_state: NetworkState


class SecurityMode(t.enum8):
    NO_SECURITY = 0x00
    PRECONFIGURED_NETWORK_KEY = 0x01
    NETWORK_KEY_FROM_TC = 0x02
    ONLY_TCLK = 0x03


class ZDPResponseHandling(t.bitmap16):
    NONE = 0x0000
    NodeDescRsp = 0x0001


class FormNetwork(t.Struct):
    role: DeviceType
    policy: t.Bool
    nwk_cfg0: t.uint8_t
    nwk_cfg1: t.uint32_t


class CommandId(t.uint16_t):
    networkinit = 0x0000
    start = 0x0001
    device_state = 0x0002
    change_network_state = 0x0003
    form_network = 0x0004
    permit_joining = 0x0005
    panid_get = 0x000B
    panid_set = 0x000C
    extpanid_get = 0x000D
    extpanid_set = 0x000E
    channel_mask_get = 0x000F
    channel_mask_set = 0x0010
    current_channel_get = 0x0013
    current_channel_set = 0x0014
    network_key_get = 0x0017
    network_key_set = 0x0018
    nwk_frame_counter_get = 0x0019
    nwk_frame_counter_set = 0x001A
    aps_designed_coordinator_get = 0x001B
    aps_designed_coordinator_set = 0x001C
    short_addr_get = 0x001D
    short_addr_set = 0x001E
    long_addr_get = 0x001F
    long_addr_set = 0x0020
    nwk_update_id_get = 0x0023
    nwk_update_id_set = 0x0024
    trust_center_address_get = 0x0025
    trust_center_address_set = 0x0026
    link_key_get = 0x0027
    link_key_set = 0x0028
    security_mode_get = 0x0029
    security_mode_set = 0x002A
    use_predefined_nwk_panid_set = 0x002B
    addendpoint = 0x0100
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


class IndexedKey(t.Struct):
    index: t.uint8_t
    key: t.KeyData


class LinkKey(t.Struct):
    ieee: t.EUI64
    key: t.KeyData


class IndexedEndpoint(t.Struct):
    index: t.uint8_t
    descriptor: SimpleDescriptor


class UpdateNeighborAction(t.enum8):
    ADD = 0x01


class Command(t.Struct):
    flags: t.uint16_t
    command_id: CommandId
    seq: t.uint8_t
    payload: Bytes


COMMAND_SCHEMAS = {
    CommandId.networkinit: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.start: (
        {
            "payload_length": PAYLOAD_LENGTH,
            "autostart": t.Bool,
        },
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.form_network: (
        {
            "payload_length": PAYLOAD_LENGTH,
            "form_mwk": FormNetwork,
        },
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {
            "payload_length": t.uint16_t,
            "extended_panid": t.EUI64,
            "panid": t.uint16_t,
            "channel": t.uint8_t,
        },
    ),
    CommandId.permit_joining: (
        {
            "payload_length": PAYLOAD_LENGTH,
            "form_mwk": FormNetwork,
        },
        {
            "payload_length": t.uint16_t,
            "permit": t.uint8_t,
        },
        {
            "payload_length": t.uint16_t,
            "permit": t.uint8_t,
        },
    ),
    CommandId.extpanid_get: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {"payload_length": t.uint16_t, "ieee": t.EUI64},
        {},
    ),
    CommandId.extpanid_set: (
        {"payload_length": PAYLOAD_LENGTH, "ieee": t.EUI64},
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.panid_get: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {"payload_length": t.uint16_t, "panid": t.uint16_t},
        {},
    ),
    CommandId.panid_set: (
        {"payload_length": PAYLOAD_LENGTH, "panid": t.PanId},
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.short_addr_get: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {"payload_length": t.uint16_t, "short_addr": t.uint16_t},
        {},
    ),
    CommandId.short_addr_set: (
        {"payload_length": PAYLOAD_LENGTH, "short_addr": t.uint16_t},
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.long_addr_get: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {"payload_length": t.uint16_t, "ieee": t.EUI64},
        {},
    ),
    CommandId.long_addr_set: (
        {"payload_length": PAYLOAD_LENGTH, "ieee": t.EUI64},
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.current_channel_get: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {"payload_length": t.uint16_t, "channel": t.uint8_t},
        {},
    ),
    CommandId.current_channel_set: (
        {"payload_length": PAYLOAD_LENGTH, "channel": t.uint8_t},
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.channel_mask_get: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {"payload_length": t.uint16_t, "channel_mask": t.uint32_t},
        {},
    ),
    CommandId.channel_mask_set: (
        {"payload_length": PAYLOAD_LENGTH, "channel_mask": t.Channels},
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.addendpoint: (
        {
            "payload_length": PAYLOAD_LENGTH,
            "endpoint": t.uint8_t,
            "profileId": t.uint16_t,
            "deviceId": t.uint16_t,
            "appFlags": t.uint8_t,
            "inputClusterCount": t.uint8_t,
            "outputClusterCount": t.uint8_t,
            "inputClusterList": t.List[t.uint8_t],
            "outputClusterList": t.List[t.uint8_t],
        },
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.device_state: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {
            "payload_length": t.uint16_t,
            "device_state": DeviceState,
        },
        {},
    ),
    CommandId.change_network_state: (
        {
            "payload_length": PAYLOAD_LENGTH,
            "network_state": t.uint8_t,
        },
        {
            "payload_length": t.uint16_t,
            "network_state": t.uint8_t,
        },
        {},
    ),
    CommandId.aps_data_request: (
        {
            "payload_length": PAYLOAD_LENGTH,
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
            "asdu": t.List[t.uint8_t],
        },
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.aps_data_indication: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {
            "payload_length": t.uint16_t,
            "device_state": DeviceState,
            "dst_addr_mode": t.uint8_t,
            "dst_addr": t.EUI64,
            "dst_ep": t.uint8_t,
            "src_addr_mode": t.uint8_t,
            "src_addr": t.EUI64,
            "src_ep": t.uint8_t,
            "profile_id": t.uint16_t,
            "cluster_id": t.uint16_t,
            "indication_status": TXStatus,
            "security_status": t.uint8_t,
            "lqi": t.uint8_t,
            "rx_time": t.uint32_t,
            "asdu_length": t.uint32_t,
            "asdu": t.List[t.uint8_t],
        },
        {
            "payload_length": t.uint16_t,
            "device_state": DeviceState,
            "dst_addr_mode": t.uint8_t,
            "dst_addr": t.EUI64,
            "dst_ep": t.uint8_t,
            "src_addr_mode": t.uint8_t,
            "src_addr": t.EUI64,
            "src_ep": t.uint8_t,
            "profile_id": t.uint16_t,
            "cluster_id": t.uint16_t,
            "indication_status": TXStatus,
            "security_status": t.uint8_t,
            "lqi": t.uint8_t,
            "rx_time": t.uint32_t,
            "asdu_length": t.uint32_t,
            "asdu": t.List[t.uint8_t],
        },
    ),
    CommandId.aps_data_confirm: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {
            "payload_length": t.uint16_t,
            "device_state": DeviceState,
            "dst_addr_mode": t.uint8_t,
            "dst_addr": t.EUI64,
            "dst_ep": t.uint8_t,
            "src_ep": t.uint8_t,
            "tx_time": t.uint32_t,
            "request_id": t.uint8_t,
            "confirm_status": TXStatus,
            "asdu_length": t.uint32_t,
            "asdu": t.List[t.uint8_t],
        },
        {
            "payload_length": t.uint16_t,
            "device_state": DeviceState,
            "dst_addr_mode": t.uint8_t,
            "dst_addr": t.EUI64,
            "dst_ep": t.uint8_t,
            "src_ep": t.uint8_t,
            "tx_time": t.uint32_t,
            "confirm_status": TXStatus,
            "asdu_length": t.uint32_t,
            "asdu": t.List[t.uint8_t],
        },
    ),
    CommandId.network_key_get: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {"payload_length": t.uint16_t, "nwk_key": t.KeyData},
        {},
    ),
    CommandId.network_key_set: (
        {"payload_length": PAYLOAD_LENGTH, "nwk_key": t.KeyData},
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.nwk_frame_counter_get: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {"payload_length": t.uint16_t, "nwk_frame_counter": t.uint32_t},
        {},
    ),
    CommandId.nwk_frame_counter_set: (
        {"payload_length": PAYLOAD_LENGTH, "nwk_frame_counter": t.uint32_t},
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.aps_designed_coordinator_get: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {"payload_length": t.uint16_t, "role": t.uint8_t},
        {},
    ),
    CommandId.aps_designed_coordinator_set: (
        {"payload_length": PAYLOAD_LENGTH, "role": t.uint8_t},
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.use_predefined_nwk_panid_set: (
        {"payload_length": PAYLOAD_LENGTH, "predefined": t.Bool},
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.nwk_update_id_get: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {"payload_length": t.uint16_t, "nwk_update_id": t.uint8_t},
        {},
    ),
    CommandId.nwk_update_id_set: (
        {"payload_length": PAYLOAD_LENGTH, "nwk_update_id": t.uint8_t},
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.trust_center_address_get: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {"payload_length": t.uint16_t, "trust_center_addr": t.EUI64},
        {},
    ),
    CommandId.trust_center_address_set: (
        {"payload_length": PAYLOAD_LENGTH, "trust_center_addr": t.EUI64},
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.link_key_get: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {"payload_length": t.uint16_t, "link_key": LinkKey},
        {},
    ),
    CommandId.link_key_set: (
        {"payload_length": PAYLOAD_LENGTH, "link_key": t.KeyData},
        {
            "payload_length": t.uint16_t,
            "status": Status,
        },
        {},
    ),
    CommandId.security_mode_get: (
        {
            "payload_length": PAYLOAD_LENGTH,
        },
        {"payload_length": t.uint16_t, "security_mode": SecurityMode},
        {},
    ),
    CommandId.security_mode_set: (
        {"payload_length": PAYLOAD_LENGTH, "security_mode": SecurityMode},
        {
            "payload_length": t.uint16_t,
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
        self._device_state = DeviceState(
            network_state=NetworkState.OFFLINE,
        )

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
        return self._device_state.network_state

    async def connect(self) -> None:
        assert self._uart is None
        self._uart = await zigpy_espzb.uart.connect(self._config, self)

        await self.network_init()

        device_state_rsp = await self.send_command(CommandId.device_state)
        self._device_state = device_state_rsp["device_state"]

        self._data_poller_task = asyncio.create_task(self._data_poller())

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

    async def send_command(self, cmd, **kwargs) -> Any:
        while True:
            try:
                return await self._command(cmd, **kwargs)
            except MismatchedResponseError as exc:
                LOGGER.debug("Firmware responded incorrectly (%s), retrying", exc)

    async def _command(self, cmd, **kwargs):
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
            elif name in ("frame_length", "payload_length"):
                value = param_type
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

        if PAYLOAD_LENGTH in payload:
            payload = list_replace(
                lst=payload,
                old=PAYLOAD_LENGTH,
                new=t.uint16_t(
                    sum(len(p) for p in payload[payload.index(PAYLOAD_LENGTH) + 1 :])
                ).serialize(),
            )

        command = Command(
            flags=0x0000,
            command_id=cmd,
            seq=None,
            payload=b"".join(payload),
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

        if command.flags == 0x0010:
            _, rx_schema, _ = COMMAND_SCHEMAS[command.command_id]
        elif command.flags == 0x0020:
            _, _, rx_schema = COMMAND_SCHEMAS[command.command_id]

        fut = None
        wrong_fut_cmd_id = None

        try:
            fut = self._awaiting[command.seq][command.command_id][0]
        except IndexError:
            # XXX: The firmware can sometimes respond with the wrong response. Find the
            # future associated with it so we can throw an appropriate error.
            for cmd_id, futs in self._awaiting[command.seq].items():
                if futs:
                    fut = futs[0]
                    wrong_fut_cmd_id = cmd_id
                    break

        try:
            params, rest = t.deserialize_dict(command.payload, rx_schema)
        except Exception:
            LOGGER.warning("Failed to parse command %s", command, exc_info=True)

            if fut is not None and not fut.done():
                fut.set_exception(
                    APIException(f"Failed to deserialize command: {command}")
                )

            return

        if rest:
            LOGGER.debug("Unparsed data remains after frame: %s, %s", command, rest)

        if "payload_length" in params:
            running_length = itertools.accumulate(
                len(v.serialize()) if v is not None else 0 for v in params.values()
            )
            length_at_param = dict(zip(params.keys(), running_length))

            assert (
                len(data) - length_at_param["payload_length"] - 5
                == params["payload_length"]
            )

        LOGGER.debug(
            "Received command %s%s (seq %d)", command.command_id, params, command.seq
        )

        status = Status.SUCCESS
        if "status" in params:
            status = params["status"]

        exc = None

        if wrong_fut_cmd_id is not None:
            exc = MismatchedResponseError(
                command.command_id,
                params,
                (
                    f"Response is mismatched! Sent {wrong_fut_cmd_id},"
                    f" received {command.command_id}"
                ),
            )
        elif status != Status.SUCCESS:
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

        if handler := getattr(self, f"_handle_{command.command_id}", None):
            handler_params = {
                k: v
                for k, v in params.items()
                if k not in ("frame_length", "payload_length")
            }

            # Queue up the callback within the event loop
            asyncio.get_running_loop().call_soon(lambda: handler(**handler_params))

    async def _data_poller(self):
        while True:
            await self._data_poller_event.wait()
            self._data_poller_event.clear()

            if self._device_state.network_state == NetworkState.OFFLINE:
                continue

            # Poll data indication
            rsp = await self.send_command(CommandId.aps_data_indication)
            self._handle_device_state_changed(
                Status.SUCCESS, device_state=rsp["device_state"]
            )

            if rsp["device_state"] == NetworkState.INDICATION:
                self._app.packet_received(
                    t.ZigbeePacket(
                        src=t.AddrModeAddress(
                            addr_mode=rsp["src_addr_mode"],
                            address=rsp["src_addr"],
                        ),
                        src_ep=rsp["src_ep"],
                        dst=t.AddrModeAddress(
                            addr_mode=rsp["dst_addr_mode"],
                            address=rsp["dst_addr"],
                        ),
                        dst_ep=rsp["dst_ep"],
                        tsn=None,
                        profile_id=rsp["profile_id"],
                        cluster_id=rsp["cluster_id"],
                        data=t.SerializableBytes(rsp["asdu"]),
                        lqi=rsp["lqi"],
                        rssi=rsp["rssi"],
                    )
                )

            # Poll data confirm
            rsp = await self.send_command(CommandId.aps_data_confirm)
            self._handle_device_state_changed(
                Status.SUCCESS, device_state=rsp["device_state"]
            )

    def _handle_device_state_changed(
        self,
        status: t.Status,
        device_state: DeviceState,
        reserved: t.uint8_t = 0,
    ) -> None:
        if device_state.network_state != self.network_state:
            LOGGER.debug(
                "Network device_state transition: %s -> %s",
                self.network_state.name,
                device_state.network_state.name,
            )

        self._device_state = device_state
        self._data_poller_event.set()

    def _handle_device_state(
        self,
        status: t.Status,
        device_state: DeviceState,
        reserved1: t.uint8_t,
        reserved2: t.uint8_t,
    ) -> None:
        self._handle_device_state_changed(status=status, device_state=device_state)

    async def network_init(self):
        await self.send_command(CommandId.networkinit)
        await self.form_network(
            FormNetwork(
                role=DeviceType.COORDINATOR, policy=False, nwk_cfg0=0x14, nwk_cfg1=0
            )
        )
        await self.start(False)

        return Status.SUCCESS

    async def channel_mask(self):
        rssult = []
        rsp = await self.send_command(CommandId.channel_mask_get)

        for index in range(32):
            if (rsp["channel_mask"] & (1 << index)) != 0:
                rssult.append(index)

        return rssult

    async def set_channel_mask(self, parameter: t.Channels):
        rsp = await self.send_command(
            CommandId.channel_mask_set, channel_mask=parameter
        )

        return rsp["status"]

    async def form_network(self, parameter: FormNetwork):
        rsp = await self.send_command(
            CommandId.form_network,
            form_mwk=parameter,
        )

        return rsp["status"]

    async def start(self, parameter: t.uint8_t):
        rsp = await self.send_command(CommandId.start, autostart=parameter)

        return rsp["status"]

    async def mac_address(self):
        rsp = await self.send_command(CommandId.long_addr_get)

        return rsp["ieee"]

    async def set_mac_address(self, parameter: t.EUI64):
        rsp = await self.send_command(CommandId.long_addr_set, ieee=parameter)

        return rsp["status"]

    async def nwk_address(self):
        rsp = await self.send_command(CommandId.short_addr_get)

        return rsp["short_addr"]

    async def set_nwk_address(self, parameter: t.uint16_t):
        rsp = await self.send_command(CommandId.short_addr_set, short_addr=parameter)

        return rsp["status"]

    async def nwk_panid(self):
        rsp = await self.send_command(CommandId.panid_get)

        return rsp["panid"]

    async def set_nwk_panid(self, parameter: t.PanId):
        rsp = await self.send_command(CommandId.panid_set, panid=parameter)

        return rsp["status"]

    async def nwk_extended_panid(self):
        rsp = await self.send_command(CommandId.extpanid_get)

        return rsp["ieee"]

    async def set_nwk_extended_panid(self, parameter: t.ExtendedPanId):
        rsp = await self.send_command(CommandId.extpanid_set, panid=parameter)

        return rsp["status"]

    async def current_channel(self):
        rsp = await self.send_command(CommandId.current_channel_get)

        return rsp["channel"]

    async def nwk_update_id(self):
        rsp = await self.send_command(CommandId.nwk_update_id_get)

        return rsp["nwk_update_id"]

    async def set_nwk_update_id(self, parameter: t.uint8_t):
        rsp = await self.send_command(
            CommandId.nwk_update_id_set, nwk_update_id=parameter
        )

        return rsp["status"]

    async def network_key(self):
        rsp = await self.send_command(CommandId.network_key_get)

        indexed_key = IndexedKey(index=0, key=rsp["nwk_key"])

        return indexed_key

    async def set_network_key(self, parameter: IndexedKey):
        rsp = await self.send_command(CommandId.network_key_set, nwk_key=parameter.key)

        return rsp["status"]

    async def nwk_frame_counter(self):
        rsp = await self.send_command(CommandId.nwk_frame_counter_get)

        return rsp["nwk_frame_counter"]

    async def set_nwk_frame_counter(self, parameter: t.uint32_t):
        rsp = await self.send_command(
            CommandId.nwk_frame_counter_set,
            nwk_frame_counter=parameter,
        )

        return rsp["status"]

    async def trust_center_address(self):
        rsp = await self.send_command(CommandId.trust_center_address_get)

        return rsp["trust_center_addr"]

    async def set_trust_center_address(self, parameter: t.EUI64):
        rsp = await self.send_command(
            CommandId.trust_center_address_set, trust_center_addr=parameter
        )

        return rsp["status"]

    async def link_key(self, parameter: Any = None) -> Any:
        rsp = await self.send_command(CommandId.link_key_get)

        return rsp["link_key"]

    async def set_link_key(self, parameter: LinkKey):
        rsp = await self.send_command(CommandId.link_key_set, link_key=parameter.key)

        return rsp["status"]

    async def security_mode(self):
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
        input_clusters: t.LVList[t.uint16_t],
        output_clusters: t.LVList[t.uint16_t],
    ):
        inputClusterList = t.LVList[t.uint16_t].serialize(input_clusters)
        outputClusterList = t.LVList[t.uint16_t].serialize(output_clusters)

        if profile == 0xC05E:
            return Status.SUCCESS

        rsp = await self.send_command(
            CommandId.addendpoint,
            endpoint=endpoint,
            profileId=profile,
            deviceId=device_type,
            appFlags=device_version,
            inputClusterCount=len(input_clusters),
            outputClusterCount=len(output_clusters),
            inputClusterList=t.List(inputClusterList[1:]),
            outputClusterList=t.List(outputClusterList[1:]),
        )

        return rsp["status"]

    async def set_use_predefined_nwk_panid(self, parameter: t.Bool):
        rsp = await self.send_command(
            CommandId.use_predefined_nwk_panid_set,
            predefined=parameter,
        )

        return rsp["status"]

    async def set_permit_join(self, parameter: t.uint8_t):
        rsp = await self.send_command(
            CommandId.permit_join_set,
            role=parameter,
        )

        return rsp["status"]

    async def set_watchdog_ttl(self, parameter: t.uint16_t):
        rsp = await self.send_command(
            CommandId.watchdog_ttl_set,
            role=parameter,
        )

        return rsp["status"]

    async def aps_designed_coordinator(self):
        rsp = await self.send_command(
            CommandId.aps_designed_coordinator_get,
            reserved=0,
        )

        return rsp["role"]

    async def set_aps_designed_coordinator(self, parameter: t.uint8_t):
        rsp = await self.send_command(
            CommandId.aps_designed_coordinator_set,
            role=parameter,
        )

        return rsp["status"]

    async def aps_extended_panid(self):
        rsp = await self.send_command(CommandId.extpanid_get)

        return rsp["ieee"]

    async def set_aps_extended_panid(self, parameter: t.ExtendedPanId):
        rsp = await self.send_command(CommandId.extpanid_set, ieee=parameter)

        return rsp["status"]

    async def aps_data_request(
        self,
        dst_addr: t.EUI64,
        dst_ep: t.uint8_t,
        src_addr: t.EUI64,
        src_ep: t.uint8_t,
        profile: t.uint16_t,
        addr_mode: DeviceAddrMode,
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
                rsp = await self.send_command(
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
                self._handle_device_state_changed(
                    status=rsp["status"],
                    device_state=DeviceState(network_state=NetworkState.CONNECTED),
                )
                return

    async def get_device_state(self) -> DeviceState:
        rsp = await self.send_command(CommandId.device_state)

        return rsp["device_state"]

    async def change_network_state(self, new_state: NetworkState) -> None:
        await self.send_command(CommandId.change_network_state, network_state=new_state)

    async def add_neighbour(
        self, nwk: t.NWK, ieee: t.EUI64, mac_capability_flags: t.uint8_t
    ) -> None:
        await self.send_command(
            CommandId.update_neighbor,
            action=UpdateNeighborAction.ADD,
            nwk=nwk,
            ieee=ieee,
            mac_capability_flags=mac_capability_flags,
        )
