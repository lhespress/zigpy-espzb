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
        self._energy_scan_future: asyncio.Future | None = None
        self._network_update_future: asyncio.Future | None = None
        # Fired when we receive FormNetworkInd which indicates the network is actually formed.
        # Note: FormNetworkRsp only means the command was accepted; formation completion is async.
        self._form_network_event = asyncio.Event()
        self._form_network_pending = False
        self._last_form_network_ind: dict[str, Any] | None = None
        # Track pending APS data requests by sequence number for confirm handling
        self._pending_aps_requests: dict[int, dict[str, Any]] = {}
        # Store last APS request for matching 0x3e responses (ZDO loopback)
        self._last_aps_request: dict[str, Any] | None = None

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
        if exc is not None:
            LOGGER.warning(
                "Serial %r connection lost unexpectedly: %r",
                self._config[CONF_DEVICE_PATH],
                exc,
            )
        else:
            LOGGER.debug(
                "Serial %r connection closed",
                self._config[CONF_DEVICE_PATH],
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
            # Only call handler for indications, not responses
            # Responses are handled via futures above
            if command.frame_type == FrameType.Indicate:
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

    def _extract_nwk_addr_from_indication(
        self,
        addr_type: int,
        src_addr: t.EUI64,
        dst_addr: int,
    ) -> int:
        """Extract NWK address from indication based on address type.
        
        Args:
            addr_type: Address type (0 = NWK 16-bit, 1 = IEEE 64-bit)
            src_addr: Source address union (8 bytes, interpreted based on addr_type)
            dst_addr: Destination address (16-bit, may be incorrect from NCP)
            
        Returns:
            16-bit NWK address
        """
        if addr_type == 0:
            # NWK address mode: extract 16-bit address from first 2 bytes (little-endian)
            src_bytes = src_addr.serialize()
            nwk_addr = int.from_bytes(src_bytes[:2], 'little')
            return nwk_addr
        else:
            # IEEE address mode: we can't directly get NWK from IEEE here
            # Fall back to dst_addr (which may be incorrect)
            return dst_addr

    def _handle_attribute_read(
        self,
        status: t.uint8_t,
        frame_control: t.uint8_t,
        manuf_code: t.uint16_t,
        tsn: t.uint8_t,
        rssi: t.uint8_t,
        src_addr_type: t.uint8_t,
        src_addr: t.EUI64,
        dst_addr: t.uint16_t,
        src_ep: t.uint8_t,
        dst_ep: t.uint8_t,
        cluster_id: t.uint16_t,
        profile_id: t.uint16_t,
        command_id: t.uint8_t,
        command_direction: t.uint8_t,
        command_is_common: t.uint8_t,
        variable_count: t.uint8_t,
        attribute_data: Bytes,
    ):
        """Handle ZCL attribute read response indication (loopback).
        
        When the coordinator sends a ZCL request to itself, the NCP
        responds with an attribute_read indication containing the response.
        
        Per documentation:
        - variable_count is at fixed offset 26 in the header
        - Each attribute: status(1) + attr_id(2) + type(1) + size(2) + value(N) = 6+N bytes
        
        Actual NCP behavior:
        - variable_count may be 0, with actual count in attribute_data[1]
        - Each attribute appears to be 7 bytes (with extra padding)
        """
        LOGGER.debug(
            "Received attribute_read indication: status=%d, tsn=%d, "
            "src_ep=%d, dst_ep=%d, cluster_id=0x%04x, profile_id=0x%04x, "
            "command_id=%d, variable_count=%d, attribute_data=%s",
            status,
            tsn,
            src_ep,
            dst_ep,
            cluster_id,
            profile_id,
            command_id,
            variable_count,
            attribute_data.hex() if len(attribute_data) <= 32 else f"{attribute_data[:32].hex()}...",
        )
        
        # Build the ZCL Read Attributes Response frame
        # Format: [frame_control, tsn, command_id, ...attribute responses...]
        
        # Build the ZCL response frame
        zcl_frame = bytearray()
        
        # Frame control: server-to-client (0x08), global command
        # If manufacturer specific, add 0x04
        if manuf_code != 0:
            zcl_frame.append(0x1C)  # global, server-to-client, disable default, mfr specific
            zcl_frame.extend(manuf_code.to_bytes(2, 'little'))
        else:
            zcl_frame.append(0x18)  # global, server-to-client, disable default response
        
        zcl_frame.append(tsn)
        zcl_frame.append(0x01)  # Read Attributes Response command
        
        # Parse attribute data per NCP documentation format:
        # Each attribute: 7 + value_size bytes
        #   offset 0: status (1)
        #   offset 1: attribute.id (2, LE)
        #   offset 3: attribute.data.type (1)
        #   offset 4: attribute.data.size (2, LE)
        #   offset 6: attribute.data.value (N)
        #   After value: 1 byte padding/extra (to make fixed part 7 bytes)
        
        LOGGER.debug(
            "Parsing %d attributes from attribute_data (%d bytes)",
            variable_count, len(attribute_data),
        )
        
        offset = 0
        for i in range(variable_count):
            # Minimum 7 bytes per attribute (fixed part per documentation "7 + value_size")
            if offset + 7 > len(attribute_data):
                LOGGER.warning(
                    "Not enough data for attribute %d: need at least 7 bytes at offset %d, "
                    "have %d bytes total",
                    i + 1, offset, len(attribute_data),
                )
                break
            
            # Parse attribute fields
            attr_status = attribute_data[offset]
            attr_id = int.from_bytes(attribute_data[offset+1:offset+3], 'little')
            attr_type = attribute_data[offset+3]
            value_size = int.from_bytes(attribute_data[offset+4:offset+6], 'little')
            
            LOGGER.debug(
                "  Attribute %d: status=0x%02X, attr_id=0x%04X, type=0x%02X, size=%d",
                i + 1, attr_status, attr_id, attr_type, value_size,
            )
            
            # Extract value if present (starts at offset 6, before the extra byte)
            attr_value = b''
            if value_size > 0:
                # Value is between offset+6 and the extra byte
                if offset + 6 + value_size + 1 <= len(attribute_data):
                    attr_value = attribute_data[offset+6:offset+6+value_size]
                else:
                    LOGGER.warning(
                        "Not enough data for attribute %d value: need %d bytes at offset %d",
                        i + 1, value_size, offset + 6,
                    )
                    # Try to get as much as possible
                    available = len(attribute_data) - (offset + 7)
                    if available > 0:
                        value_size = min(value_size, available)
                        attr_value = attribute_data[offset+6:offset+6+value_size]
            
            # Build ZCL response: attr_id(2) + status(1) + [type(1) + value] if SUCCESS
            zcl_frame.extend(attr_id.to_bytes(2, 'little'))
            zcl_frame.append(attr_status)
            
            if attr_status == 0x00:  # SUCCESS - include type and value
                zcl_frame.append(attr_type)
                zcl_frame.extend(attr_value)
            
            # Move to next attribute: 7 bytes fixed + value_size
            offset += 7 + value_size
        
        LOGGER.debug(
            "Constructed ZCL response: %s",
            zcl_frame.hex() if len(zcl_frame) <= 32 else f"{bytes(zcl_frame[:32]).hex()}...",
        )
        
        # Determine NWK address based on src_addr_type or stored request
        # The NCP's dst_addr field may be incorrect (e.g., 0xFE00 instead of 0xFFFE)
        if self._last_aps_request is not None:
            # Prefer stored request information (most reliable)
            req_dst_addr = self._last_aps_request.get("dst_addr")
            if req_dst_addr is not None:
                # Extract NWK address from EUI64 (first 2 bytes in little-endian)
                nwk_addr = int.from_bytes(req_dst_addr.serialize()[:2], 'little')
            else:
                # Fall back to parsing from indication based on addr_type
                nwk_addr = self._extract_nwk_addr_from_indication(src_addr_type, src_addr, dst_addr)
            req_src_ep = self._last_aps_request.get("src_ep", src_ep)
            req_dst_ep = self._last_aps_request.get("dst_ep", dst_ep)
        else:
            # No stored request, parse from indication based on addr_type
            nwk_addr = self._extract_nwk_addr_from_indication(src_addr_type, src_addr, dst_addr)
            req_src_ep = src_ep
            req_dst_ep = dst_ep
        
        LOGGER.debug(
            "Using NWK address 0x%04X for ZCL response (src_addr_type=%d)",
            nwk_addr,
            src_addr_type,
        )
        
        # Build source address using the correct NWK address
        src_address = t.AddrModeAddress(
            addr_mode=t.AddrMode.NWK,
            address=nwk_addr,
        )
        
        # Create the ZigbeePacket with the ZCL response
        self._app.packet_received(
            t.ZigbeePacket(
                src=src_address,
                src_ep=req_src_ep,
                dst=src_address,  # Loopback: dst is same as src
                dst_ep=req_dst_ep,
                tsn=tsn,
                profile_id=profile_id,
                cluster_id=cluster_id,
                data=t.SerializableBytes(bytes(zcl_frame)),
                lqi=255,
                rssi=rssi if rssi != 0 else None,
            )
        )
        
        # Clear the last request
        self._last_aps_request = None

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

    def _handle_form_network(
        self, extended_panid: t.EUI64, panid: t.PanId, channel: t.uint8_t
    ) -> None:
        """Handle FormNetworkInd.

        This indication means the network formation actually completed and the
        final parameters are known. This must be used as the readiness gate
        before sending network-management commands like NetworkUpdateReq.
        """
        self._last_form_network_ind = {
            "extended_panid": extended_panid,
            "panid": panid,
            "channel": int(channel),
        }
        self._form_network_pending = False
        self._form_network_event.set()

    def _handle_network_update(self, status: Status) -> None:
        """Handle NetworkUpdateInd notification from firmware."""
        LOGGER.info("Network update notification: status=%s", status)

        fut = self._network_update_future
        if fut is not None and not fut.done():
            fut.set_result(status)

    def _handle_aps_data_confirm(
        self,
        network_state: NetworkState,
        dst_addr_mode: ExtendedAddrMode,
        dst_addr: t.EUI64,
        dst_ep: t.uint8_t,
        src_ep: t.uint8_t,
        tx_time: t.uint32_t,
        confirm_status: TXStatus,
        asdu_length: t.uint32_t,
        asdu: Bytes,
    ) -> None:
        """Handle APS data confirm indication.
        
        This indicates the result of an APS data request transmission.
        The confirm_status tells us if the packet was successfully sent.
        We notify the waiting aps_data_request call to reduce retry attempts.
        
        Special case: confirm_status=0x3e indicates a ZDO loopback response.
        In this case, the asdu contains the ZDO response data, not the original request.
        """
        LOGGER.debug(
            "Received APS data confirm: dst_addr=%s, dst_ep=%d, src_ep=%d, "
            "confirm_status=%s, asdu_length=%d",
            dst_addr,
            dst_ep,
            src_ep,
            confirm_status,
            asdu_length,
        )
        
        # Special handling for confirm_status=0x3e (ZDO loopback response)
        # When device sends ZDO request to itself, NCP returns the response
        # embedded in ApsDataConfirmInd with status=0x3e
        # Note: For broadcast messages, 0x3e is just a success confirmation, not a response
        if confirm_status.value == 0x3E and len(asdu) >= 3 and self._last_aps_request is not None:
            last_req = self._last_aps_request
            
            # Check if this was a broadcast request (don't treat as ZDO response)
            last_dst_addr = last_req.get("dst_addr")
            if last_dst_addr is not None:
                # EUI64 serializes in little-endian format, so 0xFFFC becomes \xfc\xff at the start
                # Check first 2 bytes of serialized address
                dst_addr_bytes = last_dst_addr.serialize()[:2]
                is_broadcast = dst_addr_bytes in (
                    b'\xfc\xff',  # 0xFFFC - ALL_ROUTERS_AND_COORDINATOR (little-endian)
                    b'\xfd\xff',  # 0xFFFD - ALL_ROUTERS (little-endian)
                    b'\xff\xff',  # 0xFFFF - BROADCAST_ALL (little-endian)
                )
                if is_broadcast:
                    LOGGER.debug(
                        "0x3e confirm for broadcast request, treating as success confirmation"
                    )
                    # For broadcast, 0x3e means success - notify the pending request
                    # Extract sequence based on profile_id:
                    # - ZDO (profile_id=0): TSN at asdu[0]
                    # - ZCL (profile_id!=0): TSN at asdu[1]
                    profile_id = last_req.get("profile_id", 0)
                    if profile_id == 0 and len(asdu) > 0:
                        sequence = asdu[0]
                    elif profile_id != 0 and len(asdu) > 1:
                        sequence = asdu[1]
                    else:
                        sequence = None
                    
                    if sequence is not None and sequence in self._pending_aps_requests:
                            pending = self._pending_aps_requests[sequence]
                            future = pending["future"]
                            if not future.done():
                                # Treat 0x3e as SUCCESS for broadcast
                                future.set_result(TXStatus.SUCCESS)
                                LOGGER.debug(
                                    "Notified pending broadcast APS request (sequence=%d) as SUCCESS",
                                    sequence,
                                )
                    # Clear last request and return early
                    self._last_aps_request = None
                    return
                elif last_req.get("profile_id") == 0:
                    # This is a ZDO loopback response (unicast to self)
                    request_cluster_id = last_req.get("cluster_id", 0)
                    response_cluster_id = request_cluster_id + 0x8000  # Response ID
                    tsn = last_req.get("sequence", 0)
                    
                    LOGGER.debug(
                        "Detected ZDO loopback response: request_cluster=0x%04x, "
                        "response_cluster=0x%04x, tsn=%d, asdu=%s",
                        request_cluster_id,
                        response_cluster_id,
                        tsn,
                        asdu.hex() if len(asdu) <= 32 else f"{asdu[:32].hex()}...",
                    )
                    
                    # Construct ZigbeePacket and pass to application
                    # Use the last request's dst_addr as src for the response
                    req_dst_addr = last_req.get("dst_addr")
                    
                    self._app.packet_received(
                        t.ZigbeePacket(
                            src=addr_mode_with_eui64_to_addr_mode_address(
                                last_req.get("addr_mode", ExtendedAddrMode.MODE_16_ENDP_PRESENT),
                                req_dst_addr,
                            ),
                            src_ep=0,  # ZDO endpoint
                            dst=addr_mode_with_eui64_to_addr_mode_address(
                                last_req.get("addr_mode", ExtendedAddrMode.MODE_16_ENDP_PRESENT),
                                req_dst_addr,
                            ),
                            dst_ep=0,  # ZDO endpoint
                            tsn=tsn,
                            profile_id=0,  # ZDO
                            cluster_id=response_cluster_id,
                            data=t.SerializableBytes(asdu),
                            lqi=0,
                            rssi=None,
                        )
                    )
                    
                    # Clear the last request
                    self._last_aps_request = None
                    return
        
        # Normal confirm handling: extract sequence number from asdu
        # The sequence number position depends on the message type:
        # - ZDO (profile_id=0): TSN is at asdu[0]
        # - ZCL (profile_id!=0): TSN is at asdu[1] (after frame control byte)
        if len(asdu) > 0:
            # Determine sequence position based on profile_id from last request
            profile_id = 0
            if self._last_aps_request is not None:
                profile_id = self._last_aps_request.get("profile_id", 0)
            
            if profile_id == 0:
                # ZDO: TSN is first byte
                sequence = asdu[0]
            else:
                # ZCL: TSN is second byte (after frame control)
                if len(asdu) > 1:
                    sequence = asdu[1]
                else:
                    LOGGER.warning(
                        "ZCL asdu too short to extract TSN: asdu=%s",
                        asdu.hex(),
                    )
                    return
            
            # Find the pending request and notify it
            if sequence in self._pending_aps_requests:
                pending = self._pending_aps_requests[sequence]
                future = pending["future"]
                
                if not future.done():
                    future.set_result(confirm_status)
                    LOGGER.debug(
                        "Notified pending APS request (sequence=%d) with confirm_status=%s",
                        sequence,
                        confirm_status,
                    )
                else:
                    LOGGER.debug(
                        "Pending APS request (sequence=%d) future already done",
                        sequence,
                    )
            else:
                LOGGER.debug(
                    "No pending APS request found for sequence=%d",
                    sequence,
                )
        else:
            LOGGER.warning(
                "APS data confirm received with empty asdu, cannot extract sequence number",
            )
        
        # Log the confirmation status for debugging
        if confirm_status != TXStatus.SUCCESS and confirm_status.value != 0x3E:
            LOGGER.warning(
                "APS data request failed: confirm_status=%s, dst_addr=%s",
                confirm_status,
                dst_addr,
            )
        else:
            LOGGER.debug(
                "APS data request confirmed successful: dst_addr=%s",
                dst_addr,
            )

    def _handle_energy_scan(
        self,
        status: t.uint8_t,
        channel_count: t.uint8_t,
        energy_values: Bytes,
    ) -> None:
        """Handle energy scan indication.
        
        Based on observed data format: status (uint8), channel_count (uint8), 
        followed by energy values. The energy values may be in channel order (11-26)
        or in a different format. We'll parse them based on channel_count.
        """
        LOGGER.debug(
            "Received energy scan indication: status=0x%02x, channel_count=%d, energy_values_len=%d, data=%s",
            status,
            channel_count,
            len(energy_values),
            energy_values.hex(),
        )
        
        result = {}
        channels = list(t.Channels.ALL_CHANNELS)
        
        # Parse energy values
        # Based on observed data format: energy_values contains (channel, energy) pairs
        # Format: [channel11, energy11, channel12, energy12, ..., channel26, energy26]
        # So energy_values length should be channel_count * 2
        
        if len(energy_values) >= channel_count * 2:
            # Parse as (channel, energy) pairs - this is the expected format
            # Energy values are signed int8: convert from unsigned byte to signed integer
            for i in range(0, min(len(energy_values) - 1, channel_count * 2), 2):
                if i + 1 < len(energy_values):
                    channel = energy_values[i]
                    energy_unsigned = energy_values[i + 1]
                    # Convert unsigned byte (0-255) to signed int8 (-128 to 127)
                    energy_signed = energy_unsigned if energy_unsigned < 128 else energy_unsigned - 256
                    if 11 <= channel <= 26:
                        result[channel] = float(energy_signed)
        elif len(energy_values) == channel_count:
            # Fallback: parse as simple array (one energy value per channel in order)
            # Energy values are signed int8: convert from unsigned byte to signed integer
            for i in range(min(channel_count, len(channels))):
                if i < len(energy_values):
                    energy_unsigned = energy_values[i]
                    # Convert unsigned byte (0-255) to signed int8 (-128 to 127)
                    energy_signed = energy_unsigned if energy_unsigned < 128 else energy_unsigned - 256
                    result[channels[i]] = float(energy_signed)
        else:
            # Unexpected format
            LOGGER.warning(
                "Unexpected energy scan data format: channel_count=%d, data_len=%d, expected %d or %d bytes",
                channel_count,
                len(energy_values),
                channel_count * 2,
                channel_count,
            )
            # Fill with zeros for all channels if we can't parse
            for channel in channels:
                result[channel] = 0.0
        
        # Ensure all channels in ALL_CHANNELS are present (fill missing with 0)
        for channel in channels:
            if channel not in result:
                result[channel] = 0.0
        
        LOGGER.debug("Parsed energy scan results: %s", result)
        
        if self._energy_scan_future is not None and not self._energy_scan_future.done():
            self._energy_scan_future.set_result(result)

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
        # FormNetworkRsp only indicates acceptance; we must wait for FormNetworkInd
        # before considering the network formed/usable for management commands.
        self._form_network_pending = True
        self._last_form_network_ind = None
        self._form_network_event.clear()

        await self.send_command(
            commands.FormNetworkReq(
                role=role,
                install_code_policy=install_code_policy,
                max_children=max_children,
                ed_timeout=ed_timeout,
                keep_alive=keep_alive,
            )
        )

        # Wait until the NCP tells us the network is actually formed
        await self.wait_for_form_network_ind(timeout=30.0)

    async def start(self, autostart: bool) -> Status:
        await self.send_command(commands.StartReq(autostart=autostart))

        # Give stack a moment to settle; formation is signaled via FormNetworkInd
        await asyncio.sleep(0.2)

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
    
    async def set_current_channel(self, channel: int) -> None:
        # Device expects uint32_t channel mask, not single channel value
        # Convert single channel (11-26) to channel mask
        # Zigbee channel mask: channel 11 = bit 10, channel 12 = bit 11, etc.
        # Mask = 1 << (channel - 1)
        if not (11 <= channel <= 26):
            raise ValueError(f"Invalid channel: {channel}, must be between 11 and 26")
        
        # Use ShiftedChannels to convert channel to mask
        channel_mask = ShiftedChannels.from_channel_list([channel])
        await self.send_command(commands.CurrentChannelSetReq(channel=channel_mask))

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
            # Create a future to wait for APS data confirm for this attempt
            confirm_future = asyncio.Future()
            self._pending_aps_requests[sequence] = {
                "future": confirm_future,
                "dst_addr": dst_addr,
                "dst_ep": dst_ep,
                "src_ep": src_ep,
                "sequence": sequence,
                "cluster_id": cluster,
                "profile_id": profile,
                "addr_mode": addr_mode,
            }
            # Also store as last request for matching 0x3e responses
            self._last_aps_request = self._pending_aps_requests[sequence]
            
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
                
                # Wait for APS data confirm with timeout
                # If confirm indicates failure, we can skip remaining retries
                try:
                    async with asyncio_timeout(COMMAND_TIMEOUT):
                        confirm_status = await confirm_future
                        
                        # Check if this is a broadcast address
                        # For broadcast, 0x3e is a success indication
                        # EUI64 serializes in little-endian format, so 0xFFFC becomes \xfc\xff at the start
                        dst_addr_bytes = dst_addr.serialize()[:2]
                        is_broadcast = dst_addr_bytes in (
                            b'\xfc\xff',  # 0xFFFC - ALL_ROUTERS_AND_COORDINATOR (little-endian)
                            b'\xfd\xff',  # 0xFFFD - ALL_ROUTERS (little-endian)
                            b'\xff\xff',  # 0xFFFF - BROADCAST_ALL (little-endian)
                        )
                        
                        # Treat 0x3e as success for broadcast messages
                        is_success = (
                            confirm_status == TXStatus.SUCCESS or
                            (is_broadcast and confirm_status.value == 0x3E)
                        )
                        
                        if not is_success:
                            # Transmission failed immediately
                            LOGGER.debug(
                                "APS data request confirm failed: status=%s, sequence=%d",
                                confirm_status,
                                sequence,
                            )
                            # If this is the last retry attempt, raise exception
                            if delay is None:
                                raise CommandError(
                                    Status.ERROR,
                                    f"APS data request failed after retries: {confirm_status}",
                                )
                            # Otherwise, continue to next retry
                            continue
                        else:
                            # Success - we can return early
                            LOGGER.debug(
                                "APS data request confirmed successful: sequence=%d%s",
                                sequence,
                                " (broadcast 0x3e)" if is_broadcast and confirm_status.value == 0x3E else "",
                            )
                            return
                except asyncio.TimeoutError:
                    # Confirm timeout - the request was sent but we didn't get confirm
                    # This might mean the packet was sent but confirm is delayed
                    # or the packet failed silently. Continue with normal flow.
                    LOGGER.debug(
                        "APS data confirm timeout for sequence %d, assuming sent",
                        sequence,
                    )
                    # Return anyway since the request was accepted
                    return
                    
            except CommandError as ex:
                LOGGER.debug("'aps_data_request' failure: %s", ex)
                if delay is None or ex.status != Status.BUSY:
                    raise

                LOGGER.debug("retrying 'aps_data_request' in %ss", delay)
                await asyncio.sleep(delay)
            finally:
                # Clean up pending request for this attempt
                if sequence in self._pending_aps_requests:
                    del self._pending_aps_requests[sequence]

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
        # Reset clears volatile state; any prior formation indication is no longer valid.
        self._form_network_pending = False
        self._last_form_network_ind = None
        self._form_network_event.clear()

    async def factory_reset(self):
        await self.send_command(commands.SystemFactoryReq(), wait_for_response=False)
        await self._poll_until_running()
        # Factory reset wipes network settings.
        self._form_network_pending = False
        self._last_form_network_ind = None
        self._form_network_event.clear()

    async def wait_for_form_network_ind(self, *, timeout: float = 30.0) -> dict[str, Any]:
        """Wait until we receive FormNetworkInd.

        Returns the last FormNetworkInd payload as a dict.
        """
        if self._form_network_event.is_set() and self._last_form_network_ind is not None:
            return self._last_form_network_ind

        async with asyncio_timeout(timeout):
            await self._form_network_event.wait()

        # Event is set, but keep a defensive fallback
        return self._last_form_network_ind or {}

    async def system_firmware(self):
        rsp = await self.send_command(commands.SystemFirmwareReq())

        return rsp.firmware_version

    async def system_model(self):
        rsp = await self.send_command(commands.SystemModelReq())

        return rsp.payload

    async def system_manufacturer(self):
        rsp = await self.send_command(commands.SystemManufacturerReq())

        return rsp.payload

    async def persist_config(self) -> None:
        """Persist network configuration to NVS.
        
        This command writes all network parameters that have been set via
        set_xxx() commands to non-volatile storage (NVS). Parameters are
        only written to memory until this command is called.
        
        This should be called after setting all network parameters in
        write_network_info() to ensure they persist across reboots.
        """
        rsp = await self.send_command(commands.PersistConfigReq())
        if rsp.status != Status.SUCCESS:
            raise CommandError(rsp.status, f"Failed to persist config: {rsp.status}")

    async def energy_scan(self, channel_mask: t.uint32_t, duration: t.uint8_t) -> dict[int, float]:
        """Perform energy scan and wait for results.
        
        Returns:
            Dictionary mapping channel number to energy level (0-255)
        """
        # Create a future to wait for the energy scan indication
        self._energy_scan_future = asyncio.Future()
        
        try:
            await self.send_command(commands.EnergyScanReq(channel_mask=channel_mask, duration=duration))
            
            # Wait for the energy scan indication with timeout
            try:
                async with asyncio_timeout(COMMAND_TIMEOUT * 10):  # Allow more time for scanning
                    result = await self._energy_scan_future
                    return result
            except asyncio.TimeoutError:
                LOGGER.warning("Timeout waiting for energy scan indication")
                return {}
        finally:
            self._energy_scan_future = None

    async def network_update(self, channel: int, duration: t.uint8_t, dst_addr: t.uint16_t, scan_count: t.uint8_t, nwk_update_id: t.uint8_t):
        if not (11 <= channel <= 26):
            raise ValueError(f"Invalid channel: {channel}, must be between 11 and 26")

        # Wait for firmware notification if available; fall back to polling on timeout.
        if self._network_update_future is not None and not self._network_update_future.done():
            self._network_update_future.cancel()

        self._network_update_future = asyncio.Future()

        try:
            await self.send_command(
                commands.NetworkUpdateReq(
                    channel_mask=ShiftedChannels.from_channel_list([channel]),
                    duration=duration,
                    dst_addr=dst_addr,
                    scan_count=scan_count,
                    nwk_update_id=nwk_update_id,
                )
            )

            try:
                async with asyncio_timeout(COMMAND_TIMEOUT * 10):
                    ind_status: Status = await self._network_update_future
                    if ind_status != Status.SUCCESS:
                        LOGGER.warning(
                            "Network update notification returned status=%s", ind_status
                        )
            except asyncio.TimeoutError:
                LOGGER.debug(
                    "No network update notification received; falling back to polling"
                )
        finally:
            fut = self._network_update_future
            if fut is not None and not fut.done():
                fut.cancel()
            self._network_update_future = None
