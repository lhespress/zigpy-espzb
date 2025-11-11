"""ControllerApplication for Espressif ZNSP protocol based adapters."""

from __future__ import annotations

import asyncio
import importlib.metadata
import logging
import sys
from typing import Any

if sys.version_info[:2] < (3, 11):
    from async_timeout import timeout as asyncio_timeout
else:
    from asyncio import timeout as asyncio_timeout

import zigpy.application
import zigpy.config
import zigpy.device
import zigpy.endpoint
import zigpy.exceptions
from zigpy.exceptions import FormationFailure, NetworkNotFormed
import zigpy.state
import zigpy.types as t
import zigpy.util
import zigpy.zdo.types as zdo_t

from zigpy_espzb.api import Znsp
from zigpy_espzb.types import (
    DeviceType,
    ExtendedAddrMode,
    NetworkState,
    SecurityMode,
    TransmitOptions,
)

LOGGER = logging.getLogger(__name__)

CHANGE_NETWORK_POLL_TIME = 1
CHANGE_NETWORK_STATE_DELAY = 2
SEND_CONFIRM_TIMEOUT = 60

ENERGY_SCAN_ATTEMPTS = 5


class ControllerApplication(zigpy.application.ControllerApplication):
    _probe_config_variants = [
        {zigpy.config.CONF_DEVICE_BAUDRATE: 115200},
    ]

    _watchdog_period = 600 * 0.75

    def __init__(self, config: dict[str, Any]):
        """Initialize instance."""
        # Remove experimental.concurrency keys that are not allowed in zigpy 0.84.0+
        if "experimental" in config:
            experimental = config.get("experimental")
            if isinstance(experimental, dict) and "concurrency" in experimental:
                # concurrency is a dict with PacketPriority keys, remove it entirely
                del experimental["concurrency"]
                if not experimental:  # Remove empty experimental dict
                    del config["experimental"]

        super().__init__(config=config)
        self._api = None

        self._reconnect_task = None

    async def _watchdog_feed(self):
        # TODO: implement a proper software-driven watchdog
        await self._api.get_network_state()

    async def connect(self):
        api = Znsp(self, self._config[zigpy.config.CONF_DEVICE])

        try:
            await api.connect()
        except Exception:
            api.close()
            raise

        await api.reset()
        await api.network_init()

        self._api = api

    async def disconnect(self):
        if self._api is not None:
            self._api.close()
            self._api = None

    async def permit_with_link_key(self, node: t.EUI64, link_key: t.KeyData, time_s=60):
        raise NotImplementedError()

    async def energy_scan(self, channels: t.Channels, duration_exp: int, count: int) -> dict[int, float]:
        """Perform an energy scan on the specified channels.
        
        Args:
            channels: Channels to scan
            duration_exp: Duration exponent (0-14), actual duration = 2^(duration_exp+1) * 15.36ms
            count: Number of scans per channel (not used by NCP, kept for compatibility)
            
        Returns:
            Dictionary mapping channel number to energy level (0-255)
        """
        from zigpy_espzb.types import ShiftedChannels
        
        # Convert zigpy Channels to ShiftedChannels (channel_mask)
        channel_mask = ShiftedChannels.from_zigpy_channels(channels)
        
        # Convert duration_exp to duration (uint8_t)
        # The NCP expects duration in units of 15.36ms * 2^(duration_exp)
        # For compatibility, we use duration_exp directly as duration
        # Duration should be 0-14, but NCP may expect different format
        duration = min(max(duration_exp, 0), 14)
        
        # Call the API energy_scan method and wait for results
        result = await self._api.energy_scan(channel_mask=channel_mask, duration=duration)
        
        LOGGER.debug(
            "Energy scan completed for channels %s with duration_exp=%d, got %d results",
            channels,
            duration_exp,
            len(result),
        )
        
        # Ensure all requested channels are in the result (fill missing with 0)
        # zigpy expects all channels to be present
        for channel in channels:
            if channel not in result:
                result[channel] = 0.0
        
        return result

    async def start_network(self):
        await self.load_network_info(load_devices=False)
        await self.register_endpoints()

        # Create the coordinator device
        coordinator = zigpy.device.Device(
            application=self,
            ieee=self.state.node_info.ieee,
            nwk=self.state.node_info.nwk,
        )
        self.devices[self.state.node_info.ieee] = coordinator

        await self._api.start(autostart=False)
        await self._api.form_network(role=DeviceType.COORDINATOR)

        await coordinator.schedule_initialize()

        # FormNetworkInd indicates the network is actually formed, but `node_info.nwk` may still
        # be the pre-formation placeholder (0xFFFE) read during initialization. Refresh it now.
        try:
            nwk = await self._api.get_nwk_address()
        except Exception as exc:
            LOGGER.debug("Failed to refresh coordinator NWK address after form: %s", exc)
        else:
            # Coordinators always use NWK address 0x0000. Some firmware returns 0xFFFE until
            # the address is explicitly queried after formation; normalize it here.
            if nwk == 0xFFFE:
                nwk = 0x0000

            nwk = t.NWK(nwk)
            if self.state.node_info.nwk != nwk:
                LOGGER.debug(
                    "Updating coordinator NWK address after form: %s -> %s",
                    self.state.node_info.nwk,
                    nwk,
                )
                self.state.node_info.nwk = nwk
                coordinator.nwk = nwk

    async def _change_network_state(
        self,
        target_state: NetworkState,
        *,
        timeout: int = 10 * CHANGE_NETWORK_POLL_TIME,
    ):
        async def change_loop():
            while True:
                try:
                    network_state = await self._api.get_network_state()
                except asyncio.TimeoutError:
                    LOGGER.debug("Failed to poll device state")
                else:
                    if network_state == target_state:
                        break

                await asyncio.sleep(CHANGE_NETWORK_POLL_TIME)

        await self._api.change_network_state(target_state)

        try:
            async with asyncio_timeout(timeout):
                await change_loop()
        except asyncio.TimeoutError:
            if target_state != NetworkState.CONNECTED:
                raise

            raise FormationFailure("Network formation refused.")

    async def reset_network_info(self):
        await self._api.factory_reset()

    async def write_network_info(self, *, network_info, node_info):
        await self._api.factory_reset()
        await self._api.network_init()

        role = {
            zdo_t.LogicalType.Coordinator: DeviceType.COORDINATOR,
            zdo_t.LogicalType.Router: DeviceType.ROUTER,
        }[node_info.logical_type]

        await self._api.set_network_role(role)
        await self._api.set_nwk_address(node_info.nwk)

        if node_info.ieee != t.EUI64.UNKNOWN:
            await self._api.set_mac_address(node_info.ieee)
            node_ieee = node_info.ieee
        else:
            node_ieee = await self._api.get_mac_address()

        await self._api.set_use_predefined_nwk_panid(True)
        await self._api.set_nwk_panid(network_info.pan_id)
        await self._api.set_nwk_extended_panid(network_info.extended_pan_id)
        await self._api.set_nwk_update_id(network_info.nwk_update_id)
        await self._api.set_network_key(network_info.network_key.key)
        await self._api.set_nwk_frame_counter(network_info.network_key.tx_counter)

        if network_info.network_key.seq != 0:
            LOGGER.warning(
                "Doesn't support non-zero network key sequence number: %s",
                network_info.network_key.seq,
            )

        tc_link_key_partner_ieee = network_info.tc_link_key.partner_ieee

        if tc_link_key_partner_ieee == t.EUI64.UNKNOWN:
            tc_link_key_partner_ieee = node_ieee

        await self._api.set_trust_center_address(tc_link_key_partner_ieee)
        await self._api.set_link_key(network_info.tc_link_key.key)

        if network_info.security_level == 0x00:
            await self._api.set_security_mode(SecurityMode.NO_SECURITY)
        else:
            await self._api.set_security_mode(SecurityMode.PRECONFIGURED_NETWORK_KEY)

        await self._api.set_channel(network_info.channel)
        
        # Persist all network parameters to NVS
        await self._api.persist_config()

    async def load_network_info(self, *, load_devices=False):
        channel = await self._api.get_current_channel()

        if not 11 <= channel <= 26:
            raise NetworkNotFormed(f"Channel is invalid: {channel}")

        network_info = self.state.network_info
        node_info = self.state.node_info

        role = await self._api.get_network_role()

        if role == DeviceType.COORDINATOR:
            node_info.logical_type = zdo_t.LogicalType.Coordinator
        else:
            node_info.logical_type = zdo_t.LogicalType.Router

        node_info.nwk = await self._api.get_nwk_address()
        node_info.ieee = await self._api.get_mac_address()

        # TODO: implement firmware commands to read the board name, manufacturer
        node_info.manufacturer = await self._api.system_manufacturer()
        node_info.model = await self._api.system_model()

        # TODO: implement firmware command to read out the firmware version and build ID
        node_info.version = f"{int(self._api.firmware_version):#010x}"

        network_info.source = f"zigpy-espzb@{importlib.metadata.version('zigpy-espzb')}"
        network_info.metadata = {}

        network_info.pan_id = await self._api.get_nwk_panid()
        network_info.extended_pan_id = await self._api.get_nwk_extended_panid()
        network_info.channel = await self._api.get_current_channel()
        network_info.channel_mask = await self._api.get_channel_mask()
        network_info.nwk_update_id = await self._api.get_nwk_update_id()

        if network_info.channel in (0, 255):
            raise NetworkNotFormed(f"Channel is invalid: {network_info.channel}")

        network_info.network_key.key = await self._api.get_network_key()
        network_info.network_key.tx_counter = await self._api.get_nwk_frame_counter()

        network_info.tc_link_key = zigpy.state.Key()
        network_info.tc_link_key.key = await self._api.get_link_key()
        network_info.tc_link_key.partner_ieee = (
            await self._api.get_trust_center_address()
        )

        security_mode = await self._api.get_security_mode()

        if security_mode == SecurityMode.NO_SECURITY:
            network_info.security_level = 0x00
        elif security_mode == SecurityMode.PRECONFIGURED_NETWORK_KEY:
            network_info.security_level = 0x05
        else:
            LOGGER.warning("Unsupported security mode %r", security_mode)
            network_info.security_level = 0x05

    async def force_remove(self, dev):
        """Forcibly remove device from NCP."""

    async def _move_network_to_channel(
        self, new_channel: int, new_nwk_update_id: int
    ) -> None:
        """Move device to a new channel."""
        LOGGER.info("Changing channel from %s to %s", self.state.network_info.channel, new_channel)

        # Ensure the network is actually formed before sending NetworkUpdateReq.
        # FormNetworkRsp only indicates acceptance; formation completion is signaled by FormNetworkInd.
        try:
            await self._api.wait_for_form_network_ind(timeout=30.0)
        except Exception as e:
            # If we're already connected (e.g. network pre-existed), continue;
            # otherwise fail fast rather than sending updates while OFFLINE.
            try:
                state = await self._api.get_network_state()
            except Exception:
                state = None

            if state not in (NetworkState.CONNECTED, NetworkState.INDICATION):
                raise

            LOGGER.debug(
                "Proceeding with channel update without recent FormNetworkInd (state=%r): %s",
                state,
                e,
            )
        
        # Bump NWK Update ID so routers/end-devices follow the change
        await self._api.set_nwk_update_id(new_nwk_update_id)

        # Update channel mask to the target channel and broadcast to network
        # duration=0xFE means channel change, dst_addr=0xFFFD means all routers and coordinator
        await self._api.network_update(new_channel, 0xFE, 0xFFFD, 0, new_nwk_update_id)
        
        # Verify channel was changed before waiting for reconnection. Firmware now
        # handles the channel migration itself, and sends a notification on completion,
        # so we only log and wait.
        try:
            current_channel = await self._api.get_current_channel()
            if current_channel != new_channel:
                LOGGER.info(
                    "Channel not changed yet (current: %s, expected: %s); waiting for stack to switch...",
                    current_channel,
                    new_channel,
                )
        except Exception as e:
            LOGGER.warning("Could not verify channel before waiting: %s", e)
        
        LOGGER.info("Waiting for network to reconnect on channel %s...", new_channel)

        # Wait for the NCP to come back online on the new channel
        async def wait_connected():
            poll_count = 0
            while True:
                poll_count += 1
                try:
                    state = await self._api.get_network_state()
                    state_value = state.value if hasattr(state, "value") else state
                    state_name = state.name if hasattr(state, "name") else str(state)
                    LOGGER.info(
                        "Polling network state (attempt %d): %s (value: %d, type: %s)",
                        poll_count,
                        state_name,
                        state_value,
                        type(state).__name__,
                    )
                    # Accept both CONNECTED (2) and INDICATION (5) as connected states
                    is_connected = state == NetworkState.CONNECTED
                    is_indication = state == NetworkState.INDICATION
                    # Also check by value as a fallback
                    is_connected_by_value = state_value == 2
                    is_indication_by_value = state_value == 5
                    LOGGER.debug(
                        "State comparison: CONNECTED=%s/%s, INDICATION=%s/%s",
                        is_connected,
                        is_connected_by_value,
                        is_indication,
                        is_indication_by_value,
                    )
                    if is_connected or is_indication or is_connected_by_value or is_indication_by_value:
                        LOGGER.info("Network reconnected, verifying channel change...")
                        # Verify the channel was actually changed
                        try:
                            actual_channel = await self._api.get_current_channel()
                            if actual_channel == new_channel:
                                LOGGER.info(
                                    "Channel change confirmed: device is now on channel %s",
                                    new_channel,
                                )
                                return
                            else:
                                LOGGER.warning(
                                    "Channel change verification failed: expected %s, got %s. "
                                    "Network may need more time to switch channels.",
                                    new_channel,
                                    actual_channel,
                                )
                                # Continue polling to see if channel changes
                                if poll_count < 10:  # Give it a few more attempts
                                    await asyncio.sleep(CHANGE_NETWORK_POLL_TIME)
                                    continue
                                else:
                                    raise FormationFailure(
                                        f"Channel change failed: expected {new_channel}, "
                                        f"but device is still on channel {actual_channel}"
                                    )
                        except FormationFailure:
                            raise
                        except Exception as e:
                            LOGGER.warning(
                                "Could not verify channel change: %s. Assuming success.", e
                            )
                            return
                except asyncio.TimeoutError:
                    # Log timeout but keep polling
                    LOGGER.warning(
                        "Network state query timed out (attempt %d), retrying...",
                        poll_count,
                    )
                except Exception as e:
                    LOGGER.warning(
                        "Error querying network state (attempt %d): %s, retrying...",
                        poll_count,
                        e,
                    )
                await asyncio.sleep(CHANGE_NETWORK_POLL_TIME)

        # Use a bounded wait to avoid hanging indefinitely
        try:
            async with asyncio_timeout(30):
                await wait_connected()
        except asyncio.TimeoutError:
            LOGGER.error(
                "Timeout waiting for network to reconnect on channel %s after 30 seconds",
                new_channel,
            )
            raise

    async def move_network_to_channel(self, new_channel: int) -> None:
        """Move network to a new channel (public API)."""
        # Calculate new NWK update ID (increment current one)
        current_nwk_update_id = self.state.network_info.nwk_update_id
        new_nwk_update_id = (current_nwk_update_id + 1) % 256
        
        # Call our implementation which already handles reconnection
        await self._move_network_to_channel(new_channel, new_nwk_update_id)
        
        # Update the state to reflect the new channel
        self.state.network_info.channel = new_channel
        self.state.network_info.nwk_update_id = new_nwk_update_id

    async def add_endpoint(self, descriptor: zdo_t.SimpleDescriptor) -> None:
        """Register a new endpoint on the device."""

        await self._api.add_endpoint(
            endpoint=descriptor.endpoint,
            profile=descriptor.profile,
            device_type=descriptor.device_type,
            device_version=descriptor.device_version,
            input_clusters=descriptor.input_clusters,
            output_clusters=descriptor.output_clusters,
        )

    async def send_packet(self, packet):
        LOGGER.debug("Sending packet: %r", packet)

        try:
            device = self.get_device_with_address(packet.dst)
        except (KeyError, ValueError):
            device = None

        if packet.dst.addr_mode == t.AddrMode.IEEE:
            LOGGER.warning("IEEE addressing is not supported, falling back to NWK")

            if device is None:
                raise ValueError(f"Cannot find device with IEEE {packet.dst.address}")

            packet = packet.replace(
                dst=t.AddrModeAddress(addr_mode=t.AddrMode.NWK, address=device.nwk)
            )

        assert packet.src.addr_mode == t.AddrMode.NWK
        src_addr = t.EUI64(
            [
                packet.src.address % 0x100,
                packet.src.address >> 8,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        )

        dst_addr_mode = {
            t.AddrMode.NWK: ExtendedAddrMode.MODE_16_ENDP_PRESENT,
            t.AddrMode.IEEE: ExtendedAddrMode.MODE_64_ENDP_PRESENT,
            t.AddrMode.Group: ExtendedAddrMode.MODE_16_GROUP_ENDP_NOT_PRESENT,
            t.AddrMode.Broadcast: ExtendedAddrMode.MODE_16_GROUP_ENDP_NOT_PRESENT,
        }[packet.dst.addr_mode]

        dst_addr = t.EUI64(
            [
                packet.dst.address % 0x100,
                packet.dst.address >> 8,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        )

        tx_options = TransmitOptions.NONE

        if t.TransmitOptions.ACK in packet.tx_options:
            tx_options |= TransmitOptions.ACK_TX

        if t.TransmitOptions.APS_Encryption in packet.tx_options:
            tx_options |= TransmitOptions.SECURITY_ENABLED

        async with self._limit_concurrency(priority=getattr(packet, "priority", None)):
            await self._api.aps_data_request(
                dst_addr=dst_addr,
                dst_ep=packet.dst_ep,
                src_addr=src_addr,
                src_ep=packet.src_ep,
                profile=packet.profile_id or 0,
                addr_mode=dst_addr_mode,
                cluster=packet.cluster_id,
                sequence=packet.tsn,
                options=tx_options,
                radius=packet.radius or 0,
                data=packet.data.serialize(),
            )

    async def permit_ncp(self, time_s=60):
        assert 0 <= time_s <= 254

        await self._device.zdo.permit(time_s)
        # TODO: this does not work, the NCP responds again with:
        #   Unknown command received: Command(
        #     version=0,
        #     frame_type=<FrameType.Response: 1>,
        #     reserved=0,
        #     command_id=<CommandId.undefined_0xffff: 65535>,
        #     seq=144,
        #     length=1,
        #     payload=b'\x02'
        #   )

        # await self._api.set_permit_join(time_s)

