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
import zigpy.types
import zigpy.types as t
import zigpy.util
import zigpy.zdo.types as zdo_t

from zigpy_espzb.api import DeviceType, NetworkState, SecurityMode, Znsp
import zigpy_espzb.types as espzb_t

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

        super().__init__(config=zigpy.config.ZIGPY_SCHEMA(config))
        self._api = None

        self._pending = zigpy.util.Requests()
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

        # TODO: Most commands fail if the network is not formed. Why?
        await api.network_init()
        await api.form_network(role=DeviceType.COORDINATOR)
        await api.start(autostart=False)

        self._api = api

    async def disconnect(self):
        if self._api is not None:
            self._api.close()
            self._api = None

    async def permit_with_link_key(self, node: t.EUI64, link_key: t.KeyData, time_s=60):
        raise NotImplementedError()

    async def start_network(self):
        await self._api.start(autostart=True)

        await self.load_network_info(load_devices=False)
        await self.register_endpoints()

        # Create the coordinator device
        coordinator = zigpy.device.Device(
            application=self,
            ieee=self.state.node_info.ieee,
            nwk=self.state.node_info.nwk,
        )
        self.devices[self.state.node_info.ieee] = coordinator

        # TODO: why does the coordinator respond to the loopback ZDO Active_EP_req with
        # [242, 242]? It should include endpoints 1 and 2, we registered them.
        await coordinator.schedule_initialize()

        # TODO: add our registered endpoints manually so things don't crash. These
        # should be discovered automatically.
        coordinator.add_endpoint(1)
        coordinator.add_endpoint(2)

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
        await self._api.leave_network()

    async def write_network_info(self, *, network_info, node_info):
        await self._api.reset()
        await self._api.network_init()
        await self._api.form_network(role=DeviceType.COORDINATOR)
        await self._api.start(autostart=False)

        role = {
            zdo_t.LogicalType.Coordinator: DeviceType.COORDINATOR,
            zdo_t.LogicalType.Router: DeviceType.ROUTER,
        }[node_info.logical_type]

        await self._api.set_network_role(role)
        await self._api.set_nwk_address(node_info.nwk)

        if node_info.ieee != zigpy.types.EUI64.UNKNOWN:
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

        if tc_link_key_partner_ieee == zigpy.types.EUI64.UNKNOWN:
            tc_link_key_partner_ieee = node_ieee

        await self._api.set_trust_center_address(tc_link_key_partner_ieee)
        await self._api.set_link_key(network_info.tc_link_key.key)

        if network_info.security_level == 0x00:
            await self._api.set_security_mode(SecurityMode.NO_SECURITY)
        else:
            await self._api.set_security_mode(SecurityMode.PRECONFIGURED_NETWORK_KEY)

        await self._api.set_channel(network_info.channel)

        # TODO: Network settings do not persist. How do you write them?
        await self._api.reset()
        await self._api.network_init()
        await self._api.form_network(role=DeviceType.COORDINATOR)
        await self._api.start(autostart=True)

    async def load_network_info(self, *, load_devices=False):
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
        node_info.manufacturer = "Espressif Systems"
        node_info.model = "ESP32H2"

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
        raise NotImplementedError()

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

        force_relays = None

        dst_addr = packet.dst.address
        addr_mode = packet.dst.addr_mode
        if packet.dst.addr_mode != zigpy.types.AddrMode.IEEE:
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
        if packet.dst.addr_mode == zigpy.types.AddrMode.Broadcast:
            addr_mode = zigpy.types.AddrMode.Group

        if packet.dst.addr_mode != zigpy.types.AddrMode.IEEE:
            src_addr = t.EUI64(
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

        if packet.source_route is not None:
            force_relays = packet.source_route

        tx_options = espzb_t.ZnspTransmitOptions.NONE

        if zigpy.types.TransmitOptions.ACK in packet.tx_options:
            tx_options |= espzb_t.ZnspTransmitOptions.ACK_ENABLED

        if zigpy.types.TransmitOptions.APS_Encryption in packet.tx_options:
            tx_options |= espzb_t.ZnspTransmitOptions.SECURITY_ENABLED

        async with self._limit_concurrency():
            await self._api.aps_data_request(
                dst_addr=dst_addr,
                dst_ep=packet.dst_ep,
                src_addr=src_addr,
                src_ep=packet.src_ep,
                profile=packet.profile_id or 0,
                addr_mode=addr_mode,
                cluster=packet.cluster_id,
                sequence=packet.tsn,
                options=tx_options,
                radius=packet.radius or 0,
                data=packet.data.serialize(),
                relays=force_relays,
                extended_timeout=packet.extended_timeout,
            )

    async def permit_ncp(self, time_s=60):
        assert 0 <= time_s <= 254

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
