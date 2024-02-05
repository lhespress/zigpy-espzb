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
import zigpy.util
import zigpy.zdo.types as zdo_t

import zigpy_espzb
from zigpy_espzb import types as t
from zigpy_espzb.api import (
    IndexedKey,
    LinkKey,
    NetworkState,
    SecurityMode,
    Status,
    Znsp,
)
import zigpy_espzb.exception

LOGGER = logging.getLogger(__name__)

CHANGE_NETWORK_POLL_TIME = 1
CHANGE_NETWORK_STATE_DELAY = 2
DELAY_NEIGHBOUR_SCAN_S = 1500
SEND_CONFIRM_TIMEOUT = 60

PROTO_VER_MANUAL_SOURCE_ROUTE = 0x010C
PROTO_VER_WATCHDOG = 0x0108
PROTO_VER_NEIGBOURS = 0x0107

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

        self._delayed_neighbor_scan_task = None
        self._reconnect_task = None

        self._written_endpoints = set()

    async def _watchdog_feed(self):
        await self._api.set_watchdog_ttl(int(self._watchdog_period / 0.75))

    async def connect(self):
        api = Znsp(self, self._config[zigpy.config.CONF_DEVICE])

        try:
            await api.connect()
        except Exception:
            api.close()
            raise

        self._api = api
        self._written_endpoints.clear()

    async def disconnect(self):
        if self._delayed_neighbor_scan_task is not None:
            self._delayed_neighbor_scan_task.cancel()
            self._delayed_neighbor_scan_task = None

        if self._api is not None:
            self._api.close()
            self._api = None

    async def permit_with_link_key(self, node: t.EUI64, link_key: t.KeyData, time_s=60):
        await self._api.set_link_key(
            LinkKey(ieee=node, key=link_key),
        )
        await self.permit(time_s)

    async def start_network(self):
        await self.register_endpoints()
        await self.load_network_info(load_devices=False)
        await self._change_network_state(NetworkState.CONNECTED)

        coordinator = await ZnspDevice.new(
            self,
            self.state.node_info.ieee,
            self.state.node_info.nwk,
            self.state.node_info.model,
        )

        self.devices[self.state.node_info.ieee] = coordinator

        self._delayed_neighbor_scan_task = asyncio.create_task(
            self._delayed_neighbour_scan()
        )

    async def _change_network_state(
        self,
        target_state: NetworkState,
        *,
        timeout: int = 10 * CHANGE_NETWORK_POLL_TIME,
    ):
        async def change_loop():
            while True:
                try:
                    device_state = await self._api.get_device_state()
                except asyncio.TimeoutError:
                    LOGGER.debug("Failed to poll device state")
                else:
                    if NetworkState(device_state.network_state) == target_state:
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
        await self.form_network()

    async def write_network_info(self, *, network_info, node_info):
        try:
            await self._api.set_nwk_frame_counter(network_info.network_key.tx_counter)
        except zigpy_espzb.exception.CommandError as ex:
            assert ex.status == Status.UNSUPPORTED
            LOGGER.warning(
                "Doesn't support writing the network frame counter with this firmware"
            )

        if node_info.logical_type == zdo_t.LogicalType.Coordinator:
            await self._api.set_aps_designed_coordinator(1)
        else:
            await self._api.set_aps_designed_coordinator(0)

        await self._api.set_nwk_address(node_info.nwk)

        if node_info.ieee != zigpy.types.EUI64.UNKNOWN:
            await self._api.set_mac_address(node_info.ieee)
            node_ieee = node_info.ieee
        else:
            ieee = await self._api.mac_address()
            node_ieee = zigpy.types.EUI64(ieee)

        if network_info.channel is not None:
            channel_mask = zigpy.types.Channels.from_channel_list(
                [network_info.channel]
            )

            if network_info.channel_mask and channel_mask != network_info.channel_mask:
                LOGGER.warning(
                    "Channel mask %s will be replaced with current logical channel %s",
                    network_info.channel_mask,
                    channel_mask,
                )
        else:
            channel_mask = network_info.channel_mask

        await self._api.set_channel_mask(channel_mask)
        await self._api.set_use_predefined_nwk_panid(True)
        await self._api.set_nwk_panid(network_info.pan_id)
        await self._api.set_aps_extended_panid(network_info.extended_pan_id)
        await self._api.set_nwk_update_id(network_info.nwk_update_id)

        await self._api.set_network_key(
            IndexedKey(index=0, key=network_info.network_key.key),
        )

        if network_info.network_key.seq != 0:
            LOGGER.warning(
                "Doesn't support non-zero network key sequence number: %s",
                network_info.network_key.seq,
            )

        tc_link_key_partner_ieee = network_info.tc_link_key.partner_ieee

        if tc_link_key_partner_ieee == zigpy.types.EUI64.UNKNOWN:
            tc_link_key_partner_ieee = node_ieee

        await self._api.set_trust_center_address(
            tc_link_key_partner_ieee,
        )
        await self._api.set_link_key(
            LinkKey(
                ieee=tc_link_key_partner_ieee,
                key=network_info.tc_link_key.key,
            ),
        )

        if network_info.security_level == 0x00:
            await self._api.set_security_mode(SecurityMode.NO_SECURITY)
        else:
            await self._api.set_security_mode(SecurityMode.ONLY_TCLK)

        await self._change_network_state(NetworkState.OFFLINE)
        await asyncio.sleep(CHANGE_NETWORK_STATE_DELAY)
        await self._change_network_state(NetworkState.CONNECTED)

    async def load_network_info(self, *, load_devices=False):
        network_info = self.state.network_info
        node_info = self.state.node_info

        ieee = await self._api.mac_address()
        node_info.ieee = zigpy.types.EUI64(ieee)
        designed_coord = await self._api.aps_designed_coordinator()

        if designed_coord == 0x01:
            node_info.logical_type = zdo_t.LogicalType.Coordinator
        else:
            node_info.logical_type = zdo_t.LogicalType.Router

        node_info.nwk = await self._api.nwk_address()

        node_info.manufacturer = "Espressif Systems"

        node_info.model = "ESP32H2"

        node_info.version = f"{int(self._api.firmware_version):#010x}"

        network_info.source = f"zigpy-espzb@{importlib.metadata.version('zigpy-espzb')}"
        network_info.metadata = {
            "espzb": {
                "version": node_info.version,
            }
        }

        network_info.pan_id = await self._api.nwk_panid()
        network_info.extended_pan_id = await self._api.aps_extended_panid()

        if network_info.extended_pan_id == zigpy.types.EUI64.convert(
            "00:00:00:00:00:00:00:00"
        ):
            network_info.extended_pan_id = await self._api.nwk_extended_panid()

        network_info.channel = await self._api.current_channel()
        network_info.channel_mask = await self._api.channel_mask()
        network_info.nwk_update_id = await self._api.nwk_update_id()

        if network_info.channel == 0:
            raise NetworkNotFormed("Network channel is zero")

        indexed_key = await self._api.network_key()

        network_info.network_key = zigpy.state.Key()
        network_info.network_key.key = indexed_key.key

        try:
            network_info.network_key.tx_counter = await self._api.nwk_frame_counter()
        except zigpy_espzb.exception.CommandError as ex:
            assert ex.status == Status.UNSUPPORTED

        network_info.tc_link_key = zigpy.state.Key()
        network_info.tc_link_key.partner_ieee = await self._api.trust_center_address()

        link_key = await self._api.link_key(
            network_info.tc_link_key.partner_ieee,
        )
        network_info.tc_link_key.key = link_key.key

        security_mode = await self._api.security_mode()

        if security_mode == SecurityMode.NO_SECURITY:
            network_info.security_level = 0x00
        elif security_mode == SecurityMode.ONLY_TCLK:
            network_info.security_level = 0x05
        else:
            LOGGER.warning("Unsupported security mode %r", security_mode)
            network_info.security_level = 0x05

    async def force_remove(self, dev):
        """Forcibly remove device from NCP."""

    async def energy_scan(
        self, channels: t.Channels.ALL_CHANNELS, duration_exp: int, count: int
    ) -> dict[int, float]:
        results = await super().energy_scan(
            channels=channels, duration_exp=duration_exp, count=count
        )

        return {c: v * 3 for c, v in results.items()}

        for i in range(ENERGY_SCAN_ATTEMPTS):
            try:
                rsp = await self._device.zdo.Mgmt_NWK_Update_req(
                    zigpy.zdo.types.NwkUpdate(
                        ScanChannels=channels,
                        ScanDuration=duration_exp,
                        ScanCount=count,
                    )
                )
                break
            except (asyncio.TimeoutError, zigpy.exceptions.DeliveryError):
                if i == ENERGY_SCAN_ATTEMPTS - 1:
                    raise

                continue

        _, scanned_channels, _, _, energy_values = rsp
        return dict(zip(scanned_channels, energy_values))

    async def _move_network_to_channel(
        self, new_channel: int, new_nwk_update_id: int
    ) -> None:
        """Move device to a new channel."""
        channel_mask = zigpy.types.Channels.from_channel_list([new_channel])
        await self._api.set_channel_mask(channel_mask)
        await self._api.set_nwk_update_id(new_nwk_update_id)

        await self._change_network_state(NetworkState.OFFLINE)
        await asyncio.sleep(CHANGE_NETWORK_STATE_DELAY)
        await self._change_network_state(NetworkState.CONNECTED)

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

        tx_options = t.ZnspTransmitOptions.NONE

        if zigpy.types.TransmitOptions.ACK in packet.tx_options:
            tx_options |= t.ZnspTransmitOptions.ACK_ENABLED

        if zigpy.types.TransmitOptions.APS_Encryption in packet.tx_options:
            tx_options |= t.ZnspTransmitOptions.SECURITY_ENABLED

        async with self._limit_concurrency():
            await self._api.aps_data_request(
                dst_addr=dst_addr,
                dst_ep=packet.dst_ep,
                src_addr=src_addr,
                src_ep=packet.src_ep,
                profile=packet.profile_id,
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
        await self._api.set_permit_join(time_s)

    async def restore_neighbours(self) -> None:
        """Restore children."""
        coord = self.get_device(ieee=self.state.node_info.ieee)

        for neighbor in self.topology.neighbors[coord.ieee]:
            try:
                device = self.get_device(ieee=neighbor.ieee)
            except KeyError:
                continue

            descr = device.node_desc
            LOGGER.debug(
                "device: 0x%04x - %s %s, FFD=%s, Rx_on_when_idle=%s",
                device.nwk,
                device.manufacturer,
                device.model,
                descr.is_full_function_device if descr is not None else None,
                descr.is_receiver_on_when_idle if descr is not None else None,
            )
            if (
                descr is None
                or descr.is_full_function_device
                or descr.is_receiver_on_when_idle
            ):
                continue

            LOGGER.debug("Restoring %s as direct child", device)

            try:
                await self._api.add_neighbour(
                    nwk=device.nwk,
                    ieee=device.ieee,
                    mac_capability_flags=descr.mac_capability_flags,
                )
            except zigpy_espzb.exception.CommandError as ex:
                assert ex.status == Status.FAILURE
                LOGGER.debug("Failed to add device to neighbor table: %s", ex)

    async def _delayed_neighbour_scan(self) -> None:
        """Scan coordinator's neighbours."""
        await asyncio.sleep(DELAY_NEIGHBOUR_SCAN_S)
        coord = self.get_device(ieee=self.state.node_info.ieee)
        await self.topology.scan(devices=[coord])


class ZnspDevice(zigpy.device.Device):
    """Zigpy Device representing Coordinator."""

    def __init__(self, model: str, *args):
        """Initialize instance."""

        super().__init__(*args)
        self._model = model

    async def add_to_group(self, grp_id: int, name: str = None) -> None:
        group = self.application.groups.add_group(grp_id, name)

        for epid in self.endpoints:
            if not epid:
                continue  # skip ZDO
            group.add_member(self.endpoints[epid])
        return [0]

    async def remove_from_group(self, grp_id: int) -> None:
        for epid in self.endpoints:
            if not epid:
                continue  # skip ZDO
            self.application.groups[grp_id].remove_member(self.endpoints[epid])
        return [0]

    @property
    def manufacturer(self):
        return "Espressif Systems"

    @property
    def model(self):
        return self._model

    @classmethod
    async def new(cls, application, ieee, nwk, model: str):
        """Create or replace zigpy device."""
        dev = cls(model, application, ieee, nwk)

        if ieee in application.devices:
            from_dev = application.get_device(ieee=ieee)
            dev.status = from_dev.status
            dev.node_desc = from_dev.node_desc
            for ep_id, from_ep in from_dev.endpoints.items():
                if not ep_id:
                    continue  # Skip ZDO
                ep = dev.add_endpoint(ep_id)
                ep.profile_id = from_ep.profile_id
                ep.device_type = from_ep.device_type
                ep.status = from_ep.status
                ep.in_clusters = from_ep.in_clusters
                ep.out_clusters = from_ep.out_clusters
        else:
            application.devices[ieee] = dev
            await dev.initialize()

        return dev
