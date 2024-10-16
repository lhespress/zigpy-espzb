"""Data types module."""

from __future__ import annotations

import zigpy.types as t


class Bytes(bytes):
    def serialize(self):
        return self

    @classmethod
    def deserialize(cls, data):
        return cls(data), b""


class TransmitOptions(t.bitmap8):
    NONE = 0x00

    # Security enabled transmission
    SECURITY_ENABLED = 0x01
    # Use NWK key (obsolete)
    USE_NWK_KEY_R21OBSOLETE = 0x02
    # Extension: do not include long src/dst addresses into NWK hdr
    NO_LONG_ADDR = 0x02
    # Acknowledged transmission
    ACK_TX = 0x04
    # Fragmentation permitted
    FRAG_PERMITTED = 0x08
    # Include extended nonce in APS security frame
    INC_EXT_NONCE = 0x10


class ExtendedAddrMode(t.enum8):
    # DstAddress and DstEndpoint not present
    MODE_DST_ADDR_ENDP_NOT_PRESENT = 0x00
    # 16-bit group address for DstAddress; DstEndpoint not present
    MODE_16_GROUP_ENDP_NOT_PRESENT = 0x01
    # 16-bit address for DstAddress and DstEndpoint present
    MODE_16_ENDP_PRESENT = 0x02
    # 64-bit extended address for DstAddress and DstEndpoint present
    MODE_64_ENDP_PRESENT = 0x03

    @classmethod
    def from_zigpy_addr_mode(cls, addr_mode: t.AddrMode) -> ExtendedAddrMode:
        """Convert a Zigpy AddrMode to an ExtendedAddrMode."""
        return {
            t.AddrMode.IEEE: cls.MODE_64_ENDP_PRESENT,
            t.AddrMode.NWK: cls.MODE_16_ENDP_PRESENT,
            t.AddrMode.Group: cls.MODE_16_GROUP_ENDP_NOT_PRESENT,
            t.AddrMode.Broadcast: cls.MODE_16_GROUP_ENDP_NOT_PRESENT,
        }[addr_mode]

    def to_zigpy_addr_mode(self) -> t.AddrMode:
        """Convert a Zigpy AddrMode to an ExtendedAddrMode."""
        return {
            self.MODE_64_ENDP_PRESENT: t.AddrMode.IEEE,
            self.MODE_16_ENDP_PRESENT: t.AddrMode.NWK,
            self.MODE_DST_ADDR_ENDP_NOT_PRESENT: t.AddrMode.NWK,
            self.MODE_16_GROUP_ENDP_NOT_PRESENT: t.AddrMode.Group,
            self.MODE_16_GROUP_ENDP_NOT_PRESENT: t.AddrMode.Broadcast,
            # TODO: why is this necessary?
            0xFF: t.AddrMode.NWK,
        }[self]


def addr_mode_with_eui64_to_addr_mode_address(
    addr_mode: ExtendedAddrMode, address: t.EUI64
) -> t.AddrModeAddress:
    """Convert an address mode and an EUI64 address to an AddrModeAddress."""
    address_short, _ = t.uint16_t.deserialize(address.serialize()[:2])
    zigpy_addr_mode = addr_mode.to_zigpy_addr_mode()

    if zigpy_addr_mode == t.AddrMode.IEEE:
        address = address
    elif zigpy_addr_mode == t.AddrMode.NWK:
        address = t.NWK(address_short)
    elif zigpy_addr_mode == t.AddrMode.Group:
        address = t.Group(address_short)
    elif zigpy_addr_mode == t.AddrMode.Broadcast:
        address = t.BroadcastAddress(address_short)
    else:
        raise ValueError(f"Unknown address mode: {zigpy_addr_mode}")

    return t.AddrModeAddress(addr_mode=zigpy_addr_mode, address=address)


class ShiftedChannels(t.bitmap32):
    """Zigbee Channels."""

    # fmt: off
    CHANNEL_11 =   0b00000000000000000000100000000000
    CHANNEL_12 =   0b00000000000000000001000000000000
    CHANNEL_13 =   0b00000000000000000010000000000000
    CHANNEL_14 =   0b00000000000000000100000000000000
    CHANNEL_15 =   0b00000000000000001000000000000000
    CHANNEL_16 =   0b00000000000000010000000000000000
    CHANNEL_17 =   0b00000000000000100000000000000000
    CHANNEL_18 =   0b00000000000001000000000000000000
    CHANNEL_19 =   0b00000000000010000000000000000000
    CHANNEL_20 =   0b00000000000100000000000000000000
    CHANNEL_21 =   0b00000000001000000000000000000000
    CHANNEL_22 =   0b00000000010000000000000000000000
    CHANNEL_23 =   0b00000000100000000000000000000000
    CHANNEL_24 =   0b00000001000000000000000000000000
    CHANNEL_25 =   0b00000010000000000000000000000000
    CHANNEL_26 =   0b00000100000000000000000000000000
    ALL_CHANNELS = 0b00000111111111111111100000000000
    NO_CHANNELS =  0b00000000000000000000000000000000
    # fmt: on

    __iter__ = t.Channels.__iter__
    from_channel_list = classmethod(t.Channels.from_channel_list.__func__)

    @classmethod
    def from_zigpy_channels(cls, channels: t.Channels) -> ShiftedChannels:
        """Convert a Zigpy Channels to a ShiftedChannels."""
        return cls.from_channel_list(tuple(channels))


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


class TXStatus(t.enum8):
    SUCCESS = 0x00

    @classmethod
    def _missing_(cls, value):
        chained = t.APSStatus(value)
        status = t.uint8_t.__new__(cls, chained.value)
        status._name_ = chained.name
        status._value_ = value
        return status
