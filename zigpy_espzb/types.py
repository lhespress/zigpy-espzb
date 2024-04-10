"""Data types module."""

from __future__ import annotations

import zigpy.types as t


def serialize_dict(data, schema):
    chunks = []

    for key in schema:
        value = data[key]
        if value is None:
            break

        if not isinstance(value, schema[key]):
            value = schema[key](value)

        chunks.append(value.serialize())

    return b"".join(chunks)


def deserialize_dict(data, schema):
    result = {}
    for name, type_ in schema.items():
        try:
            result[name], data = type_.deserialize(data)
        except ValueError:
            if data:
                raise

            result[name] = None
    return result, data


def list_replace(lst: list, old: object, new: object) -> list:
    """Replace all occurrences of `old` with `new` in `lst`."""
    return [new if x == old else x for x in lst]


class Bytes(bytes):
    def serialize(self):
        return self

    @classmethod
    def deserialize(cls, data):
        return cls(data), b""


class ZnspTransmitOptions(t.bitmap8):
    NONE = 0x00
    ACK_ENABLED = 0x01
    SECURITY_ENABLED = 0x02


class ExtendedAddrMode(t.enum8):
    Unknown = 0x00
    IEEE = 0x01
    NWK = 0x02
    Group = 0x03
    Broadcast = 0x0F


def addr_mode_with_eui64_to_addr_mode_address(
    addr_mode: ExtendedAddrMode, address: t.EUI64
) -> t.AddrModeAddress:
    """Convert an address mode and an EUI64 address to an AddrModeAddress."""
    address_short, _ = t.uint16_t.deserialize(address.serialize()[:2])

    if addr_mode == ExtendedAddrMode.IEEE:
        address = address
    elif addr_mode == ExtendedAddrMode.NWK:
        address = t.NWK(address_short)
    elif addr_mode == ExtendedAddrMode.Group:
        address = t.Group(address_short)
    elif addr_mode == ExtendedAddrMode.Broadcast:
        address = t.BroadcastAddress(address_short)
    elif addr_mode == ExtendedAddrMode.Unknown:
        # TODO: Is this correct? It seems to be used only for loopback
        address = address_short
        addr_mode = t.AddrMode.NWK
    else:
        raise ValueError(f"Unknown address mode: {addr_mode}")

    return t.AddrModeAddress(addr_mode=t.AddrMode(addr_mode), address=address)


class ShiftedChannels(t.bitmap32):
    """Zigbee Channels."""

    CHANNEL_11 = 0b00000000000000000000010000000000
    CHANNEL_12 = 0b00000000000000000000100000000000
    CHANNEL_13 = 0b00000000000000000001000000000000
    CHANNEL_14 = 0b00000000000000000010000000000000
    CHANNEL_15 = 0b00000000000000000100000000000000
    CHANNEL_16 = 0b00000000000000001000000000000000
    CHANNEL_17 = 0b00000000000000010000000000000000
    CHANNEL_18 = 0b00000000000000100000000000000000
    CHANNEL_19 = 0b00000000000001000000000000000000
    CHANNEL_20 = 0b00000000000010000000000000000000
    CHANNEL_21 = 0b00000000000100000000000000000000
    CHANNEL_22 = 0b00000000001000000000000000000000
    CHANNEL_23 = 0b00000000010000000000000000000000
    CHANNEL_24 = 0b00000000100000000000000000000000
    CHANNEL_25 = 0b00000001000000000000000000000000
    CHANNEL_26 = 0b00000010000000000000000000000000
    ALL_CHANNELS = 0b00000011111111111111110000000000
    NO_CHANNELS = 0b00000000000000000000000000000000

    __iter__ = t.Channels.__iter__
    from_channel_list = classmethod(t.Channels.from_channel_list.__func__)

    @classmethod
    def from_zigpy_channels(cls, channels: t.Channels) -> ShiftedChannels:
        """Convert a Zigpy Channels to a ShiftedChannels."""
        return cls.from_channel_list(tuple(channels))
