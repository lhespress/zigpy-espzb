"""Data types module."""

from zigpy.types import bitmap8


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


class ZnspTransmitOptions(bitmap8):
    NONE = 0x00
    ACK_ENABLED = 0x01
    SECURITY_ENABLED = 0x02


class DeviceAddrMode:
    # TODO: implement this class
    pass
