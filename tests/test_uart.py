"""Unit tests for UART."""

from unittest.mock import Mock

from zigpy_espzb.uart import Gateway


async def test_gateway():
    api = Mock()
    Gateway(api)
