"""Unit tests for API class."""

from unittest.mock import Mock

import zigpy.config as config

from zigpy_espzb.api import Znsp


async def test_api():
    app = Mock()
    Znsp(
        app,
        {
            config.CONF_DEVICE_PATH: "/dev/null",
        },
    )
