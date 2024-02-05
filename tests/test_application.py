"""Unit tests for main ControllerApplication class."""

import zigpy.config as config

from zigpy_espzb.zigbee.application import ControllerApplication


async def test_application():
    ControllerApplication(
        {
            config.CONF_DEVICE: {
                config.CONF_DEVICE_PATH: "/dev/null",
            }
        }
    )
