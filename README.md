# zigpy-espzb

[![Build Status](https://travis-ci.org/zigpy/zigpy-espzb.svg?branch=master)](https://travis-ci.org/zigpy/zigpy-espzb)
[![Coverage](https://coveralls.io/repos/github/zigpy/zigpy-espzb/badge.svg?branch=master)](https://coveralls.io/github/zigpy/zigpy-espzb?branch=master)

**zigpy-espzb** is a Python 3 implementation to implement support for [Espressif ZNSP (Zigbee NCP Serial Protocol)](https://docs.espressif.com/projects/esp-zigbee-sdk/en/latest/esp32h2/application.html) based [Zigbee](https://www.zigbee.org) radio adapters with the [zigpy library (an open-source Python Zigbee stack project)](https://github.com/zigpy/).

The goal of this project is to native Zigbee Coordinator radio adapter support using [Zigbee NCP (Network Co-Processor) application firmware](https://github.com/espressif/esp-zigbee-sdk/tree/main/examples/esp_zigbee_ncp) with Espressif Systems ESP32-C6/ESP32-H2 based Zigbee modules via the [zigpy](https://github.com/zigpy/) project.

This together with the zigpy library and a home automation software application with compatible Zigbee gateway implementation, like the [Home Assistant's ZHA (Zigbee Home Automation) integration component](https://www.home-assistant.io/integrations/zha), you can directly control other Zigbee devices from most product manufacturers.

# Back-story and use cases

Note! Zigbee NCP support for [ESP32](https://en.wikipedia.org/wiki/ESP32) is still in very early development in Espressif Zigbee SDK (based on [DSR ZBOSS stack as part of "ZBOSS Open Initiative", a.k.a. ZOI](https://dsr-zoi.com/)). It is currently compatible with ESP32-C6 and ESP32-H2, both containing 802.15.4 radio, and are officially recognized as Zigbee-Compliant platforms by the CSA (Connectivity Standards Alliance, formerly the Zigbee Alliance), of which [Espressif](https://www.espressif.com) is a board and promoter member.

Development is initially focused on Zigbee Coordinator functionality using "ESP Thread Border Router SDK" development kit hardware. That implementation provides an all-in-one embedded Zigbee (or Thread) to Wi-Fi Serial-over-IP proxy solution, with the board designed using two-SoC set-up consisting of an ESP32-H2 SoC for Zigbee (or Thread) in combination with an ESP32-S3 SoC (with internal UART/SPI communication) for Wi-Fi/Ethernet bridging.

Alternative to the ESP32-H2 (which only supports 802.15.4), the ESP32-C6 SoC/module development board was launched more recently and features built-in WiFi 6, BLE 5.0, and 802.15.4, including Zigbee (or Thread), all on the same chip. It could thus be used as a single-chip Zigbee Coordinator Serial-over-IP proxy solution over Wi-Fi, or over Ethernet physical layer if combined with a PHY Ethernet implementation on a board for RJ45 wired connection. 

# Hardware requirements

Supported targets	are ESP32-H2 and ESP32-C6, tested with the official devkits and modules from Espressif as reference hardware:

- https://www.espressif.com.cn/en/products/devkits
- https://www.espressif.com.cn/en/products/modules

Development is primarily being done with Espressif's ESP Thread Border Router SDK hardware (based on ESP32-H2-MINI-1 module):

- https://docs.espressif.com/projects/esp-thread-br/en/latest/
  - https://github.com/espressif/esp-zigbee-sdk/tree/main/examples/esp_zigbee_gateway
    - https://github.com/espressif/esp-thread-br
    - https://github.com/espressif/esp-idf/tree/master/examples/openthread/ot_br
    - https://openthread.io/guides/border-router/espressif-esp32
 
# Firmware

Development and testing in the zigpy-espzb project are done with a firmware image built using the ZNSP NCP host example from Espressif:

-  https://github.com/espressif/esp-zigbee-sdk/tree/main/examples/esp_zigbee_ncp

Compatible compiled ZNSP NCP host firmware images are required to be flashed on the ESP32-C6 or ESP32-H2 device with a serial connection.

Precompiled images might be provided in the future.

# Releases via PyPI

Tagged versions will eventually also be released via PyPI

- https://pypi.org/project/zigpy-espzb/
- https://pypi.org/project/zigpy-espzb/#history
- https://pypi.org/project/zigpy-espzb/#files

# External documentation and reference

Note! The official documentation for the ZNSP can currently be obtained from Espressif Systems:

- https://docs.espressif.com/projects/esp-zigbee-sdk
  - https://github.com/espressif/esp-zigbee-sdk/tree/main/examples/esp_zigbee_ncp
- https://docs.espressif.com/projects/esp-zigbee-sdk/en/latest/esp32/
  - https://docs.espressif.com/projects/esp-zigbee-sdk/en/latest/esp32h2/application.html
  - https://docs.espressif.com/projects/esp-zigbee-sdk/en/latest/esp32c6/application.html

# How to contribute

If you are looking to contribute to this project or upstream we suggest that you post an issue and follow the steps in these guides:

- https://github.com/espressif/esp-zigbee-sdk/issues
- https://github.com/firstcontributions/first-contributions/blob/master/README.md
- https://github.com/firstcontributions/first-contributions/blob/master/github-desktop-tutorial.md

Some developers might also be interested in receiving donations in the form of hardware such as Zigbee modules or devices, and even if such donations are most often donated with no strings attached it could in many cases help the developers motivation and indirect improve the development of this project.

## Other radio libraries for zigpy to use as reference projects

### zigpy-znp
The **[zigpy-znp](https://github.com/zigpy/zigpy-znp)** zigpy radio library for Texas Instruments Z-Stack ZNP interface and has been used a reference to base the zigpy-espzb and nrf-zboss-ncp radio libraries on. zigpy-znp is very stable with TI Z-Stack 3.x.x and ([zigpy-znp also offers some stand-alone CLI tools](https://github.com/zigpy/zigpy-znp/blob/dev/TOOLS.md) that are unique for Texas Instruments hardware and Zigbee stack.

### zigpy-zboss

The **[zigpy-zboss](https://github.com/kardia-as/nrf-zboss-ncp)** zigpy radio library for nRF ZBOSS NCP. The development of the zigpy-zboss radio library for zigpy in turn stems from information learned from the work in the **[zigpy-znp](https://github.com/zigpy/zigpy-znp)** project.

### zigpy-deconz
The **[zigpy-deconz](https://github.com/zigpy/zigpy-deconz)** is another mature radio library for Dresden Elektronik's [deCONZ Serial Protocol interface](https://github.com/dresden-elektronik/deconz-serial-protocol) that is used by the deconz firmware for their ConBee and RaspBee seriies of Zigbee Coordinator adapters. Existing zigpy developers previous advice has been to also look at zigpy-deconz since it is somewhat similar to the ZBOSS serial protocol implementation.

##### zigpy deconz parser
[zigpy-deconz-parser](https://github.com/zha-ng/zigpy-deconz-parser) allow developers to parse Home Assistant's ZHA component debug logs using the zigpy-deconz radio library if you are using a deCONZ based adapter like ConBee or RaspBee.

### bellows
The **[bellows](https://github.com/zigpy/bellows)** is made Silicon Labs [EZSP (EmberZNet Serial Protocol)](https://www.silabs.com/documents/public/user-guides/ug100-ezsp-reference-guide.pdf) interface and is another mature zigpy radio library project worth taking a look at as a reference, (as both it and some other zigpy radio libraries have some unique features and functions that others do not).

# Related projects

### zigpy
**[zigpy](https://github.com/zigpy/zigpy)** is a **[Zigbee protocol stack](https://en.wikipedia.org/wiki/Zigbee)** integration project to implement the **[Zigbee Home Automation](https://www.zigbee.org/)** standard as a Python library. Zigbee Home Automation integration with zigpy allows you to connect one of many off-the-shelf Zigbee adapters using one of the available Zigbee radio library modules compatible with zigpy to control Zigbee devices. There is currently support for controlling Zigbee device types such as binary sensors (e.g. motion and door sensors), analog sensors (e.g. temperature sensors), lightbulbs, switches, and fans. Zigpy is tightly integrated with **[Home Assistant](https://www.home-assistant.io)**'s **[ZHA component](https://www.home-assistant.io/components/zha/)** and provides a user-friendly interface for working with a Zigbee network.

### zigpy-cli (zigpy command line interface)
[zigpy-cli](https://github.com/zigpy/zigpy-cli) is a unified command line interface for zigpy radios. The goal of this project is to allow low-level network management from an intuitive command line interface and to group useful Zigbee tools into a single binary.

### ZHA Device Handlers
ZHA deviation handling in Home Assistant relies on the third-party [ZHA Device Handlers](https://github.com/zigpy/zha-device-handlers) project (also known unders zha-quirks package name on PyPI). Zigbee devices that deviate from or do not fully conform to the standard specifications set by the [Zigbee Alliance](https://www.zigbee.org) may require the development of custom [ZHA Device Handlers](https://github.com/zigpy/zha-device-handlers) (ZHA custom quirks handler implementation) to for all their functions to work properly with the ZHA component in Home Assistant. These ZHA Device Handlers for Home Assistant can thus be used to parse custom messages to and from non-compliant Zigbee devices. The custom quirks implementations for zigpy implemented as ZHA Device Handlers for Home Assistant are a similar concept to that of [Hub-connected Device Handlers for the SmartThings platform](https://docs.smartthings.com/en/latest/device-type-developers-guide/) as well as that of [zigbee-herdsman converters as used by Zigbee2mqtt](https://www.zigbee2mqtt.io/how_tos/how_to_support_new_devices.html), meaning they are each virtual representations of a physical device that expose additional functionality that is not provided out-of-the-box by the existing integration between these platforms.

### ZHA integration component for Home Assistant
[ZHA integration component for Home Assistant](https://www.home-assistant.io/integrations/zha/) is a reference implementation of the zigpy library as integrated into the core of **[Home Assistant](https://www.home-assistant.io)** (a Python based open source home automation software). There are also other GUI and non-GUI projects for Home Assistant's ZHA components which builds on or depends on its features and functions to enhance or improve its user-experience, some of those are listed and linked below.

#### ZHA Toolkit
[ZHA Toolkit](https://github.com/mdeweerd/zha-toolkit) is a custom service for "rare" Zigbee operations using the [ZHA integration component](https://www.home-assistant.io/integrations/zha) in [Home Assistant](https://www.home-assistant.io/). The purpose of ZHA Toolkit and its Home Assistant 'Services' feature, is to provide direct control over low level zigbee commands provided in ZHA or zigpy that are not otherwise available or too limited for some use cases. ZHA Toolkit can also; serve as a framework to do local low level coding (the modules are reloaded on each call), provide access to some higher level commands such as ZNP backup (and restore), make it easier to perform one-time operations where (some) Zigbee knowledge is sufficient and avoiding the need to understand the inner workings of ZHA or Zigpy (methods, quirks, etc).

#### ZHA Device Exporter
[zha-device-exporter](https://github.com/dmulcahey/zha-device-exporter) is a custom component for Home Assistant to allow the ZHA component to export lists of Zigbee devices.

#### ZHA Network Visualization Card
[zha-network-visualization-card](https://github.com/dmulcahey/zha-network-visualization-card) was a custom Lovelace element for Home Assistant which visualizes the Zigbee network for the ZHA component.

#### ZHA Network Card
[zha-network-card](https://github.com/dmulcahey/zha-network-card) was a custom Lovelace card for Home Assistant that displays ZHA component Zigbee network and device information in Home Assistant
