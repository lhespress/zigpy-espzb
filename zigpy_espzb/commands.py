"""Serial command schemas."""

import zigpy.types as t

from zigpy_espzb.types import (
    Bytes,
    DeviceType,
    ExtendedAddrMode,
    FirmwareVersion,
    NetworkState,
    SecurityMode,
    ShiftedChannels,
    Status,
    TransmitOptions,
    TXStatus,
)


class CommandId(t.enum16):
    network_init = 0x0000
    start = 0x0001
    network_state = 0x0002
    stack_status_handler = 0x0003
    form_network = 0x0004
    permit_joining = 0x0005
    join_network = 0x0006
    leave_network = 0x0007
    start_scan = 0x0008
    scan_complete_handler = 0x0009
    stop_scan = 0x000A
    panid_get = 0x000B
    panid_set = 0x000C
    extpanid_get = 0x000D
    extpanid_set = 0x000E
    primary_channel_mask_get = 0x000F
    primary_channel_mask_set = 0x0010
    secondary_channel_mask_get = 0x0011
    secondary_channel_mask_set = 0x0012
    current_channel_get = 0x0013
    current_channel_set = 0x0014
    tx_power_get = 0x0015
    tx_power_set = 0x0016
    network_key_get = 0x0017
    network_key_set = 0x0018
    nwk_frame_counter_get = 0x0019
    nwk_frame_counter_set = 0x001A
    network_role_get = 0x001B
    network_role_set = 0x001C
    short_addr_get = 0x001D
    short_addr_set = 0x001E
    long_addr_get = 0x001F
    long_addr_set = 0x0020
    channel_masks_get = 0x0021
    channel_masks_set = 0x0022
    nwk_update_id_get = 0x0023
    nwk_update_id_set = 0x0024
    trust_center_address_get = 0x0025
    trust_center_address_set = 0x0026
    link_key_get = 0x0027
    link_key_set = 0x0028
    security_mode_get = 0x0029
    security_mode_set = 0x002A
    use_predefined_nwk_panid_set = 0x002B
    short_to_ieee = 0x002C
    ieee_to_short = 0x002D
    add_endpoint = 0x0100
    remove_endpoint = 0x0101
    attribute_read = 0x0102
    attribute_write = 0x0103
    attribute_report = 0x0104
    attribute_discover = 0x0105
    aps_read = 0x0106
    aps_write = 0x0107
    report_config = 0x0108
    bind_set = 0x0200
    unbind_set = 0x0201
    find_match = 0x0202
    aps_data_request = 0x0300
    aps_data_indication = 0x0301
    aps_data_confirm = 0x0302
    system_reset = 0x0400
    system_factory = 0x0401
    system_firmware = 0x0402
    system_model = 0x0403
    system_manufacturer = 0x0404


class FrameType(t.enum4):
    Request = 0
    Response = 1
    Indicate = 2


class CommandFrame(t.Struct):
    version: t.uint4_t
    frame_type: FrameType
    reserved: t.uint8_t

    command_id: CommandId
    seq: t.uint8_t
    length: t.uint16_t
    payload: Bytes


class BaseCommand(t.Struct):
    pass


class NetworkInitReq(BaseCommand):
    pass


class NetworkInitRsp(BaseCommand):
    status: Status


class StartReq(BaseCommand):
    autostart: t.Bool


class StartRsp(BaseCommand):
    status: Status


class FormNetworkReq(BaseCommand):
    role: DeviceType
    install_code_policy: t.Bool

    # For coordinators/routers
    max_children: t.uint8_t = t.StructField(
        requires=lambda f: f.role in (DeviceType.ROUTER, DeviceType.COORDINATOR)
    )

    # For end devices
    ed_timeout: t.uint8_t = t.StructField(
        requires=lambda f: f.role == DeviceType.END_DEVICE
    )
    keep_alive: t.uint32_t = t.StructField(
        requires=lambda f: f.role == DeviceType.END_DEVICE
    )


class FormNetworkRsp(BaseCommand):
    status: Status


class FormNetworkInd(BaseCommand):
    extended_panid: t.EUI64
    panid: t.PanId
    channel: t.uint8_t


class PermitJoiningReq(BaseCommand):
    duration: t.uint8_t


class PermitJoiningRsp(BaseCommand):
    status: Status


class PermitJoiningInd(BaseCommand):
    duration: t.uint8_t


class LeaveNetworkReq(BaseCommand):
    pass


class LeaveNetworkRsp(BaseCommand):
    status: Status


class LeaveNetworkInd(BaseCommand):
    short_addr: t.NWK
    device_addr: t.EUI64
    rejoin: t.Bool


class ExtpanidGetReq(BaseCommand):
    pass


class ExtpanidGetRsp(BaseCommand):
    ieee: t.EUI64


class ExtpanidSetReq(BaseCommand):
    ieee: t.EUI64


class ExtpanidSetRsp(BaseCommand):
    status: Status


class PanidGetReq(BaseCommand):
    pass


class PanidGetRsp(BaseCommand):
    panid: t.PanId


class PanidSetReq(BaseCommand):
    panid: t.PanId


class PanidSetRsp(BaseCommand):
    status: Status


class ShortAddrGetReq(BaseCommand):
    pass


class ShortAddrGetRsp(BaseCommand):
    short_addr: t.NWK


class ShortAddrSetReq(BaseCommand):
    short_addr: t.NWK


class ShortAddrSetRsp(BaseCommand):
    status: Status


class LongAddrGetReq(BaseCommand):
    pass


class LongAddrGetRsp(BaseCommand):
    ieee: t.EUI64


class LongAddrSetReq(BaseCommand):
    ieee: t.EUI64


class LongAddrSetRsp(BaseCommand):
    status: Status


class CurrentChannelGetReq(BaseCommand):
    pass


class CurrentChannelGetRsp(BaseCommand):
    channel: t.uint8_t


class CurrentChannelSetReq(BaseCommand):
    channel: t.uint8_t


class CurrentChannelSetRsp(BaseCommand):
    status: Status


class PrimaryChannelMaskGetReq(BaseCommand):
    pass


class PrimaryChannelMaskGetRsp(BaseCommand):
    channel_mask: ShiftedChannels


class PrimaryChannelMaskSetReq(BaseCommand):
    channel_mask: ShiftedChannels


class PrimaryChannelMaskSetRsp(BaseCommand):
    status: Status


class AddEndpointReq(BaseCommand):
    endpoint: t.uint8_t
    profile_id: t.uint16_t
    device_id: t.uint16_t
    app_flags: t.uint8_t
    input_cluster_count: t.uint8_t
    output_cluster_count: t.uint8_t
    input_cluster_list: t.List[t.uint16_t]
    output_cluster_list: t.List[t.uint16_t]


class AddEndpointRsp(BaseCommand):
    status: Status


class NetworkStateReq(BaseCommand):
    pass


class NetworkStateRsp(BaseCommand):
    network_state: NetworkState


class StackStatusHandlerReq(BaseCommand):
    pass


class StackStatusHandlerRsp(BaseCommand):
    network_state: t.uint8_t


class StackStatusHandlerInd(BaseCommand):
    network_state: t.uint8_t


class ApsDataRequestReq(BaseCommand):
    dst_addr: t.EUI64
    dst_endpoint: t.uint8_t
    src_endpoint: t.uint8_t
    address_mode: ExtendedAddrMode
    profile_id: t.uint16_t
    cluster_id: t.uint16_t
    tx_options: TransmitOptions
    use_alias: t.Bool
    alias_src_addr: t.EUI64
    alias_seq_num: t.uint8_t
    radius: t.uint8_t
    asdu_length: t.uint32_t
    asdu: Bytes


class ApsDataRequestRsp(BaseCommand):
    status: Status


class ApsDataIndicationRsp(BaseCommand):
    network_state: NetworkState
    dst_addr_mode: ExtendedAddrMode
    dst_addr: t.EUI64
    dst_ep: t.uint8_t
    src_addr_mode: ExtendedAddrMode
    src_addr: t.EUI64
    src_ep: t.uint8_t
    profile_id: t.uint16_t
    cluster_id: t.uint16_t
    indication_status: TXStatus
    security_status: t.uint8_t
    lqi: t.uint8_t
    rx_time: t.uint32_t
    asdu_length: t.uint32_t
    asdu: Bytes


class ApsDataIndicationInd(BaseCommand):
    network_state: NetworkState
    dst_addr_mode: ExtendedAddrMode
    dst_addr: t.EUI64
    dst_ep: t.uint8_t
    src_addr_mode: ExtendedAddrMode
    src_addr: t.EUI64
    src_ep: t.uint8_t
    profile_id: t.uint16_t
    cluster_id: t.uint16_t
    indication_status: TXStatus
    security_status: t.uint8_t
    lqi: t.uint8_t
    rx_time: t.uint32_t
    asdu_length: t.uint32_t
    asdu: Bytes


class ApsDataConfirmReq(BaseCommand):
    pass


class ApsDataConfirmRsp(BaseCommand):
    network_state: NetworkState
    dst_addr_mode: ExtendedAddrMode
    dst_addr: t.EUI64
    dst_ep: t.uint8_t
    src_ep: t.uint8_t
    tx_time: t.uint32_t
    request_id: t.uint8_t
    confirm_status: TXStatus
    asdu_length: t.uint32_t
    asdu: Bytes


class ApsDataConfirmInd(BaseCommand):
    network_state: NetworkState
    dst_addr_mode: ExtendedAddrMode
    dst_addr: t.EUI64
    dst_ep: t.uint8_t
    src_ep: t.uint8_t
    tx_time: t.uint32_t
    confirm_status: TXStatus
    asdu_length: t.uint32_t
    asdu: Bytes


class NetworkKeyGetReq(BaseCommand):
    pass


class NetworkKeyGetRsp(BaseCommand):
    nwk_key: t.KeyData


class NetworkKeySetReq(BaseCommand):
    nwk_key: t.KeyData


class NetworkKeySetRsp(BaseCommand):
    status: Status


class NwkFrameCounterGetReq(BaseCommand):
    pass


class NwkFrameCounterGetRsp(BaseCommand):
    nwk_frame_counter: t.uint32_t


class NwkFrameCounterSetReq(BaseCommand):
    nwk_frame_counter: t.uint32_t


class NwkFrameCounterSetRsp(BaseCommand):
    status: Status


class NetworkRoleGetReq(BaseCommand):
    pass


class NetworkRoleGetRsp(BaseCommand):
    role: DeviceType


class NetworkRoleSetReq(BaseCommand):
    role: DeviceType


class NetworkRoleSetRsp(BaseCommand):
    status: Status


class UsePredefinedNwkPanidSetReq(BaseCommand):
    predefined: t.Bool


class UsePredefinedNwkPanidSetRsp(BaseCommand):
    status: Status


class NwkUpdateIdGetReq(BaseCommand):
    pass


class NwkUpdateIdGetRsp(BaseCommand):
    nwk_update_id: t.uint8_t


class NwkUpdateIdSetReq(BaseCommand):
    nwk_update_id: t.uint8_t


class NwkUpdateIdSetRsp(BaseCommand):
    status: Status


class TrustCenterAddressGetReq(BaseCommand):
    pass


class TrustCenterAddressGetRsp(BaseCommand):
    trust_center_addr: t.EUI64


class TrustCenterAddressSetReq(BaseCommand):
    trust_center_addr: t.EUI64


class TrustCenterAddressSetRsp(BaseCommand):
    status: Status


class LinkKeyGetReq(BaseCommand):
    pass


class LinkKeyGetRsp(BaseCommand):
    ieee: t.EUI64
    key: t.KeyData


class LinkKeySetReq(BaseCommand):
    key: t.KeyData


class LinkKeySetRsp(BaseCommand):
    status: Status


class SecurityModeGetReq(BaseCommand):
    pass


class SecurityModeGetRsp(BaseCommand):
    security_mode: SecurityMode


class SecurityModeSetReq(BaseCommand):
    security_mode: SecurityMode


class SecurityModeSetRsp(BaseCommand):
    status: Status


class SystemResetReq(BaseCommand):
    pass


class SystemResetRsp(BaseCommand):
    status: Status

class SystemResetInd(BaseCommand):
    error: t.uint32_t

class SystemFactoryReq(BaseCommand):
    pass


class SystemFactoryRsp(BaseCommand):
    status: Status

class SystemFactoryInd(BaseCommand):
    error: t.uint32_t

class SystemFirmwareReq(BaseCommand):
    pass


class SystemFirmwareRsp(BaseCommand):
    firmware_version: FirmwareVersion


class SystemModelReq(BaseCommand):
    pass


class SystemModelRsp(BaseCommand):
    payload: t.CharacterString


class SystemManufacturerReq(BaseCommand):
    pass


class SystemManufacturerRsp(BaseCommand):
    payload: t.CharacterString


COMMAND_SCHEMAS = {
    CommandId.network_init: (
        NetworkInitReq,
        NetworkInitRsp,
        None,
    ),
    CommandId.start: (
        StartReq,
        StartRsp,
        None,
    ),
    CommandId.form_network: (
        FormNetworkReq,
        FormNetworkRsp,
        FormNetworkInd,
    ),
    CommandId.permit_joining: (
        PermitJoiningReq,
        PermitJoiningRsp,
        PermitJoiningInd,
    ),
    CommandId.leave_network: (
        LeaveNetworkReq,
        LeaveNetworkRsp,
        LeaveNetworkInd,
    ),
    CommandId.extpanid_get: (
        ExtpanidGetReq,
        ExtpanidGetRsp,
        None,
    ),
    CommandId.extpanid_set: (
        ExtpanidSetReq,
        ExtpanidSetRsp,
        None,
    ),
    CommandId.panid_get: (
        PanidGetReq,
        PanidGetRsp,
        None,
    ),
    CommandId.panid_set: (
        PanidSetReq,
        PanidSetRsp,
        None,
    ),
    CommandId.short_addr_get: (
        ShortAddrGetReq,
        ShortAddrGetRsp,
        None,
    ),
    CommandId.short_addr_set: (
        ShortAddrSetReq,
        ShortAddrSetRsp,
        None,
    ),
    CommandId.long_addr_get: (
        LongAddrGetReq,
        LongAddrGetRsp,
        None,
    ),
    CommandId.long_addr_set: (
        LongAddrSetReq,
        LongAddrSetRsp,
        None,
    ),
    CommandId.current_channel_get: (
        CurrentChannelGetReq,
        CurrentChannelGetRsp,
        None,
    ),
    CommandId.current_channel_set: (
        CurrentChannelSetReq,
        CurrentChannelSetRsp,
        None,
    ),
    CommandId.primary_channel_mask_get: (
        PrimaryChannelMaskGetReq,
        PrimaryChannelMaskGetRsp,
        None,
    ),
    CommandId.primary_channel_mask_set: (
        PrimaryChannelMaskSetReq,
        PrimaryChannelMaskSetRsp,
        None,
    ),
    CommandId.add_endpoint: (
        AddEndpointReq,
        AddEndpointRsp,
        None,
    ),
    CommandId.network_state: (
        NetworkStateReq,
        NetworkStateRsp,
        None,
    ),
    CommandId.stack_status_handler: (
        StackStatusHandlerReq,
        StackStatusHandlerRsp,
        StackStatusHandlerInd,
    ),
    CommandId.aps_data_request: (
        ApsDataRequestReq,
        ApsDataRequestRsp,
        None,
    ),
    CommandId.aps_data_indication: (
        None,
        ApsDataIndicationRsp,
        ApsDataIndicationInd,
    ),
    CommandId.aps_data_confirm: (
        ApsDataConfirmReq,
        ApsDataConfirmRsp,
        ApsDataConfirmInd,
    ),
    CommandId.network_key_get: (
        NetworkKeyGetReq,
        NetworkKeyGetRsp,
        None,
    ),
    CommandId.network_key_set: (
        NetworkKeySetReq,
        NetworkKeySetRsp,
        None,
    ),
    CommandId.nwk_frame_counter_get: (
        NwkFrameCounterGetReq,
        NwkFrameCounterGetRsp,
        None,
    ),
    CommandId.nwk_frame_counter_set: (
        NwkFrameCounterSetReq,
        NwkFrameCounterSetRsp,
        None,
    ),
    CommandId.network_role_get: (
        NetworkRoleGetReq,
        NetworkRoleGetRsp,
        None,
    ),
    CommandId.network_role_set: (
        NetworkRoleSetReq,
        NetworkRoleSetRsp,
        None,
    ),
    CommandId.use_predefined_nwk_panid_set: (
        UsePredefinedNwkPanidSetReq,
        UsePredefinedNwkPanidSetRsp,
        None,
    ),
    CommandId.nwk_update_id_get: (
        NwkUpdateIdGetReq,
        NwkUpdateIdGetRsp,
        None,
    ),
    CommandId.nwk_update_id_set: (
        NwkUpdateIdSetReq,
        NwkUpdateIdSetRsp,
        None,
    ),
    CommandId.trust_center_address_get: (
        TrustCenterAddressGetReq,
        TrustCenterAddressGetRsp,
        None,
    ),
    CommandId.trust_center_address_set: (
        TrustCenterAddressSetReq,
        TrustCenterAddressSetRsp,
        None,
    ),
    CommandId.link_key_get: (
        LinkKeyGetReq,
        LinkKeyGetRsp,
        None,
    ),
    CommandId.link_key_set: (
        LinkKeySetReq,
        LinkKeySetRsp,
        None,
    ),
    CommandId.security_mode_get: (
        SecurityModeGetReq,
        SecurityModeGetRsp,
        None,
    ),
    CommandId.security_mode_set: (
        SecurityModeSetReq,
        SecurityModeSetRsp,
        None,
    ),
    CommandId.system_reset: (
        SystemResetReq,
        SystemResetRsp,
        SystemResetInd,
    ),
    CommandId.system_factory: (
        SystemFactoryReq,
        SystemFactoryRsp,
        SystemFactoryInd,
    ),
    CommandId.system_firmware: (
        SystemFirmwareReq,
        SystemFirmwareRsp,
        None,
    ),
    CommandId.system_model: (
        SystemModelReq,
        SystemModelRsp,
        None,
    ),
    CommandId.system_manufacturer: (
        SystemManufacturerReq,
        SystemManufacturerRsp,
        None,
    ),
}

COMMAND_SCHEMA_TO_COMMAND_ID = {
    req: command_id for command_id, (req, _, _) in COMMAND_SCHEMAS.items()
}
