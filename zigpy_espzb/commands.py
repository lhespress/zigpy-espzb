"""Serial command schemas."""

import zigpy.types as t

from zigpy_espzb.types import (
    Bytes,
    DeviceType,
    ExtendedAddrMode,
    NetworkState,
    SecurityMode,
    ShiftedChannels,
    Status,
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


class FrameType(t.enum4):
    Request = 0
    Response = 1
    Indicate = 2


class Command(t.Struct):
    version: t.uint4_t
    frame_type: FrameType
    reserved: t.uint8_t

    command_id: CommandId
    seq: t.uint8_t
    length: t.uint16_t
    payload: Bytes


class NetworkInitReq(t.Struct):
    pass


class NetworkInitRsp(t.Struct):
    status: Status


class NetworkInitInd(t.Struct):
    pass


class StartReq(t.Struct):
    autostart: t.Bool


class StartRsp(t.Struct):
    status: Status


class StartInd(t.Struct):
    pass


class FormNetworkReq(t.Struct):
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


class FormNetworkRsp(t.Struct):
    status: Status


class FormNetworkInd(t.Struct):
    extended_panid: t.EUI64
    panid: t.PanId
    channel: t.uint8_t


class PermitJoiningReq(t.Struct):
    duration: t.uint8_t


class PermitJoiningRsp(t.Struct):
    status: Status


class PermitJoiningInd(t.Struct):
    duration: t.uint8_t


class LeaveNetworkReq(t.Struct):
    pass


class LeaveNetworkRsp(t.Struct):
    status: Status


class LeaveNetworkInd(t.Struct):
    short_addr: t.NWK
    device_addr: t.EUI64
    rejoin: t.Bool


class ExtpanidGetReq(t.Struct):
    pass


class ExtpanidGetRsp(t.Struct):
    ieee: t.EUI64


class ExtpanidGetInd(t.Struct):
    pass


class ExtpanidSetReq(t.Struct):
    ieee: t.EUI64


class ExtpanidSetRsp(t.Struct):
    status: Status


class ExtpanidSetInd(t.Struct):
    pass


class PanidGetReq(t.Struct):
    pass


class PanidGetRsp(t.Struct):
    panid: t.PanId


class PanidGetInd(t.Struct):
    pass


class PanidSetReq(t.Struct):
    panid: t.PanId


class PanidSetRsp(t.Struct):
    status: Status


class PanidSetInd(t.Struct):
    pass


class ShortAddrGetReq(t.Struct):
    pass


class ShortAddrGetRsp(t.Struct):
    short_addr: t.NWK


class ShortAddrGetInd(t.Struct):
    pass


class ShortAddrSetReq(t.Struct):
    short_addr: t.NWK


class ShortAddrSetRsp(t.Struct):
    status: Status


class ShortAddrSetInd(t.Struct):
    pass


class LongAddrGetReq(t.Struct):
    pass


class LongAddrGetRsp(t.Struct):
    ieee: t.EUI64


class LongAddrGetInd(t.Struct):
    pass


class LongAddrSetReq(t.Struct):
    ieee: t.EUI64


class LongAddrSetRsp(t.Struct):
    status: Status


class LongAddrSetInd(t.Struct):
    pass


class CurrentChannelGetReq(t.Struct):
    pass


class CurrentChannelGetRsp(t.Struct):
    channel: t.uint8_t


class CurrentChannelGetInd(t.Struct):
    pass


class CurrentChannelSetReq(t.Struct):
    channel: t.uint8_t


class CurrentChannelSetRsp(t.Struct):
    status: Status


class CurrentChannelSetInd(t.Struct):
    pass


class PrimaryChannelMaskGetReq(t.Struct):
    pass


class PrimaryChannelMaskGetRsp(t.Struct):
    channel_mask: ShiftedChannels


class PrimaryChannelMaskGetInd(t.Struct):
    pass


class PrimaryChannelMaskSetReq(t.Struct):
    channel_mask: ShiftedChannels


class PrimaryChannelMaskSetRsp(t.Struct):
    status: Status


class PrimaryChannelMaskSetInd(t.Struct):
    pass


class AddEndpointReq(t.Struct):
    endpoint: t.uint8_t
    profile_id: t.uint16_t
    device_id: t.uint16_t
    app_flags: t.uint8_t
    input_cluster_count: t.uint8_t
    output_cluster_count: t.uint8_t
    input_cluster_list: t.List[t.uint16_t]
    output_cluster_list: t.List[t.uint16_t]


class AddEndpointRsp(t.Struct):
    status: Status


class AddEndpointInd(t.Struct):
    pass


class NetworkStateReq(t.Struct):
    pass


class NetworkStateRsp(t.Struct):
    network_state: NetworkState


class NetworkStateInd(t.Struct):
    pass


class StackStatusHandlerReq(t.Struct):
    pass


class StackStatusHandlerRsp(t.Struct):
    network_state: t.uint8_t


class StackStatusHandlerInd(t.Struct):
    network_state: t.uint8_t


class ApsDataRequestReq(t.Struct):
    dst_addr: t.EUI64
    dst_endpoint: t.uint8_t
    src_endpoint: t.uint8_t
    address_mode: t.uint8_t
    profile_id: t.uint16_t
    cluster_id: t.uint16_t
    tx_options: t.uint8_t
    use_alias: t.Bool
    src_addr: t.EUI64
    sequence: t.uint8_t
    radius: t.uint8_t
    asdu_length: t.uint32_t
    asdu: Bytes


class ApsDataRequestRsp(t.Struct):
    status: Status


class ApsDataRequestInd(t.Struct):
    pass


class ApsDataIndicationReq(t.Struct):
    pass


class ApsDataIndicationRsp(t.Struct):
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


class ApsDataIndicationInd(t.Struct):
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


class ApsDataConfirmReq(t.Struct):
    pass


class ApsDataConfirmRsp(t.Struct):
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


class ApsDataConfirmInd(t.Struct):
    network_state: NetworkState
    dst_addr_mode: ExtendedAddrMode
    dst_addr: t.EUI64
    dst_ep: t.uint8_t
    src_ep: t.uint8_t
    tx_time: t.uint32_t
    confirm_status: TXStatus
    asdu_length: t.uint32_t
    asdu: Bytes


class NetworkKeyGetReq(t.Struct):
    pass


class NetworkKeyGetRsp(t.Struct):
    nwk_key: t.KeyData


class NetworkKeyGetInd(t.Struct):
    pass


class NetworkKeySetReq(t.Struct):
    nwk_key: t.KeyData


class NetworkKeySetRsp(t.Struct):
    status: Status


class NetworkKeySetInd(t.Struct):
    pass


class NwkFrameCounterGetReq(t.Struct):
    pass


class NwkFrameCounterGetRsp(t.Struct):
    nwk_frame_counter: t.uint32_t


class NwkFrameCounterGetInd(t.Struct):
    pass


class NwkFrameCounterSetReq(t.Struct):
    nwk_frame_counter: t.uint32_t


class NwkFrameCounterSetRsp(t.Struct):
    status: Status


class NwkFrameCounterSetInd(t.Struct):
    pass


class NetworkRoleGetReq(t.Struct):
    pass


class NetworkRoleGetRsp(t.Struct):
    role: DeviceType


class NetworkRoleGetInd(t.Struct):
    pass


class NetworkRoleSetReq(t.Struct):
    role: DeviceType


class NetworkRoleSetRsp(t.Struct):
    status: Status


class NetworkRoleSetInd(t.Struct):
    pass


class UsePredefinedNwkPanidSetReq(t.Struct):
    predefined: t.Bool


class UsePredefinedNwkPanidSetRsp(t.Struct):
    status: Status


class UsePredefinedNwkPanidSetInd(t.Struct):
    pass


class NwkUpdateIdGetReq(t.Struct):
    pass


class NwkUpdateIdGetRsp(t.Struct):
    nwk_update_id: t.uint8_t


class NwkUpdateIdGetInd(t.Struct):
    pass


class NwkUpdateIdSetReq(t.Struct):
    nwk_update_id: t.uint8_t


class NwkUpdateIdSetRsp(t.Struct):
    status: Status


class NwkUpdateIdSetInd(t.Struct):
    pass


class TrustCenterAddressGetReq(t.Struct):
    pass


class TrustCenterAddressGetRsp(t.Struct):
    trust_center_addr: t.EUI64


class TrustCenterAddressGetInd(t.Struct):
    pass


class TrustCenterAddressSetReq(t.Struct):
    trust_center_addr: t.EUI64


class TrustCenterAddressSetRsp(t.Struct):
    status: Status


class TrustCenterAddressSetInd(t.Struct):
    pass


class LinkKeyGetReq(t.Struct):
    pass


class LinkKeyGetRsp(t.Struct):
    ieee: t.EUI64
    key: t.KeyData


class LinkKeyGetInd(t.Struct):
    pass


class LinkKeySetReq(t.Struct):
    key: t.KeyData


class LinkKeySetRsp(t.Struct):
    status: Status


class LinkKeySetInd(t.Struct):
    pass


class SecurityModeGetReq(t.Struct):
    pass


class SecurityModeGetRsp(t.Struct):
    security_mode: SecurityMode


class SecurityModeGetInd(t.Struct):
    pass


class SecurityModeSetReq(t.Struct):
    security_mode: SecurityMode


class SecurityModeSetRsp(t.Struct):
    status: Status


class SecurityModeSetInd(t.Struct):
    pass


COMMAND_SCHEMAS = {
    CommandId.network_init: (
        NetworkInitReq,
        NetworkInitRsp,
        NetworkInitInd,
    ),
    CommandId.start: (
        StartReq,
        StartRsp,
        StartInd,
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
        ExtpanidGetInd,
    ),
    CommandId.extpanid_set: (
        ExtpanidSetReq,
        ExtpanidSetRsp,
        ExtpanidSetInd,
    ),
    CommandId.panid_get: (
        PanidGetReq,
        PanidGetRsp,
        PanidGetInd,
    ),
    CommandId.panid_set: (
        PanidSetReq,
        PanidSetRsp,
        PanidSetInd,
    ),
    CommandId.short_addr_get: (
        ShortAddrGetReq,
        ShortAddrGetRsp,
        ShortAddrGetInd,
    ),
    CommandId.short_addr_set: (
        ShortAddrSetReq,
        ShortAddrSetRsp,
        ShortAddrSetInd,
    ),
    CommandId.long_addr_get: (
        LongAddrGetReq,
        LongAddrGetRsp,
        LongAddrGetInd,
    ),
    CommandId.long_addr_set: (
        LongAddrSetReq,
        LongAddrSetRsp,
        LongAddrSetInd,
    ),
    CommandId.current_channel_get: (
        CurrentChannelGetReq,
        CurrentChannelGetRsp,
        CurrentChannelGetInd,
    ),
    CommandId.current_channel_set: (
        CurrentChannelSetReq,
        CurrentChannelSetRsp,
        CurrentChannelSetInd,
    ),
    CommandId.primary_channel_mask_get: (
        PrimaryChannelMaskGetReq,
        PrimaryChannelMaskGetRsp,
        PrimaryChannelMaskGetInd,
    ),
    CommandId.primary_channel_mask_set: (
        PrimaryChannelMaskSetReq,
        PrimaryChannelMaskSetRsp,
        PrimaryChannelMaskSetInd,
    ),
    CommandId.add_endpoint: (
        AddEndpointReq,
        AddEndpointRsp,
        AddEndpointInd,
    ),
    CommandId.network_state: (
        NetworkStateReq,
        NetworkStateRsp,
        NetworkStateInd,
    ),
    CommandId.stack_status_handler: (
        StackStatusHandlerReq,
        StackStatusHandlerRsp,
        StackStatusHandlerInd,
    ),
    CommandId.aps_data_request: (
        ApsDataRequestReq,
        ApsDataRequestRsp,
        ApsDataRequestInd,
    ),
    CommandId.aps_data_indication: (
        ApsDataIndicationReq,
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
        NetworkKeyGetInd,
    ),
    CommandId.network_key_set: (
        NetworkKeySetReq,
        NetworkKeySetRsp,
        NetworkKeySetInd,
    ),
    CommandId.nwk_frame_counter_get: (
        NwkFrameCounterGetReq,
        NwkFrameCounterGetRsp,
        NwkFrameCounterGetInd,
    ),
    CommandId.nwk_frame_counter_set: (
        NwkFrameCounterSetReq,
        NwkFrameCounterSetRsp,
        NwkFrameCounterSetInd,
    ),
    CommandId.network_role_get: (
        NetworkRoleGetReq,
        NetworkRoleGetRsp,
        NetworkRoleGetInd,
    ),
    CommandId.network_role_set: (
        NetworkRoleSetReq,
        NetworkRoleSetRsp,
        NetworkRoleSetInd,
    ),
    CommandId.use_predefined_nwk_panid_set: (
        UsePredefinedNwkPanidSetReq,
        UsePredefinedNwkPanidSetRsp,
        UsePredefinedNwkPanidSetInd,
    ),
    CommandId.nwk_update_id_get: (
        NwkUpdateIdGetReq,
        NwkUpdateIdGetRsp,
        NwkUpdateIdGetInd,
    ),
    CommandId.nwk_update_id_set: (
        NwkUpdateIdSetReq,
        NwkUpdateIdSetRsp,
        NwkUpdateIdSetInd,
    ),
    CommandId.trust_center_address_get: (
        TrustCenterAddressGetReq,
        TrustCenterAddressGetRsp,
        TrustCenterAddressGetInd,
    ),
    CommandId.trust_center_address_set: (
        TrustCenterAddressSetReq,
        TrustCenterAddressSetRsp,
        TrustCenterAddressSetInd,
    ),
    CommandId.link_key_get: (
        LinkKeyGetReq,
        LinkKeyGetRsp,
        LinkKeyGetInd,
    ),
    CommandId.link_key_set: (
        LinkKeySetReq,
        LinkKeySetRsp,
        LinkKeySetInd,
    ),
    CommandId.security_mode_get: (
        SecurityModeGetReq,
        SecurityModeGetRsp,
        SecurityModeGetInd,
    ),
    CommandId.security_mode_set: (
        SecurityModeSetReq,
        SecurityModeSetRsp,
        SecurityModeSetInd,
    ),
}
