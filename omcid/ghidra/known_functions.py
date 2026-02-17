"""
Master mapping of known function names in the stock v7.5.1 omcid binary.

Two sources:
1. STRING_OFFSETS: __FUNCTION__ macro strings embedded in the binary.
   Key = string value, Value = file offset (add BASE_ADDR for VA).
   These are resolved by finding literal pool pointers → xref → containing function.

2. MANUAL_ADDRESSES: Functions identified by decompilation/analysis.
   Key = VA (integer), Value = function name.
   These are applied directly by address.
"""

# ── __FUNCTION__ string offsets (from `strings -t x` on stock binary) ──────────
# These strings are referenced via literal pool pointers in MIPS16e code.
# The containing function is the one that uses the __FUNCTION__ macro.

STRING_OFFSETS = {
    # Core API
    "omci_api_ctx_get": 0x4e368,
    "omci_api_usock_msg_send": 0x824e4,
    "omci_api_onu_event_link_state_change": 0x827c0,

    # Timer API
    "omci_api_timer_stop": 0x834a8,
    "omci_api_timer_start": 0x834bc,
    "omci_api_timer_delete": 0x834d4,
    "omci_api_timer_create": 0x834ec,

    # ANI-G
    "omci_api_ani_g_update": 0x836e4,
    "omci_api_ani_g_destroy": 0x836fc,

    # Equipment Extension Package
    "omci_api_equipment_extension_package_update": 0x83934,
    "omci_api_equipment_extension_package_destroy": 0x83960,
    "omci_api_equipment_extension_package_create": 0x83990,

    # Ethernet DS PMHD
    "omci_api_ethernet_ds_pmhd_thr_set": 0x83a6c,
    "omci_api_ethernet_ds_pmhd_cnt_get": 0x83a90,
    "omci_api_ethernet_ds_pmhd_cnt_reset": 0x83ab4,
    "omci_api_ethernet_ds_pmhd_total_cnt_get": 0x83ad8,

    # Energy Consumption PMHD
    "omci_api_energy_consumption_pmhd_cnt_get": 0x83b00,
    "omci_api_energy_consumption_pmhd_total_cnt_get": 0x83b2c,

    # Ethernet PMHD
    "omci_api_ethernet_pmhd_thr_set": 0x83cf4,
    "omci_api_ethernet_pmhd_cnt_get": 0x83d14,
    "omci_api_ethernet_pmhd_cnt_reset": 0x83d34,
    "omci_api_ethernet_pmhd_total_cnt_get": 0x83d58,

    # Ethernet Ext PMHD
    "omci_api_eth_ext_pmhd_total_cnt_get": 0x83f8c,

    # Ethernet US PMHD
    "omci_api_ethernet_us_pmhd_thr_set": 0x8411c,
    "omci_api_ethernet_us_pmhd_cnt_get": 0x84140,
    "omci_api_ethernet_us_pmhd_cnt_reset": 0x84164,
    "omci_api_ethernet_us_pmhd_total_cnt_get": 0x84188,

    # Extended VLAN Config Data
    "omci_api_extended_vlan_config_data_tag_oper_table_clear": 0x846dc,
    "omci_api_extended_vlan_config_data_tag_oper_table_entry_remove": 0x84714,
    "omci_api_extended_vlan_config_data_tag_oper_table_entry_add": 0x84754,
    "omci_api_ext_vlan_cfg_data_destroy": 0x847b0,
    "omci_api_ext_vlan_cfg_data_update": 0x847d4,
    "omci_api_ext_vlan_action_add": 0x8cc00,

    # FEC PMHD
    "omci_api_fec_pmhd_thr_set": 0x8ccd8,
    "omci_api_fec_pmhd_cnt_get": 0x8ccf4,
    "omci_api_fec_pmhd_total_cnt_get": 0x8cd10,

    # GAL Ethernet PMHD
    "omci_api_gal_ethernet_pmhd_thr_set": 0x8cd5c,
    "omci_api_gal_ethernet_pmhd_cnt_get": 0x8cd80,
    "omci_api_gal_ethernet_pmhd_total_cnt_get": 0x8cda4,

    # GEM Interworking TP
    "omci_api_gem_interworking_tp_update": 0x8ceb4,

    # GEM Port Network CTP
    "omci_api_gem_port_network_ctp_update": 0x8d0f4,
    "omci_api_gem_port_pmhd_cnt_get": 0x8d11c,
    "omci_api_gem_port_pmhd_cnt_reset": 0x8d13c,
    "omci_api_gem_port_pmhd_total_cnt_get": 0x8d160,

    # MAC Bridge PMHD
    "omci_api_mac_bridge_pmhd_cnt_get": 0x8d1b8,
    "omci_api_mac_bridge_pmhd_total_cnt_get": 0x8d1dc,

    # MAC Bridge Port Bridge Table Data
    "omci_api_mac_bridge_port_bridge_table_data_bridge_table_get": 0x8d2b0,
    "omci_api_mac_bridge_port_bridge_table_data_destroy": 0x8d2ec,
    "omci_api_mac_bridge_port_bridge_table_data_create": 0x8d320,

    # MAC Bridge Port Config Data
    "omci_api_mac_bridge_port_config_data_destroy": 0x8d668,
    "omci_api_mac_bridge_port_config_data_update": 0x8d698,

    # MAC Bridge Port Filter
    "omci_api_mac_bridge_port_filter_preassign_table_update": 0x8d868,
    "omci_api_mac_bridge_port_filter_preassign_table_destroy": 0x8d8a0,
    "omci_api_mac_bridge_port_filter_table_entry_remove": 0x8d98c,
    "omci_api_mac_bridge_port_filter_table_entry_add": 0x8d9c0,
    "omci_api_mac_bridge_port_filter_assign": 0x8d9f0,

    # MAC Bridge Port Ethernet PMHD
    "omci_api_mac_bridge_port_eth_pmhd_mtu_exceeded_discard_total_cnt_get": 0x8da54,
    "omci_api_mac_bridge_port_eth_pmhd_mtu_exceeded_discard_cnt_get": 0x8da9c,
    "omci_api_mac_bridge_port_pmhd_cnt_get": 0x8dadc,
    "omci_api_mac_bridge_port_pmhd_total_cnt_get": 0x8db04,

    # MAC Bridge Service Profile
    "omci_api_mac_bridge_service_profile_destroy": 0x8dc88,
    "omci_api_mac_bridge_service_profile_update": 0x8dcb4,

    # Multicast GEM Interworking TP
    "omci_api_multicast_gem_interworking_tp_multicast_address_table_entry_remove": 0x8de08,
    "omci_api_multicast_gem_interworking_tp_multicast_address_table_entry_add": 0x8de54,
    "omci_api_multicast_gem_interworking_tp_update": 0x8dea0,

    # Multicast Operations Profile
    "omci_api_multicast_operations_profile_static_acl_table_entry_remove": 0x8e02c,
    "omci_api_multicast_operations_profile_static_acl_table_entry_add": 0x8e070,

    # OLT-G
    "omci_api_olt_g_update": 0x8e240,

    # ONU-G
    "omci_api_onu_g_update": 0x8e280,
    "omci_api_onu_g_destroy": 0x8e298,
    "omci_api_onu_g_create": 0x8e2b0,

    # PPTP Ethernet UNI
    "omci_api_pptp_ethernet_uni_lan_port_enable": 0x8e918,
    "omci_api_pptp_ethernet_uni_sensed_type_get": 0x8e944,
    "omci_api_pptp_ethernet_uni_oper_state_get": 0x8e970,
    "omci_api_pptp_ethernet_uni_configuration_ind_get": 0x8e99c,
    "omci_api_pptp_ethernet_uni_config": 0x8e9d0,
    "omci_api_pptp_ethernet_uni_update": 0x8e9f4,
    "omci_api_pptp_ethernet_uni_destroy": 0x8ea18,
    "omci_api_pptp_ethernet_uni_create": 0x8ea3c,
    "omci_api_pptp_ethernet_uni_lan_is_available": 0x8ea60,

    # VEIP
    "omci_api_veip_destroy": 0x8ea8c,
    "omci_api_veip_create": 0x8eaa4,

    # PPTP LCT UNI
    "omci_api_pptp_lct_uni_update": 0x8eb84,
    "omci_api_pptp_lct_uni_destroy": 0x8eba4,
    "omci_api_pptp_lct_uni_create": 0x8ebc4,

    # Priority Queue
    "omci_api_priority_queue_update": 0x8efec,
    "omci_api_priority_queue_destroy": 0x8f00c,
    "omci_api_priority_queue_create": 0x8f02c,

    # Traffic Descriptor
    "omci_api_traffic_descriptor_destroy": 0x8f970,
    "omci_api_traffic_descriptor_update": 0x8f994,

    # Traffic Scheduler
    "omci_api_traffic_scheduler_update": 0x8fb0c,
    "omci_api_traffic_scheduler_destroy": 0x8fb30,
    "omci_api_traffic_scheduler_create": 0x8fb54,

    # VLAN Tagging Filter Data
    "omci_api_vlan_tagging_filter_data_destroy": 0x8fbcc,
    "omci_api_vlan_tagging_filter_data_update": 0x8fbf8,

    # VLAN Tagging Operation Conf Data
    "omci_api_vlan_tagging_operation_conf_data_destroy": 0x8fdb4,
    "omci_api_vlan_tagging_operation_conf_data_update": 0x8fde8,

    # ONU Dynamic Power Management
    "omci_api_onu_dyn_pwr_mngmt_ctrl_update": 0x8ff3c,

    # 802.1x Port Extension Package
    "omci_api_dotx_port_ext_pkg_pptp_eth_uni_update": 0x9000c,

    # ONU Loop Detection
    "omci_api_onu_loop_detection_packet_send": 0x90128,
    "omci_api_onu_loop_detection_destroy": 0x90150,
    "omci_api_onu_loop_detection_update": 0x90174,
    "omci_api_onu_loop_detection_create": 0x90198,
}

# ── Callback function __FUNCTION__ strings ─────────────────────────────────────
CALLBACK_STRING_OFFSETS = {
    "omci_net_iface_state_cb": 0x4e328,
    "error_cb": 0x4e678,
    "ploam_state_change_cb": 0x4e684,
    "event_cb": 0x4e69c,     # first occurrence
    "end_dl_cb": 0x6f320,
    "commit_cb": 0x6f364,
}

# ── Manually identified function addresses (from decompilation) ────────────────
# Key = entry point VA, Value = function name
MANUAL_ADDRESSES = {
    # Core API
    0x00432244: "omci_api_dev_ctl",
    0x00432538: "omci_api_init",
    0x00432bd0: "omci_api_start",

    # Mapper infrastructure
    0x00433390: "omci_api_uni2lan",
    0x004333b0: "omci_api_uni2port",
    0x00434ac0: "omci_api_mapper_explicit_map",
    0x00434de0: "omci_api_mapper_index_get",
    0x004352a0: "omci_api_mapper_explicit_unmap",

    # PPTP Ethernet UNI API (confirmed by decompilation)
    0x0043e870: "omci_api_pptp_ethernet_uni_config",
    0x0043f300: "omci_api_pptp_ethernet_uni_create",
    0x0043f36c: "omci_api_pptp_ethernet_uni_destroy",
    0x0043f4c8: "omci_api_pptp_ethernet_uni_update",
    0x0043f91c: "omci_api_pptp_ethernet_uni_lan_port_enable",
    0x0043f08c: "omci_api_pptp_ethernet_uni_lan_is_available",

    # Unknown functions (NEW in v7.5.1, need investigation)
    0x004461a0: "FUN_004461a0_from_config",    # called from _config, pppoe filter?
    0x00446624: "FUN_00446624_from_destroy",    # called from _destroy

    # Ubus and helpers
    0x00446ba0: "omci_api_sce_meter_helper",    # meter_l2_only + common_ip_handling
    0x00446cd8: "omci_api_ubus_init",
    0x00446db0: "omci_api_ubus_exit",
    0x00446e08: "omci_api_ubus_start",
    0x00446ed4: "omci_api_ubus_loop_thread",

    # Extended VLAN (from bell-aliant-dual-vlan.md)
    0x00415a44: "rx_vlan_oper_table_entry_set",
    0x004390a0: "omci_api_ext_vlan_filter2action",
    0x0043a130: "omci_api_ext_vlan_action_add_impl",

    # ME handlers (from bell-aliant analysis)
    0x004172bc: "me266_update",
    0x0041740c: "me266_validate",
    0x0041747c: "me266_shutdown",
    0x00415810: "me171_init",
    0x00415740: "me171_shutdown",

    # LCT UNI (from mac decompilation)
    0x0041a522: "me83_init_wrapper",     # calls mac_filter_add
    0x0041a2d4: "lct_mac_filter_add",
    0x0041a544: "lct_mac_filter_remove",
    0x0041a68c: "me83_shutdown",
    0x0041a258: "popen_helper",

    # Meter create (from lct decompilation)
    0x00445a68: "omci_api_meter_create",

    # ── Discovered by rename_functions.py CreateFunctionCmd (MIPS16e gaps) ────
    # These functions existed in the binary but Ghidra's auto-analysis didn't
    # create function objects for them. CreateFunctionCmd resolved them.

    # Callbacks
    0x0040887a: "omci_net_iface_state_cb",
    0x00408b8a: "event_cb",              # also error_cb, ploam_state_change_cb (shared handler)
    0x0042371e: "end_dl_cb",
    0x00423126: "commit_cb",

    # Core API
    0x004342a6: "omci_api_onu_event_link_state_change",

    # Timer API
    0x00435956: "omci_api_timer_start",
    0x004358da: "omci_api_timer_create",

    # Equipment Extension Package
    0x004367ba: "omci_api_equipment_extension_package_create",

    # PM counters (total_cnt_get and thr_set variants Ghidra missed)
    0x00436ca6: "omci_api_ethernet_ds_pmhd_thr_set",
    0x004369ee: "omci_api_ethernet_ds_pmhd_total_cnt_get",
    0x00436d36: "omci_api_energy_consumption_pmhd_total_cnt_get",
    0x00436f02: "omci_api_ethernet_pmhd_total_cnt_get",
    0x00438736: "omci_api_ethernet_us_pmhd_total_cnt_get",
    0x0043acce: "omci_api_fec_pmhd_total_cnt_get",
    0x0043aefa: "omci_api_gal_ethernet_pmhd_total_cnt_get",
    0x0043ba26: "omci_api_gem_port_pmhd_total_cnt_get",
    0x0043bd7e: "omci_api_mac_bridge_pmhd_total_cnt_get",
    0x0043d5ce: "omci_api_mac_bridge_port_eth_pmhd_mtu_exceeded_discard_total_cnt_get",
    0x0043d3c6: "omci_api_mac_bridge_port_pmhd_total_cnt_get",

    # Extended VLAN
    0x00439346: "omci_api_extended_vlan_config_data_tag_oper_table_entry_add",

    # MAC Bridge Port Bridge Table Data
    0x0043c21e: "omci_api_mac_bridge_port_bridge_table_data_bridge_table_get",
    0x0043bf22: "omci_api_mac_bridge_port_bridge_table_data_destroy",
    0x0043bece: "omci_api_mac_bridge_port_bridge_table_data_create",

    # Multicast Operations Profile
    0x0043e35a: "omci_api_multicast_operations_profile_static_acl_table_entry_remove",
    0x0043e302: "omci_api_multicast_operations_profile_static_acl_table_entry_add",

    # OLT-G, ONU-G
    0x0043e3f2: "omci_api_olt_g_update",
    0x0043e47e: "omci_api_onu_g_destroy",
    0x0043e54e: "omci_api_onu_g_create",

    # PPTP Ethernet UNI (MIPS16e wrappers)
    0x0043fa16: "omci_api_pptp_ethernet_uni_lan_port_enable_wrapper",
    0x0043f8fa: "omci_api_pptp_ethernet_uni_sensed_type_get",
    0x0043f78e: "omci_api_pptp_ethernet_uni_oper_state_get",
    0x0043f69a: "omci_api_pptp_ethernet_uni_configuration_ind_get",
}
