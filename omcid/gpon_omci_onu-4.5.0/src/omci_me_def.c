/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_common.h"
#include "omci_me_def.h"

/* customer specific ME ID's - start */

/* customer specific ME ID's - end */
extern struct me_class me_ani_g_class;
extern struct me_class me_cardholder_class;
extern struct me_class me_circuit_pack_class;
extern struct me_class me_dop1p_mapper_class;
extern struct me_class me_dot1p_rate_limiter_class;
extern struct me_class me_equipment_extension_package_class;
extern struct me_class me_extended_vlan_config_data_class;
extern struct me_class me_gal_ethernet_profile_class;
extern struct me_class me_gem_interworking_tp_class;
extern struct me_class me_gem_port_network_ctp_class;
extern struct me_class me_ip_host_config_data_class;
extern struct me_class me_large_string_class;
extern struct me_class me_mac_bridge_config_data_class;
extern struct me_class me_mac_bridge_port_bridge_table_data_class;
extern struct me_class me_mac_bridge_port_config_data_class;
extern struct me_class me_mac_bridge_port_designation_data_class;
extern struct me_class me_mac_bridge_port_filter_preassign_table_class;
extern struct me_class me_mac_bridge_port_filter_table_data_class;
extern struct me_class me_mac_bridge_service_profile_class;
extern struct me_class me_multicast_get_interworking_tp_class;
extern struct me_class me_multicast_operations_profile_class;
extern struct me_class me_multicast_subscriber_config_class;
extern struct me_class me_multicast_subscriber_monitor_class;
extern struct me_class me_olt_g_class;
extern struct me_class me_onu_data_class;
extern struct me_class me_onu_g_class;
extern struct me_class me_onu_power_shedding_class;
extern struct me_class me_240_class;
extern struct me_class me_mac_bridge_port_extension_class;
extern struct me_class me_241_class;
extern struct me_class me_241_0_class;
extern struct me_class me_242_class;
extern struct me_class me_243_class;
extern struct me_class me_244_class;
extern struct me_class me_245_class;
extern struct me_class me_246_class;
extern struct me_class me_247_class;
extern struct me_class me_248_class;
extern struct me_class me_249_class;
extern struct me_class me_250_class;
extern struct me_class me_251_class;
extern struct me_class me_252_class;
extern struct me_class me_253_class;
extern struct me_class me_254_class;
extern struct me_class me_255_class;
extern struct me_class me_virtual_ethernet_interface_point_class;
extern struct me_class me_authentication_class;
extern struct me_class me_large_string_class;
extern struct me_class me_network_address_class;
extern struct me_class me_tcp_udp_config_data_class;
extern struct me_class me_onu2_g_class;
extern struct me_class me_dot1x_port_ext_pkg_class;
extern struct me_class me_pon_pptp_class;
extern struct me_class me_port_mapping_package_class;
extern struct me_class me_pptp_ethernet_uni_class;
extern struct me_class me_pptp_lct_uni_class;
extern struct me_class me_priority_queue_class;
extern struct me_class me_sw_image_class;
extern struct me_class me_tcont_class;
extern struct me_class me_traffic_descriptor_class;
extern struct me_class me_traffic_scheduler_class;
extern struct me_class me_uni_g_class;
extern struct me_class me_vlan_tagging_filter_data_class;
extern struct me_class me_vlan_tagging_operation_config_data_class;
extern struct me_class me_pptp_pots_uni_class;
#ifdef INCLUDE_OMCI_ONU_VOIP
extern struct me_class me_voip_config_data_class;
extern struct me_class me_voip_voice_ctp_class;
extern struct me_class me_voip_media_profile_class;
extern struct me_class me_sip_user_data_class;
extern struct me_class me_sip_agent_config_data_class;
extern struct me_class me_rtp_profile_data_class;
extern struct me_class me_network_dial_plan_table_class;
extern struct me_class me_voice_service_profile_class;
extern struct me_class me_voip_line_status_class;
#endif
#ifdef INCLUDE_CLI_SUPPORT
extern struct me_class me_onu_remote_debug_class;
#endif
#ifdef INCLUDE_PM
extern struct me_class me_ethernet_ds_pmhd_class;
extern struct me_class me_ethernet_pmhd_class;
extern struct me_class me_ethernet_pmhd2_class;
extern struct me_class me_ethernet_pmhd3_class;
extern struct me_class me_ethernet_us_pmhd_class;
extern struct me_class me_fec_pmhd_class;
extern struct me_class me_gal_ethernet_class;
extern struct me_class me_gem_port_pmhd_class;
#ifdef INCLUDE_OMCI_ONU_VOIP
extern struct me_class me_rtp_pmhd_class;
extern struct me_class me_sip_call_init_pmhd_class;
extern struct me_class me_sip_agent_pmhd_class;
extern struct me_class me_call_control_pmhd_class;
#endif
extern struct me_class me_mac_bridge_pmhd_class;
extern struct me_class me_mac_bridge_port_pmhd_class;
extern struct me_class me_threshold_data1_class;
extern struct me_class me_threshold_data2_class;
extern struct me_class me_gem_port_network_ctp_pmhd_class;
extern struct me_class me_ip_host_monitoring_data_class;
#endif
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
extern struct me_class me_attribute_class;
extern struct me_class me_managed_entity_class;
extern struct me_class me_omci_class;
#endif
extern struct me_class me_onu_dyn_pwr_mngmt_ctrl_class;
extern struct me_class me_65281_class;
extern struct me_class me_65296_class;
extern struct me_class me_65297_class;
extern struct me_class me_65305_class;
extern struct me_class me_65306_class;
extern struct me_class me_65529_class;
extern struct me_class me_65530_class;

/** \addtogroup OMCI_CORE
   @{
*/

/** List of supported ME classes

   \remarks Order of Managed Entities in this list determines the order in
	    which they will be destroyed upon MIB reset (first entities
	    get destroyed first).
*/
struct me_class *me_def_class_array[] = {

/* customer specific ME ID's - start */

/* customer specific ME ID's - end */

	/* conditional compilation can be used to select which ME will be
	   included in the build */
	&me_ani_g_class,
	&me_cardholder_class,
	&me_circuit_pack_class,
	&me_dop1p_mapper_class,
	&me_dot1p_rate_limiter_class,
	&me_equipment_extension_package_class,
	&me_extended_vlan_config_data_class,
	&me_gal_ethernet_profile_class,
	&me_gem_interworking_tp_class,
	&me_gem_port_network_ctp_class,
	&me_ip_host_config_data_class,
	&me_large_string_class,
	&me_vlan_tagging_filter_data_class,
	&me_vlan_tagging_operation_config_data_class,
	&me_mac_bridge_config_data_class,
	&me_mac_bridge_port_bridge_table_data_class,
	&me_mac_bridge_port_config_data_class,
	&me_mac_bridge_port_designation_data_class,
	&me_mac_bridge_port_filter_preassign_table_class,
	&me_mac_bridge_port_filter_table_data_class,
	&me_mac_bridge_service_profile_class,
	&me_multicast_get_interworking_tp_class,
	&me_multicast_operations_profile_class,
	&me_multicast_subscriber_config_class,
	&me_multicast_subscriber_monitor_class,
	&me_olt_g_class,
	&me_onu_data_class,
	&me_onu_g_class,
	&me_onu_power_shedding_class,
	/*&me_240_class,*/
	&me_mac_bridge_port_extension_class,
	/*&me_241_class,*/
	&me_241_0_class,
	&me_242_class,
	&me_243_class,
	&me_244_class,
	&me_245_class,
	&me_246_class,
	&me_247_class,
	&me_248_class,
	&me_249_class,
	&me_250_class,
	&me_251_class,
	&me_252_class,
	&me_253_class,
	&me_254_class,
	&me_255_class,
	&me_virtual_ethernet_interface_point_class,
	&me_authentication_class,
	&me_large_string_class,
	&me_network_address_class,
	&me_tcp_udp_config_data_class,
	&me_onu2_g_class,
	&me_dot1x_port_ext_pkg_class,
	&me_pon_pptp_class,
	&me_port_mapping_package_class,
	&me_pptp_ethernet_uni_class,
	&me_pptp_lct_uni_class,
	&me_priority_queue_class,
	&me_sw_image_class,
	&me_tcont_class,
	&me_traffic_descriptor_class,
	&me_traffic_scheduler_class,
	&me_uni_g_class,
	&me_pptp_pots_uni_class,
#ifdef INCLUDE_OMCI_ONU_VOIP
	&me_voip_config_data_class,
	&me_voip_voice_ctp_class,
	&me_voip_media_profile_class,
	&me_sip_user_data_class,
	&me_sip_agent_config_data_class,
	&me_rtp_profile_data_class,
	&me_network_dial_plan_table_class,
	&me_voice_service_profile_class,
	&me_voip_line_status_class,
#endif
#ifdef INCLUDE_CLI_SUPPORT
	&me_onu_remote_debug_class,
#endif
#ifdef INCLUDE_PM
	&me_ethernet_ds_pmhd_class,
	&me_ethernet_pmhd_class,
	&me_ethernet_pmhd2_class,
	&me_ethernet_pmhd3_class,
	&me_ethernet_us_pmhd_class,
	&me_fec_pmhd_class,
	&me_gal_ethernet_class,
	&me_gem_port_pmhd_class,
#ifdef INCLUDE_OMCI_ONU_VOIP
	&me_rtp_pmhd_class,
	&me_sip_call_init_pmhd_class,
	&me_sip_agent_pmhd_class,
	&me_call_control_pmhd_class,
#endif
	&me_mac_bridge_pmhd_class,
	&me_mac_bridge_port_pmhd_class,
	&me_threshold_data1_class,
	&me_threshold_data2_class,
	&me_gem_port_network_ctp_pmhd_class,
	&me_ip_host_monitoring_data_class,
#endif
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	&me_attribute_class,
	&me_managed_entity_class,
	&me_omci_class,
#endif
	&me_onu_dyn_pwr_mngmt_ctrl_class,
	&me_65281_class,
	&me_65296_class,
	&me_65297_class,
	&me_65305_class,
	&me_65306_class,
	&me_65529_class,
	&me_65530_class
};

size_t omci_me_def_class_array_size(void)
{
	return sizeof(me_def_class_array) / sizeof(me_def_class_array[0]);
}

/** @} */
