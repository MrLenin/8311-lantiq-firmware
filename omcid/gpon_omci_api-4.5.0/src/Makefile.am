# Process this file with automake to produce Makefile.in

lib_LIBRARIES = libomciapi.a

libomciapi_a_extra = \
   @top_srcdir@/src/omci_api_common.h \
   @top_srcdir@/src/omci_api_debug.h \
   @top_srcdir@/src/omci_api_event.h \
   @top_srcdir@/src/omci_api_mapper.h \
   @top_srcdir@/src/omci_api_std_defs.h \
   @top_srcdir@/src/omci_api_timer.h \
   @top_srcdir@/include/omci_api.h \
   @top_srcdir@/include/omci_api_usock.h \
   @top_srcdir@/include/me/omci_api_ani_g.h \
   @top_srcdir@/include/me/omci_api_call_control_pmhd.h \
   @top_srcdir@/include/me/omci_api_cardholder.h \
   @top_srcdir@/include/me/omci_api_circuit_pack.h \
   @top_srcdir@/include/me/omci_api_dot1p_mapper.h \
   @top_srcdir@/include/me/omci_api_dot1p_rate_limiter.h \
   @top_srcdir@/include/me/omci_api_equipment_extension_package.h \
   @top_srcdir@/include/me/omci_api_ethernet_ds_pmhd.h \
   @top_srcdir@/include/me/omci_api_ethernet_pmhd.h \
   @top_srcdir@/include/me/omci_api_ethernet_pmhd2.h \
   @top_srcdir@/include/me/omci_api_ethernet_pmhd3.h \
   @top_srcdir@/include/me/omci_api_ethernet_us_pmhd.h \
   @top_srcdir@/include/me/omci_api_extended_vlan_config_data.h \
   @top_srcdir@/include/me/omci_api_extended_vlan_table.h \
   @top_srcdir@/include/me/omci_api_fec_pmhd.h \
   @top_srcdir@/include/me/omci_api_gal_ethernet_pmhd.h \
   @top_srcdir@/include/me/omci_api_gal_ethernet_profile.h \
   @top_srcdir@/include/me/omci_api_gem_interworking_tp.h \
   @top_srcdir@/include/me/omci_api_gem_port_network_ctp.h \
   @top_srcdir@/include/me/omci_api_gem_port_pmhd.h \
   @top_srcdir@/include/me/omci_api_rtp_pmhd.h \
   @top_srcdir@/include/me/omci_api_sip_call_init_pmhd.h \
   @top_srcdir@/include/me/omci_api_sip_agent_pmhd.h \
   @top_srcdir@/include/me/omci_api_mac_bridge_pmhd.h \
   @top_srcdir@/include/me/omci_api_mac_bridge_port_bridge_table_data.h \
   @top_srcdir@/include/me/omci_api_mac_bridge_port_config_data.h \
   @top_srcdir@/include/me/omci_api_mac_bridge_port_config_data_intern.h \
   @top_srcdir@/include/me/omci_api_mac_bridge_port_designation_data.h \
   @top_srcdir@/include/me/omci_api_mac_bridge_port_filter_preassign_table.h \
   @top_srcdir@/include/me/omci_api_mac_bridge_port_filter_table_data.h \
   @top_srcdir@/include/me/omci_api_mac_bridge_port_pmhd.h \
   @top_srcdir@/include/me/omci_api_mac_bridge_service_profile.h \
   @top_srcdir@/include/me/omci_api_mac_bridge_service_profile_intern.h \
   @top_srcdir@/include/me/omci_api_multicast_gem_interworking_tp.h \
   @top_srcdir@/include/me/omci_api_multicast_operations_profile.h \
   @top_srcdir@/include/me/omci_api_multicast_subscr_config_info.h \
   @top_srcdir@/include/me/omci_api_multicast_subscr_monitor.h \
   @top_srcdir@/include/me/omci_api_olt_g.h \
   @top_srcdir@/include/me/omci_api_onu_g.h \
   @top_srcdir@/include/me/omci_api_onu2_g.h \
   @top_srcdir@/include/me/omci_api_dot1x_port_ext_pkg.h \
   @top_srcdir@/include/me/omci_api_pptp_ethernet_uni.h \
   @top_srcdir@/include/me/omci_api_pptp_lct_uni.h \
   @top_srcdir@/include/me/omci_api_veip.h \
   @top_srcdir@/include/me/omci_api_priority_queue.h \
   @top_srcdir@/include/me/omci_api_sw_image.h \
   @top_srcdir@/include/me/omci_api_sw_image_falcon.h \
   @top_srcdir@/include/me/omci_api_tcont.h \
   @top_srcdir@/include/me/omci_api_traffic_descriptor.h \
   @top_srcdir@/include/me/omci_api_traffic_scheduler.h \
   @top_srcdir@/include/me/omci_api_uni_g.h \
   @top_srcdir@/include/me/omci_api_vlan_tagging_filter_data.h \
   @top_srcdir@/include/me/omci_api_vlan_tagging_operation_config_data.h \
   @top_srcdir@/include/me/omci_api_onu_dyn_pwr_mngmt_ctrl.h \
   @top_srcdir@/include/me/omci_api_table_access.h \
   @top_srcdir@/include/mcc/omci_api_mcc.h \
   @top_srcdir@/src/mcc/omci_api_mcc_common.h \
   @top_srcdir@/include/voip/omci_api_voip.h \
   @top_srcdir@/src/voip/omci_api_voip_common.h \
   @top_srcdir@/src/voip/omci_api_fxs.h  \
   @top_srcdir@/src/voip/omci_api_sip.h 

libomciapi_a_SOURCES = \
   omci_api.c \
   omci_api_usock.c \
   omci_api_event.c \
   omci_api_mapper.c \
   omci_api_timer.c \
   me/omci_api_ani_g.c \
   me/omci_api_call_control_pmhd.c \
   me/omci_api_cardholder.c \
   me/omci_api_circuit_pack.c \
   me/omci_api_dot1p_mapper.c \
   me/omci_api_dot1p_rate_limiter.c \
   me/omci_api_dot1x_port_ext_pkg.c \
   me/omci_api_equipment_extension_package.c \
   me/omci_api_ethernet_ds_pmhd.c \
   me/omci_api_ethernet_pmhd.c \
   me/omci_api_ethernet_pmhd2.c \
   me/omci_api_ethernet_pmhd3.c \
   me/omci_api_ethernet_us_pmhd.c \
   me/omci_api_extended_vlan_config_data.c \
   me/omci_api_extended_vlan_table.c \
   me/omci_api_fec_pmhd.c \
   me/omci_api_gal_ethernet_pmhd.c \
   me/omci_api_gal_ethernet_profile.c \
   me/omci_api_gem_interworking_tp.c \
   me/omci_api_gem_port_network_ctp.c \
   me/omci_api_gem_port_pmhd.c \
   me/omci_api_rtp_pmhd.c \
   me/omci_api_sip_call_init_pmhd.c \
   me/omci_api_sip_agent_pmhd.c \
   me/omci_api_mac_bridge_pmhd.c \
   me/omci_api_mac_bridge_port_bridge_table_data.c \
   me/omci_api_mac_bridge_port_config_data.c \
   me/omci_api_mac_bridge_port_config_data_intern.c \
   me/omci_api_mac_bridge_port_designation_data.c \
   me/omci_api_mac_bridge_port_filter_preassign_table.c \
   me/omci_api_mac_bridge_port_filter_table_data.c \
   me/omci_api_mac_bridge_port_pmhd.c \
   me/omci_api_mac_bridge_service_profile.c \
   me/omci_api_mac_bridge_service_profile_intern.c \
   me/omci_api_multicast_gem_interworking_tp.c \
   me/omci_api_multicast_operations_profile.c \
   me/omci_api_multicast_subscr_config_info.c \
   me/omci_api_multicast_subscr_monitor.c \
   me/omci_api_olt_g.c \
   me/omci_api_onu_g.c \
   me/omci_api_onu2_g.c \
   me/omci_api_pptp_ethernet_uni.c \
   me/omci_api_pptp_lct_uni.c \
   me/omci_api_veip.c \
   me/omci_api_priority_queue.c \
   me/omci_api_sw_image.c \
   me/omci_api_sw_image_falcon.c \
   me/omci_api_tcont.c \
   me/omci_api_traffic_descriptor.c \
   me/omci_api_traffic_scheduler.c \
   me/omci_api_uni_g.c \
   me/omci_api_vlan_tagging_filter_data.c \
   me/omci_api_vlan_tagging_operation_config_data.c \
   me/omci_api_onu_dyn_pwr_mngmt_ctrl.c \
   me/omci_api_table_access.c \
   mcc/omci_api_mcc.c

libomciapi_a_SOURCES += \
   me/omci_api_pptp_pots_uni.c \
   me/omci_api_sip_agent_config_data.c \
   me/omci_api_sip_user_data.c \
   me/omci_api_voip_voice_ctp.c \
   voip/omci_api_fxs.c \
   voip/omci_api_sip.c \
   voip/omci_api_voip.c

libomciapi_a_extra += \
   @top_srcdir@/include/me/omci_api_pptp_pots_uni.h \
   @top_srcdir@/include/me/omci_api_sip_agent_config_data.h \
   @top_srcdir@/include/me/omci_api_sip_user_data.h \
   @top_srcdir@/include/me/omci_api_voip_voice_ctp.h \
   @top_srcdir@/src/voip/omci_api_fxs.h \
   @top_srcdir@/src/voip/omci_api_sip.h \
   @top_srcdir@/src/voip/omci_api_voip_common.h \
   @top_srcdir@/include/voip/omci_api_voip.h

EXTRA_DIST = \
   $(libomciapi_a_extra)

AM_CFLAGS = -DLINUX -D__LINUX__ -DPJ_IS_BIG_ENDIAN=1 -DPJ_IS_LITTLE_ENDIAN=0 \
            -DONU_DEVICE_PSB980xx=@ONU_DEVICE_PSB980xx@ \
            -I@top_srcdir@/include/ \
            @IFXOS_INCLUDE_PATH@ \
            @DRIVER_INCLUDE_PATH@ \
            @PJSIP_INCLUDE_PATH@ \
            @TAPI_INCLUDE_PATH@ \
            @VMMC_INCLUDE_PATH@

libomciapi_a_CFLAGS = $(AM_CFLAGS)

