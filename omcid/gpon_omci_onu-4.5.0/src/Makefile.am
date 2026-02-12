# Process this file with automake to produce Makefile.in

bin_PROGRAMS = omcid
bin_SCRIPTS = @top_srcdir@/scripts/omci_pipe.sh
lib_LIBRARIES = libomci.a libomcidaemon.a

libomci_a_extra = \
   @top_srcdir@/src/omci_alarm.h \
   @top_srcdir@/src/omci_common.h \
   @top_srcdir@/src/omci_core.h \
   @top_srcdir@/src/omci_debug.h \
   @top_srcdir@/src/omci_list.h \
   @top_srcdir@/src/omci_me.h \
   @top_srcdir@/src/omci_me_def.h \
   @top_srcdir@/src/omci_net.h \
   @top_srcdir@/src/omci_me_handlers.h \
   @top_srcdir@/src/omci_mib.h \
   @top_srcdir@/src/omci_msg_dump.h \
   @top_srcdir@/src/omci_os.h \
   @top_srcdir@/src/omci_pm.h \
   @top_srcdir@/src/omci_self_desc.h \
   @top_srcdir@/src/omci_timeout.h \
   @top_srcdir@/src/uci/list.h \
   @top_srcdir@/src/uci/omci_uci_config.h \
   @top_srcdir@/include/omci_msg.h \
   @top_srcdir@/include/omci_types.h \
   @top_srcdir@/include/omci_interface.h \
   @top_srcdir@/include/omci_interface_types.h \
   @top_srcdir@/include/me/omci_ani_g.h \
   @top_srcdir@/include/me/omci_attribute.h \
   @top_srcdir@/include/me/omci_cardholder.h \
   @top_srcdir@/include/me/omci_circuit_pack.h \
   @top_srcdir@/include/me/omci_dot1p_mapper.h \
   @top_srcdir@/include/me/omci_dot1p_rate_limiter.h \
   @top_srcdir@/include/me/omci_equipment_extension_package.h \
   @top_srcdir@/include/me/omci_ethernet_ds_pmhd.h \
   @top_srcdir@/include/me/omci_ethernet_pmhd.h \
   @top_srcdir@/include/me/omci_ethernet_pmhd2.h \
   @top_srcdir@/include/me/omci_ethernet_pmhd3.h \
   @top_srcdir@/include/me/omci_ethernet_us_pmhd.h \
   @top_srcdir@/include/me/omci_extended_vlan_config_data.h \
   @top_srcdir@/include/me/omci_fec_pmhd.h \
   @top_srcdir@/include/me/omci_gal_ethernet_pmhd.h \
   @top_srcdir@/include/me/omci_gal_ethernet_profile.h \
   @top_srcdir@/include/me/omci_gem_interworking_tp.h \
   @top_srcdir@/include/me/omci_gem_port_network_ctp.h \
   @top_srcdir@/include/me/omci_gem_port_network_ctp_pmhd.h \
   @top_srcdir@/include/me/omci_gem_port_pmhd.h \
   @top_srcdir@/include/me/omci_rtp_pmhd.h \
   @top_srcdir@/include/me/omci_call_control_pmhd.h \
   @top_srcdir@/include/me/omci_sip_call_init_pmhd.h \
   @top_srcdir@/include/me/omci_sip_agent_pmhd.h \
   @top_srcdir@/include/me/omci_voice_service_profile.h \
   @top_srcdir@/include/me/omci_network_dial_plan_table.h \
   @top_srcdir@/include/me/omci_ip_host_config_data.h \
   @top_srcdir@/include/me/omci_ip_host_monitoring_data.h \
   @top_srcdir@/include/me/omci_large_string.h \
   @top_srcdir@/include/me/omci_mac_bridge_config_data.h \
   @top_srcdir@/include/me/omci_mac_bridge_pmhd.h \
   @top_srcdir@/include/me/omci_mac_bridge_port_bridge_table_data.h \
   @top_srcdir@/include/me/omci_mac_bridge_port_config_data.h \
   @top_srcdir@/include/me/omci_mac_bridge_port_designation_data.h \
   @top_srcdir@/include/me/omci_mac_bridge_port_filter_preassign_table.h \
   @top_srcdir@/include/me/omci_mac_bridge_port_filter_table_data.h \
   @top_srcdir@/include/me/omci_mac_bridge_port_pmhd.h \
   @top_srcdir@/include/me/omci_mac_bridge_service_profile.h \
   @top_srcdir@/include/me/omci_managed_entity.h \
   @top_srcdir@/include/me/omci_multicast_gem_interworking_tp.h \
   @top_srcdir@/include/me/omci_multicast_operations_profile.h \
   @top_srcdir@/include/me/omci_multicast_subscriber_config.h \
   @top_srcdir@/include/me/omci_multicast_subscriber_monitor.h \
   @top_srcdir@/include/me/omci_olt_g.h \
   @top_srcdir@/include/me/omci_omci.h \
   @top_srcdir@/include/me/omci_onu_data.h \
   @top_srcdir@/include/me/omci_onu_g.h \
   @top_srcdir@/include/me/omci_dot1x_port_ext_pkg.h \
   @top_srcdir@/include/me/omci_onu_power_shedding.h \
   @top_srcdir@/include/me/omci_onu_remote_debug.h \
   @top_srcdir@/include/me/omci_onu2_g.h \
   @top_srcdir@/include/me/omci_port_mapping_package.h \
   @top_srcdir@/include/me/omci_pptp_ethernet_uni.h \
   @top_srcdir@/include/me/omci_pptp_lct_uni.h \
   @top_srcdir@/include/me/omci_pptp_pots_uni.h \
   @top_srcdir@/include/me/omci_priority_queue.h \
   @top_srcdir@/include/me/omci_rtp_profile_data.h \
   @top_srcdir@/include/me/omci_sw_image.h \
   @top_srcdir@/include/me/omci_tcont.h \
   @top_srcdir@/include/me/omci_threshold_data1.h \
   @top_srcdir@/include/me/omci_threshold_data2.h \
   @top_srcdir@/include/me/omci_traffic_descriptor.h \
   @top_srcdir@/include/me/omci_traffic_scheduler.h \
   @top_srcdir@/include/me/omci_uni_g.h \
   @top_srcdir@/include/me/omci_vlan_tagging_filter_data.h \
   @top_srcdir@/include/me/omci_vlan_tagging_operation_config_data.h \
   @top_srcdir@/include/me/omci_me_240.h \
   @top_srcdir@/include/me/omci_mac_bridge_port_extension.h \
   @top_srcdir@/include/me/omci_me_241.h \
   @top_srcdir@/include/me/omci_me_241_0.h \
   @top_srcdir@/include/me/omci_me_242.h \
   @top_srcdir@/include/me/omci_me_243.h \
   @top_srcdir@/include/me/omci_me_244.h \
   @top_srcdir@/include/me/omci_me_245.h \
   @top_srcdir@/include/me/omci_me_246.h \
   @top_srcdir@/include/me/omci_me_247.h \
   @top_srcdir@/include/me/omci_me_248.h \
   @top_srcdir@/include/me/omci_me_249.h \
   @top_srcdir@/include/me/omci_me_250.h \
   @top_srcdir@/include/me/omci_me_251.h \
   @top_srcdir@/include/me/omci_me_252.h \
   @top_srcdir@/include/me/omci_me_253.h \
   @top_srcdir@/include/me/omci_me_254.h \
   @top_srcdir@/include/me/omci_me_255.h \
   @top_srcdir@/include/me/omci_virtual_ethernet_interface_point.h \
   @top_srcdir@/include/me/omci_voip_config_data.h \
   @top_srcdir@/include/me/omci_voip_voice_ctp.h \
   @top_srcdir@/include/me/omci_voip_media_profile.h \
   @top_srcdir@/include/me/omci_voip_line_status.h \
   @top_srcdir@/include/me/omci_sip_user_data.h \
   @top_srcdir@/include/me/omci_sip_agent_config_data.h \
   @top_srcdir@/include/me/omci_authentication_security_method.h \
   @top_srcdir@/include/me/omci_network_address.h \
   @top_srcdir@/include/me/omci_tcp_udp_config_data.h \
   @top_srcdir@/include/me/omci_onu_dyn_pwr_mngmt_ctrl.h \
   @top_srcdir@/include/me/omci_enhanced_security_control.h \
   @top_srcdir@/include/me/omci_ipv6_host_config_data.h \
   @top_srcdir@/include/me/omci_stub_mes.h \
   @top_srcdir@/include/me/omci_me_65529.h \
   @top_srcdir@/include/me/omci_me_65530.h

libomci_a_customer =

libomci_a_SOURCES = \
   $(libomci_a_customer) \
   omci_alarm.c \
   omci_config_api.c \
   omci_net.c \
   omci_interface.c \
   omci_core.c \
   omci_debug.c \
   omci_list.c \
   omci_me.c \
   omci_me_def.c \
   omci_me_handlers.c \
   omci_mib.c \
   omci_msg_dump.c \
   omci_pm.c \
   omci_os.c \
   omci_timeout.c \
   me/omci_ani_g.c \
   me/omci_attribute.c \
   me/omci_cardholder.c \
   me/omci_circuit_pack.c \
   me/omci_dot1p_mapper.c \
   me/omci_dot1p_rate_limiter.c \
   me/omci_equipment_extension_package.c \
   me/omci_ethernet_ds_pmhd.c \
   me/omci_ethernet_pmhd.c \
   me/omci_ethernet_pmhd2.c \
   me/omci_ethernet_pmhd3.c \
   me/omci_ethernet_us_pmhd.c \
   me/omci_extended_vlan_config_data.c \
   me/omci_fec_pmhd.c \
   me/omci_gal_ethernet_pmhd.c \
   me/omci_gal_ethernet_profile.c \
   me/omci_gem_interworking_tp.c \
   me/omci_gem_port_network_ctp.c \
   me/omci_gem_port_network_ctp_pmhd.c \
   me/omci_gem_port_pmhd.c \
   me/omci_rtp_pmhd.c \
   me/omci_call_control_pmhd.c \
   me/omci_sip_call_init_pmhd.c \
   me/omci_sip_agent_pmhd.c \
   me/omci_voice_service_profile.c \
   me/omci_network_dial_plan_table.c \
   me/omci_ip_host_config_data.c \
   me/omci_ip_host_monitoring_data.c \
   me/omci_large_string.c \
   me/omci_mac_bridge_config_data.c \
   me/omci_mac_bridge_pmhd.c \
   me/omci_mac_bridge_port_bridge_table_data.c \
   me/omci_mac_bridge_port_config_data.c \
   me/omci_mac_bridge_port_designation_data.c \
   me/omci_mac_bridge_port_filter_preassign_table.c \
   me/omci_mac_bridge_port_filter_table_data.c \
   me/omci_mac_bridge_port_pmhd.c \
   me/omci_mac_bridge_service_profile.c \
   me/omci_managed_entity.c \
   me/omci_multicast_gem_interworking_tp.c \
   me/omci_multicast_operations_profile.c \
   me/omci_multicast_subscriber_config.c \
   me/omci_multicast_subscriber_monitor.c \
   me/omci_olt_g.c \
   me/omci_omci.c \
   me/omci_onu_data.c \
   me/omci_onu_g.c \
   me/omci_dot1x_port_ext_pkg.c \
   me/omci_onu_power_shedding.c \
   me/omci_onu_remote_debug.c \
   me/omci_onu2_g.c \
   me/omci_port_mapping_package.c \
   me/omci_pptp_ethernet_uni.c \
   me/omci_pptp_lct_uni.c \
   me/omci_pptp_pots_uni.c \
   me/omci_priority_queue.c \
   me/omci_rtp_profile_data.c \
   me/omci_sw_image.c \
   me/omci_tcont.c \
   me/omci_threshold_data1.c \
   me/omci_threshold_data2.c \
   me/omci_traffic_descriptor.c \
   me/omci_traffic_scheduler.c \
   me/omci_uni_g.c \
   me/omci_vlan_tagging_filter_data.c \
   me/omci_vlan_tagging_operation_config_data.c \
   me/omci_me_240.c \
   me/omci_mac_bridge_port_extension.c \
   me/omci_me_241.c \
   me/omci_me_241_0.c \
   me/omci_me_242.c \
   me/omci_me_243.c \
   me/omci_me_244.c \
   me/omci_me_245.c \
   me/omci_me_246.c \
   me/omci_me_247.c \
   me/omci_me_248.c \
   me/omci_me_249.c \
   me/omci_me_250.c \
   me/omci_me_251.c \
   me/omci_me_252.c \
   me/omci_me_253.c \
   me/omci_me_254.c \
   me/omci_me_255.c \
   me/omci_virtual_ethernet_interface_point.c \
   me/omci_voip_config_data.c \
   me/omci_voip_voice_ctp.c \
   me/omci_voip_media_profile.c \
   me/omci_voip_line_status.c \
   me/omci_sip_user_data.c \
   me/omci_sip_agent_config_data.c \
   me/omci_authentication_security_method.c \
   me/omci_network_address.c \
   me/omci_tcp_udp_config_data.c \
   me/omci_onu_dyn_pwr_mngmt_ctrl.c \
   me/omci_enhanced_security_control.c \
   me/omci_ipv6_host_config_data.c \
   me/omci_stub_mes.c \
   uci/omci_uci_config.c \
   me/omci_me_65529.c \
   me/omci_me_65530.c

libomcidaemon_a_extra = \
   @top_srcdir@/src/daemon/omci_daemon.h

libomcidaemon_a_SOURCES = \
   cli/omci_cli_access.c \
   cli/omci_cli_autogen.c \
   daemon/omci_daemon.c \
   daemon/omci_daemon_mib.c

omcid_extra =

omcid_SOURCES =

EXTRA_DIST = \
   $(libomci_a_extra) \
   $(libomcidaemon_a_extra) \
   $(omcid_extra)

lib_dep = @OMCI_EXTRA_DEP_PATH@

# OpenWRT trunk has a suffix from TARGET_NAME
#pjsuffix=-mips-openwrt-linux-gnu
pjsuffix=-@target@
if INCLUDE_OMCI_ONU_VOIP
pjsip_library = \
	-lpjsua$(pjsuffix) \
	-lpjsip-ua$(pjsuffix) \
	-lpjsip-simple$(pjsuffix) \
	-lpjsip$(pjsuffix) \
	-lpjmedia-audiodev$(pjsuffix) \
	-lpjmedia-codec$(pjsuffix) \
	-lpjmedia$(pjsuffix) \
	-lresample$(pjsuffix) \
	-lsrtp$(pjsuffix) \
	-lpjnath$(pjsuffix) \
	-lpjlib-util$(pjsuffix) \
	-lpj$(pjsuffix) -luuid
else
pjsip_library =
endif

if INCLUDE_OMCI_ONU_UCI
if HAVE_LIB_UCI_MAP
uci_library=-luci -lucimap
else
uci_library=-luci
endif
endif

if INCLUDE_OMCI_ONU_DMALLOC
dmalloc_library = -ldmalloc
else
dmalloc_library =
endif

libomciapi_library = -lomciapi

if INCLUDE_DRIVER_SIMULATION
libomciapi_library += -lonu -loptic
endif

if INCLUDE_REMOTE_ONU
libomciapi_library += -lgponrpc
endif

if INCLUDE_CLI_SUPPORT
cli_library=-lcli
else
cli_library=
endif

AM_CFLAGS = -DLINUX -D__LINUX__ \
            -D_GNU_SOURCE \
            -I@top_srcdir@/include/ \
            @IFXOS_INCLUDE_PATH@ \
            @CLI_INCLUDE_PATH@ \
            @OMCI_API_INCLUDE_PATH@

AM_LDFLAGS = -L@builddir@ \
             @IFXOS_LIBRARY_PATH@ \
             @CLI_LIBRARY_PATH@ \
             @OMCI_API_LIBRARY_PATH@ \
             @PJSIP_LIBRARY_PATH@

libomci_a_CFLAGS = $(AM_CFLAGS)
libomcidaemon_a_CFLAGS = $(AM_CFLAGS)
omcid_CFLAGS = $(AM_CFLAGS)

omcid_DEPENDENCIES = libomcidaemon.a libomci.a $(lib_dep)

omcid_LDFLAGS = $(AM_LDFLAGS)

omcid_LDADD = libomcidaemon.a \
                          libomci.a\
                          $(libomciapi_library)\
                          $(pjsip_library)\
                          $(cli_library)\
                          $(uci_library)\
                          $(dmalloc_library)\
                          -lifxos -lpthread -lrt -lm

