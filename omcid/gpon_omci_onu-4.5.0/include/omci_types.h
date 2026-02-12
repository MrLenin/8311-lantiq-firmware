/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_types_h
#define _omci_types_h

__BEGIN_DECLS

/** \defgroup OMCI_TYPES Optical Network Unit - OMCI Types

    This module contains OMCI related type definitions
   @{
*/

#ifndef SWIG
/** Attribute number to attribute mask bit field.

   N = [1 .. 16] */
static inline uint16_t omci_attr2mask(unsigned int attr)
{
	return 1 << (16 - attr);
}

/** Check if the pointer is null */
static inline int omci_is_ptr_null(uint16_t ptr)
{
	return ptr == 0x0000 || ptr == 0xffff;
}
#endif

/** OMCI message formats (Device identifier field of OMCI message) */
enum {
	/** Baseline message format */
	OMCI_FORMAT_BASELINE = 0x0a,

	/** Extended message format */
	OMCI_FORMAT_EXTENDED = 0x0b
};

/** OMCI message results
    \see ITU-T G.984.4 II.1.3 */
enum {
	/** \par command processed successfully
	   There are two functions for
	   command processing: command interpretation and command execution.
	   This result means that the received command, such as
	   Get/Set/Test/Reboot, was properly interpreted by the ONT's command
	   interpretation function without errors and that the interpreted
	   command was successfully transferred to the ONT's command execution
	   function. */
	OMCI_MR_CMD_SUCCESS = 0,

	/** \par command processing error
	   This result means the command processing
	   failed at the ONT due to some reason not described by item
	   \ref OMCI_MR_CMD_NOT_SUPPORTED, \ref OMCI_MR_PARAM_ERROR, etc. */
	OMCI_MR_CMD_ERROR = 1,

	/** \par command not supported
	   This result means that the message type indicated in Byte 8 is not
	   supported by the ONT. */
	OMCI_MR_CMD_NOT_SUPPORTED = 2,

	/** \par parameter error
	   This result means that the command message received by the ONT was
	   errored. */
	OMCI_MR_PARAM_ERROR = 3,

	/** \par unknown Managed Entity
	   This result means that the Managed Entity class indicated in
	   Bytes 10 and 11 is not supported by the ONT. */
	OMCI_MR_UNKNOWN_ME = 4,

	/** \par unknown Managed Entity instance
	   This result means that the Managed Entity instance indicated in
	   Bytes 12 and 13 does not exist in the ONT. */
	OMCI_MR_UNKNOWN_ME_INST = 5,

	/** \par device busy
	   This result means that the command could not be processed due to
	   process-related congestion at the ONT. */
	OMCI_MR_DEVICE_BUSY = 6,

	/** \par instance exists */
	OMCI_MR_INST_EXISTS = 7,

	/** \par attribute(s) failed or unknown
	   This result means that an optional attribute is not supported by the
	   ONT or that a 35 mandatory/optional attribute could not be executed
	   by the ONT, even if it is supported. In conjunction with this result,
	   attribute masks are used to indicate which attributes failed or were
	   unknown. */
	OMCI_MR_ATTR_FAILED = 9
};

/** OMCI message types
    \see ITU-T G.984.4 Table 11-1 */
enum {
	/** Create a Managed Entity instance with its attributes */
	OMCI_MT_CREATE = 4,

	/** Delete a Managed Entity instance */
	OMCI_MT_DELETE = 6,

	/** Set one or more attributes of a Managed Entity */
	OMCI_MT_SET = 8,

	/** Get one or more attributes of a Managed Entity */
	OMCI_MT_GET = 9,

	/** Latch the alarm statuses of all managed entities and reset the
	   alarm message counter */
	OMCI_MT_GET_ALL_ALARMS = 11,

	/** Get the active alarm status of the next Managed Entity */
	OMCI_MT_GET_ALL_ALARMS_NEXT = 12,

	/** Latch the MIB */
	OMCI_MT_MIB_UPLOAD = 13,

	/** Get latched attributes of a Managed Entity instance */
	OMCI_MT_MIB_UPLOAD_NEXT = 14,

	/** Clear the MIB and re-initialize it to its default and reset the MIB
	   data sync counter to 0 */
	OMCI_MT_MIB_RESET = 15,

	/** Notification of an alarm */
	OMCI_MT_ALARM = 16,

	/** Notification of an autonomous attribute value change */
	OMCI_MT_AVC = 17,

	/** Request a test on a specific Managed Entity */
	OMCI_MT_TEST = 18,

	/** Start a software download action */
	OMCI_MT_START_SW_DL = 19,

	/** Download a section of a software image */
	OMCI_MT_DL_SECTION = 20,

	/** End of a software download action */
	OMCI_MT_END_SW_DL = 21,

	/** Activate the downloaded software image */
	OMCI_MT_ACTIVATE_SW = 22,

	/** Commit the downloaded software image */
	OMCI_MT_COMMIT_SW = 23,

	/** Synchronize the time between OLT and ONT */
	OMCI_MT_SYNC_TIME = 24,

	/** Reboot ONT or circuit pack */
	OMCI_MT_REBOOT = 25,

	/** Get the latched attribute values of the Managed Entity within the
	   current snapshot */
	OMCI_MT_GET_NEXT = 26,

	/** Notification of test result that is initiated by "Test" */
	OMCI_MT_TEST_RESULT = 27,

	/** Get current counter value associated with one or more attributes of
	   a Managed Entity */
	OMCI_MT_GET_CURR_DATA = 28
};

/** Managed entity identifiers
    \see ITU-T G.984.4 Table 11-2 */
enum {

/* customer specific ME ID's - start */

/* customer specific ME ID's - end */

	/** Invalid Managed Entity (not ITU definition) */
	OMCI_ME_INVALID = 0,

	/** ONT B-PON */
	OMCI_ME_ONT_BPON = 1,

	/** ONU data */
	OMCI_ME_ONU_DATA = 2,

	/** PON IF line cardholder */
	OMCI_ME_PON_IF_LINE_CARDHOLDER = 3,

	/** PON IF line */
	OMCI_ME_PON_IF_LINE = 4,

	/** Cardholder */
	OMCI_ME_CARDHOLDER = 5,

	/** Circuit pack */
	OMCI_ME_CIRCUIT_PACK = 6,

	/** Software image */
	OMCI_ME_SW_IMAGE = 7,

	/** UNI B-PON */
	OMCI_ME_UNI_BPON = 8,

	/** TC Adapter B-PON */
	OMCI_ME_TC_ADAPTER_BPON = 9,

	/** Physical path termination point ATM UNI */
	OMCI_ME_PPTP_ATM_UNI = 10,

	/** Physical path termination point Ethernet UNI */
	OMCI_ME_PPTP_ETHERNET_UNI = 11,

	/** Physical path termination point CES UNI */
	OMCI_ME_PPTP_CES_UNI = 12,

	/** Logical Nx64 kbit/s sub-port connection termination point */
	OMCI_ME_LOGICAL_NX64_TP = 13,

	/** Interworking VCC termination point */
	OMCI_ME_INTERWORKING_VCC_TP = 14,

	/** AAL1 profile B-PON */
	OMCI_ME_AAL1_PROFILE_BPON = 15,

	/** AAL5 profile */
	OMCI_ME_AAL5_PROFILE = 16,

	/** AAL1 protocol monitoring history data B-PON */
	OMCI_ME_AAL1_PMHD_BPON = 17,

	/** AAL1 protocol monitoring history data */
	OMCI_ME_AAL1_PMHD = 18,

	/** AAL2 profile */
	OMCI_ME_AAL2_PROFILE = 19,

	/* 20 - intentionally left blank */

	/** CES service profile-G */
	OMCI_ME_CES_SERVICE_PROFILE_G = 21,

	/* 22 - reserved */

	/** CES physical interface monitoring history data */
	OMCI_ME_CES_PIMHD = 23,

	/** Ethernet performance monitoring history data */
	OMCI_ME_ETHERNET_PMHD = 24,

	/** VP network CTP */
	OMCI_ME_VP_NETWORK_CTP = 25,

	/** ATM VP cross-connection */
	OMCI_ME_ATM_VP_CC = 26,

	/** Priority queue B-PON */
	OMCI_ME_PRIORITY_QUEUE_BPON = 27,

	/** DBR/CBR traffic descriptor */
	OMCI_ME_DBR_CBR_TRAFFIC_DESCRIPTOR = 28,

	/** UBR traffic descriptor */
	OMCI_ME_UBR_TRAFFIC_DESCRIPTOR = 29,

	/** SBR1/VBR1 traffic descriptor */
	OMCI_ME_SBR1_VBR1_TRAFFIC_DESCRIPTOR = 30,

	/** SBR2/VBR2 traffic descriptor */
	OMCI_ME_SBR2_VBR2_TRAFFIC_DESCRIPTOR = 31,

	/** SBR3/VBR3 traffic descriptor */
	OMCI_ME_SBR3_VBR3_TRAFFIC_DESCRIPTOR = 32,

	/** ABR traffic descriptor */
	OMCI_ME_ABR_TRAFFIC_DESCRIPTOR = 33,

	/** GFR traffic descriptor */
	OMCI_ME_GFR_TRAFFIC_DESCRIPTOR = 33,

	/** ABR/DT/IT traffic descriptor */
	OMCI_ME_ABR_DT_IT_TRAFFIC_DESCRIPTOR = 35,

	/** UPC disagreement monitoring history data B-PON */
	OMCI_ME_UPC_DMHD_BPON = 36,

	/* 37 - intentionally left blank */

	/** ANI */
	OMCI_ME_ANI = 38,

	/** PON TC adapter */
	OMCI_ME_PON_TC_ADAPTER = 39,

	/** PON physical path termination point */
	OMCI_ME_PON_PPTP = 40,

	/** TC adapter protocol monitoring history data */
	OMCI_ME_TC_ADAPTER_PMHD = 41,

	/** Threshold data B-PON */
	OMCI_ME_THRESHOLD_DATA_BPON = 42,

	/** Operator specific */
	OMCI_ME_OPERATOR_SPECIFIC = 43,

	/** Vendor specific */
	OMCI_ME_VENDOR_SPECIFIC = 44,

	/** MAC bridge service profile */
	OMCI_ME_MAC_BRIDGE_SERVICE_PROFILE = 45,

	/** MAC bridge configuration data */
	OMCI_ME_MAC_BRIDGE_CONFIGURATION_DATA = 46,

	/** MAC bridge port configuration data */
	OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA = 47,

	/** MAC bridge port designation data */
	OMCI_ME_MAC_BRIDGE_PORT_DESIGNATION_DATA = 48,

	/** MAC bridge port filter table data */
	OMCI_ME_MAC_BRIDGE_PORT_FILTER_TABLE_DATA = 49,

	/** MAC bridge port bridge table data */
	OMCI_ME_MAC_BRIDGE_PORT_BRIDGE_TABLE_DATA = 50,

	/** MAC bridge PM history data */
	OMCI_ME_MAC_BRIDGE_PMHD = 51,

	/** MAC bridge port PM history data */
	OMCI_ME_MAC_BRIDGE_PORT_PMHD = 52,

	/** Physical path termination point POTS UNI */
	OMCI_ME_PPTP_POTS_UNI = 53,

	/** Voice CTP */
	OMCI_ME_VOICE_CTP = 54,

	/** Voice PM history data */
	OMCI_ME_VOICE_PMHD = 55,

	/** AAL2 PVC profile B-PON */
	OMCI_ME_AAL2_PVC_PROFILE_BPON = 56,

	/** AAL2 CPS protocol monitoring history data B-PON */
	OMCI_ME_AAL2_CPS_PMHD_BPON = 57,

	/** Voice service profile AAL */
	OMCI_ME_VOICE_SERVICE_PROFILE_AAL = 58,

	/** LES service profile */
	OMCI_ME_LES_SERVICE_PROFILE = 59,

	/** AAL2 SSCS parameter profile 1 */
	OMCI_ME_AAL2_SSCS_PARAMETER_PROFILE_1 = 60,

	/** AAL2 SSCS parameter profile 2 */
	OMCI_ME_AAL2_SSCS_PARAMETER_PROFILE_2 = 61,

	/** VP PM history data */
	OMCI_ME_VP_PMHD = 62,

	/** Traffic scheduler */
	OMCI_ME_TRAFFIC_SCHEDULER_BPON = 63,

	/** T-CONT buffer */
	OMCI_ME_TCONT_BUFFER = 64,

	/** UBR+ traffic descriptor */
	OMCI_ME_UBRPLUS_TRAFFIC_DESCRIPTOR = 65,

	/** AAL2 SSCS protocol monitoring history data B-PON */
	OMCI_ME_AAL2_SSCS_PMHD_BPON = 66,

	/** IP port configuration data */
	OMCI_ME_IP_PORT_CONFIG_DATA = 67,

	/** IP router service profile */
	OMCI_ME_IP_ROUTER_SERVICE_PROFILE = 68,

	/** IP router configuration data */
	OMCI_ME_IP_ROUTER_CONFIG_DATA = 69,

	/** IP router PM history data 1 */
	OMCI_ME_IP_ROUTER_PMHD_1 = 70,

	/** IP router PM history data 2 */
	OMCI_ME_IP_ROUTER_PMHD_2 = 71,

	/** ICMP PM history data 1 */
	OMCI_ME_ICMP_PMHD_1 = 72,

	/** ICMP PM history data 2 */
	OMCI_ME_ICMP_PMHD_2 = 73,

	/** IP route table */
	OMCI_ME_IP_ROUTE_TABLE = 74,

	/** IP static routes */
	OMCI_ME_IP_STATIC_ROUTES = 75,

	/** ARP service profile */
	OMCI_ME_ARP_SERVICE_PROFILE = 76,

	/** ARP configuration data */
	OMCI_ME_ARP_CONFIG_DATA = 77,

	/** VLAN tagging operation configuration data */
	OMCI_ME_VLAN_TAGGING_OPERATION_CONFIG_DATA = 78,

	/** MAC bridge port filter preassign table */
	OMCI_ME_MAC_BRIDGE_PORT_FILTER_PREASSIGN_TABLE = 79,

	/** Physical path termination point ISDN UNI */
	OMCI_ME_PPTP_ISDN_UNI = 80,

	/* 81 - reserved */

	/** Physical path termination point video UNI */
	OMCI_ME_PPTP_VIDEO_UNI = 82,

	/** Physical path termination point LCT UNI */
	OMCI_ME_PPTP_LCT_UNI = 83,

	/** VLAN tagging filter data */
	OMCI_ME_VLAN_TAGGING_FILTER_DATA = 84,

	/** ONU B-PON */
	OMCI_ME_ONU_BPON = 85,

	/** ATM VC cross-connection */
	OMCI_ME_ATM_VC_CC = 86,

	/** VC network CTP B-PON */
	OMCI_ME_VC_NETWORK_CTP_BPON = 87,

	/** VC PM history data */
	OMCI_ME_VC_PMHD = 88,

	/** Ethernet performance monitoring history data 2 */
	OMCI_ME_ETHERNET_PMHD2 = 89,

	/** Physical path termination point video ANI */
	OMCI_ME_PPTP_VIDEO_ANI = 90,

	/** Physical path termination point 802.11 UNI */
	OMCI_ME_PPTP_80211_UNI = 91,

	/** 802.11 station management data 1 */
	OMCI_ME_80211_STATION_MANAGEMENT_DATA_1 = 92,

	/** 802.11 station management data 2 */
	OMCI_ME_80211_STATION_MANAGEMENT_DATA_2 = 93,

	/** 802.11 general purpose object */
	OMCI_ME_80211_GENERAL_PURPOSE_OBJECT = 94,

	/** 802.11 MAC&PHY operation and antenna data */
	OMCI_ME_80211_MAC_PHY_OPERATION_AND_ANTENNA_DATA = 95,

	/** 802.11 counters */
	OMCI_ME_80211_COUNTERS = 96,

	/** 802.11 PHY FHSS DSSS IR tables */
	OMCI_ME_80211_PHY_FHSS_DSSS_IR_TABLES = 97,

	/** Physical path termination point xDSL UNI part 1 */
	OMCI_ME_PPTP_XDSL_UNI_1 = 98,

	/** Physical path termination point xDSL UNI part 2 */
	OMCI_ME_PPTP_XDSL_UNI_2 = 99,

	/** xDSL line inventory and status data part 1 */
	OMCI_ME_XDSL_LINE_INVENTORY_AND_STATUS_DATA_1 = 100,

	/** xDSL line inventory and status data part 2 */
	OMCI_ME_XDSL_LINE_INVENTORY_AND_STATUS_DATA_2 = 101,

	/** xDSL channel downstream status data */
	OMCI_ME_XDSL_CHANNEL_DS_STATUS_DATA = 102,

	/** xDSL channel upstream status data */
	OMCI_ME_XDSL_CHANNEL_US_STATUS_DATA = 103,

	/** xDSL line configuration profile part 1 */
	OMCI_ME_XDSL_LINE_CONFIG_PROFILE_1 = 104,

	/** xDSL line configuration profile part 2 */
	OMCI_ME_XDSL_LINE_CONFIG_PROFILE_2 = 105,

	/** xDSL line configuration profile part 3 */
	OMCI_ME_XDSL_LINE_CONFIG_PROFILE_3 = 106,

	/** xDSL channel configuration profile */
	OMCI_ME_XDSL_CHANNEL_CONFIG_PROFILE = 107,

	/** xDSL subcarrier masking downstream profile */
	OMCI_ME_XDSL_SUBCARRIER_MASKING_DS_PROFILE = 108,

	/** xDSL subcarrier masking upstream profile */
	OMCI_ME_XDSL_SUBCARRIER_MASKING_US_PROFILE = 109,

	/** xDSL PSD mask profile */
	OMCI_ME_XDSL_PSD_MASK_PROFILE = 110,

	/** xDSL downstream RFI bands profile */
	OMCI_ME_XDSL_DS_RFI_BANDS_PROFILE = 111,

	/** xDSL xTU-C performance monitoring history data */
	OMCI_ME_XDSL_XTUC_PMHD = 112,

	/** xDSL xTU-R performance monitoring history data */
	OMCI_ME_XDSL_XTUR_PMHD = 113,

	/** xDSL xTU-C channel performance monitoring history data */
	OMCI_ME_XDSL_XTUC_CHANNEL_PMHD = 114,

	/** xDSL xTU-R channel performance monitoring history data */
	OMCI_ME_XDSL_XTUR_CHANNEL_PMHD = 115,

	/** TC adaptor performance monitoring history data xDSL */
	OMCI_ME_TC_ADAPTOR_PMHD_XDSL = 116,

	/** Physical path termination point VDSL UNI */
	OMCI_ME_PPTP_VDSL_UNI = 117,

	/** VDSL VTU-O physical data */
	OMCI_ME_VDSL_VTUO_PHYSICAL_DATA = 118,

	/** VDSL VTU-R physical data */
	OMCI_ME_VDSL_VTUR_PHYSICAL_DATA = 119,

	/** VDSL channel data */
	OMCI_ME_VDSL_CHANNEL_DATA = 120,

	/** VDSL line configuration profile */
	OMCI_ME_VDSL_LINE_CONFIG_PROFILE = 121,

	/** VDSL channel configuration profile */
	OMCI_ME_VDSL_CHANNEL_CONFIG_PROFILE = 122,

	/** VDSL band plan configuration profile */
	OMCI_ME_VDSL_BAND_PLAN_CONFIG_PROFILE = 123,

	/** VDSL VTU-O physical interface monitoring history data */
	OMCI_ME_VDSL_VTUO_PIMHD = 124,

	/** VDSL VTU-R physical interface monitoring history data */
	OMCI_ME_VDSL_VTUR_PIMHD = 125,

	/** VDSL VTU-O channel performance monitoring history data */
	OMCI_ME_VDSL_VTUO_CHANNEL_PMDH = 126,

	/** VDSL VTU-R channel performance monitoring history data */
	OMCI_ME_VDSL_VTUR_CHANNEL_PMDH = 127,

	/** Video return path service profile */
	OMCI_ME_VIDEO_RETURN_PATH_SERVICE_PROFILE = 128,

	/** Video return path statistics */
	OMCI_ME_VIDEO_RETURN_PATH_STATISTICS = 129,

	/** 802.1p mapper service profile */
	OMCI_ME_DOT1P_MAPPER_SERVICE_PROFILE = 130,

	/** OLT-G */
	OMCI_ME_OLT_G = 131,

	/** Multicast interworking VCC termination point */
	OMCI_ME_MULTICAST_INTERWORKING_VCC_TP = 132,

	/** ONU power shedding */
	OMCI_ME_ONU_POWER_SHEDDING = 133,

	/** IP host config data */
	OMCI_ME_IP_HOST_CONFIG_DATA = 134,

	/** IP host monitoring data */
	OMCI_ME_IP_HOST_MONITORING_DATA = 135,

	/** TCP/UDP config data */
	OMCI_ME_TCP_UDP_CONFIG_DATA = 136,

	/** Network address */
	OMCI_ME_NETWORK_ADDRESS = 137,

	/** VoIP config data */
	OMCI_ME_VOIP_CONFIG_DATA = 138,

	/** VoIP voice CTP */
	OMCI_ME_VOIP_VOICE_CTP = 139,

	/** Call control PM history data */
	OMCI_ME_CALL_CONTROL_PMHD = 140,

	/** VoIP line status */
	OMCI_ME_VOIP_LINE_STATUS = 141,

	/** VoIP media profile */
	OMCI_ME_VOIP_MEDIA_PROFILE = 142,

	/** RTP profile data */
	OMCI_ME_RTP_PROFILE_DATA = 143,

	/** RTP monitoring data */
	OMCI_ME_RTP_MONITORING_DATA = 144,

	/** Network dial plan table */
	OMCI_ME_NETWORK_DIAL_PLAN_TABLE = 145,

	/** VoIP application service profile */
	OMCI_ME_VOIP_APPLICATION_SERVICE_PROFILE = 146,

	/** VoIP feature access codes */
	OMCI_ME_VOIP_FEATURE_ACCESS_CODES = 147,

	/** Authentication security method */
	OMCI_ME_AUTHENTICATION_SECURITY_METHOD = 148,

	/** SIP config portal */
	OMCI_ME_SIP_CONFIG_PORTAL = 149,

	/** SIP agent config data */
	OMCI_ME_SIP_AGENT_CONFIG_DATA = 150,

	/** SIP agent monitoring data */
	OMCI_ME_SIP_AGENT_MONITORING_DATA = 151,

	/** SIP call initiation performance monitoring history data */
	OMCI_ME_SIP_CALL_INITIATION_PMHD = 152,

	/** SIP user data */
	OMCI_ME_SIP_USER_DATA = 153,

	/** MGC config portal */
	OMCI_ME_MGC_CONFIG_PORTAL = 154,

	/** MGC config data */
	OMCI_ME_MGC_CONFIG_DATA = 155,

	/** MGC monitoring data */
	OMCI_ME_MGC_MONITORING_DATA = 156,

	/** Large string */
	OMCI_ME_LARGE_STRING = 157,

	/** ONU remote debug */
	OMCI_ME_ONU_REMOTE_DEBUG = 158,

	/** Equipment protection profile */
	OMCI_ME_EQUIPMENT_PROTECTION_PROFILE = 159,

	/** Equipment extension package */
	OMCI_ME_EQUIPMENT_EXTENSION_PACKAGE = 160,

	/** Port mapping package */
	OMCI_ME_PORT_MAPPING_PACKAGE_BPON = 161,

	/** Physical Path Termination Point MoCA UNI */
	OMCI_ME_PPTP_MOCA_UNI = 162,

	/** MoCA Ethernet PM history data */
	OMCI_ME_MOCA_ETHERNET_PMHD = 163,

	/** MoCA Interface PM history data */
	OMCI_ME_MOCA_INTERFACE_PMHD = 164,

	/** VDSL2 line configuration extensions */
	OMCI_ME_VDSL2_LINE_CONFIG_EXTENSION = 165,

	/** xDSL line inventory and status data part 3 */
	OMCI_ME_XDSL_LINE_INVENTORY_AND_STATUS_DATA_3 = 166,

	/** xDSL line inventory and status data part 4 */
	OMCI_ME_XDSL_LINE_INVENTORY_AND_STATUS_DATA_4 = 167,

	/** VDSL2 line inventory and status data part 1 */
	OMCI_ME_VDSL2_LINE_INVENTORY_AND_STATUS_DATA_1 = 168,

	/** VDSL2 line inventory and status data part 2 */
	OMCI_ME_VDSL2_LINE_INVENTORY_AND_STATUS_DATA_2 = 169,

	/** VDSL2 line inventory and status data part 3 */
	OMCI_ME_VDSL2_LINE_INVENTORY_AND_STATUS_DATA_3 = 170,

	/** Extended VLAN tagging operation configuration data */
	OMCI_ME_EXTENDED_VLAN_TAGGING_OPERATION_CONFIG_DATA = 171,

	/* 172 - 239 reserved for future B-PON managed entities */

	/* 240 - 255 reserved for vendor-specific managed entities */

	/** vendor-specific ME 240 */
	OMCI_ME_240 = 240,

	/** vendor-specific ME 241 */
	OMCI_ME_241 = 241,

	/** vendor-specific ME 242 */
	OMCI_ME_242 = 242,

	/** vendor-specific ME 243 */
	OMCI_ME_243 = 243,

	/** vendor-specific ME 244 */
	OMCI_ME_244 = 244,

	/** vendor-specific ME 245 */
	OMCI_ME_245 = 245,

	/** vendor-specific ME 246 */
	OMCI_ME_246 = 246,

	/** vendor-specific ME 247 */
	OMCI_ME_247 = 247,

	/** vendor-specific ME 248 */
	OMCI_ME_248 = 248,

	/** vendor-specific ME 249 */
	OMCI_ME_249 = 249,

	/** vendor-specific ME 250 */
	OMCI_ME_250 = 250,

	/** vendor-specific ME 251 */
	OMCI_ME_251 = 251,

	/** vendor-specific ME 252 */
	OMCI_ME_252 = 252,

	/** vendor-specific ME 253 */
	OMCI_ME_253 = 253,

	/** vendor-specific ME 254 */
	OMCI_ME_254 = 254,

	/** vendor-specific ME 255 */
	OMCI_ME_255 = 255,

	/** ONU-G */
	OMCI_ME_ONU_G = 256,

	/** ONT2-G */
	OMCI_ME_ONU2_G = 257,

	/** ONU-G (deprecated in G.988) */
	OMCI_ME_ONU_G_DEPRECATED = 258,

	/** ONU2-G (deprecated in G.988) */
	OMCI_ME_ONU2_G_DEPRECATED = 259,

	/** PON IF line card-G */
	OMCI_ME_PON_IF_LINE_CARD_G = 260,

	/** PON TC adapter-G */
	OMCI_ME_PON_TC_ADAPTER_G = 261,

	/** T-CONT */
	OMCI_ME_TCONT = 262,

	/** ANI-G */
	OMCI_ME_ANI_G = 263,

	/** UNI-G */
	OMCI_ME_UNI_G = 264,

	/** ATM interworking VCC termination point */
	OMCI_ME_ATM_INTERWORKING_VCC_TP = 265,

	/** GEM interworking termination point */
	OMCI_ME_GEM_INTERWORKING_TP = 266,

	/** GEM port protocol monitoring history data */
	OMCI_ME_GEM_PORT_PMHD = 267,

	/** GEM port network CTP */
	OMCI_ME_GEM_PORT_NETWORK_CTP = 268,

	/** VP network CTP-G */
	OMCI_ME_VP_NETWORK_CTP_G = 269,

	/** VC network CTP-G */
	OMCI_ME_VC_NETWORK_CTP_G = 270,

	/** GAL TDM profile */
	OMCI_ME_GAL_TDM_PROFILE = 271,

	/** GAL Ethernet profile */
	OMCI_ME_GAL_ETHERNET_PROFILE = 272,

	/** Threshold data 1 */
	OMCI_ME_THRESHOLD_DATA1 = 273,

	/** Threshold data 2 */
	OMCI_ME_THRESHOLD_DATA2 = 274,

	/** GAL TDM protocol monitoring history data */
	OMCI_ME_GAL_TDM_PMHD = 275,

	/** GAL Ethernet protocol monitoring history data */
	OMCI_ME_GAL_ETHERNET_PMHD = 276,

	/** Priority queue */
	OMCI_ME_PRIORITY_QUEUE = 277,

	/** Traffic scheduler */
	OMCI_ME_TRAFFIC_SCHEDULER = 278,

	/** Protection data */
	OMCI_ME_PROTECTION_DATA = 279,

	/** Traffic descriptor */
	OMCI_ME_TRAFFIC_DESCRIPTOR = 280,

	/** Multicast GEM interworking termination point */
	OMCI_ME_MULTICAST_GEM_INTERWORKING_TP = 281,

	/** Pseudowire termination point */
	OMCI_ME_PSEUDOWIRE_TP = 282,

	/** RTP pseudowire parameters */
	OMCI_ME_RTP_PSEUDOWIRE_PARAMETERS = 283,

	/** Pseudowire maintenance profile */
	OMCI_ME_PSEUDOWIRE_MAINTENANCE_PROFILE = 284,

	/** Pseudowire performance monitoring history data */
	OMCI_ME_PSEUDOWIRE_PMHD = 285,

	/** Ethernet flow termination point */
	OMCI_ME_ETHERNET_FLOW_TP = 286,

	/** OMCI */
	OMCI_ME_OMCI = 287,

	/** Managed Entity */
	OMCI_ME_MANAGED_ENTITY = 288,

	/** Attribute */
	OMCI_ME_ATTRIBUTE = 289,

	/** Dot1X port extension package */
	OMCI_ME_DOT1X_PORT_EXTENSION_PACKAGE = 290,

	/** Dot1X configuration profile */
	OMCI_ME_DOT1X_CONFIG_PROFILE = 291,

	/** Dot1X performance monitoring history data */
	OMCI_ME_DOT1X_PMHD = 292,

	/** Radius performance monitoring history data */
	OMCI_ME_RADIUS_PMHD = 293,

	/** TU connection termination port */
	OMCI_ME_TU_CONNECTION_TP = 294,

	/** TU performance monitoring history data */
	OMCI_ME_TU_PMHD = 295,

	/** Ethernet performance monitoring history data 3 */
	OMCI_ME_ETHERNET_PMHD3 = 296,

	/** Port mapping package */
	OMCI_ME_PORT_MAPPING_PACKAGE = 297,

	/** Dot1 rate limiter */
	OMCI_ME_DOT1P_RATE_LIMITER = 298,

	/** Dot1ag maintenance domain */
	OMCI_ME_DOT1AG_MAINTENANCE_DOMAIN = 299,

	/** Dot1ag maintenance association */
	OMCI_ME_DOT1AG_MAINTENANCE_ASSOCIATION = 300,

	/** Dot1ag default MD level */
	OMCI_ME_DOT1AG_DEFAULT_MD_LEVEL = 301,

	/** Dot1ag MEP */
	OMCI_ME_DOT1AG_MEP = 302,

	/** Dot1ag MEP status*/
	OMCI_ME_DOT1AG_MEP_STATUS = 303,

	/** Dot1ag MEP CCM database */
	OMCI_ME_DOT1AG_MEP_CCM_DATABASE = 304,

	/** Dot1ag CFM stack */
	OMCI_ME_DOT1AG_CFM_STACK = 305,

	/** Dot1ag chassis-management info */
	OMCI_ME_DOT1AG_CHASSIS_MANAGEMENT_INFO = 306,

	/** Octet string */
	OMCI_ME_OCTET_STRING = 307,

	/** General purpose buffer */
	OMCI_ME_GENERAL_PURPOSE_BUFFER = 308,

	/** Multicast operations profile */
	OMCI_ME_MULTICAST_OPERATIONS_PROFILE = 309,

	/** Multicast subscriber config info */
	OMCI_ME_MULTICAST_SUBSCRIBER_CONFIG_INFO = 310,

	/** Multicast subscriber monitor */
	OMCI_ME_MULTICAST_SUBSCRIBER_MONITOR = 311,

	/** FEC performance monitoring history data */
	OMCI_ME_FEC_PMHD = 312,

	/* 313 - 65279 reserved for future standardization */

	/** Ethernet Frame Performance Monitoring History Data Downstream */
	OMCI_ME_ETHERNET_FRAME_PMHD_DS = 321,

	/** Ethernet Frame Performance Monitoring History Data Upstream */
	OMCI_ME_ETHERNET_FRAME_PMHD_US = 322,
	/** Virtual Ethernet interface point */
	OMCI_ME_VIRTUAL_ETHERNET_INTERFACE_POINT = 329,

	/** GEM port network CTP PMHD (renumbered 333→341 per G.988 2017
	    and shipping v7.5.1 binary) */
	OMCI_ME_GEM_PORT_NETWORK_CTP_PMHD = 341,

	/** Enhanced Security Control */
	OMCI_ME_ENHANCED_SECURITY_CONTROL = 332,

	/** ONU dynamic power management control */
	OMCI_ME_ONU_DYN_PWR_MNGMT_CTRL = 336,

	/** Ethernet Frame Extended PMHD */
	OMCI_ME_ETHERNET_EXTENDED_PMHD = 334,

	/** IPv6 Host Config Data */
	OMCI_ME_IPV6_CONFIG_DATA = 347,

	/** Energy Consumption PMHD */
	OMCI_ME_ENERGY_CONSUMPTION_PMHD = 343,

	/** PoE Control */
	OMCI_ME_POE_CTRL = 349,

	/** Ethernet Frame Extended PMHD 64-bit */
	OMCI_ME_ETHERNET_EXTENDED_PMHD_64 = 425,

	/* 65280 - 65535 reserved for vendor specific use */
	OMCI_ME_ZTE_EMOP = 65282,

	OMCI_ME_ONU_LOOP_DETECTION = 65528,

	OMCI_ME_65529 = 65529,

	OMCI_ME_65530 = 65530,

	OMCI_ME_EXT_MOP = 65531
};

/** This attribute reports whether the Managed Entity is currently capable of
   performing its function.

   It's applicable for the following Managed entities:
     - ONT-G
     - Circuit pack
     - GEM interworking termination point
     - Multicast GEM interworking termination point
     - Physical path termination point Ethernet UNI
     - Physical path termination point 802.11 UNI
     - Physical path termination point xDSL UNI part 1
     - Physical path termination point CES UNI
     - Physical path termination point POTS UNI
     - Physical path termination point MoCA UNI
     - Physical path termination point video UNI
     - Physical path termination point video ANI
     - Interworking VCC termination point
     - Video return path service profile
*/
enum {
	/** Operational state is enabled */
	OMCI_OPERATIONAL_STATE_ENABLED = 0,

	/** Operational state is disabled */
	OMCI_OPERATIONAL_STATE_DISABLED = 1
};

/** This attribute locks/unlocks the functions of a Managed Entity.

   It is applicable for the following Managed Entities:
      - ONT-G
      - Circuit pack
      - Dot1ag MEP
      - IP port configuration data
      - Physical path termination point Ethernet UNI
      - Physical path termination point 802.11 UNI
      - Physical path termination point xDSL UNI part 1
      - Physical path termination point CES UNI
      - Physical path termination point POTS UNI
      - Physical path termination point ISDN UNI
      - Physical path termination point MoCA UNI
      - UNI-G
      - Physical path termination point video UNI
      - Physical path termination point video ANI
      - Physical path termination point LCT UNI
      - Video return path service profile

*/
enum {
	/** Administrative state is unlocked */
	OMCI_ADMINISTRATIVE_STATE_UNLOCKED = 0,

	/** Administrative state is locked */
	OMCI_ADMINISTRATIVE_STATE_LOCKED = 1
};

/** This attribute allows the activation of alarm reporting
   control (ARC) for this PPTP.

*/
enum {
	/** When the ARC attribute is set to disabled, the PPTP is in the "ALM"
	    state, as defined in M.3100. Alarms are reported normally in the ALM
	    state. */
	OMCI_ARC_DISABLED = 0,

	/** When the ARC attribute is set to enabled, the PPTP is in
	   the "NALM-QI" state, as defined in M.3100. Alarms are suppressed in
	   this state. */
	OMCI_ARC_ENABLED = 1
};

/** Circuit pack type
  \see ITU-T G.984.4 Table 9.1.5-1/G.984.4

*/
enum {
	/** Default value */
	OMCI_CIRCUIT_PACK_TYPE_NO_LIM = 0,

	/* 1 - 12 Various ATM based UNIs */

	/** 1.544 Mbit/s local (T-interface) module */
	OMCI_CIRCUIT_PACK_C15_DS1 = 13,

	/** 2.048 Mbit/s local (T-interface) module */
	OMCI_CIRCUIT_PACK_C20_E1 = 14,

	/** 6.312 Mbit/s local (T-interface) module */
	OMCI_CIRCUIT_PACK_C63_J2 = 15,

	/** Configurable DS1/E1 module */
	OMCI_CIRCUIT_PACK_C_DS1_E1 = 16,

	/** Configurable DS1/E1/J1 module */
	OMCI_CIRCUIT_PACK_C_DS1_E1_J1 = 17,

	/** 6.312 Mbit/s remote (U-interface) module */
	OMCI_CIRCUIT_PACK_C63U_J2 = 18,

	/** 192 kbit/s local (T-interface) module */
	OMCI_CIRCUIT_PACK_C192K = 19,

	/** 44.736 Mbit/s local (T-interface) module */
	OMCI_CIRCUIT_PACK_C447_DS3 = 20,

	/** 34.368 Mbit/s local (T-interface) module */
	OMCI_CIRCUIT_PACK_C343_E3 = 21,

	/** Circuit pack type is 10 BaseT Ethernet LAN IF */
	OMCI_CIRCUIT_PACK_TYPE_10BASET = 22,

	/** Circuit pack type is 100 BaseT Ethernet LAN IF */
	OMCI_CIRCUIT_PACK_TYPE_100BASET = 23,

	/** Circuit pack type is 10/100 BaseT Ethernet LAN IF */
	OMCI_CIRCUIT_PACK_TYPE_10100BASET = 24,

	/* 25 - 27 Various non-Ethernet LAN technologies */

	/** 1.544 Mbit/s local (T-interface) module */
	OMCI_CIRCUIT_PACK_C15_J1 = 28,

	/** ATM OC-3 SMF UNI */
	OMCI_CIRCUIT_PACK_A150SMF_SONET = 29,

	/** ATM OC-3 MMF UNI */
	OMCI_CIRCUIT_PACK_A150MMF_SONET = 30,

	/** ATM OC-3 UTP UNI */
	OMCI_CIRCUIT_PACK_A150UTP_SONET = 31,

	/** Plain old telephony service */
	OMCI_CIRCUIT_PACK_POTS = 32,

	/** ISDN basic rate interface */
	OMCI_CIRCUIT_PACK_ISDN_BRI = 33,

	/** Gigabit Ethernet optical IF */
	OMCI_CIRCUIT_PACK_GIGABIT_OPTICAL_ETHER = 34,

	/** xDSL IF */
	OMCI_CIRCUIT_PACK_XDSL = 35,

	/** SHDSL IF */
	OMCI_CIRCUIT_PACK_SHDSL = 36,

	/** VDSL IF */
	OMCI_CIRCUIT_PACK_VDSL = 37,

	/** Video module */
	OMCI_CIRCUIT_PACK_VIDEO_SERVICE = 38,

	/** Local craft terminal interface */
	OMCI_CIRCUIT_PACK_LCT = 39,

	/** IEEE 802.11 interface */
	OMCI_CIRCUIT_PACK_802_11 = 40,

	/** Combination xDSL and POTS interfaces */
	OMCI_CIRCUIT_PACK_XDSL_POTS = 41,

	/** Combination VDSL (G.993.1) and POTS interfaces */
	OMCI_CIRCUIT_PACK_VDSL_POTS = 42,

	/** Circuit packs such as removable power supply modules or ONU
	   controllers */
	OMCI_CIRCUIT_PACK_COMMON_EQUIPMENT = 43,

	/** Circuit pack that combines both functions */
	OMCI_CIRCUIT_PACK_VIDEO_UNI_PON_IF = 44,

	/** Circuit pack with several types of ANI and/or UNI. Suggested for
	   use with the port mapping package-G Managed Entity */
	OMCI_CIRCUIT_PACK_MIXED_SERVICES_EQUIPMENT = 45,

	/** MoCA */
	OMCI_CIRCUIT_PACK_MOCA = 46,

	/** Circuit pack type is 10/100/1000 BaseT Ethernet LAN IF */
	OMCI_CIRCUIT_PACK_TYPE_101001000BASET = 47,

	/* 48 - 242 reserved */

	/** Circuit pack type is G-PON interface,
	   1244 MB/s ds and 155 Mb/s us */
	OMCI_CIRCUIT_PACK_TYPE_GPON1244155 = 243,

	/** Circuit pack type is G-PON interface,
	   1244 MB/s ds and 622 Mb/s us */
	OMCI_CIRCUIT_PACK_TYPE_GPON1244622 = 244,

	/** Circuit pack type is G-PON interface,
	   1244 MB/s ds and 1244 Mb/s us */
	OMCI_CIRCUIT_PACK_TYPE_GPON12441244 = 245,

	/** Circuit pack type is G-PON interface,
	   2488 MB/s ds and 155 Mb/s us */
	OMCI_CIRCUIT_PACK_TYPE_GPON2488155 = 246,

	/** Circuit pack type is G-PON interface,
	   2488 MB/s ds and 622 Mb/s us */
	OMCI_CIRCUIT_PACK_TYPE_GPON2488622 = 247,

	/** Circuit pack type is G-PON interface,
	   2488 MB/s ds and 1244 Mb/s us */
	OMCI_CIRCUIT_PACK_TYPE_GPON24881244 = 248,

	/** Circuit pack type is G-PON interface,
	   2488 MB/s ds and 2488 Mb/s us */
	OMCI_CIRCUIT_PACK_TYPE_GPON24882488 = 249,

	/* 250 - 254 G-PON and B-PON interfaces of diverse rates */

	/** Plug-and-play / Unrecognized module */
	OMCI_CIRCUIT_PACK_PNP_UNKNOWN = 255
};

/** @} */

__END_DECLS

#endif
