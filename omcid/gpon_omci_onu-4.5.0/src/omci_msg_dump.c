/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#define OMCI_DBG_MODULE OMCI_DBG_MODULE_MSG_DUMP

#include "omci_core.h"
#include "omci_msg_dump.h"
#include "omci_debug.h"

#ifndef OMCI_DEBUG_DISABLE

/** \addtogroup OMCI_MSG_DUMP

   @{
*/
#if defined(INCLUDE_FORMATTED_OMCI_DUMP) && !defined(OMCI_DEBUG_DISABLE)

/** This switch indicates if verbose message dump is fully compatible
   (at least tries to be) with OCS message dump.
   0 - indicates NO
   1 - indicates YES (that is compatible) */
#define OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE                  0

/** Print padding data

   \param[in] prefix   Padding prefix; NULL for default = Padding
   \param[in] data      Attributes data
   \param[in] data_size Attributes data size
*/
static void padding_print(const char *prefix, const void *data,
			  size_t data_size)
{
	unsigned int i;
	const uint8_t *attr_data;

	if (prefix == NULL) {
		dbg_naked(OMCI_DBG_PRN, OMCI_DBG_MODULE_MSG_DUMP,
			  "\nPadding:");
	} else {
		dbg_naked(OMCI_DBG_PRN, OMCI_DBG_MODULE_MSG_DUMP,
			  "\n%s:", prefix);
	}

	for (i = 0; i < data_size; i++) {
		attr_data = (const uint8_t *)data + i;

		if (i % 16 == 0) {
			dbg_naked(OMCI_DBG_PRN, OMCI_DBG_MODULE_MSG_DUMP, "\n");
		}

		dbg_naked(OMCI_DBG_PRN, OMCI_DBG_MODULE_MSG_DUMP,
			  " %02x", *attr_data);
	}
}

/** Print OMCI payload attributes

   \param[in] context   OMCI context pointer
   \param[in] class_id  Managed Entity class id
   \param[in] data      Attributes data
   \param[in] data_size Attributes data size
   \param[in] attr_mask Attributes mask
*/
static void attr_print(struct omci_context *context,
		       uint16_t class_id,
		       const void *data,
		       size_t data_size,
		       uint16_t attr_mask)
{
	unsigned int i;
	unsigned int attr;
	size_t attr_size;
	size_t attr_size_sum = 0;
	const struct me_class *me_class;
	const uint8_t *attr_data;
	uint16_t attr16;
	uint32_t attr32;
	enum omci_error error;
	/** \todo handle errors */

	error = mib_me_class_resolve(context, class_id, &me_class);
	if (error != OMCI_SUCCESS)
		return;

	for (attr = 1; attr <= OMCI_ATTRIBUTES_NUM; attr++) {
		if (!(attr_mask & omci_attr2mask(attr)))
			continue;

		attr_size = me_attr_size_get(me_class, attr);

		if (!attr_size)
			continue;

		attr_data = (const uint8_t *)data + attr_size_sum;
		attr_size_sum += attr_size;

		if (attr_size_sum > data_size)
			return;

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
		dbg_naked(OMCI_DBG_PRN, OMCI_DBG_MODULE_MSG_DUMP,
			  "\n%.25s =",
			  me_attr_name_get(me_class, attr));
#else
		dbg_naked(OMCI_DBG_PRN, OMCI_DBG_MODULE_MSG_DUMP,
			  "\n#%u =", attr);
#endif

		if (me_attr_type_get(me_class, attr) == OMCI_ATTR_TYPE_STR) {
			dbg_naked(OMCI_DBG_PRN, OMCI_DBG_MODULE_MSG_DUMP, " ");

			for (i = 0; i < me_attr_size_get(me_class, attr); i++) {
				dbg_naked(OMCI_DBG_PRN,
					  OMCI_DBG_MODULE_MSG_DUMP,
					  "%02x", attr_data[i]);
			}

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
			dbg_naked(OMCI_DBG_PRN, OMCI_DBG_MODULE_MSG_DUMP,
				  " \"");

			for (i = 0; i < me_attr_size_get(me_class, attr); i++) {
				dbg_naked(OMCI_DBG_PRN,
					  OMCI_DBG_MODULE_MSG_DUMP,
					  "%c", attr_data[i]);
			}

			dbg_naked(OMCI_DBG_PRN, OMCI_DBG_MODULE_MSG_DUMP, "\"");
#endif
		} else {
			switch (attr_size) {
			case sizeof(uint8_t):
				dbg_naked(OMCI_DBG_PRN,
					  OMCI_DBG_MODULE_MSG_DUMP,
					  " 0x%02x", *(uint8_t *)attr_data);

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
				dbg_naked(OMCI_DBG_PRN,
					  OMCI_DBG_MODULE_MSG_DUMP,
					  " (%u)", *(uint8_t *)attr_data);
#endif

				break;

			case sizeof(uint16_t):
				if (me_attr_prop_get(me_class, attr)
				    & OMCI_ATTR_PROP_NO_SWAP) {
					memcpy(&attr16, attr_data, sizeof(uint16_t));
				} else {
					memcpy(&attr16, attr_data, sizeof(uint16_t));
					attr16 = ntoh16(attr16);
				}

				dbg_naked(OMCI_DBG_PRN,
					  OMCI_DBG_MODULE_MSG_DUMP,
					  " 0x%04x", attr16);

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
				dbg_naked(OMCI_DBG_PRN,
					  OMCI_DBG_MODULE_MSG_DUMP,
					  " (%u)", attr16);

#endif
				break;

			case sizeof(uint32_t):
				if (me_attr_prop_get(me_class, attr)
				    & OMCI_ATTR_PROP_NO_SWAP) {
					memcpy(&attr32, attr_data, sizeof(uint32_t));
				} else {
					memcpy(&attr32, attr_data, sizeof(uint32_t));
					attr32 = ntoh32(attr32);
				}

				dbg_naked(OMCI_DBG_PRN,
					  OMCI_DBG_MODULE_MSG_DUMP,
					  " 0x%08x", attr32);

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
				dbg_naked(OMCI_DBG_PRN,
					  OMCI_DBG_MODULE_MSG_DUMP,
					  " (%u)", attr32);
#endif
				break;

			case 5:	/* copy to long long and printout ?! */

			default:
				for (i = 0; i < attr_size; i++) {
					dbg_naked(OMCI_DBG_PRN,
						  OMCI_DBG_MODULE_MSG_DUMP,
						  " %02x", attr_data[i]);
				}
			}

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0) \
			&& defined(INCLUDE_OMCI_SELF_DESCRIPTION)

			if (strncmp("Administrative state",
				    me_attr_name_get(me_class, attr),
				    DESC_MAX_NAME_LEN)
			    == 0) {

				if (*(uint8_t *)attr_data ==
				    OMCI_ADMINISTRATIVE_STATE_UNLOCKED) {
					dbg_naked(OMCI_DBG_PRN,
						  OMCI_DBG_MODULE_MSG_DUMP,
						  " unlocked");
				} else if (*(uint8_t *)attr_data ==
					   OMCI_ADMINISTRATIVE_STATE_LOCKED) {
					dbg_naked(OMCI_DBG_PRN,
						  OMCI_DBG_MODULE_MSG_DUMP,
						  " locked");
				}
			}

			if (strncmp("Operational state",
				    me_attr_name_get(me_class, attr),
				    DESC_MAX_NAME_LEN)
			    == 0) {

				if (*(uint8_t *)attr_data ==
				    OMCI_OPERATIONAL_STATE_ENABLED) {
					dbg_naked(OMCI_DBG_PRN,
						  OMCI_DBG_MODULE_MSG_DUMP,
						  " enabled");
				} else if (*(uint8_t *)attr_data ==
					   OMCI_OPERATIONAL_STATE_DISABLED) {
					dbg_naked(OMCI_DBG_PRN,
						  OMCI_DBG_MODULE_MSG_DUMP,
						  " disabled");
				}
			}
#endif
		}
	}

	if (attr_size_sum < data_size) {
		padding_print(NULL,
			      (const uint8_t *)data + attr_size_sum,
			      data_size - attr_size_sum);
	}
}

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
/** Print attributes mask

   \param[in] attr_mask Attributes mask
*/
static void attr_mask_print(uint16_t attr_mask)
{
	unsigned int attr;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP, " { ");

	for (attr = 1; attr <= 16; attr++)
		if (attr_mask & omci_attr2mask(attr)) {
			dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
				  "%u ", attr);
		}

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP, "}");
}
#endif

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
/** Print alarm mask

  \param[in] alarm_mask Alarm mask
*/
static void alarm_mask_print(const uint8_t alarm_mask[OMCI_ALARMS_NUM / 8])
{
	uint8_t byte, alarm, offset = 0;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP, " { ");

	for (byte = 0; byte < OMCI_ALARMS_NUM / 8; byte++) {
		for (alarm = 0; alarm < 8; alarm++)
			if (alarm_mask[byte] & (1 << ((8 - alarm) - 1))) {
				dbg_naked(OMCI_DBG_MSG,
					  OMCI_DBG_MODULE_MSG_DUMP,
					  "%u ", alarm + offset);
			}

		offset += 8;
	}

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP, "}");
}
#endif

/** Response result strings */
static const char *rsp_result[] = {
	"Command processed successfully",
	"Command processing error",
	"Command not supported",
	"Parameter error",
	"Unknown Managed Entity",
	"Unknown Managed Entity instance",
	"Device busy",
	"Instance exists",
	"",
	"Attribute(s) failed or unknown"
};

/** Get response result string

   \param[in] result Result code
*/
static const char *rsp_result_get(unsigned int result)
{
	static const char na[] = "n/a";

	if (result < sizeof(rsp_result) / sizeof(rsp_result[0]))
		return rsp_result[result];

	return na;
}

/** Actions strings */
static const char *actions[] = {
	"-",
	"-",
	"-",
	"-",
	"create",

	"create complete connection (deprecated)",
	"delete",
	"delete complete connection (deprecated)",
	"set",
	"get",

	"get complete connection (deprecated)",
	"get all alarms",
	"get all alarms next",
	"MIB upload",
	"MIB upload next",

	"MIB reset",
	"alarm",
	"Attribute value change",
	"Test",
	"Start software download",

	"Download section",
	"End software download",
	"Activate software",
	"Commit software",
	"Synchronize Time",

	"reboot",
	"get next",
	"Test result",
	"get current data"
};

/** Get action string

   \param[in] action Action number
*/
static const char *action_get(unsigned int action)
{
	static const char na[] = "n/a";

	if (action < sizeof(actions) / sizeof(actions[0]))
		return actions[action];

	return na;
}

/** Managed Entity class strings 0 - 171 */
static const char *classes0_171[] = {
	"None",
	"ONT B-PON",
	"ONT data",
	"PON IF line cardholder",
	"PON IF line card",

	"Cardholder",
	"Circuit pack",
	"Software image",
	"UNI B-PON",
	"TC Adapter B-PON",

	"PPTP ATM UNI",
	"PPTP Ethernet UNI",
	"PPTP CES UNI",
	"Logical Nx64 kbit/s sub-port connection TP",
	"Interworking VCC TP",

	"AAL1 profile B-PON",
	"AAL5 profile",
	"AAL1 PMHD B-PON",
	"AAL5 PMHD data",
	"AAL2 profile",

	"blank",
	"CES service profile-G",
	"reserved",
	"CES physical interface monitoring history data",
	"Ethernet PMHD",

	"VP network CTP-G",
	"ATM VP cross-connection",
	"Priority queue B-PON",
	"DBR/CBR traffic descriptor",
	"UBR traffic descriptor",

	"SBR1/VBR1 traffic descriptor",
	"SBR2/VBR2 traffic descriptor",
	"SBR3/VBR3 traffic descriptor",
	"ABR traffic descriptor",
	"GFR traffic descriptor",

	"ABT/DT/IT traffic descriptor",
	"UPC disagreement monitoring history data B-PON",
	"blank",
	"ANI",
	"PON TC adapter",

	"PON PPTP",
	"TC adapter PMHD",
	"Threshold data B-PON",
	"Operator specific",
	"Vendor specific",

	"MAC bridge service profile",
	"MAC bridge configuration data",
	"MAC bridge port configuration data",
	"MAC bridge port designation data",
	"MAC bridge port filter table data",

	"MAC bridge port bridge table data",
	"MAC bridge PMHD",
	"MAC bridge port PMHD",
	"PPTP POTS UNI",
	"Voice CTP",

	"Voice PMHD",
	"AAL2 PVC profile B-PON",
	"AAL2 CPS PMHD B-PON",
	"Voice service profile AAL",
	"LES service profile",

	"AAL2 SSCS parameter profile1",
	"AAL2 SSCS parameter profile2",
	"VP PMHD",
	"Traffic scheduler",
	"T-CONT buffer",

	"UBR+ traffic descriptor",
	"AAL2 SSCS PMHD B-PON",
	"IP port configuration data",
	"IP router service profile",
	"IP router configuration data",

	"IP router PMHD 1",
	"IP router PMHD 2",
	"ICMP PMHD 1",
	"ICMP PMHD 2",
	"IP route table",

	"IP static routes",
	"ARP service profile",
	"ARP configuration data",
	"VLAN tagging operation configuration data",
	"MAC bridge port filter preassign table",

	"PPTP ISDN UNI",
	"reserved",
	"PPTP video UNI",
	"PPTP LCT UNI",
	"VLAN tagging filter data",

	"ONU B-PON",
	"ATM VC cross-connection",
	"VC network CTP B-PON",
	"VC PMHD",
	"Ethernet PMHD 2",

	"PPTP video ANI",
	"PPTP 802.11 UNI",
	"802.11 station management data 1",
	"802.11 station management data 2",
	"802.11 general purpose object",

	"802.11 MAC&PHY operation and antenna data",
	"802.11 counters",
	"802.11 PHY FHSS DSSS IR tables",
	"PPTP xDSL UNI part 1",
	"PPTP xDSL UNI part 2",

	"xDSL line inventory and status data part 1",
	"xDSL line inventory and status data part 2",
	"xDSL channel downstream status data",
	"xDSL channel upstream status data",
	"xDSL line configuration profile part 1",

	"xDSL line configuration profile part 2",
	"xDSL line configuration profile part 3",
	"xDSL channel configuration profile",
	"xDSL subcarrier masking downstream profile",
	"xDSL subcarrier masking upstream profile",

	"xDSL PSD mask profile",
	"xDSL downstream RFI bands profile",
	"xDSL xTU-C PMHD",
	"xDSL xTU-R PMHD",
	"xDSL xTU-C channel PMHD",

	"xDSL xTU-R channel PMHD",
	"TC adaptor PMHD xDSL",
	"PPTP VDSL UNI",
	"VDSL VTU-O physical data",
	"VDSL VTU-R physical data",

	"VDSL channel data",
	"VDSL line configuration profile",
	"VDSL channel configuration profile",
	"VDSL band plan configuration profile",
	"VDSL VTU-O physical interface monitoring history data",

	"VDSL VTU-R physical interface monitoring history Data",
	"VDSL VTU-O channel PMHD",
	"VDSL VTU-R channel PMHD",
	"Video return path service profile",
	"Video return path statistics",

	"802.1p mapper service profile",
	"OLT-G",
	"Multicast interworking VCC TP",
	"ONT power shedding",
	"IP host config data",

	"IP host monitoring data",
	"TCP/UDP config data",
	"Network address",
	"VoIP config data",
	"VoIP voice CTP",

	"Call control PMHD",
	"VoIP line status",
	"VoIP media profile",
	"RTP profile data",
	"RTP monitoring data",

	"Network dial plan table",
	"VoIP application service profile",
	"VoIP feature access codes",
	"Authentication security method",
	"SIP config portal",

	"SIP agent config data",
	"SIP agent monitoring data",
	"SIP call initiation PMHD",
	"SIP user data",
	"MGC config portal",

	"MGC config data",
	"MGC monitoring data",
	"LargeString",
	"ONT remote debug",
	"Equipment protection profile",

	"Equipment extension package",
	"Port mapping package",
	"PPTP MoCA UNI",
	"MoCA Ethernet PMHD",
	"MoCA Interface PMHD",

	"VDSL2 line configuration extensions",
	"xDSL line inventory and status data part 3",
	"xDSL line inventory and status data part 4",
	"VDSL2 line inventory and status data part 1",
	"VDSL2 line inventory and status data part 2",

	"VDSL2 line inventory and status data part 3",
	"Extended VLAN tagging operation config data"
};

/** Managed Entity class strings 256 - 312 */
static const char *classes256_312[] = {
	"ONT-G",
	"ONT2-G",
	"ONU-G",
	"ONU2-G",

	"PON IF line card-G",
	"PON TC adapter-G",
	"T-CONT",
	"ANI-G",
	"UNI-G",

	"ATM interworking VCC TP",
	"GEM interworking TP",
	"GEM port PMHD",
	"GEM port network CTP",
	"VP network CTP-G",

	"VC network CTP-G",
	"GAL TDM profile",
	"GAL Ethernet profile",
	"Threshold data 1",
	"Threshold data 2",

	"GAL TDM PMHD",
	"GAL Ethernet PMHD",
	"Priority queue-G",
	"Traffic scheduler-G",
	"Protection data",

	"Traffic descriptor",
	"Multicast GEM interworking TP",
	"Pseudowire TP",
	"RTP pseudowire parameters",
	"Pseudowire maintenance profile",

	"Pseudowire PMHD",
	"Ethernet flow TP",
	"OMCI",
	"Managed entity",
	"Attribute",

	"Dot1X port extension package",
	"Dot1X configuration profile",
	"Dot1X PMHD",
	"Radius PMHD",
	"TU connection termination port",

	"TU PMHD",
	"Ethernet PMHD 3",
	"Port mapping package-G",
	"Dot1 rate limiter",
	"Dot1ag maintenance domain",

	"Dot1ag maintenance association",
	"Dot1ag default MD level",
	"Dot1ag MEP",
	"Dot1ag MEP status",
	"Dot1ag MEP CCM database",

	"Dot1ag CFM stack",
	"Dot1ag chassis-management info",
	"Octet string",
	"General purpose buffer",
	"Multicast operations profile",

	"Multicast subscriber config info",
	"Multicast subscriber monitor",
	"FEC PMHD"
};

/** Managed Entity class strings 321 - 322 */
static const char *classes321_322[] = {
	"Ethernet Frame PMDH Downstream",
	"Ethernet Frame PMDH Upstream"
};

/** Get Managed Entity class string

   \param[in] class_id Managed Entity class number
*/
static const char *class_get(unsigned int class_id)
{
	static const char na[] = "n/a";

	static const char reserved_bpon[] =
		"Reserved for future B-PON managed entities";
	static const char reserved_vendor_bpon[] =
		"Reserved for vendor-specific managed entities";
	static const char reserved[] = "Reserved for future standardization";
	static const char reserved_vendor[] =
		"Reserved for vendor specific use";
	static const char mac_bridge_port_ext[] =
		"MAC bridge port extension";

	if (class_id <= 171)
		return classes0_171[class_id];

	if (class_id >= 172 && class_id <= 239)
		return reserved_bpon;

	if (class_id == 240)
		return mac_bridge_port_ext;

	if (class_id >= 241 && class_id <= 255)
		return reserved_vendor_bpon;

	if (class_id >= 256 && class_id <= 312)
		return classes256_312[class_id - 256];

	if (class_id >= 313 && class_id <= 320)
		return reserved;

	if (class_id >= 321 && class_id <= 322)
		return classes321_322[class_id - 321];

	if (class_id >= 323 && class_id <= 65279)
		return reserved;

	if (class_id >= 65280 && class_id <= 65535)
		return reserved_vendor;

	return na;
}

/** Verbose message dump handler */
typedef void (verbose_handler) (struct omci_context *context,
				const union omci_msg *msg);

/** Empty message handler

   \param[in] msg OMCI message pointer
*/
static void empty_msg(const union omci_msg *msg)
{
	padding_print(NULL, msg->msg.contents, sizeof(msg->msg.contents));
}

/** "Create" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void create_msg(struct omci_context *context,
		       const union omci_msg *msg)
{
	const struct me_class *me_class;
	uint16_t attr_mask;
	enum omci_error error;

	error = mib_me_class_resolve(context,
				     ntoh16(msg->msg.header.class_id),
				     &me_class);
	if (error != OMCI_SUCCESS)
		return;

	attr_mask = me_class->sbc_attr_mask;

	attr_print(context,
		   ntoh16(msg->msg.header.class_id),
		   msg->create.values,
		   sizeof(msg->create.values),
		   attr_mask);
}

/** "Delete" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void delete_msg(struct omci_context *context,
		       const union omci_msg *msg)
{
	empty_msg(msg);
}

/** "Set" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void set_msg(struct omci_context *context,
		    const union omci_msg *msg)
{
	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nAttribute mask = 0x%04x",
		  ntoh16(msg->set.attr_mask));

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
	attr_mask_print(ntoh16(msg->set.attr_mask));
#endif

	attr_print(context,
		   ntoh16(msg->msg.header.class_id),
		   msg->set.values,
		   sizeof(msg->set.values),
		   ntoh16(msg->set.attr_mask));
}

/** "Get" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void get_msg(struct omci_context *context,
		    const union omci_msg *msg)
{
	uint16_t attr_mask = ntoh16(msg->get.attr_mask);

	dbg_naked(OMCI_DBG_MSG,
		  OMCI_DBG_MODULE_MSG_DUMP,
		  "\nAttribute mask = 0x%04x", attr_mask);

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
	attr_mask_print(ntoh16(msg->get.attr_mask));
#endif

	padding_print(NULL, msg->get.padding, sizeof(msg->get.padding));
}

/** "Get all alarms" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void get_all_alarms_msg(struct omci_context *context,
			       const union omci_msg *msg)
{
	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nAlarm retrieval mode = 0x%02x",
		  msg->get_all_alarms.mode);

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
	if (msg->get_all_alarms.mode == 0) {
		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  " - Regardless of ARC status");
	} else {
		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  " - Not currently under ARC");
	}
#endif

	padding_print(NULL, msg->get_all_alarms.padding,
		      sizeof(msg->get_all_alarms.padding));
}

/** "Get all alarms next" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void get_all_alarms_next_msg(struct omci_context *context,
				    const union omci_msg *msg)
{
	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nCmd sequence number = 0x%04x",
		  ntoh16(msg->get_all_alarms_next.seq_num));

	padding_print(NULL, msg->get_all_alarms_next.padding,
		      sizeof(msg->get_all_alarms_next.padding));
}

/** "MIB upload" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void mib_upload_msg(struct omci_context *context,
			   const union omci_msg *msg)
{
	empty_msg(msg);
}

/** "MIB upload next" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void mib_upload_next_msg(struct omci_context *context,
				const union omci_msg *msg)
{
	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nCmd sequence number = 0x%04x",
		  ntoh16(msg->mib_upload_next.seq_num));

	padding_print(NULL, msg->mib_upload_next.padding,
		      sizeof(msg->mib_upload_next.padding));
}

/** "Alarm" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void alarm_msg(struct omci_context *context,
		      const union omci_msg *msg)
{
	unsigned int i;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP, "\nAlarm mask = ");

	for (i = 0; i < OMCI_ALARM_BITMAP_SIZE; i++) {
		dbg_naked(OMCI_DBG_MSG,
			  OMCI_DBG_MODULE_MSG_DUMP,
			  "%02x", msg->alarm.alarm_bitmap[i]);

	}

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
	alarm_mask_print(msg->alarm.alarm_bitmap);
#endif

	padding_print(NULL, msg->alarm.padding, sizeof(msg->alarm.padding));

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nAlarm sequence number = 0x%02x",
		  msg->alarm.seq_num);
}

/** "AVC" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void avc_msg(struct omci_context *context,
		    const union omci_msg *msg)
{
	uint16_t attr_mask = ntoh16(ntoh16(msg->avc.attr_mask));

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nAttribute mask = 0x%04x", attr_mask);

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
	attr_mask_print(ntoh16(msg->avc.attr_mask));
#endif

	attr_print(context,
		   ntoh16(msg->msg.header.class_id),
		   msg->avc.values,
		   sizeof(msg->avc.values),
		   attr_mask);
}

/** "MIB reset" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void mib_reset_msg(struct omci_context *context,
			  const union omci_msg *msg)
{
	empty_msg(msg);
}

/** "Start SW download" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void start_sw_dl_msg(struct omci_context *context,
			    const union omci_msg *msg)
{
	unsigned int i;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nWindow size -1 = 0x%02x",
		  msg->start_dl.window_size);

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nImage size = 0x%08x bytes",
		  ntoh32(msg->start_dl.image_size));

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nUpdated in parallel = 0x%02x",
		  msg->start_dl.update_num);

	for (i = 0; i < 9; i++) {
		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  "\nSoftware image #%u = 0x%04x",
			  i + 1,
			  ntoh16(msg->start_dl.sw_img_inst[i]));
	}

	padding_print(NULL, msg->start_dl.padding,
		      sizeof(msg->start_dl.padding));
}

/** "Download section" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void dl_section_msg(struct omci_context *context,
			   const union omci_msg *msg)
{
	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nDownload section number = 0x%02x",
		  msg->dl_section.sect_num);

	padding_print("Data", msg->dl_section.data,
		      sizeof(msg->dl_section.data));
}

/** "End SW download" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void end_sw_dl_msg(struct omci_context *context,
			  const union omci_msg *msg)
{
	unsigned int i;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nCRC-32 = 0x%08x",
		  ntoh32(msg->end_dl.crc));

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nImage size = 0x%04x bytes",
		  ntoh32(msg->end_dl.image_size));

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nUpdated in parallel = 0x%02x",
		  msg->end_dl.update_num);

	for (i = 0; i < 9; i++) {
		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  "\nSoftware image #%u = 0x%04x",
			  i + 1,
			  ntoh16(msg->end_dl.sw_img_inst[i]));
	}

	padding_print(NULL, msg->end_dl.padding, sizeof(msg->end_dl.padding));
}

/** "Activate image" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void activate_image_msg(struct omci_context *context,
			       const union omci_msg *msg)
{
	empty_msg(msg);
}

/** "Commit image" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void commit_image_msg(struct omci_context *context,
			     const union omci_msg *msg)
{
	empty_msg(msg);
}

/** "Synchronize time" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void sync_time_msg(struct omci_context *context,
			  const union omci_msg *msg)
{
	empty_msg(msg);
}

/** "Reboot" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void reboot_msg(struct omci_context *context,
		       const union omci_msg *msg)
{
	empty_msg(msg);
}

/** "Get next" message handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void get_next_msg(struct omci_context *context,
			 const union omci_msg *msg)
{
	uint16_t attr_mask = ntoh16(msg->get_next.attr_mask);

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nAttribute mask = 0x%04x", attr_mask);

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
	attr_mask_print(ntoh16(msg->get_next.attr_mask));
#endif

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nCmd sequence number = 0x%04x",
		  ntoh16(msg->get_next.seq_num));

	padding_print(NULL, msg->get_next.padding,
		      sizeof(msg->get_next.padding));
}

/** Messages handlers */
static verbose_handler *msg_handler[] = {
	NULL,
	NULL,
	NULL,
	NULL,
	/* Create */
	create_msg,

	NULL,
	/* Delete */
	delete_msg,
	NULL,
	/* Set */
	set_msg,
	/* Get */
	get_msg,

	NULL,
	/* Get all alarms */
	get_all_alarms_msg,
	/* Get all alarms next */
	get_all_alarms_next_msg,
	/* MIB upload */
	mib_upload_msg,
	/* MIB upload next */
	mib_upload_next_msg,

	/* MIB reset */
	mib_reset_msg,
	/* Alarm */
	alarm_msg,
	/* Attribute value change */
	avc_msg,
	/* Test */
	NULL,
	/* Start software download */
	start_sw_dl_msg,

	/* Download section */
	dl_section_msg,
	/* End software download */
	end_sw_dl_msg,
	/* Activate software */
	activate_image_msg,
	/* Commit software */
	commit_image_msg,
	/* Synchronize Time */
	sync_time_msg,

	/* Reboot */
	reboot_msg,
	/* Get next */
	get_next_msg,
	/* Test result */
	NULL,
	/* Get current data */
	get_msg
};

/** "Create" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void create_rsp(struct omci_context *context,
		       const union omci_msg *msg)
{
	uint8_t result = msg->create_rsp.result;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nResult = 0x%02x - %s"
		  "\nAttribute execution mask = 0x%04x",
		  result,
		  rsp_result_get(result),
		  ntoh16(msg->create_rsp.attr_exec_mask));

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
	attr_mask_print(ntoh16(msg->create_rsp.attr_exec_mask));
#endif

	padding_print(NULL, msg->create_rsp.padding,
		      sizeof(msg->create_rsp.padding));
}

/** "Delete" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void delete_rsp(struct omci_context *context,
		       const union omci_msg *msg)
{
	uint8_t result = msg->delete_rsp.result;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nResult = 0x%02x - %s",
		  result,
		  rsp_result_get(result));

	padding_print(NULL, msg->delete_rsp.padding,
		      sizeof(msg->delete_rsp.padding));
}

/** "Set" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void set_rsp(struct omci_context *context,
		    const union omci_msg *msg)
{
	uint8_t result = msg->set_rsp.result;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nResult = 0x%02x - %s",
		  result,
		  rsp_result_get(result));

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nOptional attribute mask = 0x%04x",
		  ntoh16(msg->set_rsp.opt_attr_mask));

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
	attr_mask_print(ntoh16(msg->set_rsp.opt_attr_mask));
#endif

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nAttribute execution mask = 0x%04x",
		  ntoh16(msg->set_rsp.attr_exec_mask));

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
	attr_mask_print(ntoh16(msg->set_rsp.attr_exec_mask));
#endif

	padding_print(NULL, msg->set_rsp.padding, sizeof(msg->set_rsp.padding));
}

/** "Get" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void get_rsp(struct omci_context *context,
		    const union omci_msg *msg)
{
	uint16_t attr_mask = ntoh16(msg->get_rsp.attr_mask);
	uint8_t result = msg->get_rsp.result;
	unsigned int attr;
	bool show_attr = true;
	const struct me_class *me_class = NULL;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nResult = 0x%02x - %s"
		  "\nAttribute mask = 0x%04x",
		  result,
		  rsp_result_get(result),
		  attr_mask);

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
	attr_mask_print(ntoh16(msg->get_rsp.attr_mask));
#endif

	(void)mib_me_class_resolve(context,
				   ntoh16(msg->msg.header.class_id), &me_class);

	if (me_class) {
		for (attr = 1; attr <= OMCI_ATTRIBUTES_NUM; attr++) {
			if (!(attr_mask & omci_attr2mask(attr)))
				continue;

			if (me_attr_type_get(me_class, attr) ==
			    OMCI_ATTR_TYPE_TBL) {
				show_attr = false;
				break;
			}
		}
	}

	if (show_attr) {
		attr_print(context,
			   ntoh16(msg->msg.header.class_id),
			   msg->get_rsp.values,
			   sizeof(msg->get_rsp.values),
			   attr_mask);

		dbg_naked(OMCI_DBG_MSG,
			  OMCI_DBG_MODULE_MSG_DUMP,
			  "\nOptional attribute mask = 0x%04x",
			  ntoh16(msg->get_rsp.opt_attr_mask));

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
		attr_mask_print(ntoh16(msg->get_rsp.opt_attr_mask));
#endif

		dbg_naked(OMCI_DBG_MSG,
			  OMCI_DBG_MODULE_MSG_DUMP,
			  "\nAttribute execution mask = 0x%04x",
			  ntoh16(msg->get_rsp.attr_exec_mask));

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
		attr_mask_print(ntoh16(msg->get_rsp.attr_exec_mask));
#endif
	} else {
		dbg_naked(OMCI_DBG_MSG,
			  OMCI_DBG_MODULE_MSG_DUMP,
			  "\nSize = 0x%04x",
			  ntoh32(msg->get_tbl_rsp.size));

		padding_print(NULL,
			      msg->get_tbl_rsp.padding,
			      sizeof(msg->get_tbl_rsp.padding)
			      + sizeof(msg->get_tbl_rsp.opt_attr_mask)
			      + sizeof(msg->get_tbl_rsp.attr_exec_mask));
	}
}

/** "Get all alarms" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void get_all_alarms_rsp(struct omci_context *context,
			       const union omci_msg *msg)
{
	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\number of subsequent commands = 0x%04x",
		  ntoh16(msg->get_all_alarms_rsp.seq_num));

	padding_print(NULL, msg->get_all_alarms_rsp.padding,
		      sizeof(msg->get_all_alarms_rsp.padding));
}

/** "Get all alarms next" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void get_all_alarms_next_rsp(struct omci_context *context,
				    const union omci_msg *msg)
{
	unsigned int i;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nEntity class reported alarms = 0x%04x - %s",
		  ntoh16(msg->get_all_alarms_next_rsp.class_id),
		  class_get(ntoh16(msg->get_all_alarms_next_rsp.class_id)));

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nEntity instance reported alarms = 0x%04x",
		  ntoh16(msg->get_all_alarms_next_rsp.instance_id));

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP, "\nAlarms bitmap = ");

	for (i = 0; i < OMCI_ALARM_BITMAP_SIZE; i++) {
		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  "%02x",
			  msg->get_all_alarms_next_rsp.alarm_bitmap[i]);
	}

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
	alarm_mask_print(msg->get_all_alarms_next_rsp.alarm_bitmap);
#endif
}

/** "MIB upload" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void mib_upload_rsp(struct omci_context *context,
			   const union omci_msg *msg)
{
	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\number of subsequent commands = 0x%04x",
		  ntoh16(msg->mib_upload_rsp.seq_num));

	padding_print(NULL, msg->mib_upload_rsp.padding,
		      sizeof(msg->mib_upload_rsp.padding));
}

/** "MIB upload next" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void mib_upload_next_rsp(struct omci_context *context,
				const union omci_msg *msg)
{
	uint16_t attr_mask = ntoh16(msg->mib_upload_next_rsp.attr_mask);

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nObject entity class = 0x%04x - %s",
		  ntoh16(msg->mib_upload_next_rsp.class_id),
		  class_get(ntoh16(msg->mib_upload_next_rsp.class_id)));

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nObject entity instance = %u",
		  ntoh16(msg->mib_upload_next_rsp.instance_id));

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nAttribute mask = 0x%04x", attr_mask);

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
	attr_mask_print(attr_mask);
#endif

	attr_print(context,
		   ntoh16(msg->msg.header.class_id),
		   msg->mib_upload_next_rsp.values,
		   sizeof(msg->mib_upload_next_rsp.values), attr_mask);
}

/** "MIB reset" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void mib_reset_rsp(struct omci_context *context,
			  const union omci_msg *msg)
{
	uint8_t result = msg->mib_reset_rsp.result;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nResult = 0x%02x - %s",
		  result,
		  rsp_result_get(result));

	padding_print(NULL, msg->mib_reset_rsp.padding,
		      sizeof(msg->mib_reset_rsp.padding));
}

/** "Start SW download" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void start_sw_dl_rsp(struct omci_context *context,
			    const union omci_msg *msg)
{
	unsigned int i;

	uint8_t result = msg->start_dl_rsp.result;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nResult = 0x%02x - %s",
		  result,
		  rsp_result_get(result));

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nWindow size = 0x%02x + 1",
		  msg->start_dl_rsp.window_size);

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nUpdated in parallel = 0x%02x",
		  msg->start_dl_rsp.update_num);

	for (i = 0; i < 9; i++) {
		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  "\nSoftware image #%u = 0x%04x",
			  i + 1,
			  ntoh16(msg->start_dl_rsp.req[i].sw_img_inst));

		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  "\nResult #%u = 0x%02x",
			  i + 1, msg->start_dl_rsp.req[i].result);
	}

	padding_print(NULL, msg->start_dl_rsp.padding,
		      sizeof(msg->start_dl_rsp.padding));
}

/** "Download section" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void dl_section_rsp(struct omci_context *context,
			   const union omci_msg *msg)
{
	uint8_t result = msg->dl_section_rsp.result;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nResult = 0x%02x - %s",
		  result,
		  rsp_result_get(result));

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nDownload section number = 0x%02x",
		  msg->dl_section_rsp.sect_num);

	padding_print(NULL, msg->dl_section_rsp.padding,
		      sizeof(msg->dl_section_rsp.padding));
}

/** "End SW download" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void end_sw_dl_rsp(struct omci_context *context,
			  const union omci_msg *msg)
{
	unsigned int i;

	uint8_t result = msg->end_dl_rsp.result;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nResult = 0x%02x - %s",
		  result,
		  rsp_result_get(result));

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nUpdated in parallel = 0x%02x",
		  msg->end_dl_rsp.update_num);

	for (i = 0; i < 9; i++) {
		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  "\nSoftware image #%u = 0x%04x",
			  i + 1,
			  ntoh16(msg->end_dl_rsp.req[i].sw_img_inst));

		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  "\nResult #%u = 0x%02x",
			  i + 1, msg->end_dl_rsp.req[i].result);
	}

	padding_print(NULL, msg->end_dl_rsp.padding,
		      sizeof(msg->end_dl_rsp.padding));
}

/** "Activate image" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void activate_image_rsp(struct omci_context *context,
			       const union omci_msg *msg)
{
	uint8_t result = msg->activate_image_rsp.result;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nResult = 0x%02x - %s",
		  result,
		  rsp_result_get(result));

	padding_print(NULL, msg->activate_image_rsp.padding,
		      sizeof(msg->activate_image_rsp.padding));
}

/** "Commit image" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void commit_image_rsp(struct omci_context *context,
			     const union omci_msg *msg)
{
	activate_image_rsp(context, msg);
}

/** "Synchronize time" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void sync_time_handle_rsp(struct omci_context *context,
				 const union omci_msg *msg)
{
	activate_image_rsp(context, msg);
}

/** "Reboot" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void reboot_rsp(struct omci_context *context,
		       const union omci_msg *msg)
{
	activate_image_rsp(context, msg);
}

/** "Get next" message response handler

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void get_next_rsp(struct omci_context *context,
			 const union omci_msg *msg)
{
	uint16_t attr_mask = ntoh16(msg->get_next_rsp.attr_mask);
	uint8_t result = msg->get_next_rsp.result;

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nResult = 0x%02x - %s"
		  "\nAttribute mask = 0x%04x",
		  result,
		  rsp_result_get(result),
		  attr_mask);

#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
	attr_mask_print(ntoh16(msg->get_next_rsp.attr_mask));
#endif

	padding_print("Data",
		      msg->get_next_rsp.values,
		      sizeof(msg->get_next_rsp.values));
}

/** Message responses handlers */
static verbose_handler *rsp_handler[] = {
	NULL,
	NULL,
	NULL,
	NULL,
	/* Create */
	create_rsp,

	NULL,
	/* Delete */
	delete_rsp,
	NULL,
	/* Set */
	set_rsp,
	/* Get */
	get_rsp,

	NULL,
	/* Get all alarms */
	get_all_alarms_rsp,
	/* Get all alarms next */
	get_all_alarms_next_rsp,
	/* MIB upload */
	mib_upload_rsp,
	/* MIB upload next */
	mib_upload_next_rsp,

	/* MIB reset */
	mib_reset_rsp,
	/* Alarm */
	NULL,
	/* Attribute value change */
	NULL,
	/* Test */
	NULL,
	/* Start software download */
	start_sw_dl_rsp,

	/* Download section */
	dl_section_rsp,
	/* End software download */
	end_sw_dl_rsp,
	/* Activate software */
	activate_image_rsp,
	/* Commit software */
	commit_image_rsp,
	/* Synchronize Time */
	sync_time_handle_rsp,

	/* Reboot */
	reboot_rsp,
	/* Get next */
	get_next_rsp,
	/* Test result */
	NULL,
	/* Get current date */
	get_rsp
};

/** Verbose OMCI message dump

   \param[in] context OMCI context pointer
   \param[in] msg     OMCI message pointer
*/
static void msg_dump_verbose(struct omci_context *context,
			     const union omci_msg *msg)
{
	static const char msg_separator[] =
#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
		"*********************************"
		"*********************************" "*************";
#else
		"*********************************";
#endif

	static const char request_separator[] =
#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
		"+++++++++++++++++++++++++++++++++"
		"+++++++++++++++++++++++++++++++++" "+++++++++++++";
#else
		"+++++++++++++++++++++++++++++++++";
#endif

	static const char response_separator[] =
#if (OMCI_FORMATTED_OMCI_DUMP_OCS_COMPATIBLE == 0)
		"---------------------------------"
		"---------------------------------" "-------------";
#else
		"---------------------------------";
#endif

	/* print header */
	if (omci_msg_type_ar_get(msg) == 0 && omci_msg_type_ak_get(msg) == 0) {
		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  "\n\nOMCI Message Header\n%s", msg_separator);
	} else if (omci_msg_type_ar_get(msg) == 1) {
		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  "\n\nOMCI Request Message Header\n%s",
			  request_separator);
	} else if (omci_msg_type_ak_get(msg) == 1) {
		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  "\n\nOMCI Response Message Header\n%s",
			  response_separator);
	}

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
		  "\nTransaction id   = 0x%04x"
		  "\nMessage type     = 0x%02x - %s, "
		  "DB = %u, AR = %u, AK = %u"
		  "\nDevice id        = 0x%02x"
		  "\nEntity class     = %u (0x%04x) - %s"
		  "\nEntity instance  = 0x%04x"
		  "\n",
		  ntoh16(msg->msg.header.tci),
		  msg->msg.header.type,
		  action_get(omci_msg_type_mt_get(msg)),
		  omci_msg_type_db_get(msg),
		  omci_msg_type_ar_get(msg),
		  omci_msg_type_ak_get(msg),
		  msg->msg.header.dev_id,
		  ntoh16(msg->msg.header.class_id),
		  ntoh16(msg->msg.header.class_id),
		  class_get(ntoh16(msg->msg.header.class_id)),
		  ntoh16(msg->msg.header.instance_id));

	if (omci_msg_type_ar_get(msg) == 0 && omci_msg_type_ak_get(msg) == 0) {
		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  "\nOMCI Message Content\n%s", msg_separator);
	} else if (omci_msg_type_ar_get(msg) == 1) {
		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  "\nOMCI Request Message Content\n%s",
			  request_separator);
	} else if (omci_msg_type_ak_get(msg) == 1) {
		dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP,
			  "\nOMCI Response Message Content\n%s",
			  response_separator);
	}

	/* print message specific */
	if (omci_msg_type_ak_get(msg) == 1) {
		if ((unsigned)omci_msg_type_mt_get(msg) <
		    (sizeof(rsp_handler) / sizeof(rsp_handler[0])))
			if (rsp_handler[omci_msg_type_mt_get(msg)] != NULL) {
				rsp_handler[omci_msg_type_mt_get(msg)](context,
								       msg);
				dbg_naked(OMCI_DBG_MSG,
					  OMCI_DBG_MODULE_MSG_DUMP, "\n\n");
				return;
			}
	} else {
		if ((unsigned)omci_msg_type_mt_get(msg) <
		    (sizeof(msg_handler) / sizeof(msg_handler[0])))
			if (msg_handler[omci_msg_type_mt_get(msg)] != NULL) {
				msg_handler[omci_msg_type_mt_get(msg)](context,
								       msg);
				dbg_naked(OMCI_DBG_MSG,
					  OMCI_DBG_MODULE_MSG_DUMP, "\n\n");
				return;
			}
	}

	dbg_naked(OMCI_DBG_MSG, OMCI_DBG_MODULE_MSG_DUMP, "\n\n");
}
#endif

/** OMCI message dump

   \param[in] msg OMCI message pointer
*/
static void msg_dump_normal(const union omci_msg *msg)
{
	int i;

	for (i = 0; i < 40; i++) {
		if (i != 0 && i % 16 == 0) {
			dbg_naked(dbg_modules[OMCI_DBG_MODULE_MSG_DUMP].
				  level,
				  OMCI_DBG_MODULE_MSG_DUMP, "\n");

		}

		dbg_naked(dbg_modules[OMCI_DBG_MODULE_MSG_DUMP].level,
			  OMCI_DBG_MODULE_MSG_DUMP,
			  " %02x", *((uint8_t *)msg + i));
	}

	dbg_naked(OMCI_DBG_PRN, OMCI_DBG_MODULE_MSG_DUMP, "\n");
}

void msg_dump(struct omci_context *context,
	      const char *prefix,
	      const union omci_msg *msg,
	      unsigned int number)
{

	enum omci_dbg dbg_lvl;

	dbg_in(__func__, "%p, %p", (void *)prefix, (void *)msg);

	dbg_lvl = dbg_modules[OMCI_DBG_MODULE_MSG_DUMP].level;

	if (dbg_lvl == OMCI_DBG_PRN || dbg_lvl == OMCI_DBG_MSG) {
#if defined(INCLUDE_FORMATTED_OMCI_DUMP) && !defined(OMCI_DEBUG_DISABLE)
		if (dbg_lvl == OMCI_DBG_PRN) {
			dbg_prn("OMCI #%u %s", number, prefix);
			msg_dump_normal(msg);
		} else if (dbg_lvl == OMCI_DBG_MSG) {
			dbg_msg("OMCI #%u %s", number, prefix);
			msg_dump_verbose(context, msg);
		}
#else
		msg_dump_normal(msg);
#endif
	}

	dbg_out(__func__);
}

/** @} */

#endif
