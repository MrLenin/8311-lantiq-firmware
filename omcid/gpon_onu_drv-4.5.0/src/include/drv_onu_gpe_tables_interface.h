/******************************************************************************

                               Copyright  2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_gpe_tables_interface.h
   This is the GPON Packet Engine header file that defines table access
   functions.

   A global table access function is provided to access any of the
   GPE tables as well as a set of dedicated functions for specific tables
   to make the handling more convenient.

   The variable types (8, 16, or 32 bit) reflect the values ranges
   that are defined by the hardware table sizes etc. If hardware
   resources are increased, the variable type definition might need
   to be changed. Check drv_onu_resource.h for changes.
*/
#ifndef _drv_onu_gpe_tables_interface_h_
#define _drv_onu_gpe_tables_interface_h_

#include "drv_onu_std_defs.h"
#include "drv_onu_types.h"
#include "drv_onu_gpe_tables.h"
#include "drv_onu_resource.h"
#include "drv_onu_resource_gpe.h"

#ifndef __PACKED__
#  if defined (__GNUC__) || defined (__GNUG__)
   /* GNU C or C++ compiler */
#    define __PACKED__ __attribute__ ((packed))
#  else
   /* Byte alignment adjustment */
#    pragma pack(1)
#    if !defined (_PACKED_)
#      define __PACKED__	/* nothing */
#    endif
#  endif
#  define __PACKED_DEFINED__
#endif

EXTERN_C_BEGIN
/** \addtogroup ONU_MAPI_REFERENCE
   @{
*/

/** \addtogroup ONU_GPE
   @{
*/

/** Structure used for the re-initialization of a configuration table. */
struct gpe_reinit_table {
	/** Table identifier */
	uint32_t table_id;
};


/** Union to retrieve specified GPE tables.
    Used by \ref FIO_GPE_TABLE_ENTRY_GET and \ref FIO_GPE_TABLE_ENTRY_READ.
    For more details on filling "in" parameter please refer to inline
    descriptions within "gpe_table". */
union gpe_table_entry_u {
	/** Specifies GPE table to retrieve. */
	struct gpe_table in;
	/** Retrieved GPE table data. */
	struct gpe_table_entry out;
};

/** Structure to specify Bridge Port configuration data.
*/
struct gpe_bridge_port {
	/** Bridge port index. */
	uint32_t index;
	/** Bridge port table. */
	struct gpe_bridge_port_table gpe_bridge_port_tbl;
	/** Bridge port limitation table. */
	struct gpe_learning_limitation_table gpe_learning_limitation_tbl;
} __PACKED__;

/** Union to retrieve Bridge Port Configuration data.
    Used by \ref FIO_GPE_BRIDGE_PORT_CFG_GET.
*/
union gpe_bridge_port_cfg_get_u {
	/** Specified Bridge Port Index. */
	struct gpe_bridge_port_index in;
	/** Retrieved Bridge Port Configuration Data. */
	struct gpe_bridge_port out;
};

/** Union to retrieve FID table data.
    Used by FIO_GPE_FID_GET.
*/
union gpe_fid_get_u {
	/** Forwarding ID table input parameters.
	    For more details on
	    specifying input parameters please refer to the
	    \ref gpe_fwd_id_table fields definitions. */
	struct gpe_table_entry in;
	/** Retrieved Forwarding ID table. */
	struct gpe_table_entry out;
};

/** Structure to specify Extended VLAN configuration.
*/
struct gpe_ext_vlan_custom {
	/** FID value for custom match */
	uint32_t tpid:16;
	/** reserved field */
	uint32_t res1:14;
	/** X is true */
	uint32_t xtrue:1;
	/** activate X */
	uint32_t defrule:1;
	/** reserved field */
	uint32_t res2:16;
	/** Ethernet type for the custom match */
	uint32_t ety1:16;
	/** reserved field */
	uint32_t res3:16;
	/** Ethernet type for the custom match */
	uint32_t ety2:16;
	/** reserved field */
	uint32_t res4:16;
	/** Ethernet type for the custom match */
	uint32_t ety3:16;
	/** reserved field */
	uint32_t res5:16;
	/** Ethernet type for the custom match */
	uint32_t ety4:16;
	/** Ethernet type mask for the custom match */
	uint32_t etymask:16;
	/** Ethernet type for the custom match */
	uint32_t ety5:16;
	/** Spare1 mask for custom match (future use) */
	uint32_t spare1mask:16;
	/** Spare1 field for custom match (future use) */
	uint32_t spare1:16;
	/** Spare2 mask for custom match (future use) */
	uint32_t spare2mask:16;
	/** Spare2 field for custom match (future use) */
	uint32_t spare2:16;
} __PACKED__;

/** Structure to specify Extended VLAN index.
*/
struct gpe_ext_vlan_index {
	/** Extended VLAN index. */
	uint32_t index;
};

/** Structure to specify Extended VLAN translation.
*/
struct gpe_ext_vlan_translate {
	/** Extended VLAN index. */
	uint32_t index;
	/** Extended VLAN translation bits */
	struct gpe_extended_translation_in in;
	/** Extended VLAN translation result bits */
	struct gpe_extended_translation_out out;
};

/** Structure to access the VLAN tagging filter configuration. */
struct gpe_tagg_filter {
	/** Tagging filter index. */
	uint32_t index;
	/** Tag filter bits */
	struct gpe_tagg_filter_in in;
	/** Tag filter result bits */
	struct gpe_tagg_filter_out out;
};

/** Data structure to specify Extended VLAN data.
    Used by \ref FIO_GPE_EXT_VLAN_SET and \ref gpe_ext_vlan_get_u.
*/
struct gpe_ext_vlan {
	/** Extended VLAN index. */
	uint32_t index;
	/** Maximum number of VLANs that can be handled concurrently.
	    Value is limited to \ref ONU_GPE_MAX_VLANS.*/
	uint32_t max_vlans;
	/** Extended VLAN table. */
	struct gpe_extended_vlan_table extended_vlan_tbl;
	/** VLAN rule table used with extended VLAN table. */
	struct gpe_vlan_rule_table vlan_rule_tbl[ONU_GPE_MAX_VLANS];
	/** VLAN treatment table used with extended VLAN table. */
	struct gpe_vlan_treatment_table vlan_treatment_tbl[ONU_GPE_MAX_VLANS];
	/** number of valid VLAN rule and treatment table entries. */
	uint16_t num_valid_rules;
} __PACKED__;

/** Union to retrieve Extended VLAN data.
    Used by \ref FIO_GPE_EXT_VLAN_GET.
*/
union gpe_ext_vlan_get_u {
	/** Extended VLAN Index. */
	struct gpe_ext_vlan_index in;
	/** Retrieved Extended VLAN data. */
	struct gpe_ext_vlan out;
};

/** Structure to specify Tagging filter table index.
*/
struct gpe_tagging_index {
	/** Tagging filter table index. */
	uint32_t index;
};

/** Data structure for the Tagging filter table data.
    Used by \ref FIO_GPE_TAGGING_FILTER_SET and \ref gpe_tagging_filter_get_u.
*/
struct gpe_tagging {
	/** Tagging filter table index. */
	uint32_t index;
	/** Tagging filter table. */
	struct gpe_tagging_filter_table tagging_filter_tbl;
	/** VLAN table used with tagging filter table. */
	struct gpe_vlan_table vlan_tbl[ONU_GPE_MAX_VLANS];
	/** Number of valid VLAN tables. */
	uint16_t num_valid_vlans;
} __PACKED__;

/** Union to retrieve Tagging filter table data.
    Used by \ref FIO_GPE_TAGGING_FILTER_GET.
*/
union gpe_tagging_filter_get_u {
	/** Tagging filter table index. */
	struct gpe_tagging_index in;
	/** Retrieved Tagging filter table data. */
	struct gpe_tagging out;
};

/** Union to retrieve Long forwarding unicast based on IPv6 address table.
    Used by \ref FIO_GPE_LONG_FWD_ADD.
*/
union gpe_ipv6_uc_entry_get_u {
	/** Long forwarding unicast based on IPv6 address table input
	    parameters.
	    For more details on  specifying input parameters please
	    refer to the \ref gpe_long_fwd_table_ipv6 fields definitions. */
	struct gpe_long_fwd_table_ipv6 in;
	/** Retrieved Long forwarding unicast based on IPv6 address table. */
	struct gpe_long_fwd_table_ipv6 out;
};

/** Union to retrieve Long forwarding multicast based on IPv6 address table.
    Used by \ref FIO_GPE_LONG_FWD_ADD.
*/
union gpe_ipv6_mc_entry_get_u {
	/** Long forwarding multicast based on IPv6 address table input
	    parameters.
	    For more details on  specifying input parameters please
	    refer to the \ref gpe_long_fwd_table_ipv6_mc fields definitions. */
	struct gpe_long_fwd_table_ipv6_mc in;
	/** Retrieved Long forwarding multicast based on IPv6 address table. */
	struct gpe_long_fwd_table_ipv6_mc out;
};

/** Structure to control COP Tracing debug feature.
*/
struct gpe_cop_tracing {
	/** Specifies COP index. Valid range from 0 to
	    ONU_GPE_NUMBER_OF_COP - 1*/
	uint32_t cop_idx;
	/** COP Trace enable/disable*/
	uint32_t trace_enable;
};

/** Structure to control COP Tracing debug feature.
*/
struct gpe_cop_debug {
	/** COP debug mask */
	uint32_t copmsk;
	/** COP debug steps */
	uint32_t stepcnt;
};

/** Access Control List parameter type 1.
    Used by \ref gpe_acl_table_entry.
*/
enum gpe_acl_param1_type {
	/** None */
	GPE_ACL_PARAM1_NONE = 0,
	/** IPv4 source address. */
	GPE_ACL_PARAM1_IPV4_SA = 1,
	/** IPv4 destination address. */
	GPE_ACL_PARAM1_IPV4_DA = 2,
	/** IPv4 protocol type. */
	GPE_ACL_PARAM1_IPV4_PROT = 3,
	/** IPv6 source address. */
	GPE_ACL_PARAM1_IPV6_SA = 4,
	/** IPv6 destination address. */
	GPE_ACL_PARAM1_IPV6_DA = 5
};

/** Access Control List parameter type 2.
    Used by \ref gpe_acl_table_entry.
*/
enum gpe_acl_param2_type {
	/** None */
	GPE_ACL_PARAM2_NONE = 0,
	/** IPv4 source address. */
	GPE_ACL_PARAM2_MAC_SA = 1,
	/** IPv4 destination address. */
	GPE_ACL_PARAM2_MAC_DA = 2,
	/** Ethertype. */
	GPE_ACL_PARAM2_ETHERTYPE = 3,
	/** TCP source port. */
	GPE_ACL_PARAM2_TCP_SP = 4,
	/** TCP destination port. */
	GPE_ACL_PARAM2_TCP_DP = 5,
	/** UDP source port. */
	GPE_ACL_PARAM2_UDP_SP = 6,
	/** UDP destination port. */
	GPE_ACL_PARAM2_UDP_DP = 7,
	/** TCP or UDP source port. */
	GPE_ACL_PARAM2_TCP_UDP_SP = 8,
	/** TCP or UDP destination port. */
	GPE_ACL_PARAM2_TCP_UDP_DP = 9
};

/** Access Control List (ACL) table entry index
    Used by \ref FIO_GPE_ACL_TABLE_ENTRY_DELETE and
    \ref FIO_GPE_ACL_TABLE_ENTRY_GET. */
struct gpe_acl_table_entry_idx {
	/** Table entry index, valid from 0 to ONU_GPE_ACL_FILTER_TABLE_SIZE-1 */
	uint8_t acl_filter_index;
};

/** Data structure to specify entry in the Access Control List (ACL) table.
    Used by \ref FIO_GPE_ACL_TABLE_ENTRY_GET and
    \ref FIO_GPE_ACL_TABLE_ENTRY_SET. */
struct gpe_acl_table_entry {
	/** Table entry index, valid from 0 to ONU_GPE_ACL_FILTER_TABLE_SIZE-1 */
	uint32_t acl_filter_index;
	/** End of list indication */
	uint32_t last_entry;
	/** Parameter 1, provides for layer-3 filtering.
	  The contents can be one of the following types:
	  - IPv4 source address
	  - IPv4 destination address
	  - IPv4 protocol type
	  - IPv6 source address
	  - IPv6 destination address
	  Unused bit positions (in case of IPv4) are set to 0.
	  The actual type is selected by param1_type. */
	uint8_t param1[16];
	/** Parameter 2, provides for layer-2 or layer-4 filtering.
	The contents can be one of the following types:
	- MAC source address
	- MAC destination address
	- Ethertype
	- TCP source port
	- TCP destination port
	- UDP source port
	- UDP destination port
	- TCP or UDP source port
	- TCP or UDP destination port
	The actual type is selected by param2_type.
	*/
	uint8_t param2[6];
	/** Parameter Mask 1, each bit of parameter 1 can be excluded from
	    comparison (masked) in IPv4 mode. Bit 0 controls parameter1(0), and so
	    on.
	    - 0: Ignore (do not use the selected bit position for comparison).
	    - 1: Use (use the selected bit position for comparison).
	*/
	uint32_t param1_mask;
	/** Parameter type 1 */
	enum gpe_acl_param1_type param1_type;
	/** Parameter type 2 */
	enum gpe_acl_param2_type param2_type;
	/** Forwarding ID */
	uint32_t fid;
	/** Forwarding ID enable.
	- false: ignore VLAN(s)
	- true: check VLAN(s) */
	uint32_t fid_en;
	/** Ingress port enable mask.
	- Bit 0: LAN port 1
	- Bit 1: LAN port 2
	- Bit 2: LAN port 3
	- Bit 3: LAN port 4
	- others: reserved, set to 0. */
	uint32_t ingress_port_enable;
};

/** Union to retrieve an entry from the Access Control List (ACL) table.
    Used by \ref FIO_GPE_ACL_TABLE_ENTRY_GET.
*/
union gpe_acl_table_entry_u {
	/** Specifies ACL entry to retrieve. */
	struct gpe_acl_table_entry_idx in;
	/** Retrieved ACL entry data. */
	struct gpe_acl_table_entry out;
};

/** Structure to define the firmware constants of the SCE.
   Used by \ref FIO_GPE_SCE_CONSTANTS_GET and \ref FIO_GPE_SCE_CONSTANTS_SET. */
struct gpe_sce_constants {
	/** Enable the firmware to process data. Do not change this value!!! */
	uint32_t packet_processing_enable;
	/** The default FID is used for untagged or unknown packets.
	The eight leftmost bits of the value are used,
	the 24 rightmost bits are set to 0. */
	uint32_t default_fid;
	/** Default outer VID. */
	uint16_t default_outer_vid;
	/** Default inner VID. */
	uint16_t default_inner_vid;
	/** Default DSCP value. The six leftmost bits of the value are used,
	the 26 rightmost bits are set to 0. */
	uint32_t default_dscp;
	/** unused */
	uint32_t unused0;
	/** Forwarding table size. This value is used by the aging process. */
	uint32_t fwd_table_size;
	/** TPID value A. Used to identify a VLAN tag. */
	uint16_t tpid_a;
	/** TPID value B. Used to identify a VLAN tag. */
	uint16_t tpid_b;
	/** TPID value C. Used to identify a VLAN tag. */
	uint16_t tpid_c;
	/** TPID value D. Used to identify a VLAN tag. */
	uint16_t tpid_d;
	/** Unused data value. Do not change this value. */
	uint32_t unused;
	/** Internal firmware timing control. Do not change this value. */
	uint32_t added_latency;
	/** unused */
	uint32_t unused1;
	/** MAC Address of Local CPU, used for LCT.
	    MAC=aa:bb:cc:dd:ee:ff corresponds to
	    local_cpu_mac[0]=aa,local_cpu_mac[1]=bb,local_cpu_mac[2]=cc,
	    local_cpu_mac[3]=dd,local_cpu_mac[4]=ee,local_cpu_mac[5]=ff */
	uint8_t local_cpu_mac[6];
	/** Dual token bucket meter ID for ANI exception traffic for both
	    the ANI ingress as well as the ANI egress.
	    Must be less than \ref ONU_GPE_MAX_SHAPER.*/
	uint32_t ani_exception_meter_id;
	/** Enable bit for both ingress and egress dual token bucket meter
	    selection for ANI exception traffic. */
	uint32_t ani_exception_enable;
	/** Threshold for ANI exceptions including IGMP for both directions
	    the ANI Ingress and ANI egress, Unit: packets/28 ms, 0: policer is disabled */
	uint32_t ani_except_policer_threshold;
	/** Threshold for non-IGMP UNI exceptions excluding IGMP for both directions
	    the UNI Ingress and UNI egress, Unit: packets/28 ms, 0: policer is disabled */
	uint32_t uni_except_policer_threshold;
	/** Threshold for IGMP exceptions for both directions UNI Ingress
	    and UNI Egress, Unit: packets/28 ms, 0: policer is disabled */
	uint32_t igmp_except_policer_threshold;
	/** Policer/meter mode selection:
	    0: Use layer 2 packet size information, if available; else use
	         layer 2
	    1: Use layer 2 packet length information always. */
	uint32_t meter_l2_only_enable;
} __PACKED__;

/** Structure to add a LAN port to a multicast flow.
   Used by \ref FIO_GPE_SHORT_FWD_MAC_MC_PORT_ADD and
   \ref FIO_GPE_SHORT_FWD_MAC_MC_PORT_DELETE. */
struct gpe_mac_mc_port {
	/** Forwarding ID (optionally used, set to default FID otherwise). */
	uint32_t fid;
	/** LAN port to be added to the multicast group (0 to 3). */
	uint32_t lan_port_index;
	/** Control flag to separate IGMP and OMCI access to the table.
	    - 0: non-IGMP entry, must not be deleted by IGMP.
	    - 1: IGMP entry, can be deleted by IGMP. */
	uint32_t igmp;
	/** MAC multicast address of multicast group to be joined.
	    MAC=aa:bb:cc:dd:ee:ff corresponds to
	    mc_mac[0]=aa,mc_mac[1]=bb,mc_mac[2]=cc,
	    mc_mac[3]=dd,mc_mac[4]=ee,mc_mac[5]=ff */
	uint8_t mc_mac[6];
} __PACKED__;

/** Structure to add a LAN port to a multicast flow.
   Used by \ref FIO_GPE_SHORT_FWD_MAC_MC_PORT_MODIFY. */
struct gpe_mac_mc_port_modify {
	/** Bridge Index. */
	uint32_t bridge_index;
	/** Port map index (UNI or ANI). */
	uint32_t port_map_index;
	/** Forwarding ID (optionally used, set to default FID otherwise). */
	uint32_t fid;
	/** Control flag to separate IGMP and OMCI access to the table.
	    - 0: non-IGMP entry, must not be deleted by IGMP.
	    - 1: IGMP entry, can be deleted by IGMP. */
	uint32_t igmp;
	/** MAC multicast address of multicast group to be joined.
	    MAC=aa:bb:cc:dd:ee:ff corresponds to
	    mc_mac[0]=aa,mc_mac[1]=bb,mc_mac[2]=cc,
	    mc_mac[3]=dd,mc_mac[4]=ee,mc_mac[5]=ff */
	uint8_t mc_mac[6];
} __PACKED__;

/** Structure to add a LAN port to a multicast flow.
    Used by \ref FIO_GPE_SHORT_FWD_IPV4_MC_PORT_ADD and
    \ref FIO_GPE_SHORT_FWD_IPV4_MC_PORT_DELETE. */
struct gpe_ipv4_mc_port {
	/** Forwarding ID (optionally used, set to default FID otherwise). */
	uint32_t fid;
	/** LAN port to be added to the multicast group (0 to 3). */
	uint32_t lan_port_index;
	/** Control flag to separate IGMP and OMCI access to the table.
	    - 0: non-IGMP entry, must not be deleted by IGMP.
	    - 1: IGMP entry, can be deleted by IGMP. */
	uint32_t igmp;
	/** MAC multicast IP address of multicast group to be joined.
	    IP=aaa.bbb:ccc:ddd corresponds to
	    ip[0]=aaa,ip[1]=bbb,ip[2]=ccc,ip[3]=ddd*/
	uint8_t ip[4];
} __PACKED__;

/** Structure to add a LAN port to a multicast flow.
    Used by \ref FIO_GPE_SHORT_FWD_IPV4_MC_PORT_MODIFY. */
struct gpe_ipv4_mc_port_modify {
	/** Bridge Index. */
	uint32_t bridge_index;
	/** Port map index (UNI or ANI). */
	uint32_t port_map_index;
	/** Forwarding ID (optionally used, set to default FID otherwise). */
	uint32_t fid;
	/** Control flag to separate IGMP and OMCI access to the table.
	- 0: non-IGMP entry, must not be deleted by IGMP.
	- 1: IGMP entry, can be deleted by IGMP. */
	uint32_t igmp;
	/** MAC multicast IP address of multicast group to be joined.
	    IP=aaa.bbb:ccc:ddd corresponds to
	    ip[0]=aaa,ip[1]=bbb,ip[2]=ccc,ip[3]=ddd*/
	uint8_t ip[4];
} __PACKED__;

/** Structure to define the SCE Local CPU MAC address.
    Used by \ref FIO_GPE_SCE_MAC_GET and \ref FIO_GPE_SCE_MAC_SET. */
struct gpe_sce_mac {
	/** MAC Address of Local CPU, used for LCT.
	    MAC=aa:bb:cc:dd:ee:ff corresponds to
	    local_cpu_mac[0]=aa,local_cpu_mac[1]=bb,local_cpu_mac[2]=cc,
	    local_cpu_mac[3]=dd,local_cpu_mac[4]=ee,local_cpu_mac[5]=ff */
	uint8_t local_cpu_mac[6];
} __PACKED__;

/** Structure to handle input data for FID assignment.
    Used by gpe_vlan_fid_u. */
struct gpe_vlan_fid_in {
	/** Outer VLAN Tag, including VLAN ID, DEI, and PCP.
	    bit[0:11] - VLAN ID, bit[12] - DEI, bit[13:15] - PCP*/
	uint32_t vlan_1;
	/** Inner VLAN ID, including VLAN ID, DEI, and PCP. 
	    Set to 0 if unused.
	    bit[0:11] - VLAN ID, bit[12] - DEI, bit[13:15] - PCP*/
	uint32_t vlan_2;
} __PACKED__;

/** Structure to handle output data for FID assignment.
	Used by gpe_vlan_fid_u. */
struct gpe_vlan_fid_out{
	/** Forwarding ID. */
	uint32_t fid;
} __PACKED__;

/** Union to handle FID table data.
    Used by \ref FIO_GPE_VLAN_FID_ADD and \ref FIO_GPE_VLAN_FID_GET.
*/
union gpe_vlan_fid_u {
	/** Forwarding ID function input parameters. */
	struct gpe_vlan_fid_in in;
	/** Forwarding ID function output parameters. */
	struct gpe_vlan_fid_out out;
};


/* IOCTL Command Declaration - GPE Table Access Functions
   ======================================================
*/

/** Magic number */
#define GPE_TABLE_MAGIC 5

/**
   Set a table entry. This is a global function to write to any of the GPE
   tables. The table is selected by its table index. A sub index is used if
   multiple instances of a table are existing in hardware. Multiple instances
   of the same table can be written by a single call of this function.

   This function uses the selected table's defined addressing mode and set the
   "valid" indication true. Calling this function will never create an
   "invalid" (unused) entry in the table.

   See \ref FIO_GPE_TABLE_ENTRY_WRITE for another access type.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if one of the given values is invalid
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_TABLE_ENTRY_SET _IOW(GPE_TABLE_MAGIC, \
				     0x0, struct gpe_table_entry)

/**
   Get a table entry. This is a global function to access any of the GPE tables.
   The table is selected by its table index. A sub index is used if multiple
   instances of a table are existing in hardware. Multiple instances of a table
   must be read one by one, one function call each.

   The table get function returns a result only if the target entry is valid
   (in use). The table access type depends on the selected table's nature:
   - Addressed by an INDEX, if the table type is ARRAY or VARRAY.
   - Addresses by the CRC32 value of a KEY, if the table type is HASH.
   - Addressed by a KEY directly, if the table type is LIST or LLIST.

   See \ref FIO_GPE_TABLE_ENTRY_READ for another access type.

   \param gpe_table_entry_u Pointer to \ref gpe_table_entry_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_TABLE_ENTRY_GET _IOWR(GPE_TABLE_MAGIC, \
				      0x1, union gpe_table_entry_u)

/**
   Add a table entry. This is a global function to read from any of the GPE tables.
   The table is selected by its table index. A sub index is used if multiple
   instances of a table are existing in hardware. Multiple instances of the same
   table can be written by a single call of this function.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if one of the given values is invalid
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_TABLE_ENTRY_ADD _IOW(GPE_TABLE_MAGIC, \
				      0x2, struct gpe_table_entry)

/**
   Delete a table entry.
   This is a global function to delete an entry from any of the GPE tables.
   The table is selected by its table index. A sub index is used if multiple
   instances of a table are existing in hardware. Multiple instances of the same
   table can be deleted by a single call of this function.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if one of the given values is invalid
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_TABLE_ENTRY_DELETE _IOW(GPE_TABLE_MAGIC, \
					 0x3, struct gpe_table_entry)

/**
   Read a table entry. This is a debug function to read from any of the GPE
   tables on a low level and shall not be used in productive software code.
   The table is selected by its table index. A sub index is used if
   multiple instances of a table are existing in hardware. Multiple instances
   of a table must be read one by one, one function call each.

   The table read function always performs a low-level read access, returning
   a result even if the table entry is invalid (unused).

   See \ref FIO_GPE_TABLE_ENTRY_GET for another access type.

   \param gpe_table_entry_u Pointer to \ref gpe_table_entry_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_TABLE_ENTRY_READ _IOWR(GPE_TABLE_MAGIC, \
				       0x4, union gpe_table_entry_u)

/**
   Write a table entry. This is a debug function to write to any of the GPE
   tables on a low level and shall not be used in productive software code.
   The table is selected by its table index. A sub index is used if
   multiple instances of a table are existing in hardware. Multiple instances
   of a table must be read one by one, one function call each.

   This functions performs an indexed low-level write access. the "valid"
   indication must be set explicitly, otherwise an "invalid" (unused) entry
   is created.

   See \ref FIO_GPE_TABLE_ENTRY_SET for another access type.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_TABLE_ENTRY_WRITE _IOW(GPE_TABLE_MAGIC, \
					0x5, struct gpe_table_entry)

/**
   Get a bridge port entry.
   This is a dedicated function to access the learning limitation table and
   the bridge port table in one function call.
   The table is selected by its table index. Multiple instances of a table
   must be read one by one, one function call each.

   \param gpe_bridge_port_cfg_get_u Pointer to \ref gpe_bridge_port_cfg_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_BRIDGE_PORT_CFG_GET _IOWR(GPE_TABLE_MAGIC, \
					  0x6, union gpe_bridge_port_cfg_get_u)

/**
   Set a bridge port entry.
   This is a dedicated function to access the learning limitation table and
   the bridge port table in one function call.
   The table is selected by its table index. Multiple instances of a table
   must be set one by one, one function call each.

   \param gpe_bridge_port Pointer to \ref gpe_bridge_port.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_BRIDGE_PORT_CFG_SET _IOW(GPE_TABLE_MAGIC, \
					 0x7, struct gpe_bridge_port)

/**
   Get VLAN table entry. This is a dedicated function to read the VLAN table.
   The table is selected by its table index. Multiple instances of a table
   must be read one by one, one function call each.

   \param gpe_ext_vlan_get_u Pointer to \ref gpe_ext_vlan_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_EXT_VLAN_GET _IOWR(GPE_TABLE_MAGIC, \
				   0x8, union gpe_ext_vlan_get_u)

/**
   Set VLAN table entry. This is a dedicated function to access the VLAN table
   entries.
   The table is selected by its table index. Multiple instances of a table
   must be read one by one, one function call each.

   \param gpe_ext_vlan Pointer to \ref gpe_ext_vlan.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_EXT_VLAN_SET _IOW(GPE_TABLE_MAGIC, \
				  0x9, struct gpe_ext_vlan)

/**
   Do VLAN table entry. This is a dedicated function to access the VLAN table
   entries.
   The table is selected by its table index. Multiple instances of a table
   must be read one by one, one function call each.

   \param gpe_ext_vlan_translate Pointer to \ref gpe_ext_vlan_translate.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_EXT_VLAN_DO _IOWR(GPE_TABLE_MAGIC, \
				  0xA, struct gpe_ext_vlan_translate)

/**
   Add FID table entry. This is a dedicated function to access the FID table
   entries.
   The table is selected by its table index. Multiple instances of a table
   must be read one by one, one function call each.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_FID_ADD _IOW(GPE_TABLE_MAGIC, 0xB, struct gpe_table_entry)

/**
   Delete FID table entry. This is a dedicated function to access the FID table
   entries.
   The table is selected by its table index. Multiple instances of a table
   must be read one by one, one function call each.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_FID_DELETE _IOW(GPE_TABLE_MAGIC, 0xC, struct gpe_table_entry)

/**
   Add IPv6 multicast table entry.
   This is a dedicated function to access the IPv6 multicast table entries.
   The table is selected by its table index. Multiple instances of a table
   must be read one by one, one function call each.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_LONG_FWD_ADD _IOW(GPE_TABLE_MAGIC, \
				       0xD, struct gpe_table_entry)

/**
   Delete IPv6 multicast table entry.
   This is a dedicated function to access the IPv6 multicast table entries.
   The table is selected by its table index. Multiple instances of a table
   must be read one by one, one function call each.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_LONG_FWD_DELETE _IOW(GPE_TABLE_MAGIC, \
					0xE, struct gpe_table_entry)

/**
   Get a VLAN tagging filter table entry.
   This is a dedicated function to access the VLAN tagging filter table entries.
   The table is selected by its table index. Multiple instances of a table
   must be read one by one, one function call each.

   \param gpe_tagging_filter_get_u Pointer to \ref gpe_tagging_filter_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_TAGGING_FILTER_GET _IOWR(GPE_TABLE_MAGIC, \
				  0xF, union gpe_tagging_filter_get_u)

/**
   Set a VLAN tagging filter table entry.
   This is a dedicated function to access the VLAN tagging filter table entries.
   The table is selected by its table index. Multiple instances of a table
   must be read one by one, one function call each.

   \param gpe_tagging Pointer to \ref gpe_tagging.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_TAGGING_FILTER_SET _IOW(GPE_TABLE_MAGIC, \
				 0x10, struct gpe_tagging)

/**
   Read table0 table entry.
   This is a dedicated function to access the table configurations.
   The table is selected by its table index. A sub index is used if multiple
   instances of a table are existing in hardware. Multiple instances of a table
   must be read one by one, one function call each.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_COP_TABLE0_READ _IOW(GPE_TABLE_MAGIC, \
				 0x11, struct gpe_table_entry)

/**
   Add SHORT FWD MAC table entry. This is a dedicated function to access the
   short forwarding table entries.
   The table is selected by its table index. Multiple instances of a table
   must be read one by one, one function call each.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_SHORT_FWD_ADD _IOW(GPE_TABLE_MAGIC, 0x12, \
				   struct gpe_table_entry)

/**
   Delete SHORT FWD MAC table entry. This is a dedicated function to access the
   short forwarding table entries.
   The table is selected by its table index. Multiple instances of a table
   must be read one by one, one function call each.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_SHORT_FWD_DELETE _IOW(GPE_TABLE_MAGIC, 0x13, \
				      struct gpe_table_entry)

/**
   Enable COP debug tracing feature.

   \param gpe_cop_tracing Pointer to \ref gpe_cop_tracing.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_COP_DEBUG_SET _IOW(GPE_TABLE_MAGIC, 0x14, \
					    struct gpe_cop_tracing)

/**
   MAC table re-learning.

   \param gpe_table_entry Pointer to \ref gpe_table_entry

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SHORT_FWD_RELEARN _IOW(GPE_TABLE_MAGIC, 0x15, \
						struct gpe_table_entry)


/**
   Set custom EXTVLAN match values.
   The ETY fields of \ref gpe_ext_vlan_custom may be set for
   customized matching of EXTVLAN tagged frames.
   Standard initialization values are:
   - extvlancustom.tpid = ONU_ETHERTYPE_CVLAN;
	- extvlancustom.ety1 = ONU_ETHERTYPE_IPV4;
	- extvlancustom.ety2 = ONU_ETHERTYPE_PPPOE_DISC;
	- extvlancustom.ety3 = ONU_ETHERTYPE_PPPOE_SESS;
	- extvlancustom.ety4 = ONU_ETHERTYPE_ARP;
	- extvlancustom.ety5 = ONU_ETHERTYPE_IPV6;

   Other fields must not be touched, therefore this function should be
   used in read modify get mode using FIO_GPE_EXT_VLAN_CUSTOM_GET
   before writing.

   \param gpe_ext_vlan_custom Pointer to \ref gpe_ext_vlan_custom.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - ONU_STATUS_ERR: if the write access was corrupted
*/
#define FIO_GPE_EXT_VLAN_CUSTOM_SET _IOW(GPE_TABLE_MAGIC, 0x16, \
						struct gpe_ext_vlan_custom)

/**
   Hardware coprocessor debug control.

   \param uint32_t Debug control value.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_COP_DEBUG_SERVER _IOW(GPE_TABLE_MAGIC, 0x17, \
		uint32_t)

/**
   Change an entry of the MAC/IPv4 forwarding table.

   \param gpe_table_entry Pointer to \ref gpe_table_entry

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SHORT_FWD_FORWARD _IOW(GPE_TABLE_MAGIC, 0x18, \
						struct gpe_table_entry)


/**
   Delete a table entry. This is a global function to search an entry from any
   of the GPE tables.
   The table is selected by its table index. A sub index is used if multiple
   instances of a table are existing in hardware. Multiple instances of the same
   table can be deleted by a single call of this function.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if one of the given values is invalid
   - GPE_STATUS_NO_SUPPORT: if the given table index is invalid
*/
#define FIO_GPE_TABLE_ENTRY_SEARCH _IOW(GPE_TABLE_MAGIC, \
					 0x19, struct gpe_table_entry)

/**
   Activate a VLAN tagging filter entry.

   \param gpe_tagg_filter Pointer to \ref gpe_tagg_filter.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_TAGGING_FILTER_DO _IOWR(GPE_TABLE_MAGIC, 0x1A, \
						struct gpe_tagg_filter)

/**
   Re-initialize a configuration table.

   \param gpe_reinit_table Pointer to \ref gpe_reinit_table.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_TABLE_REINIT _IOW(GPE_TABLE_MAGIC, \
				     0x1B, struct gpe_reinit_table)

/**
   Change an entry of the IPv6 forwarding table.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_LONG_FWD_FORWARD _IOW(GPE_TABLE_MAGIC, 0x1C, \
						struct gpe_table_entry)

/**
   Get custom EXTVLAN match values.
   See FIO_GPE_EXT_VLAN_CUSTOM_SET function for more details.

   \param gpe_ext_vlan_custom Pointer to \ref gpe_ext_vlan_custom.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - ONU_STATUS_ERR: if the write access was corrupted
*/
#define FIO_GPE_EXT_VLAN_CUSTOM_GET _IOR(GPE_TABLE_MAGIC, 0x1D, \
						struct gpe_ext_vlan_custom)

/**
   Set the MAC bridge aging time.

   \param sce_aging_time Pointer to \ref sce_aging_time.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the aging time is invalid
*/
#define FIO_GPE_AGING_TIME_SET _IOW(GPE_TABLE_MAGIC, 0x1E, \
						struct sce_aging_time)

/**
   Read the MAC bridge aging time back.

   \param sce_aging_time Pointer to \ref sce_aging_time.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the aging time is invalid
*/
#define FIO_GPE_AGING_TIME_GET _IOWR(GPE_TABLE_MAGIC, 0x1F, \
						struct sce_aging_time)

/**
   Calculate the age of a MAC table entry.

   \param sce_mac_entry_age Pointer to \ref sce_mac_entry_age.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the aging time is invalid
*/
#define FIO_GPE_AGE_GET _IOWR(GPE_TABLE_MAGIC, 0x20, struct sce_mac_entry_age)

/**
   Trigger a MAC table entry aging.

   \param gpe_table_entry Pointer to \ref gpe_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_AGE _IOW(GPE_TABLE_MAGIC, 0x21, struct gpe_table_entry)

/**
   Set the MAC bridge aging time in debug mode (for debugging only).

   \param sce_aging_time Pointer to \ref sce_aging_time.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the aging time is invalid
*/
#define FIO_GPE_AGING_TIME_SET_DEBUG _IOW(GPE_TABLE_MAGIC, 0x22, \
						struct sce_aging_time)

/**
   Define an access control rule.

   \param gpe_acl_table_entry Pointer to \ref gpe_acl_table_entry.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the table index is invalid
*/
#define FIO_GPE_ACL_TABLE_ENTRY_SET _IOW(GPE_TABLE_MAGIC, 0x23, \
						struct gpe_acl_table_entry)

/**
   Read an access control rule back.

   \param gpe_acl_table_entry_u Pointer to \ref gpe_acl_table_entry_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the table index is invalid
*/
#define FIO_GPE_ACL_TABLE_ENTRY_GET _IOWR(GPE_TABLE_MAGIC, 0x24, \
						union gpe_acl_table_entry_u)

/**
   Clear (invalidate) an access control rule.

   \param gpe_acl_table_entry_idx Pointer to \ref gpe_acl_table_entry_idx.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the table index is invalid
*/
#define FIO_GPE_ACL_TABLE_ENTRY_DELETE _IOW(GPE_TABLE_MAGIC, 0x25, \
						struct gpe_acl_table_entry_idx)

/**
   Read the firmware constants of the Shared Classification Engine (SCE).

   \param gpe_sce_constants Pointer to \ref gpe_sce_constants.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_CONSTANTS_GET _IOWR(GPE_TABLE_MAGIC, 0x26, \
						struct gpe_sce_constants)

/**
   Update the firmware constants of the Shared Classification Engine (SCE).

   \param gpe_sce_constants Pointer to \ref gpe_sce_constants.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_CONSTANTS_SET _IOW(GPE_TABLE_MAGIC, 0x27, \
						struct gpe_sce_constants)

/**
   Read SCE Local CPU MAC address.

   \param gpe_sce_mac Pointer to \ref gpe_sce_mac.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_MAC_GET _IOR(GPE_TABLE_MAGIC, 0x28, struct gpe_sce_mac)

/**
   Update SCE Local CPU MAC address.

   \param gpe_sce_mac Pointer to \ref gpe_sce_mac.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
*/
#define FIO_GPE_SCE_MAC_SET _IOW(GPE_TABLE_MAGIC, 0x29, struct gpe_sce_mac)

/**
   Add a LAN port to a multicast group by MAC multicast table modification.

   \param gpe_mac_mc_port Pointer to \ref gpe_mac_mc_port.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the lan_port_index is invalid
   - GPE_STATUS_VALUE_RANGE_ERR: if the MAC address is not multicast
   - GPE_STATUS_NOT_AVAILABLE: if the IGMP flag does not match an existing entry
*/
#define FIO_GPE_SHORT_FWD_MAC_MC_PORT_ADD _IOW(GPE_TABLE_MAGIC, 0x2A, \
                                            struct gpe_mac_mc_port)

/**
   Remove a LAN port from a multicast group by MAC multicast table modification.

   \param gpe_mac_mc_port Pointer to \ref gpe_mac_mc_port.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the lan_port_index is invalid
   - GPE_STATUS_VALUE_RANGE_ERR: if the MAC address is not multicast
   - GPE_STATUS_NOT_AVAILABLE: if the MAC address does not exist
   - GPE_STATUS_NOT_AVAILABLE: if the IGMP flag does not match
*/
#define FIO_GPE_SHORT_FWD_MAC_MC_PORT_DELETE _IOW(GPE_TABLE_MAGIC, 0x2B, \
                                            struct gpe_mac_mc_port)


/**
   Modify a port of a multicast group by MAC multicast table modification.

   \param gpe_mac_mc_port_modify Pointer to \ref gpe_mac_mc_port_modify.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the lan_port_index is invalid
   - GPE_STATUS_VALUE_RANGE_ERR: if the MAC address is not multicast
   - GPE_STATUS_NOT_AVAILABLE: if the MAC address does not exist
   - GPE_STATUS_NOT_AVAILABLE: if the IGMP flag does not match
*/
#define FIO_GPE_SHORT_FWD_MAC_MC_PORT_MODIFY _IOW(GPE_TABLE_MAGIC, 0x2C, \
                                            struct gpe_mac_mc_port_modify)

/**
   Add an FID definition for a given VLAN tag.

   \param gpe_vlan_fid_u Pointer to \ref gpe_vlan_fid_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the VLAN tag definition is invalid
   - GPE_STATUS_NOT_AVAILABLE: if the FID table is full
   - GPE_STATUS_ERR: in case of any other error
*/
#define FIO_GPE_VLAN_FID_ADD _IOWR(GPE_TABLE_MAGIC, 0x2D, union gpe_vlan_fid_u)

/**
   Read the FID definition for a given VLAN tag.

   \param gpe_vlan_fid_u Pointer to \ref gpe_vlan_fid_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the VLAN tag definition is invalid
   - GPE_STATUS_NOT_AVAILABLE: if there is no FID assigned for the given VLAN
   - GPE_STATUS_ERR: in case of any other error
*/
#define FIO_GPE_VLAN_FID_GET _IOWR(GPE_TABLE_MAGIC, 0x2E, union gpe_vlan_fid_u)

/**
   Delete the FID definition for a given VLAN tag.

   \param gpe_vlan_fid_in Pointer to \ref gpe_vlan_fid_in.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the VLAN tag definition is invalid
   - GPE_STATUS_NOT_AVAILABLE: if there is no FID assigned for the given VLAN
   - GPE_STATUS_ERR: in case of any other error
*/
#define FIO_GPE_VLAN_FID_DELETE _IOW(GPE_TABLE_MAGIC, 0x2F, \
					struct gpe_vlan_fid_in)


/**
   Add a LAN port to a multicast group by IPv4 multicast table modification.

   \param gpe_ipv4_mc_port Pointer to \ref gpe_ipv4_mc_port.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the lan_port_index is invalid
   - GPE_STATUS_NOT_AVAILABLE: if the IGMP flag does not match an existing entry
*/
#define FIO_GPE_SHORT_FWD_IPV4_MC_PORT_ADD _IOW(GPE_TABLE_MAGIC, 0x30, \
                                            struct gpe_ipv4_mc_port)

/**
   Remove a LAN port from a multicast group by IPv4 multicast table
   modification.

   \param gpe_ipv4_mc_port Pointer to \ref gpe_ipv4_mc_port.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the lan_port_index is invalid
   - GPE_STATUS_NOT_AVAILABLE: if the IPv4 address does not exist
   - GPE_STATUS_NOT_AVAILABLE: if the IGMP flag does not match
*/
#define FIO_GPE_SHORT_FWD_IPV4_MC_PORT_DELETE _IOW(GPE_TABLE_MAGIC, 0x31, \
                                            struct gpe_ipv4_mc_port)


/**
   Modify a port of a multicast group by IPv4 multicast table modification.

   \param gpe_ipv4_mc_port_modify Pointer to \ref gpe_ipv4_mc_port_modify.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - ONU_STATUS_OK: if successful
   - GPE_STATUS_VALUE_RANGE_ERR: if the lan_port_index is invalid
   - GPE_STATUS_NOT_AVAILABLE: if the IPv4 address does not exist
   - GPE_STATUS_NOT_AVAILABLE: if the IGMP flag does not match
*/
#define FIO_GPE_SHORT_FWD_IPV4_MC_PORT_MODIFY _IOW(GPE_TABLE_MAGIC, 0x32, \
                                            struct gpe_ipv4_mc_port_modify)

/*! @} */

/** @} */

EXTERN_C_END
#ifdef __PACKED_DEFINED__
#  if !defined (__GNUC__) && !defined (__GNUG__)
#    pragma pack()
#  endif
#  undef __PACKED_DEFINED__
#  undef __PACKED__
#endif
#endif				/* _drv_onu_gpe_tables_interface_h_ */
