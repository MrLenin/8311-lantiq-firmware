/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_multicast_operations_profile_h
#define _omci_multicast_operations_profile_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MULTICAST_OPERATIONS_PROFILE Multicast Operations Profile Managed Entity

    This Managed Entity expresses the multicast policy. A multi-dwelling unit
    ONU may have several such policies, which are linked to subscribers as
    required. Some of the attributes configure IGMP snooping and proxy
    parameters, in case the defaults do not suffice, as described in RFCs 2236,
    3376, 3810, and 2933.
    Instances of this Managed Entity are created and deleted by the OLT.
    An instance of this Managed Entity may be associated with zero or more
    instances of the multicast subscriber configuration information Managed
    Entity.

    @{
*/

/** MOP IGMP/MLD version code points */
#define OMCI_MOP_IGMP_V1		1
#define OMCI_MOP_IGMP_V2		2
#define OMCI_MOP_IGMP_V3		3
#define OMCI_MOP_MLD_V1		16
#define OMCI_MOP_MLD_V2		17

/** Dynamic/Static ACL table entry delete operation */
#define OMCI_ACL_TABLE_ENTRY_DELETE                              (1 << 15)

/** Dynamic/Static ACL table entry set operation */
#define OMCI_ACL_TABLE_ENTRY_SET                                 (1 << 14)

/** Dynamic/Static ACL table entry */
struct omci_acl_table {
	/** Table index */
	uint16_t index;

	/** GEM port ID */
	uint16_t gem_port_id;

	/** VLAN ID */
	uint16_t vlan_id;

	/** Source IP address */
	uint8_t source_ip[4];

	/** Destination IP address of the start of the multicast range */
	uint8_t dest_start_ip[4];

	/** Destination IP address of the end of the multicast range */
	uint8_t dest_end_ip[4];

	/** Imputed group bandwidth */
	uint32_t group_bandwidth;

	/** Reserved */
	uint16_t reserved;

} __PACKED__;

/** Lost groups list table entry */
struct omci_lost_groups_table {
	/** VLAN ID */
	uint16_t vlan_id;

	/** Source IP address */
	uint8_t source_ip[4];

	/** Multicast destination IP address */
	uint8_t dest_ip[4];

} __PACKED__;

/** This structure holds the attributes of the Multicast Operations Profile
    Managed Entity.
*/
struct omci_me_multicast_operations_profile {
	/** IGMP Version

	    This attribute specifies the version of IGMP to be supported.
	    Support of a given version implies compatible support of previous
	    versions.  If the ONU cannot support the version requested, it
	    should deny an attempt to write or create the Managed Entity.
	    The coding is:
	    - 0x00 reserved
	    - 0x01 IGMP version 1 (no longer used)
	    - 0x02 IGMP version 2
	    - 0x03 IGMP version 3
	    The default value is 0x02.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t igmp_version;

	/** IGMP Function

	    This attribute enables an IGMP function. The default value 0x00
	    specifies transparent IGMP snooping only. The value 0x01 specifies
	    snooping with proxy reporting (SPR). The value 0x02 specifies IGMP
	    proxy. The function must be consistent with the capabilities
	    specified by the other IGMP configuration attributes.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t igmp_function;

	/** Immediate Leave

	    This boolean attribute enables the immediate leave function.
	    The default value OMCI_FALSE disables immediate leave,
	    OMCI_TRUE enables immediate leave.

	    This attribute is readable and writable by the OLT.
	*/
	bool immediate_leave;

	/** Upstream IGMP Tag Control Information

	    Under control of the upstream IGMP Tag Control Information (TCI)
	    attribute, the upstream IGMP TCI attribute defines a VLAN ID
	    and P-bits to add to upstream IGMP messages.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t us_igmp_tag_ctrl_info;

	/** Upstream IGMP Tag Control

	    This attribute controls the upstream IGMP TCI attribute.
	    The coding is:
	    - 0x00 Pass upstream IGMP traffic transparently, neither adding,
	    stripping nor modifying tags that may be present.
	    - 0x01 Add a VLAN tag (including P bits) to upstream IGMP traffic.
	    The VLAN is specified by the upstream IGMP TCI attribute.
	    - 0x02 Replace the entire TCI (VLAN ID plus P bits) on upstream
	    IGMP traffic. The new tag is specified by the upstream IGMP
	    TCI attribute.
	    - 0x03 Replace only the VLAN ID on upstream IGMP traffic, retaining
	    the original CFI and P bits. The new VLAN ID is specified by
	    the VLAN field of the upstream IGMP TCI attribute.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t us_igmp_tag_ctrl;

	/** Upstream IGMP Rate

	    This attribute limits the maximum rate of upstream IGMP traffic.
	    Traffic in excess of this limit is silently discarded. The
	    attribute value is specified in messages/second.
	    The default value of 0x00000000 imposes no rate limit on this
	    traffic.

	    This attribute is readable and writable by the OLT.
	*/
	uint32_t us_igmp_rate;

	/** Dynamic Access Control List Table

	    This attribute is a list that specifies one or more multicast group
	    address ranges.
	    Each list entry is a vector of eight components:
	    - Table index (2 byte).
	    The first two bytes of each entry are treated as the index of the
	    table. It is the responsibility of the OLT to assign and track table
	    indices and content. The ONU should deny set operations that
	    create range overlaps.
	    The two MSBs of this field determine the meaning of a set
	    operation. These bits are returned as 00 during get next
	    operations.
		- 0x00 Reserved
		- 0x01 Write this entry into the table. Overwrite any
		existing entry with the same table index.
		- 0x10 Delete this entry from the table. The remaining
		fields are not meaningful.
		- 0x11 Clear all entries from the table. The remaining
		fields are not meaningful.
	    - GEM port ID (2 byte).
	    - VLAN ID, this field specifies the VLAN carrying the multicast
	    group downstream. The VLAN ID resides in the 12 least significant
	    bits, the remaining bits are set to 0 and not used.
	    The value of 0x0000 designates an untagged downstream flow (2 byte).
	    - Source IP address. The value 0.0.0.0 specifies that the source
	    IP address is to be ignored (4 byte).
	    - Destination IP address of the start of the multicast
	    range (4 byte).
	    - Destination IP address of the end of the multicast range (4 byte).
	    - Imputed group bandwidth. Expressed in bytes/sec, the imputed group
	    bandwidth is used to decide whether or not to honor a join request
	    in the presence of a max multicast bandwidth limit. The default
	    value of 0x00000000 effectively allows this table entry to avoid
	    max bandwidth limitations (4 byte).
	    - Reserved, set to 0x0000 (2 bytes).
	    A single multicast group may be specified by setting start and end
	    destination IP addresses to the same value.
	    The maximum table size is application dependent.

	    This attribute (table) is readable and writable by the OLT.
	*/
	struct omci_acl_table dynamic_acl_table;

	/** Static Access Control List Table

	    This attribute is a list that specifies one or more multicast
	    group address ranges. Groups defined in this list are multicast on
	    the associated UNI(s) unconditionally, that is, without the need for
	    an IGMP join. The bandwidth of static multicast groups is not
	    included in the current multicast bandwidth measurement maintained
	    by the multicast subscriber monitor Managed Entity. If a join
	    message is always expected, this table may be empty.
	    Table entries have the same format as those in the dynamic access
	    control list table.
	    The maximum table size is application dependent.

	    This attribute (table) is readable and writable by the OLT.
	*/
	struct omci_acl_table static_acl_table;

	/** Lost Groups List Table

	    This attribute is a list of groups from the dynamic access control
	    list table for which there is an active join, but no downstream
	    flow is present, possibly because of source failure, but also
	    possibly because of misconfiguration somewhere upstream. After a
	    join, the ONT should wait a reasonable time for upstream processing
	    before declaring a group to be lost.
	    Each entry is a vector of the following components:
	    - VLAN ID, 0x0000 if not used (2 byte)
	    - Source IP address, 0.0.0.0 if not used (4 byte)
	    - Multicast destination IP address (4 byte)

	    This attribute (table) is read-only by the OLT.
	*/
	struct omci_lost_groups_table lost_groups_table;

	/** Robustness

	    This attribute allows tuning for possible packet loss in the
	    network.
	    The default value 0x00 causes the ONU to follow the IETF
	    recommendation to copy the robustness value from query messages
	    originating further upstream.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t robustness;

	/** Querier IP Address

	    This attribute specifies the IP address to be used by a proxy
	    querier.
	    Although it is not a legitimate IP address, the default
	    value 0.0.0.0 is legal in this case (see IETF RFC 4541).

	    This attribute is readable and writable by the OLT.
	*/
	uint32_t querier_ip_addr;

	/** Query Interval

	    This attribute specifies the interval between general queries in
	    seconds.
	    The default is 125 seconds.

	    This attribute is readable and writable by the OLT.
	*/
	uint32_t query_interval;

	/** Query Maximum Response Time

	    This attribute is the max response time added by the proxy into
	    general query messages directed to UNIs. It is expressed in tenths
	    of seconds, with a default of 100 (10 seconds).

	    This attribute is readable and writable by the OLT.
	*/
	uint32_t query_max_rsp_time;

	/** Last Member Query Interval

	    This attribute specifies the max response time inserted into
	    group-specific queries sent to UNIs in response to group leave
	    messages.  It is also the repetition rate of [robustness]
	    transmissions of the query. It is specified in tenths of seconds,
	    with a default of 10 (1 second).

	    This attribute is readable and writable by the OLT.
	*/
	uint32_t last_member_query_interval;

	/** Unauthorized Join Request Behavior

	    This boolean attribute specifies the ONU's behaviour when it
	    receives an IGMP join request for a group that is not authorized in
	    the dynamic address control list table, or an IGMPv3 membership
	    report for groups, none of which are authorized in the dynamic ACL.
	    The default value OMCI_FALSE specifies that the ONU silently discard
	    the IGMP request. The value OMCI_TRUE specifies that the ONU
	    forwards the request in upstream direction. The ONT does not attempt
	    to honour the request for the unauthorized group(s) in either case.
	*/
	bool unauthorized_join_request_behavior;
	/** Downstream IGMP and multicast TCI

	    This attribute controls the downstream tagging of both the IGMP/MLD
	    and multicast frames. If the first byte of this attribute is
	    non-zero, a possible extended VLAN tagging operation ME is ignored
	    for downstream IGMP/MLD and multicast frames.

	    This attribute is readable and writable by the OLT.

	    The first byte defines the control type: 
		- 0: Pass downstream IGMP/MLD and multicast traffic
		     transparently, neither stripping nor modifying tags that
		     may be present. 
		- 1: Strip the outer VLAN tag (including P bits) from downstream
		     IGMP/MLD and multicast traffic.
		- 2: Add a tag onto downstream IGMP/MLD and multicast traffic.
		     The new tag is specified by the second and third bytes of
		     this attribute. 
		- 3: Replace the tag on downstream IGMP/MLD and multicast
		     traffic. The new tag is specified by the second and third
		     bytes of this attribute. 
		- 4: Replace only the VLAN ID on downstream IGMP/MLD and
		     multicast traffic, retaining the original DEI and P bits.
		     The new VLAN ID is specified by the VLAN ID field of the
		     second and third bytes of this attribute. 
		- 5: Add a tag onto downstream IGMP/MLD and multicast traffic.
		     The new tag is specified by the VID (UNI) field of the
		     multicast service package table row of the multicast
		     subscriber config info ME that is associated with this
		     profile. If the VID (UNI) field is unspecified (0xFFFF) or
		     specifies untagged traffic, the new tag is specified by the
		     second and third bytes of this attribute. 
		- 6: Replace the tag on downstream IGMP/MLD and multicast
		     traffic. The new tag is specified by the VID (UNI) field of
		     the multicast service package table row of the multicast
		     subscriber config info ME that is associated with this
		     profile. If the VID (UNI) field specifies untagged traffic,
		     the outer VLAN tag (including P bits) is stripped from
		     downstream IGMP/MLD and multicast traffic. If the value of
		     the VID (UNI) is unspecified (0xFFFF), the new tag is
		     specified by the second and third bytes of this attribute. 
		- 7: Replace only the VID on downstream IGMP/MLD and multicast
		     traffic, retaining the original DEI and P bits. The new
		     VLAN ID is specified by the VID (UNI) field of the
		     multicast service package table row of the multicast
		     subscriber config info ME that is associated with this
		     profile. If the VID (UNI) field specifies untagged traffic,
		     the outer VLAN tag (including P bits) is stripped from
		     downstream IGMP/MLD and multicast traffic. If the value of
		     the VID (UNI) is unspecified (0xFFFF), the new tag is
		     specified by the second and third bytes of this attribute. 
	*/
	uint8_t ds_igmp_mc_tci[3];
} __PACKED__;

/** This enumerator holds the attribute numbers of the Multicast Operations
   Profile Managed Entity.
*/
enum {
	omci_me_multicast_operations_profile_igmp_version = 1,
	omci_me_multicast_operations_profile_igmp_function = 2,
	omci_me_multicast_operations_profile_immediate_leave = 3,
	omci_me_multicast_operations_profile_us_igmp_tag_ctrl_info = 4,
	omci_me_multicast_operations_profile_us_igmp_tag_ctrl = 5,
	omci_me_multicast_operations_profile_us_igmp_rate = 6,
	omci_me_multicast_operations_profile_dynamic_acl_table = 7,
	omci_me_multicast_operations_profile_static_acl_table = 8,
	omci_me_multicast_operations_profile_lost_groups_table = 9,
	omci_me_multicast_operations_profile_robustness = 10,
	omci_me_multicast_operations_profile_querier_ip_addr = 11,
	omci_me_multicast_operations_profile_query_interval = 12,
	omci_me_multicast_operations_profile_query_max_rsp_time = 13,
	omci_me_multicast_operations_profile_last_member_query_interval = 14,
	omci_me_multicast_operations_profile_unauthorized_join_request_behavior =
	    15,
	omci_me_multicast_operations_profile_ds_igmp_mc_tci = 16
};

/** @} */

/** @} */

__END_DECLS

#endif
