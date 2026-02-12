/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_multicast_gem_interworking_tp_h
#define _omci_multicast_gem_interworking_tp_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MULTICAST_GEM_INTERWORKING_TP Multicast GEM Interworking Termination Point Managed Entity

    An instance of this Managed Entity represents a point in the ONT where a
    multicast service interworks with the GEM layer. At this point, a multicast
    bit stream is reconstructed from GEM packets.

    Instances of this Managed Entity are created and deleted by the OLT.

    The default multicast operation of the PON is where all the multicast
    content streams are placed in one PON layer connection (GEM port).
    This connection is then specified in the first entry of the multicast
    address table. This single entry also specifies an all-inclusive
    IP multicast address range (e.g., 224.0.0.0 to 239.255.255.255).
    The ONT then filters the traffic based on either Ethernet MAC addresses or
    IP addresses. The GEM port network CTP Managed Entity contains the GEM port
    ID that supports all multicast connections.

    An optional multicast operation is where groups of one or more multicast
    content streams are carried over individual PON layer connections, i.e., on
    separate GEM ports, but terminate on a single multicast GEM interworking
    termination point. In this case, the OLT sets as many table entries as
    desired for the multicast control system. The ONT can initially filter
    groups based on PON layer address (GEM port). In a subsequent step, the ONU
    can also filter based on higher-layer addresses. In this case, the OLT need
    create only one instance of the GEM port network CTP ME. Though this GEM
    port network CTP Managed Entity cites only one GEM port ID, the ONT should
    regard this Managed Entity as the representative of all multicast GEM
    connections served by the multicast GEM interworking TP. The traffic
    descriptors, priority queues, and performance management features for all
    multicast connections are integrated into the single GEM port network CTP
    Managed Entity. Several multicast GEM interworking termination points can
    exist, each linked to separate bridge ports or mappers to serve different
    communities of interest in a complex ONU.

    @{
*/

/** Multicast Address Table Entry. See \ref
   omci_me_multicast_gem_interworking_tp::mc_address_table */
struct omci_me_mc_address_table {
	/** GEM Port-ID */
	uint16_t gem_port_id;

	/** Secondary Index */
	uint16_t secondary_index;

	/** IP Multicast Address Range Start */
	uint32_t ip_mc_address_range_start;

	/** IP Multicast Address Range Stop */
	uint32_t ip_mc_address_range_stop;

} __PACKED__;

/** This structure holds the attributes of the Multicast GEM Interworking
    Termination Point Managed Entity.
*/
struct omci_me_multicast_gem_interworking_tp {
	/** GEM Port Network CTP Connectivity Pointer

	    This attribute points to an instance of the GEM port network CTP
	    that is associated with this multicast GEM interworking termination
	    point.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t gem_port_network_ctp_ptr;

	/** Interworking Option

	    This attribute identifies the type of non-GEM function that is
	    being interworked. The option can be:
            - 0x00 This value is a no-op or don't care. It should be used when the
	    the multicast GEM IW TP is associated with several functions of
	    different types. It can optionally be used in all cases, since the
	    necessary information is available elsewhere. The other
	    codepoints are retained for backward compatibility.
	    - 0x01 MAC bridge LAN
	    - 0x03 IP router
	    - 0x05 IEEE 802.1p mapper

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t interworking_option;

	/** Service Profile Pointer

	    This attribute is set to 0x0000 and not used. For backward
	    compatibility, it may also be set to point to a MAC bridge service
	    profile, IP router service profile or 802.1P mapper service profile.

	    Values other than 0x0000 are ignored by the software.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t service_profile_ptr;

	/** Interworking Termination Point Pointer

	    This attribute is set to 0x0000 and not used.

	    Values other than 0x0000 are ignored by the software.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t interworking_tp_ptr;

	/** PPTP Count

	    This attribute represents the number of instances of PPTP Managed
	    Entities associated with this instance of the multicast GEM
	    interworking termination point. This attribute conveys no
	    information that is not available elsewhere, it may be set to 0xFF
	    and not used.

	    The default value is 0xFF.

	    This attribute is read-only by the OLT.
	*/
	uint8_t pppt_count;

	/** Operational State

	    This attribute reports whether the Managed Entity is currently
	    capable of performing its function. Valid values are
	    OMCI_OPERATIONAL_STATE_ENABLED (0x00) and
	    OMCI_OPERATIONAL_STATE_DISABLED (0x01).

	    This attribute is read-only by the OLT.
	*/
	uint8_t oper_state;

	/** GAL Profile Pointer

	    This attribute is set to 0x0000 and not used. For backward
	    compatibility, it may also be set to point to a GAL Ethernet
	    profile.

	    Values other than 0x0000 are ignored by the software.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t gal_profile_ptr;

	/** GAL Loopback Configuration

	    This attribute is set to 0x00 and not used.
	    Values other than 0x00 are ignored by the software.
	    This attribute is readable and writable by the OLT.
	*/
	uint8_t gal_loopback_config;

	/** Multicast Address Table

	    This attribute maps IP multicast addresses to PON layer
	    addresses. Each entry contains:
	    - GEM port ID (2 bytes)
	    - Secondary index (2 bytes)
	    - IP multicast address range start (4 bytes)
	    - IP multicast address range stop (4 bytes)

	    The first four bytes of each entry are treated as the index of the
	    list.  The secondary index allows the table to contain more than a
	    single range for a given GEM port.

	    A set action to a particular value overwrites any existing entry
	    with the same first four bytes. If the last eight bytes of a set
	    command are all zero, that entry is deleted from the list, as the
	    all-zero IP address is not valid.

	    One OMCI set message can convey up to two table entries. However,
	    OMCI does not provide robust exception handling when more than one
	    entry is included in a set command, and multiple entries per set
	    operation are not recommended.

	    \remarks The software shall respond an error, if the OLT tries to
	    set more than one table entry in a single OMCI message.
	*/
	struct omci_me_mc_address_table mc_address_table;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Multicast GEM
   Interworking Termination Point Managed Entity.
*/
enum {
	omci_me_multicast_gem_interworking_tp_gem_port_network_ctp_ptr = 1,
	omci_me_multicast_gem_interworking_tp_interworking_option = 2,
	omci_me_multicast_gem_interworking_tp_service_profile_ptr = 3,
	omci_me_multicast_gem_interwokring_tp_interworking_tp_pointer = 4,
	omci_me_multicast_gem_interworking_tp_pppt_count = 5,
	omci_me_multicast_gem_interworking_tp_oper_state = 6,
	omci_me_multicast_gem_interworking_tp_gal_profile_ptr = 7,
	omci_me_multicast_gem_interworking_tp_gal_loopback_config = 8,
	omci_me_multicast_gem_interworking_tp_mc_address_table = 9
};

/** @} */

/** @} */

__END_DECLS

#endif
