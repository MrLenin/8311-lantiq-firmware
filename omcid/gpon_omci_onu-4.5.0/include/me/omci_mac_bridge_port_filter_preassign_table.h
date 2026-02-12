/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_mac_bridge_port_filter_preassign_table_h
#define _omci_mac_bridge_port_filter_preassign_table_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MAC_BRIDGE_PORT_FILTER_PREASSIGN_TABLE MAC Bridge Port Filter Preassign Table Managed Entity

    This Managed Entity provides an alternate approach to address filtering from
    that supported through MAC bridge port filter table data.
    This alternate approach is useful when all groups of addresses are stored
    beforehand in the ONU, and this Managed Entity designates which groups are
    valid or invalid for filtering. On a circuit pack in which all groups of
    addresses are preassigned and stored locally, the ONU creates or deletes an
    instance of this Managed Entity automatically upon creation or deletion of a
    MAC bridge port configuration data Managed Entity.

    An instance of this Managed Entity is associated with an instance of a MAC
    bridge port configuration data Managed Entity.

    @{
*/

/** This structure holds the attributes of the MAC Bridge Port Filter Preassign
    Table Managed Entity.

    The following ten attributes have similar definitions. Each permits the OLT
    to specify whether MAC addresses or Ethertypes of the named type are
    forwarded (0x00) or filtered (0x01).
    In each case, the initial value of the attribute is 0x00.
*/
struct omci_me_mac_bridge_port_filter_preassign_table {
	/** IPv4 Multicast Filtering

	    Condition: MAC address between 01.00.5E.00.00.00
	    and 01.00.5E.7F.FF.FF.
	*/
	uint8_t ipv4_mc_filter_enable;

	/** IPv6 Multicast Filtering

	    Condition: MAC address between 33.33.00.00.00.00
	    and 33.33.FF.FF.FF.FF
	*/
	uint8_t ipv6_mc_filter_enable;

	/** IPv4 Broadcast Filtering

	    Condition: MAC address equal to FF.FF.FF.FF.FF.FF
	    and Ethertype equal to 0x0800
	*/
	uint8_t ipv4_bc_filter_enable;

	/** RARP Filtering

	    Condition: MAC address equal to FF.FF.FF.FF.FF.FF
	    and Ethertype equal to 0x8035
	*/
	uint8_t rarp_filter_enable;

	/** IPX Filtering

	       Condition: MAC address equal to FF.FF.FF.FF.FF.FF
	       and Ethertype equal to 0x8137
	       or MAC address equal to 09.00.1B.FF.FF.FF or 09.00.4E.00.00.02
	*/
	uint8_t ipx_filter_enable;

	/** NetBEUI Filtering

	    Condition: MAC address equal to 03.00.00.00.00.01
	*/
	uint8_t netbeui_filter_enable;

	/** AppleTalk Filtering

	    Condition: MAC address equal to FF.FF.FF.FF.FF.FF
	    and Ethertype equal to 0x809B
	    or MAC address equal to FF.FF.FF.FF.FF.FF
	    and Ethertype equal to 0x80F3
	    or MAC address between 09.00.07.00.00.00 and 09.00.07.00.00.FC
	    or MAC address equal to 09.00.07.FF.FF.FF
	*/
	uint8_t appletalk_filtering_enable;

	/** Bridge Management Information Filtering

	    Condition: MAC address between 01.80.C2.00.00.00 and 01.80.C2.00.00.FF
	*/
	uint8_t bridge_management_filter_enable;

	/** ARP Filtering

	    Condition: MAC address equal to FF.FF.FF.FF.FF.FF
	    and Ethertype equal to 0x0806

	    \remarks Note that some MAC addresses should not be handled, considering
	    the following rules of IEEE 802.1D:
	    Addresses from 01.80.C2.00.00.00 to 01.80.C2.00.00.0F are reserved.
	    Addresses from 01.80.C2.00.00.20 to 01.80.C2.00.02.0F are used for GARP
	    application addresses.
	*/
	uint8_t arp_filter_enable;

	/** PPPoE Broadcast Filtering

	    Condition: MAC address equal to FF.FF.FF.FF.FF.FF
	    and Ethertype equal to 0x8863
	*/
	uint8_t pppoe_filter_enable;

} __PACKED__;

/** This enumerator holds the attribute numbers of the MAC Bridge Port Filter
   Preassign Table Managed Entity.
*/
enum {
	omci_me_mac_bridge_port_filter_preassign_table_ipv4_mc_filter_enable
	    = 1,
	omci_me_mac_bridge_port_filter_preassign_table_ipv6_mc_filter_enable
	    = 2,
	omci_me_mac_bridge_port_filter_preassign_table_ipv4_broadcast_filter_enable
	    = 3,
	omci_me_mac_bridge_port_filter_preassign_table_rarp_filter_enable =
	    4,
	omci_me_mac_bridge_port_filter_preassign_table_ipx_filter_enable =
	    5,
	omci_me_mac_bridge_port_filter_preassign_table_netbeui_filter_enable
	    = 6,
	omci_me_mac_bridge_port_filter_preassign_table_appletalk_filter_enable
	    = 7,
	omci_me_mac_bridge_port_filter_preassign_table_bridge_management_filter_enable
	    = 8,
	omci_me_mac_bridge_port_filter_preassign_table_arp_filter_enable =
	    9,
	omci_me_mac_bridge_port_filter_preassign_table_pppoe_filter_enable =
	    10
};

/** @} */

/** @} */

__END_DECLS

#endif
