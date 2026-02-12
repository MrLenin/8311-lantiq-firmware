/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_mac_bridge_port_designation_data_h
#define _omci_mac_bridge_port_designation_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MAC_BRIDGE_PORT_DESIGNATION_DATA MAC Bridge Port Designation Data Managed Entity

    This Managed Entity records data associated with a bridge port. The ONU
    automatically creates or deletes an instance of this Managed Entity upon the
    creation or deletion of a MAC bridge port configuration data Managed Entity.

    An instance of this Managed Entity is associated with one MAC bridge port
    configuration data Managed Entity.

    @{
*/

/** This structure holds the attributes of the MAC Bridge Port Designation Data
    Managed Entity.
*/
struct omci_me_mac_bridge_port_designation_data {
	/** Designated Bridge Root Cost Port

	    This attribute contains the designated root, designated cost,
	    designated bridge and designated port, which are some of the
	    outputs of the read port parameters operation defined in 14.8.2.1
	    of IEEE 802.1D
	    - Identifier of the designated bridge for the port's
	    segment (8 byte)
	    - Bridge identifier of the root transmitted by the designated
	    bridge for the segment (8 byte)
	    - Port number of the designated port on the designated bridge
	    considered to be part of this port's segment (4 byte)
	    - Path cost contribution of the designated port to this port's
	    segment (4 byte)
	    Upon ME instantiation, the ONU sets this attribute to 0.

	    This attribute is read-only by the OLT. The value is modified by
	    the Spanning Tree software that runs on the ONU (if implemented).
	*/
	uint8_t root_cost_port[24];

	/** Port State

	    This attribute provides status information on the port (see
	    IEEE 802.1D).
	    Valid values are:
	    - 0x00 Disabled
	    - 0x01 Listening
	    - 0x02 Learning
	    - 0x03 Forwarding
	    - 0x04 Blocking
	    - 0x05 Linkdown
	    - 0x06 STP_off

	    This attribute is read-only by the OLT. The value is modified by
	    the Spanning Tree software that runs on the ONU (if implemented).

	    \remarks The value linkdown is introduced to denote the port status
	    when the Ethernet link state is down. This value distinguishes the
	    case where Ethernet is physically down from the case where Ethernet
	    is administratively down, the latter being denoted by disabled.
	    The value STP_off is introduced to denote the port status where
	    spanning tree protocol is disabled by setting the port spanning
	    tree ind attribute of the MAC bridge port configuration data to
	    false, and the Ethernet link state is up. This value distinguishes
	    whether or not frame forwarding is under control of STP.
	*/
	uint8_t port_state;

} __PACKED__;

/** This enumerator holds the attribute numbers of the MAC Bridge Port
   Designation Data Managed Entity.
*/
enum {
	omci_me_mac_bridge_port_designation_data_root_cost_port = 1,
	omci_me_mac_bridge_port_designation_data_port_state = 2
};

/** @} */

/** @} */

__END_DECLS

#endif
