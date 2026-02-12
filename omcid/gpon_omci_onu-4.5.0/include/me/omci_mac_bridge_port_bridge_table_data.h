/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_mac_bridge_port_bridge_table_data_h
#define _omci_mac_bridge_port_bridge_table_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MAC_BRIDGE_PORT_BRIDGE_TABLE_DATA MAC Bridge Port Bridge Table Data Managed Entity

    This Managed Entity reports status data associated with a bridge port. The
    ONT automatically creates or deletes an instance of this Managed Entity upon
    the creation or deletion of a MAC bridge port configuration data.

    An instance of this Managed Entity is associated with an instance of a MAC
    bridge port configuration data Managed Entity.

    @{
*/

/** Bridge Table Entry. See
   \ref omci_me_mac_bridge_port_bridge_table_data::bridge_table */
struct omci_bridge_table {
	/** Information */
	uint16_t info;

	/** MAC Address */
	uint8_t mac_address[6];

} __PACKED__;

/** This structure holds the attributes of the Mac Bridge Port Bridge Table Data
    Managed Entity.
*/
struct omci_me_mac_bridge_port_bridge_table_data {
	/** Bridge Table

	    This attribute lists known MAC destination addresses, whether they
	    are learned or statically assigned, whether packets having them as
	    destination addresses are filtered or forwarded, and their ages.
	    Each entry contains:
            - Information (2 bytes)
            - MAC address (6 bytes)

	    See ITU-T G.984.4, clause 9.3.8, for more detail.
	    Upon Managed Entity instantiation, this attribute is an empty list.

	    The attribute is read-only by the OLT.
	*/
	struct omci_bridge_table bridge_table;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Mac Bridge Port Bridge
   Table Data Managed Entity.
*/
enum {
	omci_me_mac_bridge_port_bridge_table_data_bridge_table = 1
};

/** @} */

/** @} */

__END_DECLS

#endif
