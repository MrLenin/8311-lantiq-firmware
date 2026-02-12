/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_mac_bridge_port_filter_table_data_h
#define _omci_mac_bridge_port_filter_table_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MAC_BRIDGE_PORT_FILTER_TABLE_DATA MAC Bridge Port Filter Table data Managed Entity

    This Managed Entity organizes data associated with a bridge port. The ONU
    automatically creates or deletes an instance of this Managed Entity upon the
    creation or deletion of a MAC bridge port configuration data Managed Entity.

    It is assumed that the OLT disables the learning mode in the MAC bridge
    service profile before writing to the MAC filter table.

    An instance of this Managed Entity is associated with an instance of a MAC
    bridge port configuration data Managed Entity.

    @{
*/

/** MAC Filter Table Entry. See
   \ref omci_me_mac_bridge_port_filter_table_data::mac_filter_table */
struct omci_mac_filter_table {
	/** The entry number, an index into this attribute list */
	uint8_t index;

	/** Filter byte */
	uint8_t filter_byte;

	/** MAC address */
	uint8_t mac_address[6];

} __PACKED__;

/** This structure holds the attributes of the MAC Bridge Port Filter Table
    Data Managed Entity.
*/
struct omci_me_mac_bridge_port_filter_table_data {
	/** MAC Filter Table

	    This attribute lists MAC destination addresses associated with the
	    bridge port, each with an allow/disallow forwarding indicator for
	    traffic flowing out of the bridge port. In this way, the upstream
	    traffic is filtered on the ANI-side bridge ports, and the
	    downstream traffic is filtered on the UNI-side bridge ports.
	    Each entry contains:
	    - The entry number, an index into this attribute list (1 byte)
	    - Filter byte (1 byte)
	    - MAC address (6 bytes)

	    The bits of the filter byte are assigned as follows:
	    \verbatim
	    Bit Name              Setting
	    1  Filter/forward    0: forward
				 1: filter
	    2..7 Reserved        0
	    8  Add/remove        0: remove this entry (set operation)
				 1: add this entry
	    \endverbatim

	    Upon Managed Entity instantiation, the ONT sets this attribute to
	    an empty table.

	    One OMCI set message can convey a maximum of three table entries.
	    However, OMCI does not provide robust exception handling when more
	    than one entry is included in a set command, and multiple entries
	    per set operation are not recommended.

	    \todo check the following: (also refer to remark of
	    struct omci_me_multicast_gem_interworking_tp::mc_address_table)
	    The software shall respond an error if more than three table
	    entries are contained in a single OMCI message.
	*/
	struct omci_mac_filter_table mac_filter_table;

} __PACKED__;

/** This enumerator holds the attribute numbers of the MAC Bridge Port Filter
   Table Data Managed Entity.
*/
enum {
	omci_me_mac_bridge_port_filter_table_data_mac_filter_table = 1
};

/** @} */

/** @} */

__END_DECLS

#endif
