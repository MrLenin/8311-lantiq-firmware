/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_mac_config_data_h
#define _omci_mac_config_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MAC_BRIDGE_CONFIG_DATA MAC Bridge Configuration Data Managed Entity

    This Managed Entity organizes status data associated with a MAC bridge.
    The ONT automatically creates or deletes an instance of this Managed Entity
    upon the creation or deletion of a MAC bridge service profile.

    This Managed Entity is associated with one instance of a MAC bridge.

    @{
*/

/** This structure holds the attributes of the MAC Bridge Configuration
    Data Managed Entity.
*/
struct omci_me_mac_bridge_config_data {
	/** Bridge MAC Address

	    This attribute indicates the MAC address used by the bridge. The ONU
	    sets this attribute to the value that is given by the
	    application-specific configuration.
	*/
	uint8_t bridge_mac_address[6];

	/** Bridge Priority

	    This attribute reports the priority of the bridge. The ONU copies
	    this attribute from the priority attribute of the associated MAC
	    bridge service profile. The value of this attribute changes with
	    updates to the MAC bridge service profile priority attribute.

	    See \ref omci_me_mac_bridge_service_profile::prio.
	*/
	uint16_t bridge_prio;

	/** Designated Root

	    This attribute identifies the bridge at the root of the spanning
	    tree.
	    It comprises bridge priority (2 bytes) and MAC address (6 bytes).
	*/
	uint8_t designated_root[8];

	/** Root Path Cost

	    This attribute reports the cost of the best path to the root as
	    seen from the bridge. Upon Managed Entity instantiation, the ONU
	    sets this attribute to 0.
	*/
	uint32_t root_path_cost;

	/** Bridge Port Count

	    This attribute records the number of ports linked to this bridge.
	*/
	uint8_t bridge_port_count;

	/** Root Port Number

	    This attribute contains the port number that has the lowest cost
	    from the bridge to the root bridge. The value 0 means that this
	    bridge is itself the root.
	    Upon Managed Entity instantiation, the ONU sets this attribute to 0x0000.
	*/
	uint16_t root_port_number;

	/** Hello Time

	    This attribute is the hello time received from the designated root,
	    the interval (in 256ths of a second) between hello packets. Its
	    range is 0x0100 to 0x0A00 (1..10 seconds) in accordance with IEEE
	    802.1D.  The value is application dependent.
	*/
	uint16_t hello_time;

	/** Forward Delay

	    This attribute is the forwarding delay time received from the
	    designated root, in 256ths of a second. Its range is 0x0400 to
	    0x1E00 (4..30 seconds) in accordance with IEEE 802.1D.
	    The value is application dependent.
	*/
	uint16_t forward_delay;

} __PACKED__;

/** This enumerator holds the attribute numbers of the MAC Bridge Configuration
    Data Managed Entity.
*/
enum {
	omci_me_mac_bridge_config_data_bridge_mac_address = 1,
	omci_me_mac_bridge_config_data_bridge_prio = 2,
	omci_me_mac_bridge_config_data_designated_root = 3,
	omci_me_mac_bridge_config_data_root_path_cost = 4,
	omci_me_mac_bridge_config_data_bridge_port_count = 5,
	omci_me_mac_bridge_config_data_root_port_number = 6,
	omci_me_mac_bridge_config_data_hello_time = 7,
	omci_me_mac_bridge_config_data_forward_delay = 8
};

/** @} */

/** @} */

__END_DECLS

#endif
