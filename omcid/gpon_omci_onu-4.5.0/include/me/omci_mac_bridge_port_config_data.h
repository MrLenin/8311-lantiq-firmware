/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_mac_bridge_port_config_data_h
#define _omci_mac_bridge_port_config_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MAC_BRIDGE_PORT_CONFIG_DATA MAC Bridge Port Configuration Data Managed Entity

    This Managed Entity models a port on a MAC bridge. Instances of this
    Managed Entity are created and deleted by the OLT.
    An instance of this Managed Entity is linked to an instance of the MAC
    bridge service profile. Additional bridge port control capabilities are
    provided by implicitly linked instances of some or all of:
    - MAC bridge port filter table data
    - MAC bridge port preassign table
    - VLAN tagging filter data
    - Extended VLAN tagging operation config data

    Real-time status of the bridge port is provided by implicitly linked
    instances of:
    - MAC bridge port designation data
    - MAC bridge port bridge table data

    @{
*/

/** This structure holds the attributes of the MAC Bridge Port Configuration
    Data Managed Entity.
*/
struct omci_me_mac_bridge_port_config_data {
	/** Bridge ID Pointer

	    This attribute points to an instance of the MAC bridge service
	    profile.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t bridge_id_ptr;

	/** Port Number

	    This attribute is the bridge port number. It must be unique among
	    all ports associated with a particular MAC bridge service profile.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t port_number;

	/** Termination Point Type

	    This attribute identifies the type of termination point associated
	    with this MAC bridge port. Valid values are:
	    - 0x01 Physical Path Termination Point Ethernet UNI)
	    - 0x02 Interworking VCC termination point
	    - 0x03 802.1p mapper service profile
	    - 0x04 IP host config data
	    - 0x05 GEM interworking termination point
	    - 0x06 Multicast GEM interworking termination point
	    - 0x07 Physical path termination point xDSL UNI part 1
	    - 0x08 Physical path termination point VDSL UNI
	    - 0x09 Ethernet flow termination point
	    - 0x0A Physical path termination point 802.11 UNI

	    Not all of these might be supported by a specific application.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t tp_type;

	/** Termination Point Pointer

	    This attribute points to the termination point associated with this
	    MAC bridge port. The TP type attribute indicates the type of the
	    termination point. This attribute contains its instance
	    identifier (ME ID).

	    This attribute is readable and writable by the OLT.

	    \remarks When the TP type is VDSL or xDSL, the two most significant
	    bits may be used to indicate a bearer channel.
	*/
	uint16_t tp_ptr;

	/** Port Priority

	    This attribute denotes the priority of the port. The range
	    is 0..255.

	    This attribute is readable and writable by the OLT.

	    \remarks This attribute is optional in GEM mode.
	*/
	uint16_t port_prio;

	/** Port Path Cost

	    This attribute specifies the contribution of the port to the path
	    cost toward the spanning tree root bridge. The range is 1..65535.

	    This attribute is readable and writable by the OLT.

	    \remarks This attribute is used only if the Spanning Tree protocol
	    is implemented by the application software.
	*/
	uint16_t port_path_cost;

	/** Port Spanning Tree Indication

	    The Boolean value OMCI_TRUE enables STP LAN topology change
	    detection at this port. The value OMCI_FALSE disables topology
	    change detection.

	    This attribute is readable and writable by the OLT.

	    \remarks This attribute is used only if the Spanning Tree protocol
	    is implemented by the application software.
	*/
	bool port_spanning_tree_ind;

	/** Encapsulation Method

	    This attribute is not used. It shall be set to 0x01.

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t encap_method;

	/** LAN FCS Indication

	    This attribute indicates whether frame check sequence bytes are
	    forwarded (OMCI_FALSE) or discarded (OMCI_TRUE). It is not
	    expected to be needed in G-PON applications, but is retained for
	    backward compatibility.  The setting applies in both directions of
	    transmission, and applies regardless of encapsulation method, but it
	    is meaningful only for ports on the ANI side of the MAC bridge. The
	    default value of this attribute is OMCI_FALSE, the opposite
	    setting is not supported by hardware.

	    This attribute is readable and writable by the OLT.
	*/
	bool lan_fcs_ind;

	/** Port MAC Address

	    If the termination point associated with this port has a MAC
	    address, this attribute specifies it. In this case the MAC address
	    is defined by the application.

	    This attribute is read-only by the OLT.
	*/
	uint8_t port_mac_address[6];

	/** Outbound Traffic Descriptor Pointer

	    This attribute points to a Traffic Descriptor that limits the
	    traffic rate leaving the MAC bridge.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t outbound_td_ptr;

	/** Inbound Traffic Descriptor Pointer

	    This attribute points to a Traffic Descriptor that limits the
	    traffic rate entering the MAC bridge.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t inbound_td_ptr;

	/** MAC Learning Depth

	    This attribute specifies the maximum number of UNI MAC addresses to
	    be learned by the bridge. The default value of 0x00 specifies that
	    there is no administratively-imposed limit.
	    This attribute is readable and writable by the OLT.
	*/
	uint8_t mac_learning_depth;
} __PACKED__;

/** This enumerator holds the attribute numbers of the MAC Bridge Port
   Configuration Data Managed Entity.
*/
enum {
	omci_me_mac_bridge_port_config_data_bridge_id_ptr = 1,
	omci_me_mac_bridge_port_config_data_port_number = 2,
	omci_me_mac_bridge_port_config_data_tp_type = 3,
	omci_me_mac_bridge_port_config_data_tp_ptr = 4,
	omci_me_mac_bridge_port_config_data_port_prio = 5,
	omci_me_mac_bridge_port_config_data_port_path_cost = 6,
	omci_me_mac_bridge_port_config_data_port_spanning_tree_ind = 7,
	omci_me_mac_bridge_port_config_data_encap_method = 8,
	omci_me_mac_bridge_port_config_data_lan_fcs_ind = 9,
	omci_me_mac_bridge_port_config_data_port_mac_address = 10,
	omci_me_mac_bridge_port_config_data_outbound_td_ptr = 11,
	omci_me_mac_bridge_port_config_data_inbound_td_ptr = 12,
	omci_me_mac_bridge_port_config_data_mac_learning_depth = 13
};

/** @} */

/** @} */

__END_DECLS

#endif
