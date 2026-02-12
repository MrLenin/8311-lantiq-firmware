/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_mac_bridge_service_profile_h
#define _omci_mac_bridge_service_profile_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MAC_BRIDGE_SERVICE_PROFILE MAC Bridge Service Profile Managed Entity

    This Managed Entity models a MAC bridge in its entirety. Any number of
    ports may then be associated with the bridge through pointers to the MAC
    bridge service profile Managed Entity. Instances of this Managed Entity
    are created and deleted by the OLT.
    Bridge ports are modelled by MAC bridge port configuration data managed
    entities, any number of which can point to a MAC bridge service profile.
    The real-time status of the bridge is available from an implicitly linked
    MAC bridge configuration data Managed Entity.

    @{
*/

/** This structure holds the attributes of the MAC Bridge Service Profile
    Data Managed Entity.
*/
struct omci_me_mac_bridge_service_profile {
	/** Spanning Tree Indication

	    The Boolean value OMCI_TRUE specifies that the spanning tree
	    algorithm is enabled. The value OMCI_FALSE disables spanning
	    tree.

	    This attribute is readable and writable by the OLT.

	    \remarks This attribute is used only if the Spanning Tree protocol
	    is implemented by the application software.
	    The application also defines the default value of this attribute.
	*/
	bool spanning_tree_ind;

	/** Learning Indication

	    The Boolean value OMCI_TRUE specifies that bridge learning
	    functions are enabled. The value OMCI_FALSE disables bridge
	    learning. By default, learning is enabled.

	    This attribute is readable and writable by the OLT.
	*/
	bool learning_ind;

	/** Port Bridging Indication

	    The Boolean value OMCI_TRUE specifies that bridging between
	    UNI ports is enabled. The value OMCI_FALSE disables local
	    bridging.
	    By default, bridging is disabled.

	    This attribute is readable and writable by the OLT.
	*/
	bool port_bridging_ind;

	/** Priority

	    This attribute specifies the bridge priority in the range 0..65535.
	    The value of this attribute is copied to the bridge priority
	    attribute of the associated MAC bridge configuration data Managed
	    Entity.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t prio;

	/** Maximum Age Time

	    This attribute specifies the maximum age, in 256ths of a second, of
	    received protocol information before its entry in the spanning tree
	    listing is discarded. The range is 0x0600 to 0x2800 (6..40 seconds)
	    in accordance with IEEE 802.1D.

	    This attribute is readable and writable by the OLT.

	    \remarks This attribute is used only if the Spanning Tree protocol
	    is implemented by the application software.
	    The application also defines the default value of this attribute.

	*/
	uint16_t max_age;

	/** Hello Time

	    This attribute specifies how often, in 256ths of a second, the
	    bridge advertises its presence via hello packets, while as a root
	    or attempting to become a root. The range is 0x0100 to 0x0a00
	    (1..10 seconds) in accordance with IEEE 802.1D.

	    This attribute is readable and writable by the OLT.

	    \remarks This attribute is used only if the Spanning Tree protocol
	    is implemented by the application software.
	    The application also defines the default value of this attribute
	*/
	uint16_t hello_time;

	/** Forward Delay

	    This attribute specifies the forwarding delay (in 256ths of a
	    second) when the bridge acts as the root. The range is 0x0400 to
	    0x1E00 (4..30 seconds) in accordance with IEEE 802.1D.

	    This attribute is readable and writable by the OLT.

	    \remarks This attribute is used only if the Spanning Tree protocol
	    is implemented by the application software.
	    The application also defines the default value of this attribute
	*/
	uint16_t forward_delay;

	/** Unknown MAC Address Discarding

	    The Boolean value OMCI_TRUE specifies that MAC frames with an
	    unknown destination address are discarded. The value OMCI_FALSE
	    specifies that such frames be forwarded to all allowed ports.
	    This attribute is readable and writable by the OLT.
	*/
	bool unknown_mac_discard;

	/** MAC Learning Depth

	    This attribute specifies the maximum number of UNI MAC addresses to
	    be learned by the bridge. The default value of 0x00 specifies that
	    there is no administratively-imposed limit.
	    This attribute is readable and writable by the OLT.
	*/
	uint8_t mac_learning_depth;

	/** MAC Aging Time

	    This attribute ("dynamic filtering ageing time") specifies the age
	    of dynamic filtering entries in the bridge database, after which
	    unrefreshed entries are discarded. In accordance with IEEE 802.1D
	    clause 7.9.2 and IEEE 802.1Q clause 8.8.3, the range
	    is 10..1 000 000 seconds, with a resolution of 1 second and
	    a default of 300 seconds.
	    This attribute is readable and writable by the OLT.
	*/
	uint32_t mac_aging_time;

} __PACKED__;

/** This enumerator holds the attribute numbers of the MAC Bridge Service
   Profile Data Managed Entity.
*/
enum {
	omci_me_mac_bridge_service_profile_spanning_tree_ind = 1,
	omci_me_mac_bridge_service_profile_learning_ind = 2,
	omci_me_mac_bridge_service_profile_port_bridging_ind = 3,
	omci_me_mac_bridge_service_profile_prio = 4,
	omci_me_mac_bridge_service_profile_max_age = 5,
	omci_me_mac_bridge_service_profile_hello_time = 6,
	omci_me_mac_bridge_service_profile_forward_delay = 7,
	omci_me_mac_bridge_service_profile_unknown_mac_discard = 8,
	omci_me_mac_bridge_service_profile_mac_learning_depth = 9,
	omci_me_mac_bridge_service_profile_mac_aging_time = 10
};

/** Get MAC Bridge Service Profile Bridge Group ID */
#define OMCI_MBSP_BRIDGEGRPID_GET(ME_ID) \
   ((uint8_t)((ME_ID) & 0x00ff))

/** Get MAC Bridge Service Profile Slot ID */
#define OMCI_MBSP_SLOTID_GET(ME_ID) \
   ((uint8_t)(((ME_ID) & 0xff00)) >> 8)

/** @} */

/** @} */

__END_DECLS

#endif
