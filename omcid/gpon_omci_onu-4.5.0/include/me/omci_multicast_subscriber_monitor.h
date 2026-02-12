/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_multicast_subscriber_monitor_h
#define _omci_multicast_subscriber_monitor_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MULTICAST_SUBSCRIBER_MONITOR Multicast Subscriber Monitor Managed Entity

    This managed entity provides the current status of each port with respect to
    its multicast subscriptions. It may be useful for status monitoring or
    debugging purposes. The status table includes all dynamic groups currently
    subscribed by the port.
    Instances of this managed entity are created and deleted at the request of
    the OLT. One instance may exist for each 802.1 UNI configured to support
    multicast subscription. 

    @{
*/

/** Active Group List (AGL) table entry */
struct omci_agl_table {
	/** VLAN ID */
	uint16_t vlan_id;
	/** Source IP address, 0.0.0.0 if not used */
	uint32_t source_ip;
	/** Multicast destination IP address */
	uint32_t mc_dest_ip;
	/** Best efforts actual bandwidth estimate, bytes per second  */
	uint32_t best_eff_act_bw_est;
	/** Client (set-top box) IP address, that is, the IP address of the
	    device currently joined*/
	uint32_t client_ip;
	/** Time since the most recent join of this client to the IP channel,
	    in seconds */
	uint32_t time_since_join;
	/** Reserved */
	uint16_t reserved;
} __PACKED__;

/** This structure holds the attributes of the Multicast Subscriber
    Monitor Managed Entity.
*/
struct omci_me_multicast_subscriber_monitor {
	/** Managed Entity Type

	    This attribute indicates the type of the managed Entity implicitly
	    linked by the Managed Entity ID attribute.
	    The coding is:
	    - 0x00 MAC bridge port config data
	    - 0x01 IEEE 802.1p mapper service profile

	    This attribute is readable and writable by the OLT.
	*/
	uint8_t me_type;

	/** Current multicast bandwidth

	    This attribute is the ONU’s best effort estimate of the actual
	    bandwidth currently being delivered to this particular MAC bridge
	    port over all dynamic multicast groups.

	    This attribute is readable by the OLT.
	*/
	uint32_t current_mc_bw;

	/** Join messages counter

	    This attribute counts the number of times the corresponding
	    subscriber sent a join message that was accepted. When full, the
	    counter rolls over to 0.

	    This attribute is readable by the OLT.
	*/
	uint32_t join_msg_cnt;

	/** Bandwidth exceeded counter

	    This attribute counts the number of join messages that did, or would
	    have, exceeded the max multicast bandwidth, whether accepted or
	    denied. When full, the counter rolls over to 0.

	    This attribute is readable by the OLT.
	*/
	uint32_t bw_exc_cnt;
	/** Active group list table

	    This attribute lists the groups from the dynamic access control list
	    table that are currently being actively forwarded, along with the
	    actual bandwidth of each. If a join has been recognized from more
	    than one IP source address for a given group on this UNI, there will
	    be one table entry for each.

	    This attribute is readable by the OLT.
	*/
	struct omci_agl_table agl_table;
} __PACKED__;

/** This enumerator holds the attribute numbers of the Multicast Subscriber
    Monitor Managed Entity.
*/
enum {
	omci_me_multicast_subscriber_monitor_me_type = 1,
	omci_me_multicast_subscriber_monitor_current_mc_bw = 2,
	omci_me_multicast_subscriber_monitor_max_join_msg_cnt = 3,
	omci_me_multicast_subscriber_monitor_bw_exc_cnt = 4,
	omci_me_multicast_subscriber_monitor_agl_table = 5
};

/** @} */

/** @} */

__END_DECLS

#endif
