/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_multicast_subscr_monitor_h
#define _omci_api_me_multicast_subscr_monitor_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_MULTICAST_SUBSCR_MONITOR Multicast Subscriber Monitor

   This managed entity provides the current status of each port with respect to
   its multicast subscriptions. It may be useful for status monitoring or
   debugging purposes. The status table includes all dynamic groups currently
   subscribed by the port. 

   Instances of this managed entity are created and deleted at the request of
   the OLT. One instance may exist for each 802.1 UNI configured to support
   multicast subscription. 

   @{
*/

/** Multicast Subscriber monitor data.
*/
struct omci_api_multicast_subscriber_monitor_data {
	/** Best effort estimate of the actual bandwidth currently being
	    delivered to subscriber port over all dynamic multicast groups. */
	uint32_t curr_mc_bw;
	/** Counter for the number of times subscriber sent a join message that
	    was accepted. */
	uint32_t join_msg_cnt;
	/** Counter for the number of join messages that did, or would have,
	    exceeded the max multicast bandwidth, whether accepted or denied. */
	uint32_t bw_exc_cnt;
};

/** Active Group List Table entry type definition used in
   \ref omci_api_multicast_subscriber_monitor_agl_table_get
*/
struct omci_api_multicast_subscriber_monitor_agl_table_entry {
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
};

/** Get main data of Multicast Subscriber Monitor ME

   \param[in]  ctx           OMCI API context pointer
   \param[in]  me_id         Managed  Entity identifier
   \param[out] monitor       Data
*/
enum omci_api_return omci_api_multicast_subscriber_monitor_data_get(
	struct omci_api_ctx *ctx,
	const uint16_t me_id,
	struct omci_api_multicast_subscriber_monitor_data *monitor);

/** Retrieve Active Group List Table of Multicast Subscriber Monitor ME

   \param[in]  ctx           OMCI API context pointer
   \param[in]  me_id         Managed  Entity identifier
   \param[in] linked_me_type Type of linked Managed Entity
   \param[out] entry_num     Number of entries pointed to by entries
   \param[out] entries       The pointer to the first entry
*/
enum omci_api_return omci_api_multicast_subscriber_monitor_agl_table_get(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint8_t linked_me_type,
	unsigned int *entry_num,
	struct omci_api_multicast_subscriber_monitor_agl_table_entry **entries);

/** Delete Multicast Subscriber Monitor ME resources

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return omci_api_multicast_subscriber_monitor_destroy(
	struct omci_api_ctx *ctx,
	uint16_t me_id);

/** @} */

/** @} */

__END_DECLS

#endif
