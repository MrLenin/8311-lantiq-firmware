/******************************************************************************
 * Copyright (c) 2017 - 2019 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * For licensing information, see the file 'LICENSE' in the root folder of
 * this software module.
 *
 * Adapted from gpon_omci_onu-8.6.3 for v4.5.0 with direct Falcon GPE ioctls
 * replacing the PON Adapter abstraction layer.
 ******************************************************************************/
#ifndef _omci_mcc_h
#define _omci_mcc_h

__BEGIN_DECLS

/** \addtogroup OMCI_MCC Multicast Control

   @{
*/

#include "me/omci_multicast_subscriber_monitor.h"

/** IPv4 Active Group List table entry (for mcc_port_monitor_ipv4_agl_get).
    Matches G.988 ME 311 attribute 5 format. */
struct omci_ipv4_agl_table {
	/** VLAN ID */
	uint16_t vlan_id;
	/** Source IP address, 0.0.0.0 if not used */
	uint32_t source_ip;
	/** Multicast destination IP address */
	uint32_t mc_dest_ip;
	/** Best efforts actual bandwidth estimate, bytes per second */
	uint32_t best_eff_act_bw_est;
	/** Client (set-top box) IP address */
	uint32_t client_ip;
	/** Time since the most recent join, in seconds */
	uint32_t time_since_join;
	/** Reserved */
	uint16_t reserved;
} __PACKED__;

/** IPv6 Active Group List table entry (for mcc_port_monitor_ipv6_agl_get).
    Matches G.988 ME 311 attribute 5 extended format for IPv6. */
struct omci_ipv6_agl_table {
	/** VLAN ID */
	uint16_t vlan_id;
	/** Source IPv6 address */
	uint8_t source_ip[16];
	/** Multicast destination IPv6 address */
	uint8_t mc_dest_ip[16];
	/** Best efforts actual bandwidth estimate, bytes per second */
	uint32_t best_eff_act_bw_est;
	/** Client IPv6 address */
	uint8_t client_ip[16];
	/** Time since the most recent join, in seconds */
	uint32_t time_since_join;
} __PACKED__;

/** Monitor type.
*/
enum mcc_monitor_type {
	/** Current multicast bandwidth.*/
	MCC_MONITOR_TYPE_CURRENT_MC_BANDWIDTH = 0,
	/** Join messages counter.*/
	MCC_MONITOR_TYPE_JOIN_MSG_COUNTER = 1,
	/** Bandwidth excess counter. */
	MCC_MONITOR_TYPE_BW_EXCESS_COUNTER = 2
};

/** Enumeration to specify VLAN mode.
*/
enum mcc_vlan_mode {
	/** VLAN unaware mode. */
	MCC_VLAN_MODE_UNAWARE = 0,
	/** VLAN aware mode. */
	MCC_VLAN_MODE_AWARE = 1
};

#if defined(USE_PRAGMA_PACK)
#    pragma pack(push, 1)
#endif

/** Lost group entry.
*/
struct mcc_lost_group {
	/** VLAN ID */
	uint16_t vlan_id;

	/** Source IP address */
	uint8_t src_ip[4];

	/** Multicast destination IP address. IPv4 address resides in
	    bytes 12, 13, 14 and 15 */
	uint8_t dest_ip[16];

} __PACKED__;

#if defined(USE_PRAGMA_PACK)
#    pragma pack(pop)
#endif

/** MCC Multicast Flow.
*/
struct mcc_mc_flow {
	/** VLAN identifier of the US Client sending IGMP/MLD requests.*/
	uint16_t cvid;
	/** VLAN identifier of the DS Multicast stream.*/
	uint16_t svid;
	/** Multicast destination IP address. IPv4 address resides in
	    bytes 12, 13, 14 and 15 */
	uint8_t da[16];
	/** Multicast source IP address. IPv4 address resides in
	    bytes 12, 13, 14 and 15 */
	uint8_t sa[16];
	/** Multicast client IP address. IPv4 address resides in
	    bytes 12, 13, 14 and 15 */
	uint8_t ca[16];
};

struct mcc_mc_ip_range {
	/** Destination start IP address.
	   IPv4 address is located in upper 4 bytes. */
	uint8_t da_s[16];
	/** Destination end IP address.
	    IPv4 address is located in upper 4 bytes. */
	uint8_t da_e[16];
	/** Source IP address.
	    IPv4 address is located in upper 4 bytes. */
	uint8_t sa[16];
	/** Multicast client IP address. IPv4 address resides in
	    bytes 12, 13, 14 and 15 */
	uint8_t ca[16];
};

/** MCC Multicast Flow Range.
*/
struct mcc_mc_flow_range {
	/** VLAN identifier of the US Client sending IGMP/MLD requests.*/
	uint16_t cvid;
	/** VLAN identifier of the DS Multicast stream.*/
	uint16_t svid;
	/** MC IP Range. */
	struct mcc_mc_ip_range ip_range;
};

enum omci_error mcc_port_static_flow_create(struct omci_context *context,
					    const uint16_t meid,
					    const struct mcc_mc_flow *flow);
enum omci_error mcc_port_static_flow_delete(struct omci_context *context,
					    const uint16_t meid,
					    const struct mcc_mc_flow *flow);
enum omci_error
mcc_port_static_flow_range_delete(struct omci_context *context,
				  const uint16_t meid,
				  const struct mcc_mc_flow_range *flow);

enum omci_error mcc_port_dynamic_flow_create(struct omci_context *context,
					     const uint16_t meid,
					     const struct mcc_mc_flow *flow);
enum omci_error mcc_port_dynamic_flow_delete(struct omci_context *context,
					     const uint16_t meid,
					     const struct mcc_mc_flow *flow);
enum omci_error
mcc_port_dynamic_flow_range_delete(struct omci_context *context,
				   const uint16_t meid,
				   const struct mcc_mc_flow_range *flow);

enum omci_error mcc_port_reset(struct omci_context *context,
			       const uint16_t meid);

enum omci_error mcc_port_monitor_data_get(struct omci_context *context,
					  const uint16_t meid,
					  const enum mcc_monitor_type type,
					  uint32_t *value);

enum omci_error mcc_port_monitor_ipv4_agl_get(struct omci_context *context,
					      const uint16_t meid,
					      struct omci_ipv4_agl_table **agl,
					      uint32_t *agl_num);

enum omci_error mcc_port_monitor_ipv6_agl_get(struct omci_context *context,
					      const uint16_t meid,
					      struct omci_ipv6_agl_table **agl,
					      uint32_t *agl_num);

enum omci_error mcc_policy_lgl_get(struct omci_context *context,
				   const uint16_t meid,
				   struct mcc_lost_group **lgl,
				   uint32_t *lgl_num);

enum omci_error mcc_vlan_mode_set(struct omci_context *context,
				  const enum mcc_vlan_mode vlan_mode);

enum omci_error omci_mcc_init(struct omci_context *context);
enum omci_error omci_mcc_exit(struct omci_context *context);

/** @} */

__END_DECLS

#endif
