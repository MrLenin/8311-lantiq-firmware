/******************************************************************************
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * For licensing information, see the file 'LICENSE' in the root folder of
 * this software module.
 *
 * Ported from gpon_omci_onu-8.6.3 — OMCI bridge layer.
 * These functions read ME data for MCC multicast policy decisions
 * using me_attr_read, mib_me_find, mib_walk_by_class, and tbl_ops.
 ******************************************************************************/
#ifndef _omci_mcc_omci_h
#define _omci_mcc_omci_h

__BEGIN_DECLS

/** Rate Limiter.
*/
struct mcc_omci_rl {
	/** Rate Limiter type.*/
	enum mcc_rl_type type;
	/** Rate limit (messages/second).*/
	uint32_t rate;
};

struct mcc_omci_mc_bridge_info {
	uint16_t br_id;
	uint16_t bp_id;
};

struct mcc_omci_wlist {
	struct mcc_list src_list;
	uint16_t vid;
	uint8_t pass_unauth;
	uint32_t supported_prot_mask;
};

/** OMCI IGMP/MLD protocol version handling option. Defines IGMP/MLD protocol
    version handling with respect to the "IGMP Version" OMCI attribute. */
enum mcc_omci_prot_version_option {
	/** Default option: IGMPv2 → IPv4 only, no MLD. */
	MCC_OMCI_PROT_VERSION_OPTION_DEFAULT = 0,
	/** IOP option 0: IGMPv2 → IPv4 + all MLD. */
	MCC_OMCI_PROT_VERSION_OPTION_IOP_0 = 1,
};

enum omci_error mcc_omci_port_idx_get(struct omci_context *context,
				      const uint16_t meid,
				      uint8_t *port_idx);

enum omci_error mcc_omci_port_me_get(struct omci_context *context,
				     const uint8_t port_idx,
				     const enum mcc_prot_version prot_version,
				     struct me **port);

enum omci_error mcc_omci_port_total_capacity_get(struct omci_context *context,
						 const uint8_t port_idx,
						 struct mcc_capacity *cap);

enum omci_error mcc_omci_port_service_capacity_get(struct omci_context *context,
						   const uint8_t port_idx,
						   const uint16_t cvid,
						   struct mcc_capacity *cap);

enum omci_error mcc_omci_port_ibw_enf_get(struct omci_context *context,
					  const uint8_t port_idx,
					  uint8_t *ibw_enf);

enum omci_error mcc_omci_policy_wlist_id_get(struct omci_context *context,
					     const uint16_t meid,
					     union mcc_wlist_id *wlist_id);

enum omci_error mcc_omci_rl_get(struct omci_context *context,
				const uint8_t port_idx,
				const uint16_t cvid,
				struct mcc_omci_rl *rl);

enum omci_error mcc_omci_grp_lost_alarm_set(struct omci_context *context,
					    const struct mcc_grp_entry *grp);

enum omci_error
mcc_omci_mc_bridge_info_get(struct omci_context *context,
			    const uint8_t port_idx,
			    struct mcc_omci_mc_bridge_info *info);

enum omci_error
mcc_omci_mc_addr_table_match(struct omci_context *context,
			     const uint8_t port_idx,
			     const enum mcc_prot_version prot_version,
			     const union mcc_ip_addr *ga);

void mcc_omci_lock(struct omci_context *context);

void mcc_omci_unlock(struct omci_context *context);

enum omci_error mcc_omci_flw_gmi_get(struct omci_context *context,
				     const struct mcc_flw *flw,
				     uint32_t *gmi_ms);

enum omci_error mcc_omci_flw_wlist_get(struct omci_context *context,
				       struct me *port,
				       const uint16_t cvid,
				       const uint16_t svid,
				       const enum mcc_prot_version version,
				       const union mcc_ip_addr *da,
				       struct mcc_omci_wlist *omci_wlist);

__END_DECLS

#endif
