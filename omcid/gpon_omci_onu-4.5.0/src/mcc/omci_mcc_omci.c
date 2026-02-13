/******************************************************************************
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * OMCI bridge: reads ME data using v4.5.0 access patterns for MCC policy.
 *
 * STUB: Minimal working implementation. Full rewrite in Phase 7 Step 5.
 ******************************************************************************/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_mib.h"
#include "mcc/omci_mcc_core.h"
#include "mcc/omci_mcc_omci.h"
#include "mcc/omci_mcc_pkt.h"

#include "me/omci_multicast_subscriber_config.h"
#include "me/omci_multicast_operations_profile.h"
#include "me/omci_mac_bridge_port_config_data.h"

enum omci_error mcc_omci_port_idx_get(struct omci_context *context,
				      const uint16_t meid,
				      uint8_t *port_idx)
{
	/* TODO: Phase 7 Step 5 — walk ME 47 (bridge port config data) to
	   find UNI-type bridge port linked to this ME 309 subscriber,
	   then map to LAN port index.

	   For now: use ME instance ID as port index (common convention) */
	if (!port_idx)
		return OMCI_ERROR;

	*port_idx = 0; /* Default to port 0 */
	return OMCI_SUCCESS;
}

enum omci_error mcc_omci_port_me_get(struct omci_context *context,
				     const uint8_t port_idx,
				     const enum mcc_prot_version prot_version,
				     struct me **port)
{
	/* TODO: Phase 7 Step 5 — walk ME 309 instances to find one
	   associated with the given port index */
	if (port)
		*port = NULL;
	return OMCI_ERROR;
}

enum omci_error mcc_omci_port_total_capacity_get(struct omci_context *context,
						 const uint8_t port_idx,
						 struct mcc_capacity *cap)
{
	/* TODO: Phase 7 Step 5 — read ME 309 max_simultaneous_groups +
	   max_mc_bandwidth attributes */
	if (cap) {
		cap->str = 0; /* 0 = no limit */
		cap->ibw = 0;
	}
	return OMCI_SUCCESS;
}

enum omci_error mcc_omci_port_service_capacity_get(
	struct omci_context *context,
	const uint8_t port_idx,
	const uint16_t cvid,
	struct mcc_capacity *cap)
{
	/* TODO: Phase 7 Step 5 — read ME 309 service package table */
	if (cap) {
		cap->str = 0;
		cap->ibw = 0;
	}
	return OMCI_SUCCESS;
}

enum omci_error mcc_omci_port_ibw_enf_get(struct omci_context *context,
					  const uint8_t port_idx,
					  uint8_t *ibw_enf)
{
	/* TODO: Phase 7 Step 5 — read ME 309 bandwidth_enforcement attr */
	if (ibw_enf)
		*ibw_enf = 0; /* Default: no enforcement */
	return OMCI_SUCCESS;
}

enum omci_error mcc_omci_policy_wlist_id_get(struct omci_context *context,
					     const uint16_t meid,
					     union mcc_wlist_id *wlist_id)
{
	/* TODO: Phase 7 Step 5 — read ME 310 class/instance ID */
	if (wlist_id)
		wlist_id->word = 0;
	return OMCI_SUCCESS;
}

enum omci_error mcc_omci_rl_get(struct omci_context *context,
				const uint8_t port_idx,
				const uint16_t cvid,
				struct mcc_omci_rl *rl)
{
	/* TODO: Phase 7 Step 5 — read ME 310 us_igmp_rate attr */
	if (rl) {
		rl->type = MCC_RL_TYPE_NA;
		rl->rate = 0; /* 0 = no rate limit */
	}
	return OMCI_SUCCESS;
}

enum omci_error mcc_omci_grp_lost_alarm_set(struct omci_context *context,
					    const struct mcc_grp_entry *grp)
{
	/* TODO: Phase 7 Step 5 — write lost group entry to ME 310
	   lost_groups_table attribute */
	(void)context;
	(void)grp;
	return OMCI_SUCCESS;
}

enum omci_error
mcc_omci_mc_bridge_info_get(struct omci_context *context,
			    const uint8_t port_idx,
			    struct mcc_omci_mc_bridge_info *info)
{
	/* TODO: Phase 7 Step 5 — walk ME 47 to find MC GEM bridge port
	   (tp_type == 6) for the given bridge */
	if (info) {
		info->br_id = 0;
		info->bp_id = 0;
	}
	return OMCI_ERROR;
}

enum omci_error
mcc_omci_mc_addr_table_match(struct omci_context *context,
			     const uint8_t port_idx,
			     const enum mcc_prot_version prot_version,
			     const union mcc_ip_addr *ga)
{
	/* TODO: Phase 7 Step 5 — read ME 310 dynamic_acl_table,
	   match group address against ACL entries */
	(void)context;
	(void)port_idx;
	(void)prot_version;
	(void)ga;

	/* Return SUCCESS = address is allowed */
	return OMCI_SUCCESS;
}

void mcc_omci_lock(struct omci_context *context)
{
	context_lock(context);
}

void mcc_omci_unlock(struct omci_context *context)
{
	context_unlock(context);
}

enum omci_error mcc_omci_flw_gmi_get(struct omci_context *context,
				     const struct mcc_flw *flw,
				     uint32_t *gmi_ms)
{
	/* TODO: Phase 7 Step 5 — read ME 310 query_interval + robustness,
	   calculate GMI = robustness * query_interval + query_response */
	if (gmi_ms)
		*gmi_ms = MCC_QUERY_ROBUSTNESS_DEFAULT *
			  MCC_QUERY_INTERVAL_DEFAULT +
			  MCC_QUERY_RESPONSE_INTERVAL_DEFAULT;
	return OMCI_SUCCESS;
}

enum omci_error mcc_omci_flw_wlist_get(struct omci_context *context,
				       struct me *port,
				       const uint16_t cvid,
				       const uint16_t svid,
				       const enum mcc_prot_version version,
				       const union mcc_ip_addr *da,
				       struct mcc_omci_wlist *omci_wlist)
{
	/* TODO: Phase 7 Step 5 — read ME 310 dynamic/static ACL,
	   extract matching whitelist entries */
	if (omci_wlist) {
		mcc_list_init(&omci_wlist->src_list);
		omci_wlist->vid = 0xFFFF;
		omci_wlist->pass_unauth = 0;
		omci_wlist->supported_prot_mask = 0;
	}
	return OMCI_SUCCESS;
}
