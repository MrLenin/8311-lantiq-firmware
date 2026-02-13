/******************************************************************************
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * OMCI bridge layer: reads ME data for MCC multicast policy decisions.
 * Ported from gpon_omci_onu-8.6.3 with v4.5.0 adaptations:
 *   - No ZTE EMOP (ME 65282) — only MOP (ME 309)
 *   - No service package table on ME 310 — direct MOP pointer
 *   - Single MC address table on ME 281 (IPv4 only, no split IPv4/IPv6)
 *   - tbl_ops infrastructure for table iteration (registered in Step 7)
 ******************************************************************************/

#define OMCI_DBG_MODULE OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_mib.h"

#ifdef INCLUDE_MCC

#include "mcc/omci_mcc_core.h"
#include "mcc/omci_mcc_omci.h"

#include "me/omci_mac_bridge_port_config_data.h"
#include "me/omci_multicast_subscriber_config.h"
#include "me/omci_multicast_operations_profile.h"
#include "me/omci_multicast_gem_interworking_tp.h"
#include "me/omci_gem_port_network_ctp.h"

#define WALKER3_DATA_BP_MAX	4

#define MCC_OMCI_DACL_NO_MATCH	(0 << 0)
#define MCC_OMCI_DACL_DA_MATCH	(1 << 0)
#define MCC_OMCI_DACL_SA_MATCH	(1 << 1)

struct walker3_data {
	struct me *bp_me[WALKER3_DATA_BP_MAX];
	uint8_t bp_cnt;
	uint16_t bridge_id;
};

struct me_walker_1_data {
	uint8_t lan_port_index;
	struct {
		uint16_t br_id;
		uint16_t bp_id;
	} pair;
	uint16_t pair_cnt;
};

/** Walk ME 47 instances to find the UNI bridge port for a given LAN port.
    tp_type == 1 (PPTP Ethernet UNI) or 11 (VEIP). */
static enum omci_error me_walker_1(struct omci_context *context,
				   struct me *me,
				   void *shared_data)
{
	enum omci_error error;
	struct me_walker_1_data *w_data =
		(struct me_walker_1_data *)shared_data;
	uint8_t tp_type;
	uint16_t ptr;

	if (w_data->pair_cnt)
		return OMCI_SUCCESS;

	error = me_attr_read(context, me,
			     omci_me_mac_bridge_port_config_data_tp_type,
			     &tp_type, sizeof(tp_type));
	RETURN_IF_ERROR(error);

	/* Only UNI-type bridge ports: PPTP Eth (1) or VEIP (11) */
	if (tp_type != 1 && tp_type != 11)
		return OMCI_SUCCESS;

	error = me_attr_read(context, me,
			     omci_me_mac_bridge_port_config_data_tp_ptr,
			     &ptr, sizeof(ptr));
	RETURN_IF_ERROR(error);

	if ((ptr & 0xFF) == (w_data->lan_port_index + 1)) {
		error = me_attr_read(context, me,
			      omci_me_mac_bridge_port_config_data_bridge_id_ptr,
			      &ptr, sizeof(ptr));
		RETURN_IF_ERROR(error);

		w_data->pair.br_id = ptr;
		w_data->pair.bp_id = me->instance_id;

		w_data->pair_cnt++;
	}

	return OMCI_SUCCESS;
}

/** Walk ME 47 instances to lock/unlock all MC subscriber config MEs. */
static enum omci_error me_walker_2(struct omci_context *context,
				   struct me *me,
				   void *shared_data)
{
	bool *lock = (bool *)shared_data;

	if (*lock)
		me_lock(context, me);
	else
		me_unlock(context, me);

	return OMCI_SUCCESS;
}

/** Walk ME 47 instances to find MC GEM bridge ports (tp_type == 6)
    within a given bridge. */
static enum omci_error me_walker_3(struct omci_context *context,
				   struct me *me,
				   void *shared_data)
{
	enum omci_error error = OMCI_SUCCESS;
	struct walker3_data *data = (struct walker3_data *)shared_data;
	uint8_t tp_type;
	uint16_t bridge_me_id;

	me_lock(context, me);
	error = me_attr_read(context, me,
			     omci_me_mac_bridge_port_config_data_bridge_id_ptr,
			     &bridge_me_id, sizeof(bridge_me_id));
	me_unlock(context, me);
	RETURN_IF_ERROR(error);

	if (bridge_me_id != data->bridge_id)
		return OMCI_SUCCESS;

	me_lock(context, me);
	error = me_attr_read(context, me,
			     omci_me_mac_bridge_port_config_data_tp_type,
			     &tp_type, sizeof(tp_type));
	me_unlock(context, me);
	RETURN_IF_ERROR(error);

	/* Only MC GEM bridge ports are of interest */
	if (tp_type != 6)
		return OMCI_SUCCESS;

	if (data->bp_cnt < ARRAY_SIZE(data->bp_me)) {
		data->bp_me[data->bp_cnt++] = me;
	} else {
		dbg_err("More than %zu MC GEM Bridge Ports per Bridge",
			ARRAY_SIZE(data->bp_me));
		error = OMCI_ERROR;
	}

	return error;
}

enum omci_error mcc_omci_port_idx_get(struct omci_context *context,
				      const uint16_t meid,
				      uint8_t *port_idx)
{
	enum omci_error error = OMCI_SUCCESS;
	struct me *bp;
	uint16_t uni_meid;

	dbg_in(__func__, "%p, %hu, %p", context, meid, port_idx);

	/* Find the bridge port ME */
	error = mib_me_find(context,
			    OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
			    meid, &bp);
	RETURN_IF_ERROR(error);

	/* Read its TP pointer (points to PPTP/VEIP) */
	error = me_attr_read(context, bp,
			     omci_me_mac_bridge_port_config_data_tp_ptr,
			     &uni_meid, sizeof(uni_meid));
	RETURN_IF_ERROR(error);

	error = uni2port(uni_meid, port_idx);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error mcc_omci_port_me_get(struct omci_context *context,
				     const uint8_t port_idx,
				     const enum mcc_prot_version prot_version,
				     struct me **port)
{
	enum omci_error error = OMCI_SUCCESS;
	struct mcc_omci_mc_bridge_info mc_bridge_info;

	dbg_in(__func__, "%p, %hhu, %p", context, port_idx, *port);

	error = mcc_omci_mc_bridge_info_get(context, port_idx, &mc_bridge_info);
	RETURN_IF_ERROR(error);

	error = mib_me_find(context, OMCI_ME_MULTICAST_SUBSCRIBER_CONFIG_INFO,
			    mc_bridge_info.bp_id, port);

	dbg_out_ret(__func__, error);

	return error;
}

enum omci_error mcc_omci_port_total_capacity_get(struct omci_context *context,
						 const uint8_t port_idx,
						 struct mcc_capacity *cap)
{
	enum omci_error error = OMCI_SUCCESS;
	struct me *port = NULL;
	uint16_t val16;
	uint32_t val32;

	dbg_in(__func__, "%p, %hhu, %p", context, port_idx, cap);

	error = mcc_omci_port_me_get(context, port_idx,
				     MCC_PROT_VERSION_NA, &port);
	RETURN_IF_ERROR(error);

	error = me_attr_read(context, port,
		omci_me_multicast_subscriber_config_max_simultaneous_group,
		&val16, sizeof(val16));
	RETURN_IF_ERROR(error);

	cap->str = val16;

	error = me_attr_read(context, port,
		omci_me_multicast_subscriber_config_max_mc_bw,
		&val32, sizeof(val32));
	RETURN_IF_ERROR(error);
	cap->ibw = val32;

	dbg_out_ret(__func__, error);

	return error;
}

enum omci_error mcc_omci_port_service_capacity_get(
	struct omci_context *context,
	const uint8_t port_idx,
	const uint16_t cvid,
	struct mcc_capacity *cap)
{
	dbg_in(__func__, "%p, %hhu, %hu, %p", context, port_idx, cvid, cap);

	/* v4.5.0 ME 310 has no service package table, so per-service
	   capacity is not available. Return no limit. */
	cap->ibw = 0;
	cap->str = 0;

	dbg_out_ret(__func__, OMCI_SUCCESS);

	return OMCI_SUCCESS;
}

enum omci_error mcc_omci_port_ibw_enf_get(struct omci_context *context,
					  const uint8_t port_idx,
					  uint8_t *ibw_enf)
{
	enum omci_error error = OMCI_SUCCESS;
	struct me *port = NULL;

	dbg_in(__func__, "%p, %hhu, %p", context, port_idx, ibw_enf);

	error = mcc_omci_port_me_get(context, port_idx,
				     MCC_PROT_VERSION_NA, &port);
	RETURN_IF_ERROR(error);

	error = me_attr_read(context, port,
			     omci_me_multicast_subscriber_config_bw_enforcement,
			     ibw_enf, sizeof(*ibw_enf));

	dbg_out_ret(__func__, error);

	return error;
}

enum omci_error mcc_omci_policy_wlist_id_get(struct omci_context *context,
					     const uint16_t meid,
					     union mcc_wlist_id *wlist_id)
{
	enum omci_error error = OMCI_SUCCESS;
	struct me *policy = NULL;

	dbg_in(__func__, "%p, %hu, %p", context, meid, wlist_id);

	error = mib_me_find(context, OMCI_ME_MULTICAST_OPERATIONS_PROFILE,
			    meid, &policy);
	RETURN_IF_ERROR(error);

	wlist_id->field.class_id = policy->class->class_id;
	wlist_id->field.instance_id = policy->instance_id;

	dbg_out_ret(__func__, error);

	return error;
}

/** Match a DACL entry's IPv4 address range against a group address. */
static uint8_t dacl_ipv4_match(const struct omci_acl_table *dacl,
			       const union mcc_ip_addr *da,
			       union mcc_ip_addr *sa)
{
	uint8_t ret = MCC_OMCI_DACL_NO_MATCH;
	union mcc_ip_addr snull;

	/* Match group destination IP range */
	if (memcmp(dacl->dest_start_ip, da->ipv4, 4) > 0 ||
	    memcmp(da->ipv4, dacl->dest_end_ip, 4) > 0)
		return ret;

	ret |= MCC_OMCI_DACL_DA_MATCH;

	/* Match any source — single entry with 0.0.0.0 source */
	memset(&snull, 0, sizeof(snull));
	if (memcmp(&snull, dacl->source_ip, 4) == 0)
		ret |= MCC_OMCI_DACL_SA_MATCH;

	memset(sa, 0, sizeof(*sa));
	memcpy(sa->ipv4, dacl->source_ip, 4);

	return ret;
}

/** Read DACL/SACL whitelist entries from a MOP policy ME. */
static enum omci_error
mcc_omci_policy_wlist_get(struct omci_context *context,
			  struct me *policy,
			  const uint16_t svid,
			  const enum mcc_prot_version ver,
			  const enum mcc_omci_prot_version_option ver_opt,
			  const union mcc_ip_addr *da,
			  struct mcc_omci_wlist *omci_wlist)
{
	enum omci_error error = OMCI_SUCCESS;
	const struct tbl_ops *dacl_ops;
	void *dacl;
	void *tmp;
	struct mcc_src_entry *src;
	union mcc_ip_addr sa;
	union mcc_wlist_id wlist_id;
	bool vid_found = false;
	uint8_t match = MCC_OMCI_DACL_NO_MATCH, igmp_version;
	uint32_t prot_mask = 0;

	dbg_in(__func__, "%p, %p, %hu, %u, %u, %p, %p",
	       context, policy, svid, ver, ver_opt, da, omci_wlist);

	/* Get Unauthorized join request behaviour attribute */
	error = me_attr_read(context, policy,
		omci_me_multicast_operations_profile_unauthorized_join_request_behavior,
		&omci_wlist->pass_unauth,
		sizeof(omci_wlist->pass_unauth));
	RETURN_IF_ERROR(error);

	/* Get IGMP Version attribute */
	error = me_attr_read(context, policy,
		omci_me_multicast_operations_profile_igmp_version,
		&igmp_version, sizeof(igmp_version));
	RETURN_IF_ERROR(error);

	dbg_prn("MOP %hu igmp_version=%hhu ver_opt=%d",
		policy->instance_id, igmp_version, ver_opt);

	/* Decode IGMP version attribute and set supported protocols */
	if (ver_opt == MCC_OMCI_PROT_VERSION_OPTION_DEFAULT) {
		if (igmp_version == OMCI_MOP_IGMP_V2)
			prot_mask = (1 << MCC_PROT_VERSION_IGMP_V2);

		if (igmp_version == OMCI_MOP_IGMP_V3)
			prot_mask = (1 << MCC_PROT_VERSION_IGMP_V2) |
				    (1 << MCC_PROT_VERSION_IGMP_V3);

		if (igmp_version == OMCI_MOP_MLD_V1)
			prot_mask = (1 << MCC_PROT_VERSION_MLD_V1);

		if (igmp_version == OMCI_MOP_MLD_V2)
			prot_mask = (1 << MCC_PROT_VERSION_MLD_V1) |
				    (1 << MCC_PROT_VERSION_MLD_V2);
	} else if (ver_opt == MCC_OMCI_PROT_VERSION_OPTION_IOP_0) {
		if (igmp_version == OMCI_MOP_IGMP_V2)
			prot_mask = (1 << MCC_PROT_VERSION_IGMP_V2) |
				    (1 << MCC_PROT_VERSION_MLD_V1) |
				    (1 << MCC_PROT_VERSION_MLD_V2);

		if (igmp_version == OMCI_MOP_IGMP_V3)
			prot_mask = (1 << MCC_PROT_VERSION_IGMP_V2) |
				    (1 << MCC_PROT_VERSION_IGMP_V3) |
				    (1 << MCC_PROT_VERSION_MLD_V1) |
				    (1 << MCC_PROT_VERSION_MLD_V2);

		if (igmp_version == OMCI_MOP_MLD_V1)
			prot_mask = (1 << MCC_PROT_VERSION_IGMP_V2) |
				    (1 << MCC_PROT_VERSION_IGMP_V3) |
				    (1 << MCC_PROT_VERSION_MLD_V1);

		if (igmp_version == OMCI_MOP_MLD_V2)
			prot_mask = (1 << MCC_PROT_VERSION_IGMP_V2) |
				    (1 << MCC_PROT_VERSION_IGMP_V3) |
				    (1 << MCC_PROT_VERSION_MLD_V1) |
				    (1 << MCC_PROT_VERSION_MLD_V2);
	} else {
		dbg_err("MOP %hu unsupported ver_opt %d",
			policy->instance_id, ver_opt);
		error = OMCI_ERROR_INVALID_VAL;
		RETURN_IF_ERROR(error);
	}

	/* Check if we have a match for the specified protocol version */
	if (prot_mask & (1 << ver)) {
		omci_wlist->supported_prot_mask |= prot_mask;
	} else {
		dbg_prn("MOP %hu protocol version mismatch",
			policy->instance_id);
		dbg_out_ret(__func__, error);
		return error;
	}

	dacl_ops = me_tbl_ops_get(context, policy,
		omci_me_multicast_operations_profile_dynamic_acl_table);

	if (!dacl_ops || !dacl_ops->get) {
		/* tbl_ops not yet registered — treat as empty DACL */
		memset(&sa, 0, sizeof(sa));
		src = mcc_src_create(&omci_wlist->src_list, false, NULL,
				     &sa, 0, NULL);
		RETURN_IF_MALLOC_ERROR(src);
		omci_wlist->vid = svid;
		dbg_prn("MOP %hu DACL ops unavailable, *ANY* match added",
			policy->instance_id);
		dbg_out_ret(__func__, error);
		return error;
	}

	error = dacl_ops->get(context, policy, &tmp,
			      sizeof(struct omci_acl_table), NULL);
	RETURN_IF_ERROR(error);
	dacl = tmp;

	wlist_id.field.class_id = policy->class->class_id;
	wlist_id.field.instance_id = policy->instance_id;

	if (omci_wlist->src_list.num == 0)
		DLIST_HEAD_INIT(&omci_wlist->src_list.head);

	omci_wlist->vid = 0;

	if (dacl) {
		while (dacl) {
			do {
				match = dacl_ipv4_match(
					(const struct omci_acl_table *)dacl,
					da, &sa);

				if (!match)
					break;

				/* Get VLAN of the first matched entry */
				if (!vid_found) {
					omci_wlist->vid =
					  ((const struct omci_acl_table *)
					   dacl)->vlan_id;
					vid_found = true;
				}

				src = mcc_src_create(&omci_wlist->src_list,
					false, NULL, &sa,
					((const struct omci_acl_table *)
					 dacl)->group_bandwidth,
					&wlist_id);
				RETURN_IF_MALLOC_ERROR(src);
				break;
			} while (0);

			if (match & MCC_OMCI_DACL_SA_MATCH)
				break;

			/* Get next DACL entry */
			error = dacl_ops->get(context, policy, &tmp,
					      sizeof(struct omci_acl_table),
					      dacl);
			RETURN_IF_ERROR(error);
			dacl = tmp;
		}
	} else {
		/* DACL table is empty, add *any* match entry */
		memset(&sa, 0, sizeof(sa));
		src = mcc_src_create(&omci_wlist->src_list, false, NULL,
				     &sa, 0, &wlist_id);
		RETURN_IF_MALLOC_ERROR(src);
		omci_wlist->vid = svid;
		dbg_prn("MOP %hu DACL empty, *ANY* match added",
			policy->instance_id);
	}

	dbg_out_ret(__func__, error);

	return error;
}

/** Read GMI (Group Membership Interval) from a MOP policy ME. */
static enum omci_error mcc_omci_policy_gmi_get(struct omci_context *context,
					       struct me *policy,
					       uint32_t *gmi_ms)
{
	enum omci_error error = OMCI_SUCCESS;
	uint8_t robustness;
	uint32_t query_interval, query_max_rsp_time;

	dbg_in(__func__, "%p, %p, %p", context, policy, gmi_ms);

	error = me_attr_read(context, policy,
		omci_me_multicast_operations_profile_robustness,
		&robustness, sizeof(robustness));
	RETURN_IF_ERROR(error);

	error = me_attr_read(context, policy,
		omci_me_multicast_operations_profile_query_interval,
		&query_interval, sizeof(query_interval));
	RETURN_IF_ERROR(error);

	error = me_attr_read(context, policy,
		omci_me_multicast_operations_profile_query_max_rsp_time,
		&query_max_rsp_time, sizeof(query_max_rsp_time));
	RETURN_IF_ERROR(error);

	if (robustness == 0 || query_interval == 0 || query_max_rsp_time == 0)
		*gmi_ms = 0;
	else
		*gmi_ms = (query_interval * robustness) * 1000 +
			  query_max_rsp_time * 100;

	dbg_out_ret(__func__, error);

	return error;
}

enum omci_error mcc_omci_flw_gmi_get(struct omci_context *context,
				     const struct mcc_flw *flw,
				     uint32_t *gmi_ms)
{
	enum omci_error error = OMCI_SUCCESS;
	struct me *port = NULL, *policy = NULL;
	uint16_t policy_meid;

	dbg_in(__func__, "%p, %p, %p", context, flw, gmi_ms);

	*gmi_ms = 0;

	/* v4.5.0 ME 310 has no service package table, so we always use
	   the direct mc_ops_profile_ptr path */
	error = mcc_omci_port_me_get(context, flw->port,
				     MCC_PROT_VERSION_NA, &port);
	if (error == OMCI_ERROR_ME_NOT_FOUND)
		return OMCI_SUCCESS;
	RETURN_IF_ERROR(error);

	error = me_attr_read(context, port,
		omci_me_multicast_subscriber_config_mc_ops_profile_ptr,
		&policy_meid, sizeof(policy_meid));
	RETURN_IF_ERROR(error);

	error = mib_me_find(context, OMCI_ME_MULTICAST_OPERATIONS_PROFILE,
			    policy_meid, &policy);
	RETURN_IF_ERROR(error);

	error = mcc_omci_policy_gmi_get(context, policy, gmi_ms);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, error);

	return error;
}

enum omci_error mcc_omci_flw_wlist_get(struct omci_context *context,
				       struct me *port,
				       const uint16_t cvid,
				       const uint16_t svid,
				       const enum mcc_prot_version version,
				       const union mcc_ip_addr *da,
				       struct mcc_omci_wlist *omci_wlist)
{
	enum omci_error error = OMCI_SUCCESS;
	struct me *policy = NULL;
	uint16_t policy_meid;

	dbg_in(__func__, "%p, %p, %hu, %hu, %d, %p, %p", context, port, cvid,
	       svid, version, da, omci_wlist);

	memset(omci_wlist, 0, sizeof(*omci_wlist));

	/* v4.5.0 ME 310 has no service package table, so we always use
	   the direct mc_ops_profile_ptr and IOP_0 version option */
	error = me_attr_read(context, port,
		omci_me_multicast_subscriber_config_mc_ops_profile_ptr,
		&policy_meid, sizeof(policy_meid));
	RETURN_IF_ERROR(error);

	error = mib_me_find(context, OMCI_ME_MULTICAST_OPERATIONS_PROFILE,
			    policy_meid, &policy);
	RETURN_IF_ERROR(error);

	error = mcc_omci_policy_wlist_get(context, policy,
				svid, version,
				MCC_OMCI_PROT_VERSION_OPTION_IOP_0,
				da, omci_wlist);
	RETURN_IF_ERROR(error);

	/* Clean up: if *any src* entry exists - remove everything except it,
	   remove any duplicate source entries */
	mcc_src_list_clean(&omci_wlist->src_list);

	dbg_out_ret(__func__, error);

	return error;
}

enum omci_error mcc_omci_rl_get(struct omci_context *context,
				const uint8_t port_idx,
				const uint16_t cvid,
				struct mcc_omci_rl *rl)
{
	enum omci_error error = OMCI_SUCCESS;
	struct me *port = NULL, *policy = NULL;
	uint16_t policy_meid;

	dbg_in(__func__, "%p, %hhu, %hu, %p", context, port_idx, cvid, rl);

	rl->type = MCC_RL_TYPE_NA;
	rl->rate = 0;

	error = mcc_omci_port_me_get(context, port_idx,
				     MCC_PROT_VERSION_NA, &port);
	if (error == OMCI_ERROR_ME_NOT_FOUND) {
		/* No rate limiter */
		error = OMCI_SUCCESS;
		dbg_out_ret(__func__, error);
		return error;
	}
	RETURN_IF_ERROR(error);

	/* v4.5.0 ME 310 has no service package table — use direct MOP ptr */
	error = me_attr_read(context, port,
		omci_me_multicast_subscriber_config_mc_ops_profile_ptr,
		&policy_meid, sizeof(policy_meid));
	RETURN_IF_ERROR(error);

	error = mib_me_find(context, OMCI_ME_MULTICAST_OPERATIONS_PROFILE,
			    policy_meid, &policy);
	RETURN_IF_ERROR(error);

	error = me_attr_read(context, policy,
		omci_me_multicast_operations_profile_us_igmp_rate,
		&rl->rate, sizeof(rl->rate));
	RETURN_IF_ERROR(error);

	rl->type = MCC_RL_TYPE_PORT;

	dbg_out_ret(__func__, error);

	return error;
}

enum omci_error mcc_omci_grp_lost_alarm_set(struct omci_context *context,
					    const struct mcc_grp_entry *grp)
{
	/* Lost group alarm requires MOP alarm support (alarm bit 0).
	   v4.5.0 MOP ME handler does not register HAS_ALARMS — this will
	   be enabled in Step 7 when the ME handlers are updated. */
	(void)context;
	(void)grp;
	return OMCI_SUCCESS;
}

enum omci_error
mcc_omci_mc_bridge_info_get(struct omci_context *context,
			    const uint8_t port_idx,
			    struct mcc_omci_mc_bridge_info *info)
{
	enum omci_error error = OMCI_SUCCESS;
	struct me_walker_1_data walker_1_data;

	dbg_in(__func__, "%p, %hhu, %p", context, port_idx, info);

	memset(&walker_1_data, 0, sizeof(walker_1_data));
	walker_1_data.lan_port_index = port_idx;

	error = mib_walk_by_class(context,
				  OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
				  me_walker_1, &walker_1_data);
	if (error) {
		dbg_err("class %d walk failed for LAN %hhu",
			OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA, port_idx);
		return error;
	}

	if (walker_1_data.pair_cnt == 0) {
		error = OMCI_ERROR_ME_NOT_FOUND;
		RETURN_IF_ERROR(error);
	}

	info->br_id = walker_1_data.pair.br_id;
	info->bp_id = walker_1_data.pair.bp_id;

	dbg_out_ret(__func__, error);

	return error;
}

/** Match a group address against the MC address table on a MC GEM IWTP.
    v4.5.0 has a single (IPv4) mc_address_table on ME 281. */
static enum omci_error
mcc_omci_mc_ipv4_table_match(struct omci_context *context,
			     struct me *mc_gem_iwtp,
			     const uint16_t gem_port_id,
			     const uint8_t ga[4])
{
	enum omci_error error = OMCI_SUCCESS, ret = OMCI_SUCCESS;
	const struct tbl_ops *ops;
	struct omci_me_mc_address_table *entry;
	void *tmp;

	dbg_in(__func__, "%p, %p, %hu, %p", context, mc_gem_iwtp,
	       gem_port_id, ga);

	ops = me_tbl_ops_get(context, mc_gem_iwtp,
			     omci_me_multicast_gem_interworking_tp_mc_address_table);

	if (!ops || !ops->get) {
		/* tbl_ops not yet registered — cannot match */
		dbg_prn("ME %hu no MC table ops", mc_gem_iwtp->instance_id);
		dbg_out_ret(__func__, OMCI_ERROR);
		return OMCI_ERROR;
	}

	me_lock(context, mc_gem_iwtp);

	error = ops->get(context, mc_gem_iwtp, &tmp, sizeof(*entry), NULL);
	if (error) {
		me_unlock(context, mc_gem_iwtp);
		RETURN_IF_ERROR(error);
	}

	entry = tmp;

	if (entry) {
		ret = OMCI_ERROR; /* no match yet */
		while (entry) {
			if ((entry->gem_port_id != gem_port_id) ||
			    (memcmp(&entry->ip_mc_address_range_start,
				    ga, 4) > 0 ||
			     memcmp(ga,
				    &entry->ip_mc_address_range_stop,
				    4) > 0)) {
				/* Get next entry */
				error = ops->get(context, mc_gem_iwtp, &tmp,
						 sizeof(*entry), entry);
				if (error)
					break;
				entry = tmp;
			} else {
				ret = OMCI_SUCCESS;
				dbg_prn("ME %hu MC match for GEM %hu",
					mc_gem_iwtp->instance_id,
					gem_port_id);
				break;
			}
		}
	} else {
		dbg_prn("ME %hu no MC table entries",
			mc_gem_iwtp->instance_id);
		error = OMCI_ERROR;
	}

	me_unlock(context, mc_gem_iwtp);

	error = error != OMCI_SUCCESS ? error : ret;
	dbg_out_ret(__func__, error);

	return error;
}

enum omci_error
mcc_omci_mc_addr_table_match(struct omci_context *context,
			     const uint8_t port_idx,
			     const enum mcc_prot_version prot_version,
			     const union mcc_ip_addr *ga)
{
	enum omci_error error = OMCI_SUCCESS;
	struct mcc_omci_mc_bridge_info mc_bridge_info;
	uint8_t bp_cnt;
	uint16_t bridge_id, bp_tp_pointer, gem_port_id, gem_ctp_pointer;
	struct walker3_data sd;
	struct me *mc_gem_iwtp, *gem_ctp;

	dbg_in(__func__, "%p, %hhu, %p", context, port_idx, ga);

	/* Get MC forwarding bridge ID */
	error = mcc_omci_mc_bridge_info_get(context, port_idx, &mc_bridge_info);
	RETURN_IF_ERROR(error);

	bridge_id = mc_bridge_info.br_id;

	dbg_prn("MC Bridge me_id=0x%04X", bridge_id);

	sd.bp_cnt = 0;
	sd.bridge_id = bridge_id;

	/* Find all MC GEM bridge ports within the specified bridge */
	error = mib_walk_by_class(context,
				  OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
				  me_walker_3, &sd);
	RETURN_IF_ERROR(error);

	bp_cnt = sd.bp_cnt;
	/* Go through all found MC GEM bridge ports */
	while (bp_cnt--) {
		/* Get MC GEM bridge port TP pointer */
		me_lock(context, sd.bp_me[bp_cnt]);
		error = me_attr_read(context, sd.bp_me[bp_cnt],
				     omci_me_mac_bridge_port_config_data_tp_ptr,
				     &bp_tp_pointer, sizeof(bp_tp_pointer));
		me_unlock(context, sd.bp_me[bp_cnt]);
		RETURN_IF_ERROR(error);

		/* Find MC GEM IWTP pointed by the MC bridge port */
		error = mib_me_find(context,
				    OMCI_ME_MULTICAST_GEM_INTERWORKING_TP,
				    bp_tp_pointer, &mc_gem_iwtp);
		RETURN_IF_ERROR(error);

		/* Get GEM port network CTP connectivity pointer */
		me_lock(context, mc_gem_iwtp);
		error = me_attr_read(context, mc_gem_iwtp,
			omci_me_multicast_gem_interworking_tp_gem_port_network_ctp_ptr,
			&gem_ctp_pointer, sizeof(gem_ctp_pointer));
		me_unlock(context, mc_gem_iwtp);
		RETURN_IF_ERROR(error);

		/* Get GEM port network CTP ME */
		error = mib_me_find(context, OMCI_ME_GEM_PORT_NETWORK_CTP,
				    gem_ctp_pointer, &gem_ctp);
		RETURN_IF_ERROR(error);

		/* Read GEM Port-ID */
		me_lock(context, gem_ctp);
		error = me_attr_read(context, gem_ctp,
				     omci_me_gem_port_network_ctp_gem_port_id,
				     &gem_port_id, sizeof(gem_port_id));
		me_unlock(context, gem_ctp);
		RETURN_IF_ERROR(error);

		/* v4.5.0 only has IPv4 MC address table */
		error = mcc_omci_mc_ipv4_table_match(context,
						     mc_gem_iwtp,
						     gem_port_id,
						     ga->ipv4);
		if (error == OMCI_SUCCESS)
			break;  /* Match found */

		/* No match in this MC GEM IWTP, try next */
		if (error != OMCI_ERROR)
			RETURN_IF_ERROR(error);
	}

	dbg_out_ret(__func__, error);

	return error;
}

void mcc_omci_lock(struct omci_context *context)
{
	bool lock = true;

	dbg_in(__func__, "%p", context);

	mib_lock_read(context);

	(void)mib_walk_by_class(context,
				OMCI_ME_MULTICAST_SUBSCRIBER_CONFIG_INFO,
				me_walker_2, &lock);

	(void)mib_walk_by_class(context,
				OMCI_ME_MULTICAST_OPERATIONS_PROFILE,
				me_walker_2, &lock);

	dbg_out(__func__);
}

void mcc_omci_unlock(struct omci_context *context)
{
	bool lock = false;

	dbg_in(__func__, "%p", context);

	(void)mib_walk_by_class(context,
				OMCI_ME_MULTICAST_OPERATIONS_PROFILE,
				me_walker_2, &lock);

	(void)mib_walk_by_class(context,
				OMCI_ME_MULTICAST_SUBSCRIBER_CONFIG_INFO,
				me_walker_2, &lock);

	mib_unlock(context);

	dbg_out(__func__);
}

#endif /* INCLUDE_MCC */
