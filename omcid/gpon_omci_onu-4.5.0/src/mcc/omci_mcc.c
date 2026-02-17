/******************************************************************************
 * Copyright (c) 2017 - 2019 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * MCC entry points: init, exit, monitor data, VLAN mode, flow control.
 * Adapted from gpon_omci_onu-8.6.3 for Falcon GPE.
 *
 * AGL (Active Group List) and LGL (Lost Group List) traversal ported from
 * v8.6.3, using our mcc_list infrastructure and DLIST macros for headless
 * chain iteration. Per-port locking on all flow/monitor operations.
 ******************************************************************************/
#include <unistd.h>

#define OMCI_DBG_MODULE OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_api.h"
#include "mcc/omci_mcc_core.h"
#include "mcc/omci_mcc_omci.h"
#include "mcc/omci_mcc_pkt.h"
#include "me/omci_ipv6_host_config_data.h"

/* ---- AGL (Active Group List) helpers ----------------------------------- */

static void ipv4_agl_entry_set(struct omci_ipv4_agl_table *entry,
			       const uint16_t vid,
			       const union mcc_ip_addr *da,
			       const union mcc_ip_addr *sa,
			       const union mcc_ip_addr *ca,
			       const uint32_t best_eff_act_bw_est,
			       const uint32_t time_since_join)
{
	entry->vlan_id = vid;

	if (da)
		memcpy(&entry->mc_dest_ip, da->ipv4, 4);
	else
		memset(&entry->mc_dest_ip, 0, 4);

	if (sa)
		memcpy(&entry->source_ip, sa->ipv4, 4);
	else
		memset(&entry->source_ip, 0, 4);

	if (ca)
		memcpy(&entry->client_ip, ca->ipv4, 4);
	else
		memset(&entry->client_ip, 0, 4);

	entry->best_eff_act_bw_est = best_eff_act_bw_est;
	entry->time_since_join = time_since_join;
}

static void ipv6_agl_entry_set(struct omci_ipv6_agl_table *entry,
			       const uint16_t vid,
			       const union mcc_ip_addr *da,
			       const union mcc_ip_addr *sa,
			       const union mcc_ip_addr *ca,
			       const uint32_t best_eff_act_bw_est,
			       const uint32_t time_since_join)
{
	entry->vlan_id = vid;

	if (da)
		memcpy(entry->mc_dest_ip, da->ipv6, OMCI_IPV6_ADDR_LEN);
	else
		memset(entry->mc_dest_ip, 0, OMCI_IPV6_ADDR_LEN);

	if (sa)
		memcpy(entry->source_ip, sa->ipv6, OMCI_IPV6_ADDR_LEN);
	else
		memset(entry->source_ip, 0, OMCI_IPV6_ADDR_LEN);

	if (ca)
		memcpy(entry->client_ip, ca->ipv6, OMCI_IPV6_ADDR_LEN);
	else
		memset(entry->client_ip, 0, OMCI_IPV6_ADDR_LEN);

	entry->best_eff_act_bw_est = best_eff_act_bw_est;
	entry->time_since_join = time_since_join;
}

/** Build AGL from active (non-lost) group entries on a port.
 *
 *  Two-pass pattern: call with agl=NULL to get count in *agl_num,
 *  then allocate and call again to fill the buffer.
 *
 *  The clt_le chain is a headless circular doubly-linked list threading
 *  through mcc_src_entry nodes joined from different clients for the same
 *  (group, source).  We temporarily insert a sentinel to iterate it using
 *  DLIST macros from omci_list.h.
 */
static enum omci_error mcc_port_agl_get(const struct mcc_port *port,
					const uint32_t agl_entry_size,
					void *agl,
					uint32_t *agl_num)
{
	struct mcc_flw_entry *flw;
	struct mcc_grp_entry *grp;
	struct mcc_src_entry *src, *clt_src;
	struct mcc_list_head *flw_le, *flw_nle, *grp_le, *grp_nle,
			     *src_le, *src_nle, clt_le_head,
			     *clt_le, *clt_nle;
	struct omci_ipv4_agl_table *ipv4_agl = agl;
	struct omci_ipv6_agl_table *ipv6_agl = agl;
	uint32_t max = 0;
	bool ipv6;

	if (agl_entry_size == sizeof(struct omci_ipv4_agl_table))
		ipv6 = false;
	else if (agl_entry_size == sizeof(struct omci_ipv6_agl_table))
		ipv6 = true;
	else
		return OMCI_ERROR_BOUNDS;

	DLIST_HEAD_INIT(&clt_le_head);

	MCC_LIST_FOR_EACH_SAFE(flw_le, flw_nle, &port->flw_list) {
		flw = LE2FLW(flw_le);

		MCC_LIST_FOR_EACH_SAFE(grp_le, grp_nle, &flw->grp_list) {
			grp = LE2GRP(grp_le);
			if (grp->lost)
				continue;

			if (mcc_is_ipv6(&grp->da) != ipv6)
				continue;

			MCC_LIST_FOR_EACH_SAFE(src_le, src_nle,
					       &grp->src_link_list) {
				src = GRP_LE2SRC(src_le);

				/* Insert temp sentinel into headless clt_le
				   chain to iterate client sources */
				DLIST_ADD_TAIL(&clt_le_head, &src->clt_le);

				for (clt_le = clt_le_head.next,
				     clt_nle = clt_le->next;
				     clt_le != &clt_le_head;
				     clt_le = clt_nle,
				     clt_nle = clt_le->next) {
					if (agl == NULL) {
						max += 1;
						continue;
					}

					clt_src = CLT_LE2SRC(clt_le);

					if (ipv6) {
						ipv6_agl_entry_set(
							ipv6_agl,
							flw->flw.svid,
							&grp->da,
							grp->fmode ==
							  MCC_FLT_MODE_EXCLUDE ?
							  NULL : &src->sa,
							clt_src->clt ?
							  &clt_src->clt->ca :
							  NULL,
							clt_src->ibw, 0);
					} else {
						ipv4_agl_entry_set(
							ipv4_agl,
							flw->flw.svid,
							&grp->da,
							grp->fmode ==
							  MCC_FLT_MODE_EXCLUDE ?
							  NULL : &src->sa,
							clt_src->clt ?
							  &clt_src->clt->ca :
							  NULL,
							clt_src->ibw, 0);
					}

					if (max < *agl_num) {
						ipv4_agl++;
						ipv6_agl++;
						max += 1;
					}
				}

				/* Remove temp sentinel */
				DLIST_REMOVE(&clt_le_head);

				if (grp->fmode == MCC_FLT_MODE_EXCLUDE)
					break;
			}
		}
	}

	if (agl == NULL)
		*agl_num = max;

	return OMCI_SUCCESS;
}

/** Wrapper: count AGL entries, allocate, fill.  Caller holds port lock. */
static enum omci_error mcc_port_monitor_agl_get(struct omci_context *context,
						const uint16_t meid,
						const uint32_t agl_entry_size,
						void **agl,
						uint32_t *agl_num)
{
	struct mcc_ctx *mcc;

	if (!context || !context->mcc || !agl || !agl_num)
		return OMCI_ERROR;

	mcc = (struct mcc_ctx *)context->mcc;
	uint32_t str_max;
	uint8_t port_idx;
	enum omci_error error;

	error = mcc_omci_port_idx_get(context, meid, &port_idx);
	RETURN_IF_ERROR(error);

	RETURN_IF_BOUNDS_ERROR(port_idx, mcc->max_ports - 1);

	IFXOS_LockGet(&mcc->port[port_idx].lock);

	/* First pass: count */
	error = mcc_port_agl_get(&mcc->port[port_idx], agl_entry_size,
				 NULL, &str_max);
	if (error != OMCI_SUCCESS)
		goto on_exit;

	if (str_max == 0) {
		*agl_num = 0;
		*agl = NULL;
		goto on_exit;
	}

	*agl = IFXOS_MemAlloc(str_max * agl_entry_size);
	if (*agl == NULL) {
		error = OMCI_ERROR_MEMORY;
		goto on_exit;
	}
	*agl_num = str_max;

	/* Second pass: fill */
	error = mcc_port_agl_get(&mcc->port[port_idx], agl_entry_size,
				 *agl, &str_max);
on_exit:
	IFXOS_LockRelease(&mcc->port[port_idx].lock);

	return error;
}

/* ---- LGL (Lost Group List) helper -------------------------------------- */

/** Build LGL from lost group entries across all ports for a given wlist_id.
 *  Two-pass: call with lgl=NULL to get count, then fill. */
static enum omci_error
mcc_policy_wlist_lgl_get(struct omci_context *context,
			 const union mcc_wlist_id *wlist_id,
			 struct mcc_lost_group *lgl,
			 uint32_t *lgl_num)
{
	struct mcc_ctx *mcc = (struct mcc_ctx *)context->mcc;
	uint8_t p, any;
	struct mcc_port *port;
	struct mcc_flw_entry *flw;
	struct mcc_grp_entry *grp;
	struct mcc_src_entry *src;
	struct mcc_list_head *f_le, *f_nle, *g_le, *g_nle, *s_le, *s_nle;
	uint32_t max = 0;
	bool ipv6;

	for (p = 0; p < mcc->max_ports; p++) {
		port = &mcc->port[p];

		MCC_LIST_FOR_EACH_SAFE(f_le, f_nle, &port->flw_list) {
			flw = LE2FLW(f_le);

			MCC_LIST_FOR_EACH_SAFE(g_le, g_nle,
					       &flw->grp_list) {
				grp = LE2GRP(g_le);
				any = 0;
				ipv6 = mcc_is_ipv6(&grp->da);

				MCC_LIST_FOR_EACH_SAFE(s_le, s_nle,
						&grp->src_link_list) {
					src = GRP_LE2SRC(s_le);

					if (memcmp(&src->wlist_id, wlist_id,
						   sizeof(*wlist_id)))
						continue;

					if (!grp->lost)
						continue;

					max += 1;

					if (grp->fmode ==
					    MCC_FLT_MODE_EXCLUDE)
						any = 1;

					if (lgl == NULL && any)
						break;

					if (lgl == NULL)
						continue;

					lgl->vlan_id = flw->flw.svid;

					if (ipv6)
						memcpy(lgl->dest_ip,
						       grp->da.ipv6,
						       OMCI_IPV6_ADDR_LEN);
					else
						memcpy(&lgl->dest_ip[12],
						       grp->da.ipv4, 4);

					if (any)
						memset(lgl->src_ip, 0, 4);
					else
						memcpy(lgl->src_ip,
						       ipv6 ?
						       &src->sa.ipv6[12] :
						       src->sa.ipv4, 4);

					if (max < *lgl_num)
						lgl++;
				}
			}
		}
	}

	if (lgl == NULL)
		*lgl_num = max;

	return OMCI_SUCCESS;
}

/* ---- Public entry points ----------------------------------------------- */

enum omci_error omci_mcc_init(struct omci_context *context)
{
	struct mcc_ctx *mcc;
	enum omci_error error;
	uint32_t max_ports = 0;
	uint32_t i;

	dbg_prn("MCC: init");

	mcc = IFXOS_MemAlloc(sizeof(*mcc));
	if (!mcc)
		return OMCI_ERROR_MEMORY;

	memset(mcc, 0, sizeof(*mcc));
	mcc->ctx_core = context;
	mcc->vlan_mode = MCC_VLAN_MODE_UNAWARE;

	/* Initialize device layer with shared /dev/onu0 fd */
	write(STDERR_FILENO, "[omcid] MCC: mcc_dev_init...\n", 29);
	error = mcc_dev_init(&mcc->dev,
			     omci_api_onu_fd_get(context->api),
			     omci_api_remote_get(context->api),
			     &max_ports);
	if (error != OMCI_SUCCESS) {
		dbg_err("MCC: dev init failed (%d)", error);
		IFXOS_MemFree(mcc);
		return error;
	}
	write(STDERR_FILENO, "[omcid] MCC: mcc_dev_init ok\n", 29);

	if (max_ports == 0)
		max_ports = 4; /* Falcon default: 4 UNI ports */

	mcc->max_ports = max_ports;

	/* Allocate per-port structures */
	mcc->port = IFXOS_MemAlloc(max_ports * sizeof(struct mcc_port));
	if (!mcc->port) {
		mcc_dev_shutdown(&mcc->dev);
		IFXOS_MemFree(mcc);
		return OMCI_ERROR_MEMORY;
	}

	memset(mcc->port, 0, max_ports * sizeof(struct mcc_port));

	for (i = 0; i < max_ports; i++) {
		IFXOS_LockInit(&mcc->port[i].lock);
		mcc_list_init(&mcc->port[i].flw_list);
		mcc->port[i].rl.type = MCC_RL_TYPE_NA;
		mcc_list_init(&mcc->port[i].rl.rl_list);
	}

	/* Initialize record source list */
	mcc_list_init(&mcc->rec.src_list);

	/* Store in context */
	context->mcc = mcc;

	/* Start packet receiving thread */
	write(STDERR_FILENO, "[omcid] MCC: mcc_thread_start...\n", 33);
	error = mcc_thread_start(mcc);
	if (error != OMCI_SUCCESS) {
		dbg_err("MCC: thread start failed (%d)", error);
		/* Non-fatal: MCC init succeeds but packet processing won't
		   work until thread starts. Continue anyway so that OMCI
		   provisioning can proceed. */
	}

	dbg_prn("MCC: init done, max_ports=%u", max_ports);

	return OMCI_SUCCESS;
}

enum omci_error omci_mcc_exit(struct omci_context *context)
{
	struct mcc_ctx *mcc;
	uint32_t i;

	if (!context || !context->mcc)
		return OMCI_SUCCESS;

	mcc = (struct mcc_ctx *)context->mcc;

	dbg_prn("MCC: exit");

	/* Stop packet thread */
	mcc_thread_stop(mcc);

	/* Clean up per-port data */
	if (mcc->port) {
		for (i = 0; i < mcc->max_ports; i++) {
			mcc_flw_cleanup(mcc, &mcc->port[i].flw_list);
			mcc_rl_delete(&mcc->port[i].rl);
			IFXOS_LockDelete(&mcc->port[i].lock);
		}
		IFXOS_MemFree(mcc->port);
	}

	/* Clean up record source list */
	mcc_src_list_clean(&mcc->rec.src_list);

	/* Shutdown device layer */
	mcc_dev_shutdown(&mcc->dev);

	IFXOS_MemFree(mcc);
	context->mcc = NULL;

	return OMCI_SUCCESS;
}

enum omci_error mcc_vlan_mode_set(struct omci_context *context,
				  const enum mcc_vlan_mode vlan_mode)
{
	struct mcc_ctx *mcc;
	enum omci_error error;

	if (!context || !context->mcc)
		return OMCI_ERROR;

	mcc = (struct mcc_ctx *)context->mcc;

	switch (vlan_mode) {
	case MCC_VLAN_MODE_UNAWARE:
	case MCC_VLAN_MODE_AWARE:
		error = mcc_dev_vlan_unaware_mode_enable(&mcc->dev,
			vlan_mode == MCC_VLAN_MODE_UNAWARE);
		break;
	default:
		return OMCI_ERROR_BOUNDS;
	}

	if (error == OMCI_SUCCESS)
		mcc->vlan_mode = vlan_mode;

	return error;
}

enum omci_error mcc_port_reset(struct omci_context *context,
			       const uint16_t meid)
{
	struct mcc_ctx *mcc;
	uint8_t port_idx;
	enum omci_error error;

	if (!context || !context->mcc)
		return OMCI_ERROR;

	mcc = (struct mcc_ctx *)context->mcc;

	error = mcc_omci_port_idx_get(context, meid, &port_idx);
	RETURN_IF_ERROR(error);

	RETURN_IF_BOUNDS_ERROR(port_idx, mcc->max_ports - 1);

	IFXOS_LockGet(&mcc->port[port_idx].lock);

	/* Cleanup all flow entries */
	mcc_flw_cleanup(mcc, &mcc->port[port_idx].flw_list);

	/* Delete rate limiter */
	mcc_rl_delete(&mcc->port[port_idx].rl);

	/* Reset statistics */
	mcc->port[port_idx].join_msg_cnt = 0;
	mcc->port[port_idx].exce_msg_cnt = 0;

	IFXOS_LockRelease(&mcc->port[port_idx].lock);

	return OMCI_SUCCESS;
}

enum omci_error mcc_port_monitor_data_get(struct omci_context *context,
					  const uint16_t meid,
					  const enum mcc_monitor_type type,
					  uint32_t *value)
{
	struct mcc_ctx *mcc;
	uint32_t val;
	uint8_t port_idx;
	enum omci_error error;

	if (!context || !context->mcc || !value)
		return OMCI_ERROR;

	mcc = (struct mcc_ctx *)context->mcc;

	error = mcc_omci_port_idx_get(context, meid, &port_idx);
	RETURN_IF_ERROR(error);

	RETURN_IF_BOUNDS_ERROR(port_idx, mcc->max_ports - 1);

	error = OMCI_SUCCESS;

	IFXOS_LockGet(&mcc->port[port_idx].lock);
	switch (type) {
	case MCC_MONITOR_TYPE_CURRENT_MC_BANDWIDTH:
		val = mcc_port_ibw_max_get(&mcc->port[port_idx]);
		break;
	case MCC_MONITOR_TYPE_JOIN_MSG_COUNTER:
		val = mcc->port[port_idx].join_msg_cnt;
		break;
	case MCC_MONITOR_TYPE_BW_EXCESS_COUNTER:
		val = mcc->port[port_idx].exce_msg_cnt;
		break;
	default:
		error = OMCI_ERROR_INVALID_VAL;
		break;
	}
	IFXOS_LockRelease(&mcc->port[port_idx].lock);

	if (error == OMCI_SUCCESS)
		*value = val;

	return error;
}

enum omci_error mcc_port_monitor_ipv4_agl_get(struct omci_context *context,
					      const uint16_t meid,
					      struct omci_ipv4_agl_table **agl,
					      uint32_t *agl_num)
{
	return mcc_port_monitor_agl_get(context, meid,
					sizeof(struct omci_ipv4_agl_table),
					(void **)agl, agl_num);
}

enum omci_error mcc_port_monitor_ipv6_agl_get(struct omci_context *context,
					      const uint16_t meid,
					      struct omci_ipv6_agl_table **agl,
					      uint32_t *agl_num)
{
	return mcc_port_monitor_agl_get(context, meid,
					sizeof(struct omci_ipv6_agl_table),
					(void **)agl, agl_num);
}

enum omci_error mcc_policy_lgl_get(struct omci_context *context,
				   const uint16_t meid,
				   struct mcc_lost_group **lgl,
				   uint32_t *lgl_num)
{
	struct mcc_ctx *mcc;
	union mcc_wlist_id wlist_id;
	uint32_t str_max;
	uint8_t p;
	enum omci_error error;

	if (!context || !context->mcc || !lgl || !lgl_num)
		return OMCI_ERROR;

	mcc = (struct mcc_ctx *)context->mcc;

	error = mcc_omci_policy_wlist_id_get(context, meid, &wlist_id);
	RETURN_IF_ERROR(error);

	/* Lock all ports — LGL spans all ports for a given wlist_id */
	p = 0;
	while (p < mcc->max_ports)
		IFXOS_LockGet(&mcc->port[p++].lock);

	/* First pass: count */
	error = mcc_policy_wlist_lgl_get(context, &wlist_id, NULL, &str_max);
	if (error != OMCI_SUCCESS)
		goto on_exit;

	if (str_max == 0) {
		*lgl_num = 0;
		*lgl = NULL;
		goto on_exit;
	}

	*lgl = IFXOS_MemAlloc(str_max * sizeof(struct mcc_lost_group));
	if (*lgl == NULL) {
		error = OMCI_ERROR_MEMORY;
		goto on_exit;
	}
	*lgl_num = str_max;

	/* Second pass: fill */
	error = mcc_policy_wlist_lgl_get(context, &wlist_id, *lgl, &str_max);
on_exit:
	/* Unlock all ports in reverse order */
	p = mcc->max_ports;
	while (p)
		IFXOS_LockRelease(&mcc->port[--p].lock);

	return error;
}

/* ---- Static/Dynamic flow operations ------------------------------------ */

enum omci_error mcc_port_static_flow_create(struct omci_context *context,
					    const uint16_t meid,
					    const struct mcc_mc_flow *flow)
{
	struct mcc_ctx *mcc;
	uint8_t port_idx;
	enum omci_error error;

	if (!context || !context->mcc || !flow)
		return OMCI_ERROR;

	mcc = (struct mcc_ctx *)context->mcc;
	error = mcc_omci_port_idx_get(context, meid, &port_idx);
	RETURN_IF_ERROR(error);

	RETURN_IF_BOUNDS_ERROR(port_idx, mcc->max_ports - 1);

	IFXOS_LockGet(&mcc->port[port_idx].lock);
	error = mcc_port_mc_flow_control(mcc, port_idx, true, true, flow);
	IFXOS_LockRelease(&mcc->port[port_idx].lock);

	return error;
}

enum omci_error mcc_port_static_flow_delete(struct omci_context *context,
					    const uint16_t meid,
					    const struct mcc_mc_flow *flow)
{
	struct mcc_ctx *mcc;
	uint8_t port_idx;
	enum omci_error error;

	if (!context || !context->mcc || !flow)
		return OMCI_ERROR;

	mcc = (struct mcc_ctx *)context->mcc;
	error = mcc_omci_port_idx_get(context, meid, &port_idx);
	RETURN_IF_ERROR(error);

	RETURN_IF_BOUNDS_ERROR(port_idx, mcc->max_ports - 1);

	IFXOS_LockGet(&mcc->port[port_idx].lock);
	error = mcc_port_mc_flow_control(mcc, port_idx, false, true, flow);
	IFXOS_LockRelease(&mcc->port[port_idx].lock);

	return error;
}

enum omci_error
mcc_port_static_flow_range_delete(struct omci_context *context,
				  const uint16_t meid,
				  const struct mcc_mc_flow_range *flow)
{
	struct mcc_ctx *mcc;
	uint8_t port_idx;
	enum omci_error error;

	if (!context || !context->mcc || !flow)
		return OMCI_ERROR;

	mcc = (struct mcc_ctx *)context->mcc;
	error = mcc_omci_port_idx_get(context, meid, &port_idx);
	RETURN_IF_ERROR(error);

	RETURN_IF_BOUNDS_ERROR(port_idx, mcc->max_ports - 1);

	IFXOS_LockGet(&mcc->port[port_idx].lock);
	error = mcc_port_mc_flow_range_delete(mcc, port_idx, true, flow);
	IFXOS_LockRelease(&mcc->port[port_idx].lock);

	return error;
}

enum omci_error mcc_port_dynamic_flow_create(struct omci_context *context,
					     const uint16_t meid,
					     const struct mcc_mc_flow *flow)
{
	struct mcc_ctx *mcc;
	uint8_t port_idx;
	enum omci_error error;

	if (!context || !context->mcc || !flow)
		return OMCI_ERROR;

	mcc = (struct mcc_ctx *)context->mcc;
	error = mcc_omci_port_idx_get(context, meid, &port_idx);
	RETURN_IF_ERROR(error);

	RETURN_IF_BOUNDS_ERROR(port_idx, mcc->max_ports - 1);

	IFXOS_LockGet(&mcc->port[port_idx].lock);
	error = mcc_port_mc_flow_control(mcc, port_idx, true, false, flow);
	IFXOS_LockRelease(&mcc->port[port_idx].lock);

	return error;
}

enum omci_error mcc_port_dynamic_flow_delete(struct omci_context *context,
					     const uint16_t meid,
					     const struct mcc_mc_flow *flow)
{
	struct mcc_ctx *mcc;
	uint8_t port_idx;
	enum omci_error error;

	if (!context || !context->mcc || !flow)
		return OMCI_ERROR;

	mcc = (struct mcc_ctx *)context->mcc;
	error = mcc_omci_port_idx_get(context, meid, &port_idx);
	RETURN_IF_ERROR(error);

	RETURN_IF_BOUNDS_ERROR(port_idx, mcc->max_ports - 1);

	IFXOS_LockGet(&mcc->port[port_idx].lock);
	error = mcc_port_mc_flow_control(mcc, port_idx, false, false, flow);
	IFXOS_LockRelease(&mcc->port[port_idx].lock);

	return error;
}

enum omci_error
mcc_port_dynamic_flow_range_delete(struct omci_context *context,
				   const uint16_t meid,
				   const struct mcc_mc_flow_range *flow)
{
	struct mcc_ctx *mcc;
	uint8_t port_idx;
	enum omci_error error;

	if (!context || !context->mcc || !flow)
		return OMCI_ERROR;

	mcc = (struct mcc_ctx *)context->mcc;
	error = mcc_omci_port_idx_get(context, meid, &port_idx);
	RETURN_IF_ERROR(error);

	RETURN_IF_BOUNDS_ERROR(port_idx, mcc->max_ports - 1);

	IFXOS_LockGet(&mcc->port[port_idx].lock);
	error = mcc_port_mc_flow_range_delete(mcc, port_idx, false, flow);
	IFXOS_LockRelease(&mcc->port[port_idx].lock);

	return error;
}
