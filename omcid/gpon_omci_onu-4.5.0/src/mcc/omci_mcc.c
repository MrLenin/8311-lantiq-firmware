/******************************************************************************
 * Copyright (c) 2017 - 2019 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * MCC entry points: init, exit, monitor data, VLAN mode, flow control.
 * Adapted from gpon_omci_onu-8.6.3 for Falcon GPE.
 *
 * STUB: Compiles and links. Full implementation in Phase 7 Step 6.
 ******************************************************************************/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_api.h"
#include "mcc/omci_mcc_core.h"
#include "mcc/omci_mcc_omci.h"
#include "mcc/omci_mcc_pkt.h"

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
	error = mcc_dev_init(&mcc->dev,
			     omci_api_onu_fd_get(context->api),
			     omci_api_remote_get(context->api),
			     &max_ports);
	if (error != OMCI_SUCCESS) {
		dbg_err("MCC: dev init failed (%d)", error);
		IFXOS_MemFree(mcc);
		return error;
	}

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

	if (!context || !context->mcc)
		return OMCI_ERROR;

	mcc = (struct mcc_ctx *)context->mcc;
	mcc->vlan_mode = vlan_mode;

	return mcc_dev_vlan_unaware_mode_enable(&mcc->dev,
		vlan_mode == MCC_VLAN_MODE_UNAWARE);
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
	if (error != OMCI_SUCCESS)
		return error;

	if (port_idx >= mcc->max_ports)
		return OMCI_ERROR;

	return mcc_group_list_clear(mcc, port_idx);
}

enum omci_error mcc_port_monitor_data_get(struct omci_context *context,
					  const uint16_t meid,
					  const enum mcc_monitor_type type,
					  uint32_t *value)
{
	struct mcc_ctx *mcc;
	uint8_t port_idx;
	enum omci_error error;

	if (!context || !context->mcc || !value)
		return OMCI_ERROR;

	mcc = (struct mcc_ctx *)context->mcc;

	error = mcc_omci_port_idx_get(context, meid, &port_idx);
	if (error != OMCI_SUCCESS)
		return error;

	if (port_idx >= mcc->max_ports)
		return OMCI_ERROR;

	switch (type) {
	case MCC_MONITOR_TYPE_CURRENT_MC_BANDWIDTH:
		*value = 0; /* TODO: calculate from active flows */
		break;
	case MCC_MONITOR_TYPE_JOIN_MSG_COUNTER:
		*value = mcc->port[port_idx].join_msg_cnt;
		break;
	case MCC_MONITOR_TYPE_BW_EXCESS_COUNTER:
		*value = mcc->port[port_idx].exce_msg_cnt;
		break;
	default:
		return OMCI_ERROR;
	}

	return OMCI_SUCCESS;
}

enum omci_error mcc_port_monitor_ipv4_agl_get(struct omci_context *context,
					      const uint16_t meid,
					      struct omci_ipv4_agl_table **agl,
					      uint32_t *agl_num)
{
	/* TODO: Phase 7 Step 6 — build AGL from active group entries */
	if (agl)
		*agl = NULL;
	if (agl_num)
		*agl_num = 0;
	return OMCI_SUCCESS;
}

enum omci_error mcc_port_monitor_ipv6_agl_get(struct omci_context *context,
					      const uint16_t meid,
					      struct omci_ipv6_agl_table **agl,
					      uint32_t *agl_num)
{
	/* TODO: Phase 7 Step 6 — build AGL from active group entries */
	if (agl)
		*agl = NULL;
	if (agl_num)
		*agl_num = 0;
	return OMCI_SUCCESS;
}

enum omci_error mcc_policy_lgl_get(struct omci_context *context,
				   const uint16_t meid,
				   struct mcc_lost_group **lgl,
				   uint32_t *lgl_num)
{
	/* TODO: Phase 7 Step 6 — build LGL from lost group entries */
	if (lgl)
		*lgl = NULL;
	if (lgl_num)
		*lgl_num = 0;
	return OMCI_SUCCESS;
}

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
	if (error != OMCI_SUCCESS)
		return error;

	return mcc_port_mc_flow_control(mcc, port_idx, true, true, flow);
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
	if (error != OMCI_SUCCESS)
		return error;

	return mcc_port_mc_flow_control(mcc, port_idx, false, true, flow);
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
	if (error != OMCI_SUCCESS)
		return error;

	return mcc_port_mc_flow_range_delete(mcc, port_idx, true, flow);
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
	if (error != OMCI_SUCCESS)
		return error;

	return mcc_port_mc_flow_control(mcc, port_idx, true, false, flow);
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
	if (error != OMCI_SUCCESS)
		return error;

	return mcc_port_mc_flow_control(mcc, port_idx, false, false, flow);
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
	if (error != OMCI_SUCCESS)
		return error;

	return mcc_port_mc_flow_range_delete(mcc, port_idx, false, flow);
}
