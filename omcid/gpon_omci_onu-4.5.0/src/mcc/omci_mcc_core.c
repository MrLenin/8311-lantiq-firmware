/******************************************************************************
 * Copyright (c) 2017 - 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * MCC core: group/flow/client/source management, rate limiting.
 *
 * STUB: Minimal working implementation. Full port in Phase 7 Step 4.
 ******************************************************************************/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "mcc/omci_mcc_core.h"
#include "mcc/omci_mcc_pkt.h"
#include "mcc/omci_mcc_omci.h"

bool mcc_is_ipv6(const union mcc_ip_addr *ip)
{
	/* Check if any of the IPv6-only bytes (4-15) are non-zero */
	int i;
	for (i = 4; i < 16; i++) {
		if (ip->ipv6[i] != 0)
			return true;
	}
	return false;
}

void mcc_dbg_ip(const enum omci_dbg level,
		const union mcc_ip_addr *ip,
		const char *fmt, ...)
{
	/* TODO: Phase 7 Step 4 — debug IP formatting */
	(void)level;
	(void)ip;
	(void)fmt;
}

struct mcc_src_entry *mcc_src_create(struct mcc_list *src_list,
				     const bool is_static,
				     struct mcc_clt_entry *clt,
				     const union mcc_ip_addr *sa,
				     const uint32_t ibw,
				     const union mcc_wlist_id *wlist_id)
{
	struct mcc_src_entry *src;

	src = IFXOS_MemAlloc(sizeof(*src));
	if (!src)
		return NULL;

	memset(src, 0, sizeof(*src));
	if (sa)
		memcpy(&src->sa, sa, sizeof(src->sa));
	src->ibw = ibw;
	src->is_static = is_static;
	src->clt = clt;
	if (wlist_id)
		src->wlist_id = *wlist_id;

	if (src_list)
		mcc_list_add_tail(src_list, &src->src_le);

	return src;
}

void mcc_src_list_clean(struct mcc_list *list)
{
	struct mcc_list_head *entry, *next;

	MCC_LIST_FOR_EACH_SAFE(entry, next, list) {
		mcc_list_remove(list, entry);
		IFXOS_MemFree(container_of(entry, struct mcc_src_entry, src_le));
	}
}

static void mcc_clt_list_clean(struct mcc_list *clt_list)
{
	struct mcc_list_head *entry, *next;

	MCC_LIST_FOR_EACH_SAFE(entry, next, clt_list) {
		struct mcc_clt_entry *clt = LE2CLT(entry);
		mcc_src_list_clean(&clt->src_list);
		mcc_list_remove(clt_list, entry);
		IFXOS_MemFree(clt);
	}
}

static void mcc_grp_list_clean(struct mcc_list *grp_list)
{
	struct mcc_list_head *entry, *next;

	MCC_LIST_FOR_EACH_SAFE(entry, next, grp_list) {
		struct mcc_grp_entry *grp = LE2GRP(entry);
		mcc_clt_list_clean(&grp->clt_list);
		mcc_src_list_clean(&grp->src_link_list);
		mcc_list_remove(grp_list, entry);
		IFXOS_MemFree(grp);
	}
}

void mcc_flw_cleanup(struct mcc_ctx *mcc, struct mcc_list *flw_list)
{
	struct mcc_list_head *entry, *next;

	MCC_LIST_FOR_EACH_SAFE(entry, next, flw_list) {
		struct mcc_flw_entry *flw = LE2FLW(entry);
		mcc_grp_list_clean(&flw->grp_list);
		mcc_list_remove(flw_list, entry);
		IFXOS_MemFree(flw);
	}
}

void mcc_rl_delete(struct mcc_rl *rl)
{
	struct mcc_list_head *entry, *next;

	MCC_LIST_FOR_EACH_SAFE(entry, next, &rl->rl_list) {
		mcc_list_remove(&rl->rl_list, entry);
		IFXOS_MemFree(container_of(entry, struct mcc_rl_entry, le));
	}
	rl->type = MCC_RL_TYPE_NA;
}

uint32_t mcc_port_ibw_max_get(const struct mcc_port *port)
{
	/* TODO: Phase 7 Step 4 — sum imputed bandwidth of all active flows */
	return 0;
}

enum omci_error mcc_group_list_clear(struct mcc_ctx *mcc,
				     const uint8_t port_idx)
{
	struct mcc_port *port;

	if (port_idx >= mcc->max_ports)
		return OMCI_ERROR;

	port = &mcc->port[port_idx];

	IFXOS_LockGet(&port->lock);
	mcc_flw_cleanup(mcc, &port->flw_list);
	mcc_rl_delete(&port->rl);
	port->join_msg_cnt = 0;
	port->exce_msg_cnt = 0;
	IFXOS_LockRelease(&port->lock);

	return OMCI_SUCCESS;
}

/* Packet thread function */
static int mcc_pkt_thread(IFXOS_ThreadParams_t *params)
{
	struct mcc_ctx *mcc = (struct mcc_ctx *)params->nArg1;

	dbg_prn("MCC: packet thread started");

	while (params->bRunning == IFX_TRUE) {
		struct mcc_pkt pkt;
		enum omci_error error;

		memset(&pkt, 0, sizeof(pkt));
		pkt.len = MCC_PKT_MAX_SIZE_BYTE;

		/* Block waiting for packet from exception interface */
		error = mcc_pkt_receive(mcc, &pkt);
		if (error != OMCI_SUCCESS) {
			if (error == OMCI_ERROR)
				continue;
			break; /* Socket closed or fatal error */
		}

		/* TODO: Phase 7 Step 4 — full packet dispatch:
		   1. Identify IGMP/MLD
		   2. Parse protocol headers
		   3. Classify packet type
		   4. Dispatch to flow control */
	}

	dbg_prn("MCC: packet thread exiting");

	return 0;
}

enum omci_error mcc_thread_start(struct mcc_ctx *mcc)
{
	int ret;

	ret = IFXOS_ThreadInit(&mcc->pkt_thread_ctrl,
			       "mcc_pkt",
			       mcc_pkt_thread,
			       0,
			       (unsigned long)mcc,
			       0, 0);
	if (ret != IFX_SUCCESS)
		return OMCI_ERROR;

	return OMCI_SUCCESS;
}

enum omci_error mcc_thread_stop(struct mcc_ctx *mcc)
{
	/* Cancel blocking receive */
	mcc_dev_pkt_receive_cancel(&mcc->dev);

	/* Wait for thread to exit */
	if (IFXOS_ThreadShutdown(&mcc->pkt_thread_ctrl, 2000)
	    != IFX_SUCCESS) {
		dbg_wrn("MCC: packet thread shutdown timeout");
	}

	return OMCI_SUCCESS;
}

enum omci_error
mcc_port_mc_flow_control(struct mcc_ctx *mcc,
			 const uint8_t port_idx,
			 const bool add,
			 const bool is_static,
			 const struct mcc_mc_flow *flow)
{
	/* TODO: Phase 7 Step 4 — full flow control implementation.
	   This is the core join/leave handler that:
	   1. Finds or creates the flow entry (port + cvid + svid)
	   2. Finds or creates the group entry (DA)
	   3. Handles ACL matching, bandwidth enforcement
	   4. Calls mcc_dev_port_add/remove for hardware forwarding */
	(void)mcc;
	(void)port_idx;
	(void)add;
	(void)is_static;
	(void)flow;

	return OMCI_SUCCESS;
}

enum omci_error
mcc_port_mc_flow_range_delete(struct mcc_ctx *mcc,
			      const uint8_t port_idx,
			      const bool is_static,
			      const struct mcc_mc_flow_range *flow_range)
{
	/* TODO: Phase 7 Step 4 — range delete implementation */
	(void)mcc;
	(void)port_idx;
	(void)is_static;
	(void)flow_range;

	return OMCI_SUCCESS;
}
