/******************************************************************************
 * Copyright (c) 2017 - 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * MLD protocol handler: MLDv1/v2 parsing and classification.
 *
 * STUB: Minimal working implementation. Full port in Phase 7 Step 3.
 ******************************************************************************/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "mcc/omci_mcc_core.h"
#include "mcc/omci_mcc_pkt.h"

/* Protocol context vtable for MLD */

static enum mcc_pkt_version mld_version_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_mld_hdr *mld = pkt->info.mld.p;

	if (!mld)
		return MCC_PKT_VERSION_NA;

	switch (mld->type) {
	case MCC_MLD_TYPE_LISTENER_QUERY:
	case MCC_MLD_TYPE_LISTENER_REPORT:
	case MCC_MLD_TYPE_LISTENER_DONE:
		return MCC_PKT_MLD_VERSION_1;
	case MCC_MLD_TYPE_LISTENER_V2_REPORT:
		return MCC_PKT_MLD_VERSION_2;
	default:
		return MCC_PKT_VERSION_NA;
	}
}

static bool mld_is_supported(struct mcc_pkt *pkt)
{
	return mld_version_get(pkt) != MCC_PKT_VERSION_NA;
}

static uint8_t mld_type_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_mld_hdr *mld = pkt->info.mld.p;
	if (!mld)
		return 0;
	return mld->type;
}

static void mld_ga_get(struct mcc_pkt *pkt, union mcc_ip_addr *addr)
{
	struct mcc_pkt_mld_hdr *mld = pkt->info.mld.p;
	memset(addr, 0, sizeof(*addr));
	if (mld)
		memcpy(addr->ipv6, mld->mc_addr, OMCI_IPV6_ADDR_LEN);
}

static uint16_t mld_rec_num_get(struct mcc_pkt *pkt)
{
	/* TODO: Phase 7 Step 3 — MLDv2 report record parsing */
	(void)pkt;
	return 0;
}

static uint16_t mld_rec_snum_get(struct mcc_pkt *pkt, const void *p_rec)
{
	(void)pkt;
	(void)p_rec;
	return 0;
}

static void *mld_rec_get(struct mcc_pkt *pkt, const uint16_t rec_idx)
{
	(void)pkt;
	(void)rec_idx;
	return NULL;
}

static uint8_t mld_rec_type_get(struct mcc_pkt *pkt, const void *p_rec)
{
	(void)pkt;
	(void)p_rec;
	return 0;
}

static void mld_rec_ga_get(struct mcc_pkt *pkt,
			   const void *p_rec,
			   union mcc_ip_addr *addr)
{
	(void)pkt;
	(void)p_rec;
	memset(addr, 0, sizeof(*addr));
}

static void mld_rec_sa_get(struct mcc_pkt *pkt,
			   const void *p_rec,
			   const uint16_t s_idx,
			   union mcc_ip_addr *addr)
{
	(void)pkt;
	(void)p_rec;
	(void)s_idx;
	memset(addr, 0, sizeof(*addr));
}

static uint32_t mld_max_resp_delay_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_mld_hdr *mld = pkt->info.mld.p;
	if (!mld)
		return 0;
	return (uint32_t)ntohs(mld->max_resp_delay);
}

static uint8_t mld_query_qqic_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_mld_hdr *mld = pkt->info.mld.p;
	if (!mld)
		return 0;
	return mld->qqic;
}

static uint8_t mld_query_qrv_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_mld_hdr *mld = pkt->info.mld.p;
	if (!mld)
		return MCC_QUERY_ROBUSTNESS_DEFAULT;
	return mld->qrv ? mld->qrv : MCC_QUERY_ROBUSTNESS_DEFAULT;
}

static struct mcc_pkt_protocol_context mld_prot_ctx = {
	.version_get = mld_version_get,
	.is_supported = mld_is_supported,
	.type_get = mld_type_get,
	.ga_get = mld_ga_get,
	.rec_num_get = mld_rec_num_get,
	.rec_snum_get = mld_rec_snum_get,
	.rec_get = mld_rec_get,
	.rec_type_get = mld_rec_type_get,
	.rec_ga_get = mld_rec_ga_get,
	.rec_sa_get = mld_rec_sa_get,
	.max_resp_delay_get = mld_max_resp_delay_get,
	.query_qqic_get = mld_query_qqic_get,
	.query_qrv_get = mld_query_qrv_get,
};

void const *mcc_mld_prot_ctx_get(void)
{
	return &mld_prot_ctx;
}
