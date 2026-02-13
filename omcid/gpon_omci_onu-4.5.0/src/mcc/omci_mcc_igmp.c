/******************************************************************************
 * Copyright (c) 2017 - 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * IGMP protocol handler: IGMPv1/v2/v3 parsing and classification.
 *
 * STUB: Minimal working implementation. Full port in Phase 7 Step 3.
 ******************************************************************************/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "mcc/omci_mcc_core.h"
#include "mcc/omci_mcc_pkt.h"

#include <arpa/inet.h>

/* Protocol context vtable for IGMP */

static enum mcc_pkt_version igmp_version_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_igmp_hdr *igmp = pkt->info.igmp.p;

	if (!igmp)
		return MCC_PKT_VERSION_NA;

	switch (igmp->type) {
	case MCC_IGMP_TYPE_V1_MEMBERSHIP_REPORT:
		return MCC_PKT_IGMP_VERSION_1;
	case MCC_IGMP_TYPE_MEMBERSHIP_QUERY:
	case MCC_IGMP_TYPE_V2_MEMBERSHIP_REPORT:
	case MCC_IGMP_TYPE_V2_LEAVE_GROUP:
		return MCC_PKT_IGMP_VERSION_2;
	case MCC_IGMP_TYPE_V3_MEMBERSHIP_REPORT:
		return MCC_PKT_IGMP_VERSION_3;
	default:
		return MCC_PKT_VERSION_NA;
	}
}

static bool igmp_is_supported(struct mcc_pkt *pkt)
{
	return igmp_version_get(pkt) != MCC_PKT_VERSION_NA;
}

static uint8_t igmp_type_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_igmp_hdr *igmp = pkt->info.igmp.p;
	if (!igmp)
		return 0;
	return igmp->type;
}

static void igmp_ga_get(struct mcc_pkt *pkt, union mcc_ip_addr *addr)
{
	struct mcc_pkt_igmp_hdr *igmp = pkt->info.igmp.p;
	memset(addr, 0, sizeof(*addr));
	if (igmp)
		memcpy(addr->ipv4, &igmp->group_addr, 4);
}

static uint16_t igmp_rec_num_get(struct mcc_pkt *pkt)
{
	/* TODO: Phase 7 Step 3 — IGMPv3 report record parsing */
	(void)pkt;
	return 0;
}

static uint16_t igmp_rec_snum_get(struct mcc_pkt *pkt, const void *p_rec)
{
	(void)pkt;
	(void)p_rec;
	return 0;
}

static void *igmp_rec_get(struct mcc_pkt *pkt, const uint16_t rec_idx)
{
	(void)pkt;
	(void)rec_idx;
	return NULL;
}

static uint8_t igmp_rec_type_get(struct mcc_pkt *pkt, const void *p_rec)
{
	(void)pkt;
	(void)p_rec;
	return 0;
}

static void igmp_rec_ga_get(struct mcc_pkt *pkt,
			    const void *p_rec,
			    union mcc_ip_addr *addr)
{
	(void)pkt;
	(void)p_rec;
	memset(addr, 0, sizeof(*addr));
}

static void igmp_rec_sa_get(struct mcc_pkt *pkt,
			    const void *p_rec,
			    const uint16_t s_idx,
			    union mcc_ip_addr *addr)
{
	(void)pkt;
	(void)p_rec;
	(void)s_idx;
	memset(addr, 0, sizeof(*addr));
}

static uint32_t igmp_max_resp_delay_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_igmp_hdr *igmp = pkt->info.igmp.p;
	if (!igmp)
		return 0;
	/* IGMPv2: code field is max response time in 1/10 second units */
	return (uint32_t)igmp->code * 100;
}

static uint8_t igmp_query_qqic_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_igmp_hdr *igmp = pkt->info.igmp.p;
	if (!igmp)
		return 0;
	return igmp->qqic;
}

static uint8_t igmp_query_qrv_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_igmp_hdr *igmp = pkt->info.igmp.p;
	if (!igmp)
		return MCC_QUERY_ROBUSTNESS_DEFAULT;
	return igmp->qrv ? igmp->qrv : MCC_QUERY_ROBUSTNESS_DEFAULT;
}

static struct mcc_pkt_protocol_context igmp_prot_ctx = {
	.version_get = igmp_version_get,
	.is_supported = igmp_is_supported,
	.type_get = igmp_type_get,
	.ga_get = igmp_ga_get,
	.rec_num_get = igmp_rec_num_get,
	.rec_snum_get = igmp_rec_snum_get,
	.rec_get = igmp_rec_get,
	.rec_type_get = igmp_rec_type_get,
	.rec_ga_get = igmp_rec_ga_get,
	.rec_sa_get = igmp_rec_sa_get,
	.max_resp_delay_get = igmp_max_resp_delay_get,
	.query_qqic_get = igmp_query_qqic_get,
	.query_qrv_get = igmp_query_qrv_get,
};

void const *mcc_igmp_prot_ctx_get(void)
{
	return &igmp_prot_ctx;
}
