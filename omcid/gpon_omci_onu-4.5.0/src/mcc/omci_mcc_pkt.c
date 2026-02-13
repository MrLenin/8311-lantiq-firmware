/******************************************************************************
 * Copyright (c) 2017 - 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * MCC packet processing: receive, parse, classify IGMP/MLD.
 *
 * STUB: Minimal working implementation. Full port in Phase 7 Step 3.
 ******************************************************************************/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "mcc/omci_mcc_core.h"
#include "mcc/omci_mcc_pkt.h"

#include <string.h>
#include <arpa/inet.h>

enum omci_error mcc_pkt_receive(struct mcc_ctx *mcc,
				struct mcc_pkt *pkt)
{
	uint16_t len = MCC_PKT_MAX_SIZE_BYTE;
	enum omci_error error;

	error = mcc_dev_pkt_receive(&mcc->dev, pkt->data, &len,
				    &pkt->info.llinfo);
	if (error != OMCI_SUCCESS)
		return error;

	pkt->len = len;
	pkt->drop = false;
	pkt->info.pkt_type = MCC_PKT_TYPE_NA;
	pkt->info.prot_ctx = NULL;

	/* TODO: Phase 7 Step 3 — full packet info update:
	   Parse Ethernet → IP → IGMP/MLD headers */

	return OMCI_SUCCESS;
}

enum omci_error mcc_pkt_send(struct mcc_ctx *mcc,
			     struct mcc_pkt *pkt)
{
	return mcc_dev_pkt_send(&mcc->dev, pkt->data, pkt->len,
				&pkt->info.llinfo);
}

uint8_t mcc_pkt_port_idx_get(const struct mcc_pkt_info *pkt_info)
{
	return pkt_info->llinfo.port_idx;
}

uint16_t mcc_pkt_cvid_get(const struct mcc_pkt_info *pkt_info)
{
	return pkt_info->llinfo.cvid;
}

uint16_t mcc_pkt_svid_get(const struct mcc_pkt_info *pkt_info)
{
	return pkt_info->llinfo.svid;
}

bool mcc_pkt_is_igmp(struct mcc_pkt *pkt)
{
	uint8_t *data = pkt->data;
	uint8_t offset = pkt->info.llinfo.offset_iph;

	if (pkt->len < (uint16_t)(offset + 20))
		return false;

	/* Check IP version 4 and protocol = IGMP (2) */
	if ((data[offset] >> 4) == 4 && data[offset + 9] == MCC_IP_PROTO_IGMP)
		return true;

	return false;
}

bool mcc_pkt_is_mld(struct mcc_pkt *pkt)
{
	/* TODO: Phase 7 Step 3 — check IPv6 next header chain for ICMPv6
	   with MLD type codes */
	(void)pkt;
	return false;
}

enum omci_error mcc_pkt_type_get(struct mcc_pkt *pkt,
				 enum mcc_pkt_type *type)
{
	/* TODO: Phase 7 Step 3 — classify packet type via protocol context */
	*type = MCC_PKT_TYPE_NA;
	return OMCI_SUCCESS;
}

enum omci_error mcc_pkt_rec_sa_get(struct mcc_pkt *pkt,
				   const uint16_t rec_idx,
				   const uint16_t s_idx,
				   union mcc_ip_addr *addr)
{
	/* TODO: Phase 7 Step 3 */
	(void)pkt;
	(void)rec_idx;
	(void)s_idx;
	memset(addr, 0, sizeof(*addr));
	return OMCI_SUCCESS;
}

enum omci_error mcc_pkt_da_get(struct mcc_pkt *pkt, union mcc_ip_addr *addr)
{
	/* TODO: Phase 7 Step 3 */
	(void)pkt;
	memset(addr, 0, sizeof(*addr));
	return OMCI_SUCCESS;
}

enum omci_error mcc_pkt_rec_ga_get(struct mcc_pkt *pkt,
				   const uint16_t rec_idx,
				   union mcc_ip_addr *addr)
{
	/* TODO: Phase 7 Step 3 */
	(void)pkt;
	(void)rec_idx;
	memset(addr, 0, sizeof(*addr));
	return OMCI_SUCCESS;
}

uint32_t mcc_pkt_gmi_get(struct mcc_pkt *pkt)
{
	/* Default GMI = (robustness * query_interval) + query_response_interval
	   = 2 * 125s + 10s = 260s = 260000ms */
	(void)pkt;
	return MCC_QUERY_ROBUSTNESS_DEFAULT * MCC_QUERY_INTERVAL_DEFAULT +
	       MCC_QUERY_RESPONSE_INTERVAL_DEFAULT;
}

enum omci_error mcc_pkt_rec_ca_get(struct mcc_pkt *pkt,
				   union mcc_ip_addr *addr)
{
	/* TODO: Phase 7 Step 3 */
	(void)pkt;
	memset(addr, 0, sizeof(*addr));
	return OMCI_SUCCESS;
}
