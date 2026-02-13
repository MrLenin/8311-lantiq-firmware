/******************************************************************************
 * Copyright (c) 2017 - 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * IGMP protocol handler: IGMPv1/v2/v3 parsing and classification.
 * Ported from gpon_omci_onu-8.6.3 — no hardware dependency, pure protocol.
 *
 * Protocol context vtable providing version detection, direction filtering,
 * record iteration, and address extraction for the MCC packet layer.
 *
 * Version detection: type 0x22 = v3, 0x16/0x17 = v2, 0x12 = v1,
 *   0x11 = query (v2 if size <= 8, v3 if larger).
 * Direction gating: queries downstream only, reports/leave upstream only,
 *   v1 reports always blocked.
 * IGMPv3 records: variable length, 8 + (aux_num + s_num) * 4 bytes each.
 ******************************************************************************/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_MCC

#include "omci_core.h"
#include "omci_debug.h"
#include "mcc/omci_mcc_core.h"
#include "mcc/omci_mcc_pkt.h"
#include "mcc/omci_mcc_igmp.h"

static uint8_t mcc_igmp_type_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_igmp_hdr *igmp = pkt->info.igmp.p;

	return igmp->type;
}

static bool mcc_igmp_is_supported(struct mcc_pkt *pkt)
{
	bool upstream, supported = true;
	uint8_t igmp_type = mcc_igmp_type_get(pkt);

	upstream = pkt->info.llinfo.dir_us;

	dbg_prn("IGMP packet in %s direction",
		upstream ? "UPSTREAM" : "DOWNSTREAM");

	switch (igmp_type) {
	case MCC_IGMP_TYPE_MEMBERSHIP_QUERY:
		if (upstream)
			supported = false;
		dbg_prn("IGMP query received and %s",
			supported ? "accepted" : "blocked");
		break;

	case MCC_IGMP_TYPE_V1_MEMBERSHIP_REPORT:
		supported = false;
		dbg_prn("IGMPv1 report received and blocked");
		break;

	case MCC_IGMP_TYPE_V2_MEMBERSHIP_REPORT:
		if (!upstream)
			supported = false;
		dbg_prn("IGMPv2 report received and %s",
			supported ? "accepted" : "blocked");
		break;

	case MCC_IGMP_TYPE_V3_MEMBERSHIP_REPORT:
		if (!upstream)
			supported = false;
		dbg_prn("IGMPv3 report received and %s",
			supported ? "accepted" : "blocked");
		break;

	case MCC_IGMP_TYPE_V2_LEAVE_GROUP:
		if (!upstream)
			supported = false;
		dbg_prn("IGMPv2 leave received and %s",
			supported ? "accepted" : "blocked");
		break;

	default:
		supported = false;
		dbg_err("IGMP received unknown packet type %hhu and blocked",
			igmp_type);
	}

	return supported;
}

static uint16_t mcc_igmp_rec_num_get(struct mcc_pkt *pkt)
{
	uint16_t rec_num = 0;
	struct mcc_pkt_igmp_hdr *igmp = pkt->info.igmp.p;
	struct mcc_pkt_igmp_v3_report *p_report;

	switch (igmp->type) {
	case MCC_IGMP_TYPE_V3_MEMBERSHIP_REPORT:
		p_report = (struct mcc_pkt_igmp_v3_report *)igmp;
		memcpy(&rec_num, &p_report->rec_num, sizeof(rec_num));
		break;
	case MCC_IGMP_TYPE_V2_MEMBERSHIP_REPORT:
	case MCC_IGMP_TYPE_V2_LEAVE_GROUP:
		rec_num = 1;
		break;
	default:
		rec_num = 0;
		break;
	}

	return rec_num;
}

static enum mcc_pkt_version mcc_igmp_ver_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_igmp_hdr *igmp = pkt->info.igmp.p;
	uint16_t totl, ihl;

	switch (igmp->type) {
	case MCC_IGMP_TYPE_V3_MEMBERSHIP_REPORT:
		return MCC_PKT_IGMP_VERSION_3;
	case MCC_IGMP_TYPE_V2_MEMBERSHIP_REPORT:
	case MCC_IGMP_TYPE_V2_LEAVE_GROUP:
		return MCC_PKT_IGMP_VERSION_2;
	case MCC_IGMP_TYPE_V1_MEMBERSHIP_REPORT:
		return MCC_PKT_IGMP_VERSION_1;
	case MCC_IGMP_TYPE_MEMBERSHIP_QUERY:
		totl = pkt->info.ip_hdr.ipv4.tot_len;
		ihl  = pkt->info.ip_hdr.ipv4.ihl * sizeof(uint32_t);

		if (totl > ihl) {
			if (totl - ihl > MCC_IGMP_V2_QUERY_MSG_SIZE)
				return MCC_PKT_IGMP_VERSION_3;
			else
				return MCC_PKT_IGMP_VERSION_2;
		}
		/* fall through */
	default:
		return MCC_PKT_VERSION_NA;
	}
}

/** Max Response Time from IGMP header code field.
    code < 128 → value in 1/10 second units → multiply by 100 for ms.
    code >= 128 → floating point encoding (mantissa + exponent).
    code == 0 → use default query response interval. */
static uint32_t mcc_igmp_max_resp_delay_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_igmp_hdr igmp;
	uint8_t mant, exp;
	uint32_t mrt = 0;

	memcpy(&igmp, pkt->info.igmp.p, sizeof(igmp));

	if (igmp.code == 0) {
		mrt = MCC_QUERY_RESPONSE_INTERVAL_DEFAULT;
	} else if (igmp.code < 128) {
		mrt = igmp.code * 100;
	} else {
		mant = igmp.code & 0xF;
		exp = (igmp.code >> 4) & 0x7;
		mrt = ((mant | 0x10) << (exp + 3)) * 100;
	}

	return mrt;
}

static uint8_t mcc_igmp_query_qqic_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_igmp_hdr igmp;

	memcpy(&igmp, pkt->info.igmp.p, sizeof(igmp));

	return igmp.qqic;
}

static uint8_t mcc_igmp_query_qrv_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_igmp_hdr igmp;
	uint8_t qrv;

	memcpy(&igmp, pkt->info.igmp.p, sizeof(igmp));

	qrv = igmp.qrv;

	if (qrv == 0)
		qrv = MCC_QUERY_ROBUSTNESS_DEFAULT;

	return qrv;
}

/** Get pointer to IGMPv3 group record at index rec_idx.
    Records are variable-length: 8 + (aux_num + s_num) * 4 bytes each.
    For IGMPv2, rec_idx must be 0 (treated as single-record). */
static void *mcc_igmp_rec_get(struct mcc_pkt *pkt, const uint16_t rec_idx)
{
	struct mcc_pkt_igmp_v3_report *p_report;
	struct mcc_pkt_igmp_v3_group_record *p_rec = NULL, rec;
	uint16_t rec_num, i;

	rec_num = mcc_igmp_rec_num_get(pkt);
	if (rec_idx >= rec_num)
		return NULL;

	if (mcc_igmp_ver_get(pkt) == MCC_PKT_IGMP_VERSION_3) {
		p_report = (struct mcc_pkt_igmp_v3_report *)pkt->info.igmp.p;

		p_rec = p_report->rec;
		for (i = 0; i < rec_num; i++) {
			memcpy(&rec, p_rec, sizeof(*p_rec));
			if (i == rec_idx)
				break;

			/* go to the next record */
			p_rec++;
			/* take into account floating data
			   (source addresses + auxiliary data) */
			p_rec = (struct mcc_pkt_igmp_v3_group_record *)
					(((uint8_t *)p_rec) +
						sizeof(uint32_t) *
						    (rec.aux_num + rec.s_num));
		}
	}

	return p_rec;
}

static uint16_t mcc_igmp_rec_snum_get(struct mcc_pkt *pkt, const void *p_rec)
{
	struct mcc_pkt_igmp_v3_group_record data;
	uint16_t snum = 0;

	if (p_rec) {
		memcpy(&data, p_rec, sizeof(data));
		snum = data.s_num;
	}

	return snum;
}

/** Get record type for IGMPv3 records, or synthesize for IGMPv2.
    IGMPv2 Report → CHANGE_TO_EXCLUDE (join), Leave → CHANGE_TO_INCLUDE. */
static uint8_t mcc_igmp_rec_type_get(struct mcc_pkt *pkt, const void *p_rec)
{
	enum mcc_pkt_version ver;
	struct mcc_pkt_igmp_v3_group_record rec;
	uint8_t rec_type;

	ver = mcc_igmp_ver_get(pkt);
	if (ver == MCC_PKT_IGMP_VERSION_3) {
		if (p_rec) {
			memcpy(&rec, p_rec, sizeof(rec));
			rec_type = rec.type;
		} else {
			rec_type = 0;
		}
	} else if (ver == MCC_PKT_IGMP_VERSION_2) {
		switch (mcc_igmp_type_get(pkt)) {
		case MCC_IGMP_TYPE_V2_MEMBERSHIP_REPORT:
			rec_type = MCC_IGMP_CHANGE_TO_EXCLUDE;
			break;
		case MCC_IGMP_TYPE_V2_LEAVE_GROUP:
			rec_type = MCC_IGMP_CHANGE_TO_INCLUDE;
			break;
		default:
			rec_type = 0;
			break;
		}
	} else {
		rec_type = 0;
	}

	return rec_type;
}

static void mcc_igmp_ga_get(struct mcc_pkt *pkt, union mcc_ip_addr *addr)
{
	struct mcc_pkt_igmp_hdr *igmp = pkt->info.igmp.p;

	memset(addr, 0, sizeof(*addr));
	memcpy(addr, &igmp->group_addr, sizeof(uint32_t));
}

static void mcc_igmp_rec_ga_get(struct mcc_pkt *pkt,
				const void *p_rec,
				union mcc_ip_addr *addr)
{
	struct mcc_pkt_igmp_v3_group_record *rec =
			(struct mcc_pkt_igmp_v3_group_record *)p_rec;
	memset(addr, 0, sizeof(*addr));
	memcpy(addr, &rec->data[0], sizeof(uint32_t));
}

static void mcc_igmp_rec_sa_get(struct mcc_pkt *pkt,
				const void *p_rec,
				const uint16_t s_idx,
				union mcc_ip_addr *addr)
{
	struct mcc_pkt_igmp_v3_group_record *rec =
			(struct mcc_pkt_igmp_v3_group_record *)p_rec;
	memset(addr, 0, sizeof(*addr));
	memcpy(addr, &rec->data[1 + s_idx], sizeof(uint32_t));
}

static const struct mcc_pkt_protocol_context igmp_protocol_context = {
	.version_get = mcc_igmp_ver_get,
	.is_supported = mcc_igmp_is_supported,
	.type_get = mcc_igmp_type_get,
	.ga_get = mcc_igmp_ga_get,
	.rec_num_get = mcc_igmp_rec_num_get,
	.rec_snum_get = mcc_igmp_rec_snum_get,
	.rec_type_get = mcc_igmp_rec_type_get,
	.rec_get = mcc_igmp_rec_get,
	.rec_ga_get = mcc_igmp_rec_ga_get,
	.rec_sa_get = mcc_igmp_rec_sa_get,
	.max_resp_delay_get = mcc_igmp_max_resp_delay_get,
	.query_qqic_get = mcc_igmp_query_qqic_get,
	.query_qrv_get = mcc_igmp_query_qrv_get
};

void const *mcc_igmp_prot_ctx_get(void)
{
	return &igmp_protocol_context;
}
