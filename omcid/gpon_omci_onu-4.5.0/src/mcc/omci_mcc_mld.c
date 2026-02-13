/******************************************************************************
 * Copyright (c) 2017 - 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * MLD protocol handler: MLDv1/v2 parsing and classification.
 * Ported from gpon_omci_onu-8.6.3 — no hardware dependency, pure protocol.
 *
 * Protocol context vtable providing version detection, direction filtering,
 * record iteration, and address extraction for the MCC packet layer.
 *
 * Version detection: type 131/132 = v1, 143 = v2,
 *   130 = query (v1 if size <= 8, v2 if larger).
 * Direction gating: queries downstream only, reports/done upstream only.
 * MLDv2 records: variable length, 20 + s_num*16 + aux_num*4 bytes each.
 ******************************************************************************/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_MCC

#include "omci_core.h"
#include "omci_debug.h"
#include "mcc/omci_mcc_core.h"
#include "mcc/omci_mcc_pkt.h"
#include "mcc/omci_mcc_mld.h"

static uint8_t mcc_mld_type_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_mld_hdr *mld = pkt->info.mld.p;

	return mld->type;
}

static bool mcc_mld_is_supported(struct mcc_pkt *pkt)
{
	bool upstream, supported = true;
	uint8_t mld_type = mcc_mld_type_get(pkt);

	upstream = pkt->info.llinfo.dir_us;

	dbg_prn("MLD packet in %s direction",
		upstream ? "UPSTREAM" : "DOWNSTREAM");

	switch (mld_type) {
	case MCC_MLD_TYPE_LISTENER_QUERY:
		if (upstream)
			supported = false;

		dbg_prn("MLD query received and %s",
			supported ? "accepted" : "blocked");
		break;
	case MCC_MLD_TYPE_LISTENER_REPORT:
		if (!upstream)
			supported = false;

		dbg_prn("MLD report received and %s",
			supported ? "accepted" : "blocked");
		break;
	case MCC_MLD_TYPE_LISTENER_DONE:
		if (!upstream)
			supported = false;

		dbg_prn("MLD done received and %s",
			supported ? "accepted" : "blocked");
		break;
	case MCC_MLD_TYPE_LISTENER_V2_REPORT:
		if (!upstream)
			supported = false;

		dbg_prn("MLDv2 report received and %s",
			supported ? "accepted" : "blocked");
		break;
	default:
		supported = false;
		dbg_err("MLD received unknown packet type %u and blocked",
			mld_type);
	}

	return supported;
}

static uint16_t mcc_mld_rec_num_get(struct mcc_pkt *pkt)
{
	uint16_t rec_num = 0;
	struct mcc_pkt_mld_hdr *mld = pkt->info.mld.p;
	struct mcc_pkt_mld_v2_report *p_report;

	switch (mld->type) {
	case MCC_MLD_TYPE_LISTENER_V2_REPORT:
		p_report = (struct mcc_pkt_mld_v2_report *)mld;
		memcpy(&rec_num, &p_report->rec_num, sizeof(rec_num));
		break;
	case MCC_MLD_TYPE_LISTENER_REPORT:
	case MCC_MLD_TYPE_LISTENER_DONE:
		rec_num = 1;
		break;
	default:
		rec_num = 0;
		break;
	}

	return rec_num;
}

static enum mcc_pkt_version mcc_mld_ver_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_mld_hdr *mld = pkt->info.mld.p;

	switch (mld->type) {
	case MCC_MLD_TYPE_LISTENER_REPORT:
	case MCC_MLD_TYPE_LISTENER_DONE:
		return MCC_PKT_MLD_VERSION_1;
	case MCC_MLD_TYPE_LISTENER_V2_REPORT:
		return MCC_PKT_MLD_VERSION_2;
	case MCC_MLD_TYPE_LISTENER_QUERY:
		return (pkt->info.mld.len > MCC_MLD_V1_QUERY_MSG_SIZE) ?
				MCC_PKT_MLD_VERSION_2 : MCC_PKT_MLD_VERSION_1;
	default:
		return MCC_PKT_VERSION_NA;
	}
}

/** Get pointer to MLDv2 group record at index rec_idx.
    Records are variable-length:
      20 (type + aux + s_num + mc_addr) + s_num*16 + aux_num*4 bytes each. */
static void *mcc_mld_rec_get(struct mcc_pkt *pkt, const uint16_t rec_idx)
{
	struct mcc_pkt_mld_v2_report *p_report;
	struct mcc_pkt_mld_v2_group_record *p_rec = NULL, rec;
	uint16_t rec_num, i;

	rec_num = mcc_mld_rec_num_get(pkt);
	if (rec_idx >= rec_num)
		return NULL;

	if (mcc_mld_ver_get(pkt) == MCC_PKT_MLD_VERSION_2) {
		p_report = (struct mcc_pkt_mld_v2_report *)pkt->info.mld.p;

		p_rec = p_report->rec;
		for (i = 0; i < rec_num; i++) {
			memcpy(&rec, p_rec, sizeof(*p_rec));
			if (i == rec_idx)
				break;

			/* go to the next record */
			p_rec++;
			/* take into account floating data
			   (source addresses + auxiliary data) */
			p_rec = (struct mcc_pkt_mld_v2_group_record *)
					(((uint8_t *)p_rec) +
					sizeof(uint32_t) * rec.aux_num +
					sizeof(rec.data[0]) * rec.s_num);
		}
	}

	return p_rec;
}

static uint16_t mcc_mld_rec_snum_get(struct mcc_pkt *pkt, const void *p_rec)
{
	struct mcc_pkt_mld_v2_group_record data;
	uint16_t snum = 0;

	if (p_rec) {
		memcpy(&data, p_rec, sizeof(data));
		snum = data.s_num;
	}

	return snum;
}

/** Get record type for MLDv2 records, or synthesize for MLDv1.
    MLDv1 Report → CHANGE_TO_EXCLUDE (join), Done → CHANGE_TO_INCLUDE. */
static uint8_t mcc_mld_rec_type_get(struct mcc_pkt *pkt, const void *p_rec)
{
	enum mcc_pkt_version ver;
	struct mcc_pkt_mld_v2_group_record rec;
	uint8_t rec_type;

	ver = mcc_mld_ver_get(pkt);

	if (ver == MCC_PKT_MLD_VERSION_1) {
		switch (mcc_mld_type_get(pkt)) {
		case MCC_MLD_TYPE_LISTENER_REPORT:
			rec_type = MCC_MLD_CHANGE_TO_EXCLUDE;
			break;
		case MCC_MLD_TYPE_LISTENER_DONE:
			rec_type = MCC_MLD_CHANGE_TO_INCLUDE;
			break;
		default:
			rec_type = 0;
			break;
		}
	} else if (ver == MCC_PKT_MLD_VERSION_2) {
		if (p_rec) {
			memcpy(&rec, p_rec, sizeof(rec));
			rec_type = rec.type;
		} else {
			rec_type = 0;
		}
	} else {
		rec_type = 0;
	}

	return rec_type;
}

static void mcc_mld_ga_get(struct mcc_pkt *pkt, union mcc_ip_addr *addr)
{
	struct mcc_pkt_mld_hdr *mld = pkt->info.mld.p;

	memcpy(addr, mld->mc_addr, sizeof(addr->ipv6));
}

static void mcc_mld_rec_ga_get(struct mcc_pkt *pkt,
			       const void *p_rec,
			       union mcc_ip_addr *addr)
{
	struct mcc_pkt_mld_v2_group_record *rec =
			(struct mcc_pkt_mld_v2_group_record *)p_rec;

	memcpy(addr, rec->data[0].mc_addr, sizeof(addr->ipv6));
}

static void mcc_mld_rec_sa_get(struct mcc_pkt *pkt,
			       const void *p_rec,
			       const uint16_t s_idx,
			       union mcc_ip_addr *addr)
{
	struct mcc_pkt_mld_v2_group_record *rec =
			(struct mcc_pkt_mld_v2_group_record *)p_rec;

	memcpy(addr, &rec->data[1 + s_idx], sizeof(addr->ipv6));
}

/** Max Response Delay from MLD header.
    value == 0 → use default query response interval.
    value < 32768 → milliseconds directly.
    value >= 32768 → floating point encoding (12-bit mantissa + 3-bit exp). */
static uint32_t mcc_mld_max_resp_delay_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_mld_hdr mld;
	uint16_t mant;
	uint8_t exp;
	uint32_t mrt = 0;

	memcpy(&mld, pkt->info.mld.p, sizeof(mld));

	if (mld.max_resp_delay == 0) {
		mrt = MCC_QUERY_RESPONSE_INTERVAL_DEFAULT;
	} else if (mld.max_resp_delay < 32768) {
		mrt = mld.max_resp_delay;
	} else {
		mant = mld.max_resp_delay & 0xFFF;
		exp = (mld.max_resp_delay >> 12) & 0x7;
		mrt = (mant | 0x1000) << (exp + 3);
	}

	return mrt;
}

static uint8_t mcc_mld_query_qqic_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_mld_hdr mld;

	memcpy(&mld, pkt->info.mld.p, sizeof(mld));

	return mld.qqic;
}

static uint8_t mcc_mld_query_qrv_get(struct mcc_pkt *pkt)
{
	struct mcc_pkt_mld_hdr mld;
	uint8_t qrv;

	memcpy(&mld, pkt->info.mld.p, sizeof(mld));

	qrv = mld.qrv;

	return qrv;
}

static const struct mcc_pkt_protocol_context mld_protocol_context = {
	.version_get = mcc_mld_ver_get,
	.is_supported = mcc_mld_is_supported,
	.type_get = mcc_mld_type_get,
	.ga_get = mcc_mld_ga_get,
	.rec_num_get = mcc_mld_rec_num_get,
	.rec_snum_get = mcc_mld_rec_snum_get,
	.rec_type_get = mcc_mld_rec_type_get,
	.rec_get = mcc_mld_rec_get,
	.rec_ga_get = mcc_mld_rec_ga_get,
	.rec_sa_get = mcc_mld_rec_sa_get,
	.max_resp_delay_get = mcc_mld_max_resp_delay_get,
	.query_qqic_get = mcc_mld_query_qqic_get,
	.query_qrv_get = mcc_mld_query_qrv_get
};

void const *mcc_mld_prot_ctx_get(void)
{
	return &mld_protocol_context;
}
