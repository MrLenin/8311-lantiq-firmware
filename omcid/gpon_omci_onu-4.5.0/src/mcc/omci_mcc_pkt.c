/******************************************************************************
 * Copyright (c) 2017 - 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * MCC packet processing: receive, parse, classify IGMP/MLD.
 * Ported from gpon_omci_onu-8.6.3 with Falcon GPE exception interface.
 *
 * Key adaptation: packet buffer includes 8-byte GPE exception header.
 * offset_iph is relative to the buffer start (including exception header),
 * so all pointer arithmetic from v8.6.3 works unchanged.
 ******************************************************************************/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_MCC

#include "omci_core.h"
#include "omci_debug.h"
#include "mcc/omci_mcc_core.h"
#include "mcc/omci_mcc_pkt.h"
#include "mcc/omci_mcc_dev.h"

#include <string.h>
#include <arpa/inet.h>

#define HEX_BYTES_PER_LINE	16
#define HEX_CHARS_PER_BYTE	3
#define HEX_CHARS_PER_LINE	(HEX_BYTES_PER_LINE * HEX_CHARS_PER_BYTE + 1)

/* Printout/dump MCC packet */
static void mcc_pkt_dump(const uint8_t *data, const uint32_t len)
{
	int i = 0, bytes = (int)len, stamp = 0;
	char line[HEX_CHARS_PER_LINE], *s;

	s = line;
	while (--bytes >= 0) {
		snprintf(s, HEX_CHARS_PER_BYTE + 1, " %02X", *data++);
		s += HEX_CHARS_PER_BYTE;
		i++;
		if (i >= HEX_BYTES_PER_LINE) {
			dbg_prn("\t0x%04X: %s", stamp, line);
			i = 0;
			s = line;
			stamp += HEX_BYTES_PER_LINE;
		}
	}
	if (i) {
		*s = '\0';
		dbg_prn("\t0x%04X: %s", stamp, line);
	}
}

/* Calculate IPv4 packet checksum */
static uint16_t mcc_pkt_ipv4_csum_get(const uint8_t *data, const uint32_t len)
{
	uint32_t sum = 0, bytes = len;

	while (bytes > 1) {
		sum += ((data[0] << 8) | data[1]);
		data  += 2;
		bytes -= 2;
	}

	if (bytes)
		sum += (data[0] << 8);

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

/**
 * Parse the contents of an IGMP/MLD control packet.
 *
 * Starting from offset_iph, extracts IP version, validates checksum (IPv4),
 * traverses IPv6 extension headers (Hop-by-Hop, Routing, Dest Options),
 * and locates the IGMP or MLD header. Sets the protocol context vtable
 * and classifies the packet type.
 */
static enum omci_error mcc_pkt_info_update(struct mcc_pkt *pkt)
{
	enum omci_error error = OMCI_SUCCESS;
	uint8_t *p, next_hdr, opt_hdr_len;
	uint32_t len, tlv;
	struct iphdr iphdr;
	struct ip6_ext opt_hdr;

	/* point to the start of packet */
	p = (uint8_t *)pkt->data;

	/* move to eth_type before the ip header */
	p += pkt->info.llinfo.offset_iph - 2;

	/* if the Type is "PPPoE Session" (0x8864) drop the packet */
	if (((p[0] << 8) | p[1]) == MCC_PPPOE_SESSION_STAGE) {
		dbg_wrn("unsupported Multicast over PPPoE packet (dropped)");
		return OMCI_ERROR;
	}

	/* move to the IP header */
	p += 2;

	/* get IP header */
	memcpy(&iphdr, p, sizeof(iphdr));
	if (iphdr.version == 4) {
		memcpy(&pkt->info.ip_hdr.ipv4, p, sizeof(struct iphdr));
		/* IPv4 header length */
		len = iphdr.ihl * sizeof(uint32_t);

		/* Validate header checksum */
		if (mcc_pkt_ipv4_csum_get(p, len)) {
			dbg_wrn("IPv4 wrong checksum, packet will be dropped");
			return OMCI_ERROR;
		}
	} else if (iphdr.version == 6) {
		memcpy(&pkt->info.ip_hdr.ipv6, p, sizeof(struct ip6_hdr));
		/* IPv6 header length */
		len = sizeof(struct ip6_hdr);
	} else {
		dbg_err("unsupported IP version %u", iphdr.version);
		return OMCI_ERROR;
	}
	pkt->info.ip_hdr.len = len;

	/* move to the IP packet payload */
	p += len;

	/* Check IPv4 */
	if (pkt->info.ip_hdr.ipv4.version == 4) {
		/* Check if we have IGMP packet */
		if (pkt->info.ip_hdr.ipv4.protocol == MCC_IP_PROTO_IGMP) {
			pkt->info.igmp.p = (struct mcc_pkt_igmp_hdr *)p;
			pkt->info.igmp.len =
				pkt->info.ip_hdr.ipv4.tot_len -
				pkt->info.ip_hdr.ipv4.ihl;
		} else {
			dbg_err("unsupported IP proto %u",
				pkt->info.ip_hdr.ipv4.protocol);
			return OMCI_ERROR;
		}
	}

	/* Check IPv6 */
	if (iphdr.version == 6) {
		pkt->info.mld.len =
			pkt->info.ip_hdr.ipv6.ip6_ctlun.ip6_un1.ip6_un1_plen;

		/* get 1st next header info from IPv6 header */
		next_hdr =
			pkt->info.ip_hdr.ipv6.ip6_ctlun.ip6_un1.ip6_un1_nxt;

		if (next_hdr == MCC_IP_PROTO_IPV6_HOP_BY_HOP) {
			/* get options */
			memcpy(&tlv, p + sizeof(struct ip6_ext), sizeof(tlv));
			/* get optional header */
			memcpy(&opt_hdr, p, sizeof(opt_hdr));
			/* get optional header length */
			opt_hdr_len = (opt_hdr.ip6e_len + 1) *
						MCC_IPV6_EXT_HDR_UNIT_LEN;

			/* decrease payload length by an opt header */
			pkt->info.mld.len -= opt_hdr_len;

			if (tlv == MCC_TLV_MLD) {
				opt_hdr_len = (opt_hdr.ip6e_len + 1) *
						MCC_IPV6_EXT_HDR_UNIT_LEN;
				pkt->info.mld.p =
					(struct mcc_pkt_mld_hdr *)
						(p + opt_hdr_len);
			} else {
				/* get next header info */
				next_hdr = opt_hdr.ip6e_nxt;
				/* move to the next header */
				p += opt_hdr_len;
			}
		}

		/* Traverse remaining extension headers to find ICMPv6/MLD.
		   len = offset from packet start to IPv6 payload start */
		while (((p - pkt->data) <
			(MCC_IPV6_EXT_HDR_MAX_REC_LEN + len)) &&
		       !pkt->info.mld.p) {
			if (next_hdr == MCC_IP_PROTO_IPV6_ROUTE ||
			    next_hdr == MCC_IP_PROTO_IPV6_OPTS) {
				memcpy(&opt_hdr, p, sizeof(opt_hdr));
				next_hdr = opt_hdr.ip6e_nxt;
				opt_hdr_len = (opt_hdr.ip6e_len + 1) *
						MCC_IPV6_EXT_HDR_UNIT_LEN;
				pkt->info.mld.len -= opt_hdr_len;
				p += opt_hdr_len;
			} else if (next_hdr == MCC_IP_PROTO_IPV6_ICMP) {
				pkt->info.mld.p =
					(struct mcc_pkt_mld_hdr *)p;
			} else {
				dbg_prn("unsupported next_hdr %u", next_hdr);
				break;
			}
		}
	}

	/* set protocol specific context */
	if (pkt->info.igmp.p) {
		pkt->info.prot_ctx =
		     (struct mcc_pkt_protocol_context *)
						mcc_igmp_prot_ctx_get();
	} else if (pkt->info.mld.p) {
		pkt->info.prot_ctx =
		     (struct mcc_pkt_protocol_context *)
						mcc_mld_prot_ctx_get();
	} else {
		dbg_prn("IGMP or MLD packet not found");
		return OMCI_ERROR;
	}

	/* get protocol specific packet type */
	error = mcc_pkt_type_get(pkt, &pkt->info.pkt_type);

	return error;
}

enum omci_error mcc_pkt_receive(struct mcc_ctx *mcc,
				struct mcc_pkt *pkt)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %p", mcc, pkt);

	/* reset packet info data */
	memset(&pkt->info, 0, sizeof(pkt->info));

	pkt->drop = false;
	pkt->len = sizeof(pkt->data);
	error = mcc_dev_pkt_receive(&mcc->dev, pkt->data, &pkt->len,
				    &pkt->info.llinfo);
	if (error != OMCI_SUCCESS) {
		dbg_prn("mcc pkt receive failed");
		dbg_out_ret(__func__, error);
		return error;
	}

	dbg_prn("packet received, len=%d", pkt->len);

	/* dump the received packet */
	mcc_pkt_dump(pkt->data, pkt->len);

	/* get packet information */
	error = mcc_pkt_info_update(pkt);
	if (error) {
		dbg_prn("packet info update failed");
		dbg_out_ret(__func__, error);
		return error;
	}

	/* check if protocol specific packet is supported (IGMP or MLD) */
	if (!pkt->info.prot_ctx->is_supported(pkt)) {
		dbg_wrn("packet is not supported and will be dropped");
		error = OMCI_ERROR;
		dbg_out_ret(__func__, error);
		return error;
	}

	dbg_out_ret(__func__, error);

	return error;
}

enum omci_error mcc_pkt_send(struct mcc_ctx *mcc, struct mcc_pkt *pkt)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %p", mcc, pkt);

	if (pkt->drop) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	error = mcc_dev_pkt_send(&mcc->dev, pkt->data, pkt->len,
				 &pkt->info.llinfo);
	if (error != OMCI_SUCCESS)
		dbg_err("packet send failed with error %d", error);
	else
		dbg_prn("packet sent, len=%u", pkt->len);

	dbg_out_ret(__func__, error);
	return error;
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
	return pkt->info.igmp.p ? true : false;
}

bool mcc_pkt_is_mld(struct mcc_pkt *pkt)
{
	return pkt->info.mld.p ? true : false;
}

enum omci_error mcc_pkt_type_get(struct mcc_pkt *pkt,
				 enum mcc_pkt_type *type)
{
	enum omci_error error = OMCI_SUCCESS;
	uint8_t pkt_type;

	dbg_in(__func__, "%p", pkt);

	/* get protocol specific packet type */
	pkt_type = pkt->info.prot_ctx->type_get(pkt);

	/* ...and convert it to MCC module corresponding enumeration value */
	switch (pkt_type) {
	case MCC_IGMP_TYPE_MEMBERSHIP_QUERY:
		*type = MCC_PKT_TYPE_IGMP_QUERY;
		break;
	case MCC_IGMP_TYPE_V1_MEMBERSHIP_REPORT:
		*type = MCC_PKT_TYPE_IGMP_V1_REPORT;
		break;
	case MCC_IGMP_TYPE_V2_MEMBERSHIP_REPORT:
		*type = MCC_PKT_TYPE_IGMP_V2_REPORT;
		break;
	case MCC_IGMP_TYPE_V2_LEAVE_GROUP:
		*type = MCC_PKT_TYPE_IGMP_V2_LEAVE;
		break;
	case MCC_IGMP_TYPE_V3_MEMBERSHIP_REPORT:
		*type = MCC_PKT_TYPE_IGMP_V3_REPORT;
		break;
	case MCC_MLD_TYPE_LISTENER_QUERY:
		*type = MCC_PKT_TYPE_MLD_QUERY;
		break;
	case MCC_MLD_TYPE_LISTENER_REPORT:
		*type = MCC_PKT_TYPE_MLD_V1_REPORT;
		break;
	case MCC_MLD_TYPE_LISTENER_DONE:
		*type = MCC_PKT_TYPE_MLD_V1_DONE;
		break;
	case MCC_MLD_TYPE_LISTENER_V2_REPORT:
		*type = MCC_PKT_TYPE_MLD_V2_REPORT;
		break;
	default:
		*type = MCC_PKT_TYPE_NA;
		error = OMCI_ERROR;
		break;
	}

	dbg_out_ret(__func__, error);

	return error;
}

enum omci_error mcc_pkt_rec_ga_get(struct mcc_pkt *pkt,
				   const uint16_t rec_idx,
				   union mcc_ip_addr *addr)
{
	enum omci_error error = OMCI_SUCCESS;
	enum mcc_pkt_version ver;
	void *p_rec;

	/* retrieve IGMP/MLD protocol version */
	ver = pkt->info.prot_ctx->version_get(pkt);

	if (ver == MCC_PKT_IGMP_VERSION_3 || ver == MCC_PKT_MLD_VERSION_2) {
		/* get the addressed MC record */
		p_rec = pkt->info.prot_ctx->rec_get(pkt, rec_idx);
		/* ...and retrieve MC group address from the record */
		if (p_rec)
			pkt->info.prot_ctx->rec_ga_get(pkt, p_rec, addr);
		else
			error = OMCI_ERROR;
	} else if (ver == MCC_PKT_IGMP_VERSION_2 ||
		   ver == MCC_PKT_MLD_VERSION_1) {
		/* for IGMPv2 and MLDv1 no records are defined, simply
		   retrieve the only one available MC group address */
		pkt->info.prot_ctx->ga_get(pkt, addr);
	} else {
		error = OMCI_ERROR;
	}

	return error;
}

enum omci_error mcc_pkt_rec_sa_get(struct mcc_pkt *pkt,
				   const uint16_t rec_idx,
				   const uint16_t s_idx,
				   union mcc_ip_addr *addr)
{
	enum omci_error error = OMCI_SUCCESS;
	enum mcc_pkt_version ver;
	void *p_rec;

	/* retrieve IGMP/MLD protocol version */
	ver = pkt->info.prot_ctx->version_get(pkt);

	/* MC source filtering is available for IGMPv3 and MLDv2 */
	if (ver == MCC_PKT_IGMP_VERSION_3 || ver == MCC_PKT_MLD_VERSION_2) {
		/* get protocol specific MC record */
		p_rec = pkt->info.prot_ctx->rec_get(pkt, rec_idx);

		if (p_rec) {
			if (s_idx >= pkt->info.prot_ctx->rec_snum_get(pkt,
								      p_rec))
				error = OMCI_ERROR;
			else
				pkt->info.prot_ctx->rec_sa_get(pkt, p_rec,
							       s_idx, addr);
		} else {
			error = OMCI_ERROR;
		}
	} else {
		error = OMCI_ERROR;
	}

	return error;
}

enum omci_error mcc_pkt_da_get(struct mcc_pkt *pkt, union mcc_ip_addr *addr)
{
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p", pkt, addr);

	memset(addr, 0, sizeof(*addr));

	/* get IPv4/IPv6 destination IP address */
	if (pkt->info.ip_hdr.ipv4.version == 4)
		memcpy(addr->ipv4, &pkt->info.ip_hdr.ipv4.daddr, 4);
	else if ((pkt->info.ip_hdr.ipv6.ip6_ctlun.ip6_un2_vfc >> 4) == 6)
		memcpy(addr->ipv6, &pkt->info.ip_hdr.ipv6.ip6_dst,
			OMCI_IPV6_ADDR_LEN);
	else
		error = OMCI_ERROR;

	dbg_out_ret(__func__, error);

	return error;
}

/* Get MC packet query interval (milliseconds) from QQIC field.
   QQIC < 128 → value in seconds. QQIC >= 128 → floating point encoding. */
static uint32_t mcc_pkt_qi_ms_get(struct mcc_pkt *pkt)
{
	uint8_t mant, exp, qqic;
	uint32_t qi = 0;

	qqic = pkt->info.prot_ctx->query_qqic_get(pkt);

	if (qqic == 0) {
		qi = MCC_QUERY_INTERVAL_DEFAULT;
	} else if (qqic < 128) {
		qi = qqic * 1000;
	} else {
		mant = qqic & 0xF;
		exp = (qqic >> 4) & 0x7;
		qi  = ((mant | 0x10) << (exp + 3)) * 1000;
	}

	return qi;
}

uint32_t mcc_pkt_gmi_get(struct mcc_pkt *pkt)
{
	enum mcc_pkt_version ver;
	uint8_t qrv = 0;
	uint32_t gmi, qi = 0, mrt = 0;

	ver = pkt->info.prot_ctx->version_get(pkt);

	mrt = pkt->info.prot_ctx->max_resp_delay_get(pkt);

	if (ver == MCC_PKT_IGMP_VERSION_2 || ver == MCC_PKT_MLD_VERSION_1) {
		qrv = MCC_QUERY_ROBUSTNESS_DEFAULT;
		qi  = MCC_QUERY_INTERVAL_DEFAULT;
	} else if (ver == MCC_PKT_IGMP_VERSION_3 ||
		   ver == MCC_PKT_MLD_VERSION_2) {
		qrv = pkt->info.prot_ctx->query_qrv_get(pkt);
		if (qrv == 0)
			qrv = MCC_QUERY_ROBUSTNESS_DEFAULT;
		qi = mcc_pkt_qi_ms_get(pkt);
	} else {
		dbg_wrn("IGMP/MLD Group Membership Interval undefined");
	}

	dbg_prn("QRV=%hhu, QI=%u, MRT=%u", qrv, qi, mrt);

	gmi = qi * qrv + mrt;

	return gmi;
}

enum omci_error mcc_pkt_rec_ca_get(struct mcc_pkt *pkt,
				   union mcc_ip_addr *addr)
{
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p", pkt);

	memset(addr, 0, sizeof(*addr));

	if (pkt->info.igmp.p) {
		/* retrieve IPv4 source address */
		memcpy(addr->ipv4, &pkt->info.ip_hdr.ipv4.saddr, 4);
	} else if (pkt->info.mld.p) {
		/* retrieve IPv6 source address */
		memcpy(addr->ipv6,
		       &pkt->info.ip_hdr.ipv6.ip6_src, OMCI_IPV6_ADDR_LEN);
	} else {
		error = OMCI_ERROR;
	}

	dbg_out_ret(__func__, error);

	return error;
}
