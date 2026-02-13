/******************************************************************************
 * Copyright (c) 2017 - 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * For licensing information, see the file 'LICENSE' in the root folder of
 * this software module.
 *
 * Adapted from gpon_omci_onu-8.6.3: replaced pa_mcc_pkt_info with
 * mcc_pkt_ll_info (our Falcon-specific lower layer info).
 ******************************************************************************/
#ifndef _omci_mcc_pkt_h
#define _omci_mcc_pkt_h

__BEGIN_DECLS

#include "ifxos_std_defs.h"

#if defined(LINUX)
#  include <netinet/ip.h>
#  include <netinet/ip6.h>
#  include <net/ethernet.h>
#  include <net/if.h>
#endif

#include "mcc/omci_mcc_igmp.h"
#include "mcc/omci_mcc_mld.h"

#define MCC_IS_INCLUDE		MCC_IGMP_IS_INCLUDE
#define MCC_IS_EXCLUDE		MCC_IGMP_IS_EXCLUDE
#define MCC_CHANGE_TO_INCLUDE	MCC_IGMP_CHANGE_TO_INCLUDE
#define MCC_CHANGE_TO_EXCLUDE	MCC_IGMP_CHANGE_TO_EXCLUDE
#define MCC_ALLOW_NEW_SOURCES	MCC_IGMP_ALLOW_NEW_SOURCES
#define MCC_BLOCK_OLD_SOURCES	MCC_IGMP_BLOCK_OLD_SOURCES

/** Default Query Interval, [ms].*/
#define MCC_QUERY_INTERVAL_DEFAULT		125000
/** Default Query Robustness Variable.*/
#define MCC_QUERY_ROBUSTNESS_DEFAULT		2
/** Default Query Response Interval, [ms].*/
#define MCC_QUERY_RESPONSE_INTERVAL_DEFAULT	10000

/** Exception packet maximum size*/
#define MCC_PKT_MAX_SIZE_BYTE				2048
/** IP protocol type IGMP*/
#define MCC_IP_PROTO_IGMP				2
/** IP protocol type IPv6 Route*/
#define MCC_IP_PROTO_IPV6_ROUTE				0x2B
/** IP protocol type IPv6 Destination Options*/
#define MCC_IP_PROTO_IPV6_OPTS				0x3C
/** IP protocol type IPv6 ICMP*/
#define MCC_IP_PROTO_IPV6_ICMP				0x3A
/** IP protocol type IPv6 Hop-by-Hop*/
#define MCC_IP_PROTO_IPV6_HOP_BY_HOP			0x0
/** TLV for MLD */
#define MCC_TLV_MLD					0x05020000UL
/** Ethertype value - IPv4 */
#define MCC_ETH_TYPE_IPV4				0x0800
/** Ethertype value - IPv6 */
#define MCC_ETH_TYPE_IPV6				0x86DD
/** Ethertype value - VLAN */
#define MCC_ETH_TYPE_802_1Q				0x8100
/** Ethertype value - S-VLAN */
#define MCC_ETH_TYPE_802_1AD				0x88A8
/** Ethertype value - C-VLAN */
#define MCC_ETH_TYPE_Q_IN_Q				0x9100
#define MCC_IPV6_EXT_HDR_UNIT_LEN			8
/** IPv6 maximum length of recursion within extended headers */
#define MCC_IPV6_EXT_HDR_MAX_REC_LEN			114
/** PPPoE Session Stage */
#define MCC_PPPOE_SESSION_STAGE				0x8864

#define MCC_ETH_TYPE_PROP				0x88A8

#ifndef LINUX
struct iphdr {
#if (IFXOS_BYTE_ORDER == IFXOS_LITTLE_ENDIAN)
	uint8_t	ihl:4,
		version:4;
#elif (IFXOS_BYTE_ORDER == IFXOS_BIG_ENDIAN)
	uint8_t	version:4,
		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	uint8_t	tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t	ttl;
	uint8_t	protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
};

struct in6_addr {
	union {
		uint8_t	__u6_addr8[16];
		uint16_t __u6_addr16[8];
		uint32_t __u6_addr32[4];
	} __in6_u;
};

struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			uint32_t ip6_un1_flow;
			uint16_t ip6_un1_plen;
			uint8_t  ip6_un1_nxt;
			uint8_t  ip6_un1_hlim;
		} ip6_un1;
		uint8_t ip6_un2_vfc;
	} ip6_ctlun;
	struct in6_addr ip6_src;
	struct in6_addr ip6_dst;
};

struct ip6_ext {
	uint8_t ip6e_nxt;
	uint8_t ip6e_len;
};

#ifndef CYGPKG_NET_LWIP
struct in_addr {
	uint32_t s_addr;
};
#endif

#endif /* #ifndef LINUX*/

/** IP packet header */
struct mcc_pkt_ip_hdr {
	/** IPv4 packet header */
	struct iphdr ipv4;
	/** IPv6 packet header */
	struct ip6_hdr ipv6;
	/** Packet header length */
	uint32_t len;
};

struct mcc_pkt;

/** Enumeration to define IGMP/MLD protocol version number. */
enum mcc_pkt_version {
	/** Undefined and/or not available. */
	MCC_PKT_VERSION_NA = 0,
	/** IGMP protocol version 1. */
	MCC_PKT_IGMP_VERSION_1 = 1,
	/** IGMP protocol version 2. */
	MCC_PKT_IGMP_VERSION_2 = 2,
	/** IGMP protocol version 3. */
	MCC_PKT_IGMP_VERSION_3 = 3,
	/** MLD protocol version 1. */
	MCC_PKT_MLD_VERSION_1 = 4,
	/** MLD protocol version 2. */
	MCC_PKT_MLD_VERSION_2 = 5
};

/** MCC Protocol context.*/
struct mcc_pkt_protocol_context {
	/** IGMP/MLD version get handler. */
	enum mcc_pkt_version (*version_get)(struct mcc_pkt *pkt);
	/** Is supported handler. */
	bool (*is_supported)(struct mcc_pkt *pkt);
	/** Type get handler. */
	uint8_t (*type_get)(struct mcc_pkt *pkt);
	/** Group Address get handler. */
	void (*ga_get)(struct mcc_pkt *pkt, union mcc_ip_addr *addr);

	/** Record number get handler. */
	uint16_t (*rec_num_get)(struct mcc_pkt *pkt);
	/** Record Source Address number get handler. */
	uint16_t (*rec_snum_get)(struct mcc_pkt *pkt, const void *p_rec);
	/** Record get handler. */
	void* (*rec_get)(struct mcc_pkt *pkt, const uint16_t rec_idx);
	/** Record Type get handler. */
	uint8_t (*rec_type_get)(struct mcc_pkt *pkt, const void *p_rec);
	/** Record Group Address get handler. */
	void (*rec_ga_get)(struct mcc_pkt *pkt,
			   const void *p_rec,
			   union mcc_ip_addr *addr);
	/** Record Source Address get handler. */
	void (*rec_sa_get)(struct mcc_pkt *pkt,
			   const void *p_rec,
			   const uint16_t s_idx,
			   union mcc_ip_addr *addr);

	/** Maximum Response Delay get handler. */
	uint32_t (*max_resp_delay_get)(struct mcc_pkt *pkt);

	/** Query QQIC get handler. */
	uint8_t (*query_qqic_get)(struct mcc_pkt *pkt);

	/** Query Robustness Variable get handler. */
	uint8_t (*query_qrv_get)(struct mcc_pkt *pkt);
};

/** MC packet type. */
enum mcc_pkt_type {
	/** Not available and/or undefined. */
	MCC_PKT_TYPE_NA = -1,
	/** IGMP Query packet. */
	MCC_PKT_TYPE_IGMP_QUERY = 0,
	/** IGMPv1 Report packet. */
	MCC_PKT_TYPE_IGMP_V1_REPORT = 1,
	/** IGMPv2 Report packet. */
	MCC_PKT_TYPE_IGMP_V2_REPORT = 2,
	/** IGMPv3 Leave packet. */
	MCC_PKT_TYPE_IGMP_V2_LEAVE = 3,
	/** IGMPv3 Report packet. */
	MCC_PKT_TYPE_IGMP_V3_REPORT = 4,
	/** MLD Query packet. */
	MCC_PKT_TYPE_MLD_QUERY = 5,
	/** MLDv1 Report packet. */
	MCC_PKT_TYPE_MLD_V1_REPORT = 6,
	/** MLDv1 Done packet. */
	MCC_PKT_TYPE_MLD_V1_DONE = 7,
	/** MLDv2 Report packet. */
	MCC_PKT_TYPE_MLD_V2_REPORT = 8
};

/** Packet information details.
    Adapted: uses mcc_pkt_ll_info instead of pa_mcc_pkt_info. */
struct mcc_pkt_info {
	/** IP header. */
	struct mcc_pkt_ip_hdr ip_hdr;
	/** IGMP packet. */
	struct mcc_pkt_igmp igmp;
	/** MLD packet. */
	struct mcc_pkt_mld mld;
	/** Packet type. */
	enum mcc_pkt_type pkt_type;
	/** Protocol context. */
	struct mcc_pkt_protocol_context *prot_ctx;

	/** Info provided from lower layer receive.
	    Replaces pa_mcc_pkt_info from v8.6.3. */
	struct mcc_pkt_ll_info llinfo;
};

/** Packet information and action. */
struct mcc_pkt {
	/** Length, [bytes]. */
	uint16_t len;
	/** Packet data. */
	uint8_t data[MCC_PKT_MAX_SIZE_BYTE];
	/** Indicates if the packet should be dropped. */
	bool drop;
	/** Info */
	struct mcc_pkt_info info;
};

/** MC packet record type. */
enum mcc_pkt_rec_type {
	/** Undefined or not available. */
	MCC_PKT_REC_TYPE_NA = -1,
	/** Record type is INCLUDE */
	MCC_PKT_REC_TYPE_INCLUDE = 0,
	/** Record type is EXCLUDE */
	MCC_PKT_REC_TYPE_EXCLUDE = 1,
	/** Record type is ALLOW */
	MCC_PKT_REC_TYPE_ALLOW = 2,
	/** Record type is BLOCK */
	MCC_PKT_REC_TYPE_BLOCK = 3
};

enum omci_error mcc_pkt_receive(struct mcc_ctx *mcc,
				struct mcc_pkt *pkt);

enum omci_error mcc_pkt_send(struct mcc_ctx *mcc,
			     struct mcc_pkt *pkt);

uint8_t mcc_pkt_port_idx_get(const struct mcc_pkt_info *pkt_info);

uint16_t mcc_pkt_cvid_get(const struct mcc_pkt_info *pkt_info);

uint16_t mcc_pkt_svid_get(const struct mcc_pkt_info *pkt_info);

bool mcc_pkt_is_igmp(struct mcc_pkt *pkt);

bool mcc_pkt_is_mld(struct mcc_pkt *pkt);

enum omci_error mcc_pkt_type_get(struct mcc_pkt *pkt,
				 enum mcc_pkt_type *type);

enum omci_error mcc_pkt_rec_sa_get(struct mcc_pkt *pkt,
				   const uint16_t rec_idx,
				   const uint16_t s_idx,
				   union mcc_ip_addr *addr);

enum omci_error mcc_pkt_da_get(struct mcc_pkt *pkt, union mcc_ip_addr *addr);

enum omci_error mcc_pkt_rec_ga_get(struct mcc_pkt *pkt,
				   const uint16_t rec_idx,
				   union mcc_ip_addr *addr);

uint32_t mcc_pkt_gmi_get(struct mcc_pkt *pkt);

enum omci_error mcc_pkt_rec_ca_get(struct mcc_pkt *pkt,
				   union mcc_ip_addr *addr);

__END_DECLS

#endif
