/******************************************************************************
 * Copyright (c) 2017 - 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 *
 * For licensing information, see the file 'LICENSE' in the root folder of
 * this software module.
 *
 * Ported from gpon_omci_onu-8.6.3 — no hardware dependency, pure protocol.
 ******************************************************************************/
#ifndef _omci_mcc_igmp_h
#define _omci_mcc_igmp_h

__BEGIN_DECLS

#include "ifxos_std_defs.h"

/** IGMP v2 header size on bytes*/
#define MCC_IGMPV2_HDR_SIZE				8
/** IGMP Membership Query message type*/
#define MCC_IGMP_TYPE_MEMBERSHIP_QUERY			0x11
/** IGMP v1 Membership Report message type*/
#define MCC_IGMP_TYPE_V1_MEMBERSHIP_REPORT		0x12
/** IGMP v2 Membership Report message type*/
#define MCC_IGMP_TYPE_V2_MEMBERSHIP_REPORT		0x16
/** IGMP v3 Membership Report message type*/
#define MCC_IGMP_TYPE_V3_MEMBERSHIP_REPORT		0x22
/** IGMP Leave Group message type*/
#define MCC_IGMP_TYPE_V2_LEAVE_GROUP			0x17
/** IGMP v2 Query message size [bytes]*/
#define MCC_IGMP_V2_QUERY_MSG_SIZE			8

 /** Include source address for filtering */
#define MCC_IGMP_IS_INCLUDE		1
/** Exclude source address from filtering */
#define MCC_IGMP_IS_EXCLUDE		2
/** Change to include source address for filtering */
#define MCC_IGMP_CHANGE_TO_INCLUDE	3
/** Change to exclude source address from filtering */
#define MCC_IGMP_CHANGE_TO_EXCLUDE	4
/** Allow new source addresses for filtering */
#define MCC_IGMP_ALLOW_NEW_SOURCES	5
/** Block old source addresses for filtering */
#define MCC_IGMP_BLOCK_OLD_SOURCES	6

#define MCC_IGMP_GROUP_REC_LIST_COUNT_MAX	10
#define MCC_IGMP_SOURCE_ADDR_LIST_COUNT_MAX	10

/** IGMP message header */
struct mcc_pkt_igmp_hdr {
	/** IGMP message type */
	uint8_t type;
	/** IGMP message code */
	uint8_t code;
	/** IGMP message checksum */
	uint16_t checksum;
	/** IP multicast group address */
	uint32_t group_addr;
#if (IFXOS_BYTE_ORDER == IFXOS_LITTLE_ENDIAN)
	uint32_t snum:16;
	uint32_t qqic:8;
	uint32_t qrv:3;
	uint32_t s:1;
	uint32_t res:4;
#elif (IFXOS_BYTE_ORDER == IFXOS_BIG_ENDIAN)
	uint32_t res:4;
	uint32_t s:1;
	uint32_t qrv:3;
	uint32_t qqic:8;
	uint32_t snum:16;
#else
# error	"Please fix <bits/endian.h>"
#endif
};

/** IGMP message header and length */
struct mcc_pkt_igmp {
	/** IGMP message header */
	struct mcc_pkt_igmp_hdr *p;
	/** IGMP message length */
	uint32_t len;
};

/** IGMPv2 group record. */
struct mcc_pkt_igmp_v2_group_record {
	/** IGMP message type */
	uint8_t type;
	/** IGMP message code */
	uint8_t code;
	/** IGMP message checksum */
	uint16_t checksum;
	/** IP multicast group address */
	uint32_t group_addr;
};

/** IGMPv3 group record. */
struct mcc_pkt_igmp_v3_group_record {
	uint8_t type;
	uint8_t aux_num;
	uint16_t s_num;
	uint32_t data[1];
};

/** IGMPv3 report. */
struct mcc_pkt_igmp_v3_report {
	uint8_t type;
	uint8_t reserved_0;
	uint16_t checksum;
	uint16_t reserved_1;
	uint16_t rec_num;
	struct mcc_pkt_igmp_v3_group_record rec[1];
};

struct mcc_pkt;

void const *mcc_igmp_prot_ctx_get(void);

__END_DECLS

#endif
