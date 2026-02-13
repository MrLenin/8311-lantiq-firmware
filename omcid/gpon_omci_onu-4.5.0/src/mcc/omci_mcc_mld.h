/******************************************************************************
 * Copyright (c) 2017 - 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 *
 * For licensing information, see the file 'LICENSE' in the root folder of
 * this software module.
 *
 * Ported from gpon_omci_onu-8.6.3 — no hardware dependency, pure protocol.
 ******************************************************************************/
#ifndef _omci_mcc_mld_h
#define _omci_mcc_mld_h

__BEGIN_DECLS

#include "ifxos_std_defs.h"

/** IPv6 address length in bytes */
#ifndef OMCI_IPV6_ADDR_LEN
#define OMCI_IPV6_ADDR_LEN 16
#endif

/** MLD Listener Query message type*/
#define MCC_MLD_TYPE_LISTENER_QUERY		130
/** MLD Listener Report message type*/
#define MCC_MLD_TYPE_LISTENER_REPORT		131
/** MLD Listener Done message type*/
#define MCC_MLD_TYPE_LISTENER_DONE		132
/** MLD V2 Listener Report message type*/
#define MCC_MLD_TYPE_LISTENER_V2_REPORT		143

/** MLD v1 Query message size [bytes]*/
#define MCC_MLD_V1_QUERY_MSG_SIZE		8

/** Include source address for filtering */
#define MCC_MLD_CHANGE_TO_INCLUDE	3
/** Exclude source address from filtering */
#define MCC_MLD_CHANGE_TO_EXCLUDE	4
/** Allow new source addresses for filtering */
#define MCC_MLD_ALLOW_NEW_SOURCES	5
/** Block old source addresses for filtering */
#define MCC_MLD_BLOCK_OLD_SOURCES	6

/** MLD message header */
struct mcc_pkt_mld_hdr {
	/** Type*/
	uint8_t type;
	/** Code*/
	uint8_t code;
	/** Checksum*/
	uint16_t csum;
	/** Maximum response delay*/
	uint16_t max_resp_delay;
	/** Reserved*/
	uint16_t reserved;
	/** Multicast Address*/
	uint8_t mc_addr[OMCI_IPV6_ADDR_LEN];
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

/** MLD message header and length */
struct mcc_pkt_mld {
	struct mcc_pkt_mld_hdr *p;
	uint32_t len;
};

/** MLDv1 group record. */
struct mcc_pkt_mld_v1_group_record {
	/** MLD message type */
	uint8_t type;
	/** MLD message code */
	uint8_t code;
	/** MLD message checksum */
	uint16_t checksum;
	/** Maximum response delay*/
	uint16_t max_resp_delay;
	/** Reserved*/
	uint16_t reserved;
	/** Multicast Address*/
	uint8_t mc_addr[OMCI_IPV6_ADDR_LEN];
};

/** MLDv2 group record. */
struct mcc_pkt_mld_v2_group_record {
	uint8_t type;
	uint8_t aux_num;
	uint16_t s_num;
	struct {
		uint8_t mc_addr[OMCI_IPV6_ADDR_LEN];
	} data[1];
};

/** MLDv2 report. */
struct mcc_pkt_mld_v2_report {
	uint8_t type;
	uint8_t reserved_0;
	uint16_t checksum;
	uint16_t reserved_1;
	uint16_t rec_num;
	struct mcc_pkt_mld_v2_group_record rec[1];
};

void const *mcc_mld_prot_ctx_get(void);

__END_DECLS

#endif
