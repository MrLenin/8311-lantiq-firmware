/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_api_mcc_common.h
   IGMP demonstration code header file.
*/
#ifndef _omci_api_mcc_common_h
#define _omci_api_mcc_common_h

#include "omci_api_common.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_MCC Multicast Control

   @{
*/

#include "ifxos_time.h"
#include "ifxos_thread.h"
#include "ifxos_memory_alloc.h"
#include "ifxos_lock.h"
#ifdef LINUX
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>

/** Netdev interface name for WAN/LAN exception packets*/
#define MCC_EXCEPTION_IF_NAME			"exc"
/** Egreess Queue ID for exception packets*/
#define MCC_EXCEPTION_QID		    	0xb0
/** Exception packet maximum size*/
#define MCC_PKT_MAX_SIZE_BYTE			2048
/** IP protocol type */
#define MCC_IP_PROTO_IGMP		  		2
/** Ethertype value - IPv4 */
#define MCC_ETH_TYPE_IPV4				0x0800
/** Ethertype value - IPv6 */
#define MCC_ETH_TYPE_IPV6				0x86DD
/** Ethertype value - VLAN */
#define MCC_ETH_TYPE_802_1Q				0x8100
/** Ethertype value - S-VLAN */
#define MCC_ETH_TYPE_802_1AD			0x88A8
/** Ethertype value - C-VLAN */
#define MCC_ETH_TYPE_Q_IN_Q				0x9100

/** \todo fix this value! This value is used for adding TPID for more than
          2 VLANs.
*/
#define MCC_ETH_TYPE_PROP				0x88A8

/** IGMP v2 header size on bytes*/
#define MCC_IGMPV2_HDR_SIZE	  			8
/** IGMP Memebership Query message type*/
#define MCC_IGMP_TYPE_MEMBERSHIP_QUERY  		0x11
/** IGMP v1 Memebership Report message type*/
#define MCC_IGMP_TYPE_V1_MEMBERSHIP_REPORT		0x12
/** IGMP v2 Memebership Report message type*/
#define MCC_IGMP_TYPE_V2_MEMBERSHIP_REPORT		0x16
/** IGMP v3 Memebership Report message type*/
#define MCC_IGMP_TYPE_V3_MEMBERSHIP_REPORT		0x22
/** IGMP Leave Group message type*/
#define MCC_IGMP_TYPE_V2_LEAVE_GROUP			0x17

/** Include source address for filtering */
#define MCC_IGMP_V3_REP_REC_TYPE_CHANGE_TO_INCLUDE	3
/** Exclude source address from filtering */
#define MCC_IGMP_V3_REP_REC_TYPE_CHANGE_TO_EXCLUDE	4
/** Allow new source addresses for filtering */
#define MCC_IGMP_V3_REP_REC_TYPE_ALLOW_NEW_SOURCES	5
/** Block old source addresses for filtering */
#define MCC_IGMP_V3_REP_REC_TYPE_BLOCK_OLD_SOURCES	6

#define MCC_HEX_BYTES_PER_LINE	16
#define MCC_HEX_CHARS_PER_BYTE	3
#define MCC_HEX_CHARS_PER_LINE	(MCC_HEX_BYTES_PER_LINE * \
						MCC_HEX_CHARS_PER_BYTE + 1)

/** Prefix for debug printouts */
#define MCC_RX_DUMP_PREFIX			"mcc_rx"
/** Prefix for debug printouts */
#define MCC_TX_DUMP_PREFIX			"mcc_tx"

#ifndef ETH_ALEN
/** MAC address size [byte] */
#define ETH_ALEN 6
#endif

#define MCC_IGMP_GROUP_REC_LIST_COUNT_MAX	10
#define MCC_IGMP_SOURCE_ADDR_LIST_COUNT_MAX	10
/** Average size of IGMP packets. */
#define MCC_AVERAGE_IGMP_PACKET_SIZE 		64
/** Time interval to check for lost multicast groups [s]. */
#define MCC_LOST_GROUPS_UPDATE_TIME_SEC		10

/** Add ENTRY to the PLIST tail (or before entry if PLIST points to the entry) */
#define MCC_DLIST_ADD_TAIL(ENTRY, PLIST) \
	do { \
		(PLIST)->prev->next = (ENTRY); \
		(ENTRY)->prev = (PLIST)->prev; \
		(ENTRY)->next = (PLIST); \
		(PLIST)->prev = (ENTRY); \
	} while (0)

/** Remove ENTRY from the list */
#define MCC_DLIST_REMOVE(ENTRY) \
	do { \
		(ENTRY)->next->prev = (ENTRY)->prev; \
		(ENTRY)->prev->next = (ENTRY)->next; \
	} while (0)

/** Iterate for each PLIST element using ENTRY as iterator */
#define MCC_DLIST_FOR_EACH_SAFE(ENTRY, NEXT_ENTRY, PLIST) \
	for ((ENTRY) = (PLIST)->next, (NEXT_ENTRY) = (ENTRY)->next; \
	     (ENTRY)->next != (PLIST)->next; \
	     (ENTRY) = (NEXT_ENTRY), (NEXT_ENTRY) = (ENTRY)->next)

/** Initialize list */
#define MCC_DLIST_HEAD_INIT(PLIST) \
	do { \
		(PLIST)->next = (PLIST); \
		(PLIST)->prev = (PLIST); \
	} while (0)

/** MCC software context */
struct mcc_ctx;

/** Exception packet header */
struct mcc_pkt_exc_hdr {
	/** Exception header pointer. */
	union u_onu_exception_pkt_hdr *p;
	/** Length [bytes]. */
	uint32_t len;
};

/** VLAN tag */
struct mcc_pkt_vlan_tci {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	/** VLAN ID */
	uint16_t vid:12;
	/** CFI field */
	uint16_t cfi:1;
	/** Priority bits */
	uint16_t pcp:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
	/** Priority bits */
	uint16_t pcp:3;
	/** CFI field */
	uint16_t cfi:1;
	/** VLAN ID */
	uint16_t vid:12;
#else
# error	"Please fix <bits/endian.h>"
#endif
};

union mcc_pkt_vlan_tci_u {
	struct mcc_pkt_vlan_tci tci_bit;
	uint16_t tci;
};

/** VLAN tag */
struct mcc_pkt_vlan_tag {
	uint16_t tpid;
	union mcc_pkt_vlan_tci_u u;
};

/** MAC source and destination addresses, Ethertype, no VLAN */
struct mcc_pkt_mac0_hdr {
	/** MAC destination address */
	uint8_t  ether_dhost[ETH_ALEN];
	/** MAC source address */
	uint8_t  ether_shost[ETH_ALEN];
	/** Ethertype */
	uint16_t etype;
};

/** MAC source and destination addresses, Ethertype, single VLAN */
struct mcc_pkt_mac1_hdr {
	/** MAC destination address */
	uint8_t  ether_dhost[ETH_ALEN];
	/** MAC source address */
	uint8_t  ether_shost[ETH_ALEN];
	/** VLAN tag */
	struct mcc_pkt_vlan_tag tag;
	/** Ethertype */
	uint16_t etype;
};

/** MAC source and destination addresses, Ethertype, twp VLANs */
struct mcc_pkt_mac2_hdr {
	/** MAC destination address */
	uint8_t  ether_dhost[ETH_ALEN];
	/** MAC source address */
	uint8_t  ether_shost[ETH_ALEN];
	/** Outer VLAN tag */
	struct mcc_pkt_vlan_tag tag0;
	/** Inner VLAN tag */
	struct mcc_pkt_vlan_tag tag1;
	/** Ethertype */
	uint16_t etype;
};

/** MAC source and destination addresses, Ethertype, three VLANs */
struct mcc_pkt_mac3_hdr {
	/** MAC destination address */
	uint8_t  ether_dhost[ETH_ALEN];
	/** MAC source address */
	uint8_t  ether_shost[ETH_ALEN];
	/** Outer (first) VLAN tag */
	struct mcc_pkt_vlan_tag tag0;
	/** Second VLAN tag */
	struct mcc_pkt_vlan_tag tag1;
	/** Third VLAN tag */
	struct mcc_pkt_vlan_tag tag2;
	/** Ethertype */
	uint16_t etype;
};

/** Ethernet packet headers */
struct mcc_pkt_mac_hdr {
	/** Ethernet header, no VLAN tag */
	struct mcc_pkt_mac0_hdr *mac0_hdr;
	/** Ethernet header, one VLAN tag */
	struct mcc_pkt_mac1_hdr *mac1_hdr;
	/** Etehrnet header, two VLAN tags */
	struct mcc_pkt_mac2_hdr *mac2_hdr;
	/** Ethernet header, three VLAN tags */
	struct mcc_pkt_mac3_hdr *mac3_hdr;
	uint32_t len;
};

/** IP packet header */
struct mcc_pkt_ip_hdr {
	/** IPv4 packet header */
	struct iphdr ipv4;
	/** IPv6 packet header */
	struct ip6_hdr ipv6;
	/** Packet header length */
	uint32_t len;
};

/** IGMP message header */
struct mcc_pkt_igmp_hdr {
	/** IGMP message type */
	uint8_t type;
	/** IGMP messag ecode */
	uint8_t code;
	/** IGMP message checksum */
	uint16_t checksum;
	/** IP multicast group address */
	uint32_t group_addr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t snum: 16;
	uint32_t qqic: 8;
	uint32_t qrv: 3;
	uint32_t s: 1;
	uint32_t res: 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint32_t res: 4;
	uint32_t s: 1;
	uint32_t qrv: 3;
	uint32_t qqic: 8;
	uint32_t snum: 16;
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

/** IGMPv3 group record. */
struct mcc_pkt_igmp_v3_group_record {
	uint8_t type;
	uint8_t aux_num;
	uint16_t s_num;
	uint32_t data[0];
};

/** IGMPv3 report. */
struct mcc_pkt_igmp_v3_report {
	uint8_t type;
	uint8_t reserved_0;
	uint16_t checksum;
	uint8_t reserved_1;
	uint16_t rec_num;
	struct mcc_pkt_igmp_v3_group_record rec[0];
};

/** IPv6 (MLD) is not supported at the moment
*/
struct mcc_pkt_mld {
	uint8_t *p;
	uint32_t len;
};

/** Packet information details. */
struct mcc_pkt_info {
	/** Exception header. */
	struct mcc_pkt_exc_hdr exc_hdr;
	/** MAC header + optionally VLAN tag. */
	struct mcc_pkt_mac_hdr mac_hdr;
	/** IP header. */
	struct mcc_pkt_ip_hdr ip_hdr;
	/** IGMP packet. */
	struct mcc_pkt_igmp igmp;
	/** MLD packet. */
	struct mcc_pkt_mld mld;
};

/** Packet information and action. */
struct mcc_pkt {
	/** Length, [bytes]. */
	uint32_t len;
	/** Packet data. */
	uint8_t data[MCC_PKT_MAX_SIZE_BYTE];
	/** Indicates if the packet should be dropped. */
	bool drop;
	/** Info */
	struct mcc_pkt_info info;
};

/** Structute to define Multicast source address list. */
struct mcc_src_addr_list {
	/** Source address. For IGMP V3 only*/
	uint32_t s_addr[MCC_IGMP_SOURCE_ADDR_LIST_COUNT_MAX];
	/** Number of source */
	uint32_t s_addr_num;
};

/** Enumeration to define IGMP version number. */
enum mcc_igmp_version {
	MCC_IGMP_VERSION_NA = 0,
	MCC_IGMP_VERSION_1 = 1,
	MCC_IGMP_VERSION_2 = 2,
	MCC_IGMP_VERSION_3 = 3
};

enum mcc_mc_group_state {
	MCC_MC_GROUP_STATE_NA = -1,
	MCC_MC_GROUP_STATE_INCLUDE = 0,
	MCC_MC_GROUP_STATE_EXCLUDE = 1
};

enum mcc_src_addr_list_state {
	MCC_SRC_ADDR_LIST_STATE_NA = 0,
	MCC_SRC_ADDR_LIST_STATE_ALLOW_NEW_SOURCES = 1,
	MCC_SRC_ADDR_LIST_STATE_BLOCK_OLD_SOURCES = 2
};

/** Structute to define Multicast group data. */
struct mcc_mc_group {
	/** IGMP version */
	enum mcc_igmp_version igmp_v;
	/** Group address */
	uint32_t g_addr;
	/** Multicast group state. */
	enum mcc_mc_group_state g_state;
	/** Source Address list*/
	struct mcc_src_addr_list s_addr_list;
	/** Source Address list state. Valid for IGMP V3 only. */
	enum mcc_src_addr_list_state s_addr_list_state;
	/** Client (set-top box) IP address, that is, the IP address of the
	    device currently joined/leaved*/
	uint32_t c_addr;
	/** VLAN Tag. Value 0 designates an untagged flow*/
	union mcc_pkt_vlan_tci_u vlan;
};

struct mcc_igmp_group_record_list {
	struct mcc_mc_group rec[MCC_IGMP_GROUP_REC_LIST_COUNT_MAX];
	/** Multicast group address list. */
	/** Number of valid entries in the list. */
	uint16_t count;
};

/** IGMP action types. */
enum mcc_group_action_type {
	/** Just an init value */
	GROUP_ACTION_NONE = 0,
	/** Group address add */
	GROUP_ACTION_GADDR_ADD = 1,
	/** Group address remove */
	GROUP_ACTION_GADDR_REM = 2,
	/** Source address(es) add */
	GROUP_ACTION_SADDR_ADD = 3,
	/** Source address(es) remove */
	GROUP_ACTION_SADDR_REM = 4
};


struct mcc_igmp_action_data {
	struct mcc_igmp_group_record_list rec_list;
};

struct mcc_igmp_action;

typedef enum omci_api_return (*mcc_igmp_action_do_t) (struct mcc_ctx *mcc,
				     struct mcc_pkt *pkt,
				     struct mcc_igmp_action *action);

struct mcc_igmp_action {
	struct mcc_igmp_action_data data;
	mcc_igmp_action_do_t act_do;
};

struct mcc_profile_status {
	/** IGMP rate limiter enabled/disabled */
	bool igmp_policer_enabled;
	/** IGMP rate limiter index */
	uint32_t igmp_policer_index;
};

/** Subscriber status */
struct mcc_subscr_status {
	uint32_t added_groups_count;
};

/** Added multicast group information. */
struct mcc_added_group {
	/** Multicat Group */
	struct mcc_mc_group group;
	/** LAN port index */
	uint8_t lan_port;
	/** Flow ID */
	uint8_t fid;
	/** Loss indication*/
	bool lost;
	/** Last update time (sec)*/
	time_t last_update;
	/** Time Stamp (sec)*/
	time_t ts;
	/** Imputed group bandwidth*/
	uint32_t bw;
};

/** Added multicast group information list. */
struct mcc_added_groups_list_entry {
	/** Entry */
	struct mcc_added_group entry;
	/** Next entry */
	struct mcc_added_groups_list_entry *next;
	/** Previous entry */
	struct mcc_added_groups_list_entry *prev;
};

/** Added multicast group information list. */
struct mcc_added_groups_list {
	/** MCC groups list head */
	struct mcc_added_groups_list_entry list_head;
	/** Number of entries in the list */
	uint32_t entries_num;
};

/** Structure to specify Multicast Control context.
*/
struct mcc_ctx {
	/** Thread run flag */
	bool run;
	/** ONU driver fd */
	int onu_fd;
	/** Remote ONU indication */
	bool remote;
	/** OMCI API context */
	void *api_ctx;
	/** ONU device GPE capability list */
	struct gpe_capability gpe_cap;
	/** Packet thread control structure */
	IFXOS_ThreadCtrl_t mcc_pkt_thread_ctrl;
	/** Control thread control structure */
	IFXOS_ThreadCtrl_t mcc_ctl_thread_ctrl;
	/** callback */
	omci_api_mcc_cb_t *callback;
	/** Exception RAW socket */
	int s;
	/** RAW socket addr structure */
	struct sockaddr_ll sll;
	/** Configuration access lock. */
	IFXOS_lock_t lock;
	/** IGMP/MLD multicast control packet */
	struct mcc_pkt pkt;
	/** Profiles */
	struct omci_api_mcc_profile profile[OMCI_API_MCC_MAX_PROFILES];
	/** Subscribers */
	struct omci_api_mcc_subscr_cfg subscr[OMCI_API_MCC_MAX_SUBSCRIBERS];
	/** Profile status */
	struct mcc_profile_status profile_status[OMCI_API_MCC_MAX_PROFILES];
	/** Subscriber's status */
	struct omci_api_mcc_subscr_status subscr_status[OMCI_API_MCC_MAX_SUBSCRIBERS];
	/** MC active groups list assigned to subscribers*/
	struct mcc_added_groups_list added_groups_list[OMCI_API_MCC_MAX_SUBSCRIBERS];
	/** Unassigned MC active groups list*/
	struct mcc_added_groups_list unassigned_groups_list;
	/** Groups list access lock. */
	IFXOS_lock_t groups_list_lock;
};

/** MCC software start. */
enum omci_api_return mcc_start(struct omci_api_ctx *ctx);

/** MCC software initialization. */
enum omci_api_return mcc_init(struct omci_api_ctx *ctx);

/** MCC software termination. */
enum omci_api_return mcc_exit(struct omci_api_ctx *ctx);

#endif /* LINUX */

/** @} */

__END_DECLS

#endif
