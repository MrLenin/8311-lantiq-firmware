/******************************************************************************
 * Copyright (c) 2017 - 2018 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * For licensing information, see the file 'LICENSE' in the root folder of
 * this software module.
 *
 * Adapted from gpon_omci_onu-8.6.3:
 * - Replaced PON Adapter (pa_omci_mcc_ops / ll_ctx) with mcc_dev_ctx
 * - mcc_ip_addr defined directly in omci_mcc_dev.h (not aliased from PA)
 * - MCC_VLAN_UNTAGGED / MCC_VLAN_UNAWARE_SVID defined in omci_mcc_dev.h
 ******************************************************************************/
#ifndef _omci_mcc_core_h
#define _omci_mcc_core_h

__BEGIN_DECLS

#include "ifxos_std_defs.h"
#include "ifxos_time.h"
#include "ifxos_thread.h"
#include "ifxos_lock.h"
#include "ifxos_memory_alloc.h"

#include "mcc/omci_mcc.h"
#include "mcc/omci_mcc_dev.h"

#ifndef container_of
#include <stddef.h>
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#endif

/** Maximum sources per record*/
#define MCC_REC_SRC_MAX		64

/** Time interval to check for lost multicast groups [ms]. */
#define MCC_GROUP_ACTIVITY_DETECTION_TIMEOUT_MS		10000

#define MCC_MAX(a, b) ((a) > (b) ? (a) : (b))

#define LE2QRY(LE) container_of(LE, struct mcc_qry_entry, le)

#define LE2FLW(LE) container_of(LE, struct mcc_flw_entry, le)

#define LE2GRP(LE) container_of(LE, struct mcc_grp_entry, le)

#define LE2CLT(LE) container_of(LE, struct mcc_clt_entry, le)

#define LE2RL(LE) container_of(LE, struct mcc_rl_entry, le)

#define SRC_LE2SRC(LE) container_of(LE, struct mcc_src_entry, src_le)
#define GRP_LE2SRC(LE) container_of(LE, struct mcc_src_entry, grp_le)
#define CLT_LE2SRC(LE) container_of(LE, struct mcc_src_entry, clt_le)
#define FWD_LE2SRC(LE) container_of(LE, struct mcc_src_entry, fwd_le)
#define PRT_LE2SRC(LE) container_of(LE, struct mcc_src_entry, prt_le)

/** Protocol version .*/
enum mcc_prot_version {
	/** Protocol version Not available */
	MCC_PROT_VERSION_NA = 0,
	/** IGMP v1 protocol */
	MCC_PROT_VERSION_IGMP_V1 = 1,
	/** IGMP v2 protocol */
	MCC_PROT_VERSION_IGMP_V2 = 2,
	/** IGMP v3 protocol */
	MCC_PROT_VERSION_IGMP_V3 = 3,
	/** MLD v1 protocol */
	MCC_PROT_VERSION_MLD_V1 = 16,
	/** MLD v2 protocol */
	MCC_PROT_VERSION_MLD_V2 = 17
};

/** Multicast Group value
*/
struct mcc_group_limit_val {
	/** LAN + VID (post)*/
	uint64_t global;
	/** LAN + VID (pre) + VID (post)*/
	uint64_t service;
};

/** Multicast capacity.
*/
struct mcc_capacity {
	/** Stream count.*/
	uint32_t str;
	/** Imputed bandwidth (bytes/s).*/
	uint64_t ibw;
};

enum mcc_flt_mode {
	MCC_FLT_MODE_NA = 0,
	MCC_FLT_MODE_INCLUDE = 1,
	MCC_FLT_MODE_EXCLUDE = 2
};

/** Multicast Source Address state mode.
*/
enum mcc_src_mode {
	/** Not available.*/
	MCC_SRC_MODE_NA = 0,
	/** Allow new sources.*/
	MCC_SRC_MODE_ALLOW = 1,
	/** Block old sources. */
	MCC_SRC_MODE_BLOCK = 2
};

/** Multicast Source Address action.
*/
enum mcc_sa_action {
	/** Not available.*/
	MCC_SA_ACTION_NA = 0,
	/** Add.*/
	MCC_SA_ACTION_ADD = 1,
	/** Remove.*/
	MCC_SA_ACTION_REM = 2
};

/** List Head.
    MCC uses its own doubly-linked list rather than v4.5.0's struct list,
    because MCC manages memory directly (malloc/free) rather than through
    the list_entry_alloc/free infrastructure.
*/
struct mcc_list_head {
	/** Next*/
	struct mcc_list_head *next;
	/** Prev*/
	struct mcc_list_head *prev;
};

/** List.
*/
struct mcc_list {
	/** List head.*/
	struct mcc_list_head head;
	/** Number of list entries.*/
	uint32_t num;
};

/** Initialize MCC list head */
static inline void mcc_list_init(struct mcc_list *list)
{
	list->head.next = &list->head;
	list->head.prev = &list->head;
	list->num = 0;
}

/** Add entry after a given position */
static inline void mcc_list_add(struct mcc_list_head *entry,
				struct mcc_list_head *after)
{
	after->next->prev = entry;
	entry->next = after->next;
	after->next = entry;
	entry->prev = after;
}

/** Add entry to tail of list */
static inline void mcc_list_add_tail(struct mcc_list *list,
				     struct mcc_list_head *entry)
{
	mcc_list_add(entry, list->head.prev);
	list->num++;
}

/** Remove entry from list */
static inline void mcc_list_remove(struct mcc_list *list,
				   struct mcc_list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
	if (list)
		list->num--;
}

/** Check if list is empty */
static inline bool mcc_list_is_empty(const struct mcc_list *list)
{
	return list->head.next == &list->head;
}

/** Iterate for each list entry (safe for removal) */
#define MCC_LIST_FOR_EACH_SAFE(ENTRY, NEXT, PLIST) \
	for ((ENTRY) = (PLIST)->head.next, (NEXT) = (ENTRY)->next; \
	     (ENTRY) != &(PLIST)->head; \
	     (ENTRY) = (NEXT), (NEXT) = (ENTRY)->next)

/** Iterate for each list entry (not safe for removal) */
#define MCC_LIST_FOR_EACH(ENTRY, PLIST) \
	for ((ENTRY) = (PLIST)->head.next; \
	     (ENTRY) != &(PLIST)->head; \
	     (ENTRY) = (ENTRY)->next)

/** White list identifier.
*/
union mcc_wlist_id {
	struct {
		/** Class ID.*/
		uint16_t class_id;
		/** Instance ID.*/
		uint16_t instance_id;
	} field;
	uint32_t word;
};

/** Multicast Source Address entry.
*/
struct mcc_src_entry {
	/** Source IP Address */
	union mcc_ip_addr sa;
	/** Imputed bandwidth (bytes/sec)*/
	uint32_t ibw;
	/** TBD */
	uint8_t ibw_any;
	/** Lost indication */
	uint8_t lost;
	/** Static entry indicator */
	bool is_static;
	/** White list identifier.*/
	union mcc_wlist_id wlist_id;
	/** Link to client.*/
	struct mcc_clt_entry *clt;

	/** Linked list to connect src entries within Client */
	struct mcc_list_head src_le;
	/** Linked list to connect src entries within Group */
	struct mcc_list_head grp_le;
	/** Linked list (headless) to connect src entries joined from different
	    Clients */
	struct mcc_list_head clt_le;
	/** Linked list to connect src entries within Forwarding entry */
	struct mcc_list_head fwd_le;
	/** Linked list (headless) to connect src entries joined from different
	    ports */
	struct mcc_list_head prt_le;
};

/** Multicast Client entry.
*/
struct mcc_clt_entry {
	/** Client IP Address.*/
	union mcc_ip_addr ca;
	/** Source Address list*/
	struct mcc_list src_list;
	/** Filter mode*/
	enum mcc_flt_mode fmode;
	/** Source mode*/
	enum mcc_src_mode smode;
	/** Static entry indicator */
	bool is_static;
	/** Link to group. */
	struct mcc_grp_entry *grp;

	/** Linked list entry.*/
	struct mcc_list_head le;
};

/** Multicast Group entry.
*/
struct mcc_grp_entry {
	/** Destination IP Address*/
	union mcc_ip_addr da;
	/** Client list*/
	struct mcc_list clt_list;
	/** Source list.*/
	struct mcc_list src_link_list;
	/** Filter mode.*/
	enum mcc_flt_mode fmode;
	/** Static entry indicator */
	bool is_static;
	/** Lost indication */
	uint8_t lost;
	/** Activity detection timeout identifier.*/
	unsigned long act_timeout_id;
	/** Aging timeout identifier.*/
	unsigned long age_timeout_id;
	/** Link to flow.*/
	struct mcc_flw_entry *flw;

	/** Linked list entry.*/
	struct mcc_list_head le;
};

/** Multicast Flow.
*/
struct mcc_flw {
	/** Identifier. */
	uint8_t id;
	/** Port Index. */
	uint8_t port;
	/** VLAN identifier of the US Client sending IGMP/MLD requests.*/
	uint16_t cvid;
	/** VLAN identifier of the DS Multicast stream.*/
	uint16_t svid;
};

/** Multicast flow entry.
*/
struct mcc_flw_entry {
	/** Flow.*/
	struct mcc_flw flw;
	/** Group list.*/
	struct mcc_list grp_list;

	/** Linked list entry.*/
	struct mcc_list_head le;
};

/** Multicast Group record.
*/
struct mcc_rec {
	/** Unauthorized indication.*/
	uint8_t unauth;
	/** Block unauthorized indication.*/
	uint8_t pass_unauth;
	/** Discard indication.*/
	uint8_t discard;
	/** Protocol version */
	enum mcc_prot_version version;
	/** Flow.*/
	struct mcc_flw flw;
	/** Destination IP Address*/
	union mcc_ip_addr da;
	/** Client IP Address*/
	union mcc_ip_addr ca;
	/** Source IP address(es) */
	struct mcc_list src_list;
	/** Filter mode */
	enum mcc_flt_mode fmode;
	/** Source mode */
	enum mcc_src_mode smode;
};

/** Rate Limiter type.
*/
enum mcc_rl_type {
	/** Not available */
	MCC_RL_TYPE_NA = 0,
	/** Per port */
	MCC_RL_TYPE_PORT = 1,
	/** Per service */
	MCC_RL_TYPE_SERVICE = 2
};

/** Rate Limiter entry.
*/
struct mcc_rl_entry {
	/** VLAN identifier of the US Client sending IGMP/MLD requests.
	    0xFFFF value - Unspecified. */
	uint16_t cvid;
	/** Messages count since last limit.*/
	uint32_t msg_cnt;
	/** Reference time stamp since last limit.*/
	struct timespec ref_ts;
	/** Rate limit (messages/second) */
	uint32_t rate;

	/** Linked list entry.*/
	struct mcc_list_head le;
};

/** Rate Limiter.
*/
struct mcc_rl {
	/** Type.*/
	enum mcc_rl_type type;
	/** Rate Limiter list.*/
	struct mcc_list rl_list;
};

/** Multicast port.
*/
struct mcc_port {
	/** Port access lock. */
	IFXOS_lock_t lock;
	/** Join messages counter */
	uint32_t join_msg_cnt;
	/** Bandwidth exceeded messages counter */
	uint32_t exce_msg_cnt;
	/** Flow list. */
	struct mcc_list flw_list;
	/** Rate Limiter.*/
	struct mcc_rl rl;
};

/** Structure to specify Multicast Control context.
    Adapted: replaced pa_omci_mcc_ops/ll_ctx with mcc_dev_ctx. */
struct mcc_ctx {
	/** Global MCC VLAN handling mode. */
	enum mcc_vlan_mode vlan_mode;
	/** OMCI Core Context.*/
	void *ctx_core;
	/** Falcon GPE device context (replaces PA mcc_ops + ll_ctx) */
	struct mcc_dev_ctx dev;
	/** Packet thread control structure.*/
	IFXOS_ThreadCtrl_t pkt_thread_ctrl;
	/** Record to handle IGMP/MLD requests.*/
	struct mcc_rec rec;
	/** Max number of ports */
	uint32_t max_ports;
	/** Multicast port(s).*/
	struct mcc_port *port;
};

enum omci_error mcc_thread_start(struct mcc_ctx *mcc);
enum omci_error mcc_thread_stop(struct mcc_ctx *mcc);

enum omci_error mcc_group_list_clear(struct mcc_ctx *mcc,
				     const uint8_t port_idx);

struct mcc_src_entry *mcc_src_create(struct mcc_list *src_list,
				     const bool is_static,
				     struct mcc_clt_entry *clt,
				     const union mcc_ip_addr *sa,
				     const uint32_t ibw,
				     const union mcc_wlist_id *wlist_id);

void mcc_src_list_clean(struct mcc_list *list);

void mcc_flw_cleanup(struct mcc_ctx *mcc, struct mcc_list *flw_list);
void mcc_rl_delete(struct mcc_rl *rl);

uint32_t mcc_port_ibw_max_get(const struct mcc_port *port);

bool mcc_is_ipv6(const union mcc_ip_addr *ip);

void mcc_dbg_ip(const enum omci_dbg level,
		const union mcc_ip_addr *ip,
		const char *fmt, ...);

enum omci_error
mcc_port_mc_flow_control(struct mcc_ctx *mcc,
			 const uint8_t port_idx,
			 const bool add,
			 const bool is_static,
			 const struct mcc_mc_flow *flow);

enum omci_error
mcc_port_mc_flow_range_delete(struct mcc_ctx *mcc,
			      const uint8_t port_idx,
			      const bool is_static,
			      const struct mcc_mc_flow_range *flow_range);

__END_DECLS

#endif
