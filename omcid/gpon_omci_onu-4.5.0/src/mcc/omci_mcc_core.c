/******************************************************************************
 * Copyright (c) 2017 - 2019 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 * Copyright (c) 2025 8311 Contributors
 *
 * MCC core: group/flow/client/source management, rate limiting, bandwidth
 * enforcement, activity detection, and forwarding state machine.
 *
 * Ported from gpon_omci_onu-8.6.3 with these adaptations:
 * - DLIST_* macros replaced with MCC_LIST_* (defined in omci_mcc_core.h)
 * - PA abstraction calls replaced with direct mcc_dev_* calls
 * - PA_MCC_DIR_DS/US replaced with MCC_DIR_DS/US
 * - OMCI_ERROR_RESOURCE_NOT_FOUND/MATCH_NOT_FOUND mapped to OMCI_ERROR
 ******************************************************************************/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_MCC

#include <stdarg.h>
#include <inttypes.h>

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_timeout.h"
#include "mcc/omci_mcc_core.h"
#include "mcc/omci_mcc_pkt.h"
#include "mcc/omci_mcc_dev.h"
#include "mcc/omci_mcc_omci.h"

/** IOP option 0: changes IGMPv2 → IPv4+MLD, and forces unauthorized passing */
#ifndef OMCI_IOP_OPTION_0
#define OMCI_IOP_OPTION_0 0
#endif

/* ======================================================================
 * IP address utilities
 * ====================================================================== */

bool mcc_is_ipv6(const union mcc_ip_addr *ip)
{
	return ip->ipv6[0] == 0xFF ? true : false;
}

static bool mcc_is_ip_any(const union mcc_ip_addr *ip)
{
	static const union mcc_ip_addr sa_any;

	return memcmp(&sa_any, ip, sizeof(ip->ipv6)) == 0 ? true : false;
}

void mcc_dbg_ip(const enum omci_dbg level,
		const union mcc_ip_addr *ip,
		const char *fmt, ...)
{
	char ip_str[64];
	bool ipv6 = mcc_is_ipv6(ip);
	va_list args;

	if (ipv6)
		sprintf(ip_str,
			"%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
			ip->ipv6[0],  ip->ipv6[1],  ip->ipv6[2],  ip->ipv6[3],
			ip->ipv6[4],  ip->ipv6[5],  ip->ipv6[6],  ip->ipv6[7],
			ip->ipv6[8],  ip->ipv6[9],  ip->ipv6[10], ip->ipv6[11],
			ip->ipv6[12], ip->ipv6[13], ip->ipv6[14], ip->ipv6[15]);
	else
		sprintf(ip_str, "%hhu.%hhu.%hhu.%hhu",
			ip->ipv4[0], ip->ipv4[1], ip->ipv4[2], ip->ipv4[3]);

	dbg(level, "[%s] ", ip_str);

	va_start(args, fmt);
	dbg_vnaked(level, dbg_module, fmt, args);
	va_end(args);
	dbg_naked(level, dbg_module, "\n");
}

/** Convert raw 16-byte IP representation (IPv4-mapped or IPv6) to mcc_ip_addr.
    IPv6: first byte == 0xFF, copy all 16 bytes.
    IPv4: bytes 12-15 contain IPv4 address. */
static void mcc_ip_addr_get(const uint8_t ip_raw[16],
			    union mcc_ip_addr *mc_ip)
{
	memset(mc_ip, 0, sizeof(*mc_ip));

	if (ip_raw[0] == 0xFF) /* IPv6 */
		memcpy(mc_ip->ipv6, ip_raw, sizeof(mc_ip->ipv6));
	else /* IPv4 */
		memcpy(mc_ip->ipv4, &ip_raw[12], sizeof(mc_ip->ipv4));
}

/* ======================================================================
 * Source address list management
 * ====================================================================== */

/** Find source address list entry by SA */
static struct mcc_src_entry *
mcc_src_find(const struct mcc_list *src_list, const union mcc_ip_addr *sa)
{
	struct mcc_src_entry *e;
	struct mcc_list_head *le, *nle;

	if (src_list->num == 0)
		return NULL;

	MCC_LIST_FOR_EACH_SAFE(le, nle, src_list) {
		e = SRC_LE2SRC(le);
		if (memcmp(&e->sa, sa, sizeof(*sa)) == 0)
			return e;
	}

	return NULL;
}

/** Create and add source address entry to list */
struct mcc_src_entry *mcc_src_create(struct mcc_list *src_list,
				     const bool is_static,
				     struct mcc_clt_entry *clt,
				     const union mcc_ip_addr *sa,
				     const uint32_t ibw,
				     const union mcc_wlist_id *wlist_id)
{
	struct mcc_src_entry *e;

	e = IFXOS_MemAlloc(sizeof(*e));
	if (e == NULL)
		return NULL;

	memset(e, 0, sizeof(*e));
	memcpy(&e->sa, sa, sizeof(*sa));
	e->ibw = ibw;
	e->ibw_any = 0;
	e->lost = 0;
	e->is_static = is_static;
	e->clt = clt;

	if (wlist_id != NULL)
		memcpy(&e->wlist_id, wlist_id, sizeof(e->wlist_id));

	/* Initialize all linked list heads */
	e->grp_le.next = &e->grp_le;
	e->grp_le.prev = &e->grp_le;
	e->clt_le.next = &e->clt_le;
	e->clt_le.prev = &e->clt_le;
	e->fwd_le.next = &e->fwd_le;
	e->fwd_le.prev = &e->fwd_le;
	e->prt_le.next = &e->prt_le;
	e->prt_le.prev = &e->prt_le;

	if (src_list)
		mcc_list_add_tail(src_list, &e->src_le);

	return e;
}

/** Delete source entry from list and free.
    Removes from all linked lists (grp, clt, src). */
static void mcc_src_delete(struct mcc_list *src_list,
			   struct mcc_src_entry *e)
{
	if (src_list->num == 0)
		return;

	/* Remove from group and client link lists */
	mcc_list_remove(NULL, &e->grp_le);
	mcc_list_remove(NULL, &e->clt_le);
	/* Remove from source list */
	mcc_list_remove(src_list, &e->src_le);
	IFXOS_MemFree(e);
}

static void mcc_src_update(struct mcc_src_entry *e)
{
	e->lost = 0;
}

static void mcc_src_wlist_id_set(struct mcc_src_entry *e,
				 const union mcc_wlist_id *wlist_id)
{
	memcpy(&e->wlist_id, wlist_id, sizeof(*wlist_id));
}

/** Clean source list: remove duplicates and collapse *any source* entries.
    If 0.0.0.0 (any source) exists, remove everything except that entry.
    Then remove any remaining duplicates. */
void mcc_src_list_clean(struct mcc_list *list)
{
	struct mcc_src_entry *e, *ref_e;
	struct mcc_list_head *le, *nle, *ref_le, *ref_nle;
	union mcc_ip_addr src_any;

	if (list->num == 0)
		return;

	/* Check for *any source* entry */
	memset(&src_any, 0, sizeof(src_any));

	if (mcc_src_find(list, &src_any)) {
		/* Remove everything except the *any source* entry */
		MCC_LIST_FOR_EACH_SAFE(le, nle, list) {
			e = SRC_LE2SRC(le);
			if (memcmp(&e->sa, &src_any, sizeof(src_any)) == 0)
				continue;
			mcc_src_delete(list, e);
		}
	}

	/* Remove duplicate entries */
	MCC_LIST_FOR_EACH_SAFE(ref_le, ref_nle, list) {
		ref_e = SRC_LE2SRC(ref_le);

		MCC_LIST_FOR_EACH_SAFE(le, nle, list) {
			e = SRC_LE2SRC(le);
			if (ref_e == e)
				continue;
			if (memcmp(&ref_e->sa, &e->sa, sizeof(e->sa)) == 0)
				mcc_src_delete(list, e);
		}
	}
}

/** Subtract list2 from list1 (remove matching entries from list1) */
static void mcc_src_list_subtract(struct mcc_list *list1,
				   const struct mcc_list *list2)
{
	struct mcc_src_entry *e1, *e2;
	struct mcc_list_head *l1e, *nl1e, *l2e, *nl2e;

	if (list1->num == 0 || list2->num == 0)
		return;

	MCC_LIST_FOR_EACH_SAFE(l1e, nl1e, list1) {
		e1 = SRC_LE2SRC(l1e);

		MCC_LIST_FOR_EACH_SAFE(l2e, nl2e, list2) {
			e2 = SRC_LE2SRC(l2e);
			if (memcmp(&e1->sa, &e2->sa, sizeof(e1->sa)) == 0)
				mcc_src_delete(list1, e1);
		}
	}
}

/** Create new source list as copy of list2 */
static enum omci_error mcc_src_list_create(struct mcc_list *list1,
					   const struct mcc_list *list2)
{
	struct mcc_src_entry *e, *src;
	struct mcc_list_head *le, *nle;

	if (list2->num == 0)
		return OMCI_SUCCESS;

	MCC_LIST_FOR_EACH_SAFE(le, nle, list2) {
		e = SRC_LE2SRC(le);
		src = mcc_src_create(list1, e->is_static, NULL,
				     &e->sa, e->ibw, &e->wlist_id);
		if (!src)
			return OMCI_ERROR_MEMORY;
	}

	return OMCI_SUCCESS;
}

/** Delete all entries in source list */
static void mcc_src_list_delete(struct mcc_list *src_list)
{
	struct mcc_src_entry *e;
	struct mcc_list_head *le, *nle;

	if (src_list->num == 0)
		return;

	MCC_LIST_FOR_EACH_SAFE(le, nle, src_list) {
		e = SRC_LE2SRC(le);
		mcc_src_delete(src_list, e);
	}
}

/** Get source action based on filter mode and source mode.
    Returns ADD if sources should be added to filter, REM if removed. */
static enum mcc_sa_action
mcc_src_list_action_get(const enum mcc_flt_mode fmode,
			const enum mcc_src_mode smode)
{
	if (smode == MCC_SRC_MODE_NA)
		return MCC_SA_ACTION_ADD;

	if ((smode == MCC_SRC_MODE_ALLOW && fmode == MCC_FLT_MODE_INCLUDE) ||
	    (smode == MCC_SRC_MODE_BLOCK && fmode == MCC_FLT_MODE_EXCLUDE))
		return MCC_SA_ACTION_ADD;

	if ((smode == MCC_SRC_MODE_ALLOW && fmode == MCC_FLT_MODE_EXCLUDE) ||
	    (smode == MCC_SRC_MODE_BLOCK && fmode == MCC_FLT_MODE_INCLUDE))
		return MCC_SA_ACTION_REM;

	return MCC_SA_ACTION_NA;
}

/* ======================================================================
 * Client management
 * ====================================================================== */

static struct mcc_clt_entry *mcc_clt_find(const struct mcc_list *clt_list,
					  const union mcc_ip_addr *ca)
{
	struct mcc_clt_entry *e;
	struct mcc_list_head *le, *nle;

	if (clt_list->num == 0)
		return NULL;

	MCC_LIST_FOR_EACH_SAFE(le, nle, clt_list) {
		e = LE2CLT(le);
		if (memcmp(&e->ca, ca, sizeof(*ca)) == 0)
			return e;
	}

	return NULL;
}

/** Get next client after the specified one (or first if clt==NULL) */
static struct mcc_clt_entry *mcc_clt_next(const struct mcc_list *clt_list,
					  struct mcc_clt_entry *clt)
{
	struct mcc_clt_entry *e;
	struct mcc_list_head *le, *nle;

	if (clt_list->num == 0)
		return NULL;

	MCC_LIST_FOR_EACH_SAFE(le, nle, clt_list) {
		e = LE2CLT(le);
		if (clt == NULL)
			return e;
		if (e == clt)
			return (nle != &clt_list->head) ? LE2CLT(nle) : NULL;
	}

	return NULL;
}

static struct mcc_clt_entry *mcc_clt_create(struct mcc_list *clt_list,
					    struct mcc_grp_entry *grp,
					    const bool is_static,
					    const union mcc_ip_addr *ca)
{
	struct mcc_clt_entry *e;

	e = IFXOS_MemAlloc(sizeof(*e));
	if (e == NULL)
		return NULL;

	memset(e, 0, sizeof(*e));
	memcpy(&e->ca, ca, sizeof(*ca));
	mcc_list_init(&e->src_list);
	e->fmode = MCC_FLT_MODE_INCLUDE;
	e->smode = MCC_SRC_MODE_NA;
	e->is_static = is_static;
	e->grp = grp;

	mcc_list_add_tail(clt_list, &e->le);

	return e;
}

static void mcc_clt_delete(struct mcc_list *clt_list, struct mcc_clt_entry *clt)
{
	if (clt_list->num == 0)
		return;

	mcc_src_list_delete(&clt->src_list);
	mcc_list_remove(clt_list, &clt->le);
	IFXOS_MemFree(clt);
}

static void mcc_clt_list_delete(struct mcc_list *clt_list)
{
	struct mcc_clt_entry *e;
	struct mcc_list_head *le, *nle;

	if (clt_list->num == 0)
		return;

	MCC_LIST_FOR_EACH_SAFE(le, nle, clt_list) {
		e = LE2CLT(le);
		mcc_src_list_delete(&e->src_list);
		mcc_clt_delete(clt_list, e);
	}
}

static inline void mcc_clt_fmode_set(const enum mcc_flt_mode mode,
				     struct mcc_clt_entry *clt)
{
	if (mode != MCC_FLT_MODE_NA)
		clt->fmode = mode;
}

static inline void mcc_clt_smode_set(const enum mcc_src_mode mode,
				     struct mcc_clt_entry *clt)
{
	if (mode != MCC_SRC_MODE_NA)
		clt->smode = mode;
}

/** Refresh client source list based on current filter/source mode.
    May delete the client if it becomes empty in INCLUDE mode. */
static enum omci_error mcc_clt_refresh(struct mcc_ctx *mcc,
				       const struct mcc_list *src_list,
				       struct mcc_list *clt_list,
				       struct mcc_clt_entry *clt)
{
	enum mcc_sa_action action;
	struct mcc_src_entry *e, *src;
	struct mcc_list_head *le, *nle;

	if (clt->smode == MCC_SRC_MODE_NA)
		mcc_src_list_delete(&clt->src_list);

	action = mcc_src_list_action_get(clt->fmode, clt->smode);

	if (action != MCC_SA_ACTION_NA) {
		MCC_LIST_FOR_EACH_SAFE(le, nle, src_list) {
			e = SRC_LE2SRC(le);
			src = mcc_src_find(&clt->src_list, &e->sa);
			if (action == MCC_SA_ACTION_ADD) {
				if (!src) {
					src = mcc_src_create(&clt->src_list,
							     e->is_static,
							     clt, &e->sa,
							     e->ibw,
							     &e->wlist_id);
					if (!src)
						return OMCI_ERROR_MEMORY;
				} else {
					mcc_src_update(src);
				}
			} else {
				if (src) {
					if ((src->is_static && clt->is_static) ||
					    (!src->is_static && !clt->is_static))
						mcc_src_delete(&clt->src_list, src);
				}
			}
		}

		/* If changed to INCLUDE, remove dummy 0.0.0.0 entry */
		if (clt->fmode == MCC_FLT_MODE_INCLUDE) {
			union mcc_ip_addr sa_null;

			memset(&sa_null, 0, sizeof(sa_null));
			src = mcc_src_find(&clt->src_list, &sa_null);
			if (src)
				mcc_src_delete(&clt->src_list, src);
		}
	}

	/* Remove client if it has no sources in INCLUDE mode or with BLOCK */
	if ((clt->src_list.num == 0 && (clt->fmode == MCC_FLT_MODE_INCLUDE ||
					clt->smode == MCC_SRC_MODE_BLOCK)) ||
	    (src_list->num == 0 && clt->fmode == MCC_FLT_MODE_INCLUDE)) {
		mcc_clt_delete(clt_list, clt);
	}

	return OMCI_SUCCESS;
}

/* ======================================================================
 * Group management
 * ====================================================================== */

static struct mcc_grp_entry *mcc_grp_find(const struct mcc_list *grp_list,
					  const union mcc_ip_addr *da)
{
	struct mcc_grp_entry *e;
	struct mcc_list_head *le, *nle;

	if (grp_list->num == 0)
		return NULL;

	MCC_LIST_FOR_EACH_SAFE(le, nle, grp_list) {
		e = LE2GRP(le);
		if (memcmp(&e->da, da, sizeof(*da)) == 0)
			return e;
	}

	return NULL;
}

static struct mcc_grp_entry *mcc_grp_create(struct mcc_list *grp_list,
					    struct mcc_flw_entry *flw,
					    const bool is_static,
					    const union mcc_ip_addr *da)
{
	struct mcc_grp_entry *e;

	e = IFXOS_MemAlloc(sizeof(*e));
	if (e == NULL)
		return NULL;

	memset(e, 0, sizeof(*e));
	memcpy(&e->da, da, sizeof(*da));
	mcc_list_init(&e->clt_list);
	mcc_list_init(&e->src_link_list);
	e->fmode = MCC_FLT_MODE_INCLUDE;
	e->is_static = is_static;
	e->lost = 0;
	e->act_timeout_id = 0;
	e->age_timeout_id = 0;
	e->flw = flw;

	mcc_list_add_tail(grp_list, &e->le);

	return e;
}

static void mcc_grp_delete(struct mcc_list *grp_list, struct mcc_grp_entry *e)
{
	if (grp_list->num == 0)
		return;

	mcc_clt_list_delete(&e->clt_list);
	mcc_list_remove(grp_list, &e->le);
	IFXOS_MemFree(e);
}

static void mcc_grp_list_delete(struct mcc_list *grp_list)
{
	struct mcc_grp_entry *e;
	struct mcc_list_head *le, *nle;

	if (grp_list->num == 0)
		return;

	MCC_LIST_FOR_EACH_SAFE(le, nle, grp_list) {
		e = LE2GRP(le);
		mcc_clt_list_delete(&e->clt_list);
		mcc_grp_delete(grp_list, e);
	}
}

static inline void mcc_grp_fmode_set(const enum mcc_flt_mode fmode,
				     struct mcc_grp_entry *grp)
{
	if (fmode != MCC_FLT_MODE_NA)
		grp->fmode = fmode;
}

/** Clear group connected source list (unchain from grp_le and clt_le) */
static inline void mcc_grp_slist_clr(struct mcc_list *grp_slist)
{
	struct mcc_src_entry *e;
	struct mcc_list_head *le, *nle;

	MCC_LIST_FOR_EACH_SAFE(le, nle, grp_slist) {
		e = GRP_LE2SRC(le);
		mcc_list_remove(NULL, &e->grp_le);
		mcc_list_remove(NULL, &e->clt_le);
		grp_slist->num--;
	}
	mcc_list_init(grp_slist);
}

/** Intersect group connected source lists.
    list1 = list1 ∩ list2 (by grp_le linkage). */
static void mcc_grp_slist_intersect(struct mcc_list *list1,
				    const struct mcc_list *list2)
{
	struct mcc_src_entry *e1, *e2;
	struct mcc_list_head *l1e, *nl1e, *l2e, *nl2e;
	union mcc_ip_addr sa;
	bool intersect, any = false;

	if (list2->num == 0)
		return;

	if (list1->num == 0) {
		mcc_list_init(list1);
		/* Add complete list */
		MCC_LIST_FOR_EACH_SAFE(l2e, nl2e, list2) {
			e2 = SRC_LE2SRC(l2e);
			mcc_list_add(&e2->grp_le, list1->head.prev);
			list1->num++;
		}
		return;
	}

	/* Detect *any* 0.0.0.0 source entry */
	if (list2->num == 1) {
		memset(&sa, 0, sizeof(sa));
		e2 = SRC_LE2SRC(list2->head.next);
		any = (memcmp(&e2->sa, &sa, sizeof(sa)) == 0) ? true : false;
	}

	MCC_LIST_FOR_EACH_SAFE(l1e, nl1e, list1) {
		e1 = GRP_LE2SRC(l1e);
		intersect = false;

		MCC_LIST_FOR_EACH_SAFE(l2e, nl2e, list2) {
			e2 = SRC_LE2SRC(l2e);
			if (memcmp(&e1->sa, &e2->sa, sizeof(e2->sa)) == 0) {
				intersect = true;
				/* Collect clients via clt_le */
				mcc_list_add(&e2->clt_le, e1->clt_le.prev);
				break;
			}
		}

		if (!intersect) {
			mcc_list_remove(list1, l1e);
		}
	}

	/* Handle *any* 0.0.0.0 source entry */
	if (any && list1->num == 0) {
		e2 = SRC_LE2SRC(list2->head.next);
		mcc_list_add(&e2->grp_le, list1->head.prev);
		list1->num++;
	}
}

/** Subtract group connected source lists.
    list1 = list1 \ list2 (by grp_le linkage). */
static void mcc_grp_slist_subtract(struct mcc_list *list1,
				    const struct mcc_list *list2)
{
	struct mcc_src_entry *e1, *e2;
	struct mcc_list_head *l1e, *nl1e, *l2e, *nl2e;

	if (list1->num == 0 || list2->num == 0)
		return;

	MCC_LIST_FOR_EACH_SAFE(l1e, nl1e, list1) {
		e1 = GRP_LE2SRC(l1e);
		MCC_LIST_FOR_EACH_SAFE(l2e, nl2e, list2) {
			e2 = SRC_LE2SRC(l2e);
			if (memcmp(&e1->sa, &e2->sa, sizeof(e1->sa)) == 0) {
				mcc_list_remove(list1, l1e);
			}
		}
	}
}

/** Unite group connected source lists.
    list1 = list1 ∪ list2 (by grp_le linkage). */
static void mcc_grp_slist_unite(struct mcc_list *list1,
				const struct mcc_list *list2)
{
	struct mcc_src_entry *e1, *e2;
	struct mcc_list_head *l1e, *nl1e, *l2e, *nl2e;
	bool add_new;

	if (list2->num == 0)
		return;

	if (list1->num == 0) {
		mcc_list_init(list1);
		MCC_LIST_FOR_EACH_SAFE(l2e, nl2e, list2) {
			e2 = SRC_LE2SRC(l2e);
			mcc_list_add(&e2->grp_le, list1->head.prev);
			list1->num++;
		}
		return;
	}

	MCC_LIST_FOR_EACH_SAFE(l2e, nl2e, list2) {
		add_new = true;
		e2 = SRC_LE2SRC(l2e);

		MCC_LIST_FOR_EACH_SAFE(l1e, nl1e, list1) {
			e1 = GRP_LE2SRC(l1e);
			if (memcmp(&e1->sa, &e2->sa, sizeof(e2->sa)) == 0) {
				/* Collect clients via clt_le */
				mcc_list_add(&e1->clt_le, e2->clt_le.prev);
				add_new = false;
				break;
			}
		}

		if (add_new) {
			mcc_list_add(&e2->grp_le, list1->head.prev);
			list1->num++;
		}
	}
}

/** Get connected source list for a group (RFC3376 state derivation).
    EXCLUDE: intersection of EXCLUDE client sources minus INCLUDE client sources.
    INCLUDE: union of all client sources. */
static void mcc_grp_slist_get(struct mcc_grp_entry *grp,
			      struct mcc_list *grp_slist)
{
	struct mcc_clt_entry *e;
	struct mcc_list_head *le, *nle;
	struct mcc_src_entry *src1;
	bool first_src = true;

	if (grp->fmode == MCC_FLT_MODE_EXCLUDE) {
		MCC_LIST_FOR_EACH_SAFE(le, nle, &grp->clt_list) {
			e = LE2CLT(le);

			if (first_src && (grp_slist->num > 0)) {
				src1 = GRP_LE2SRC(grp_slist->head.next);
				src1->clt_le.next = &src1->clt_le;
				src1->clt_le.prev = &src1->clt_le;
				first_src = false;
			}

			if (e->fmode == MCC_FLT_MODE_EXCLUDE)
				mcc_grp_slist_intersect(grp_slist,
							&e->src_list);
		}
		MCC_LIST_FOR_EACH_SAFE(le, nle, &grp->clt_list) {
			e = LE2CLT(le);
			if (e->fmode == MCC_FLT_MODE_INCLUDE)
				mcc_grp_slist_subtract(grp_slist,
							&e->src_list);
		}
	}

	if (grp->fmode == MCC_FLT_MODE_INCLUDE) {
		MCC_LIST_FOR_EACH_SAFE(le, nle, &grp->clt_list) {
			e = LE2CLT(le);
			mcc_grp_slist_unite(grp_slist, &e->src_list);
		}
	}
}

/** Update group filter mode and source list based on all clients (RFC3376). */
static void mcc_grp_state_update(struct mcc_grp_entry *grp)
{
	struct mcc_clt_entry *e;
	struct mcc_list_head *le, *nle;

	/* Derive group filter mode from client filter modes */
	MCC_LIST_FOR_EACH_SAFE(le, nle, &grp->clt_list) {
		e = LE2CLT(le);

		if (e->fmode == MCC_FLT_MODE_INCLUDE)
			mcc_grp_fmode_set(MCC_FLT_MODE_INCLUDE, grp);
		/* EXCLUDE overrides any INCLUDE */
		if (e->fmode == MCC_FLT_MODE_EXCLUDE)
			mcc_grp_fmode_set(MCC_FLT_MODE_EXCLUDE, grp);
	}

	mcc_grp_slist_clr(&grp->src_link_list);
	mcc_grp_slist_get(grp, &grp->src_link_list);
}

/* ======================================================================
 * Timeout handlers (activity detection + aging)
 * ====================================================================== */

static enum omci_error
mcc_grp_activity_timeout_handler(struct omci_context *context,
				 struct timeout *timeout)
{
	enum omci_error error = OMCI_SUCCESS;
	struct mcc_ctx *mcc = (struct mcc_ctx *)context->mcc;
	struct mcc_flw_entry *flw = (struct mcc_flw_entry *)timeout->arg1;
	struct mcc_grp_entry *grp = (struct mcc_grp_entry *)timeout->arg2;
	bool is_active = false;

	RETURN_IF_BOUNDS_ERROR(flw->flw.port, mcc->max_ports - 1);

	/* When OMCI is shut down we can not lock the MEs any more */
	if (context->omci_shutdown_in_progress)
		return OMCI_ERROR;

	mcc_omci_lock(context);
	IFXOS_LockGet(&mcc->port[flw->flw.port].lock);
	grp->act_timeout_id = 0;

	error = mcc_dev_port_activity_get(&mcc->dev, flw->flw.port,
					  flw->flw.id, &grp->da, &is_active);
	grp->lost = is_active ? 0 : 1;

	if (mcc_omci_grp_lost_alarm_set(context, grp))
		dbg_err("grp %p lost alarm set failed", grp);

	IFXOS_LockRelease(&mcc->port[flw->flw.port].lock);
	mcc_omci_unlock(context);

	return error;
}

static enum omci_error
mcc_grp_aging_timeout_handler(struct omci_context *context,
			      struct timeout *timeout)
{
	enum omci_error error = OMCI_SUCCESS;
	struct mcc_ctx *mcc = (struct mcc_ctx *)context->mcc;
	struct mcc_flw_entry *flw = (struct mcc_flw_entry *)timeout->arg1;
	struct mcc_grp_entry *grp = (struct mcc_grp_entry *)timeout->arg2;

	RETURN_IF_BOUNDS_ERROR(flw->flw.port, mcc->max_ports - 1);

	IFXOS_LockGet(&mcc->port[flw->flw.port].lock);
	grp->age_timeout_id = 0;

	/* Remove DA entry forwarding */
	error = mcc_dev_port_remove(&mcc->dev, flw->flw.port,
				    flw->flw.id, &grp->da);
	mcc_grp_delete(&flw->grp_list, grp);

	IFXOS_LockRelease(&mcc->port[flw->flw.port].lock);

	return error;
}

/** Refresh group: update state, manage timeouts, delete if empty. */
static enum omci_error mcc_grp_refresh(struct mcc_ctx *mcc,
				       struct mcc_flw_entry *flw,
				       struct mcc_grp_entry *grp)
{
	enum omci_error error = OMCI_SUCCESS;
	struct omci_context *context = (struct omci_context *)mcc->ctx_core;

	/* Update group state based on all clients */
	mcc_grp_state_update(grp);

	/* Remove activity timeout if pending */
	if (grp->act_timeout_id) {
		error = timeout_event_remove(context, grp->act_timeout_id);
		if (error)
			return error;
		grp->act_timeout_id = 0;
	}

	/* Remove aging timeout if pending */
	if (grp->age_timeout_id) {
		error = timeout_event_remove(context, grp->age_timeout_id);
		if (error)
			return error;
		grp->age_timeout_id = 0;
	}

	if ((grp->fmode == MCC_FLT_MODE_INCLUDE && grp->src_link_list.num == 0)
	    || (grp->clt_list.num == 0)) {
		mcc_grp_delete(&flw->grp_list, grp);
	} else {
		grp->lost = 0;

		if (!grp->is_static) {
			/* Add activity detection timeout */
			error = timeout_event_add(context, &grp->act_timeout_id,
					MCC_GROUP_ACTIVITY_DETECTION_TIMEOUT_MS,
					mcc_grp_activity_timeout_handler,
					0, 0,
					(unsigned long)flw,
					(unsigned long)grp, 0);
			if (error)
				return error;
		}
	}

	return error;
}

/* ======================================================================
 * Flow management
 * ====================================================================== */

static struct mcc_flw_entry *
mcc_flw_find(const struct mcc_list *flw_list, const uint8_t fid)
{
	struct mcc_flw_entry *e;
	struct mcc_list_head *le, *nle;

	if (flw_list->num == 0)
		return NULL;

	MCC_LIST_FOR_EACH_SAFE(le, nle, flw_list) {
		e = LE2FLW(le);
		if (e->flw.id == fid)
			return e;
	}

	return NULL;
}

static struct mcc_flw_entry *
mcc_flw_create(struct mcc_list *flw_list, const struct mcc_flw *flw)
{
	struct mcc_flw_entry *e;

	e = IFXOS_MemAlloc(sizeof(*e));
	if (e == NULL)
		return NULL;

	memset(e, 0, sizeof(*e));
	memcpy(&e->flw, flw, sizeof(*flw));
	mcc_list_init(&e->grp_list);

	mcc_list_add_tail(flw_list, &e->le);

	return e;
}

static void mcc_flw_delete(struct mcc_list *flw_list, struct mcc_flw_entry *e)
{
	if (flw_list->num == 0)
		return;

	mcc_grp_list_delete(&e->grp_list);
	mcc_list_remove(flw_list, &e->le);
	IFXOS_MemFree(e);
}

/** Cleanup flow list: remove timeouts, HW forwarding, then delete all. */
void mcc_flw_cleanup(struct mcc_ctx *mcc, struct mcc_list *flw_list)
{
	struct omci_context *context = (struct omci_context *)mcc->ctx_core;
	struct mcc_flw_entry *fe;
	struct mcc_grp_entry *ge;
	struct mcc_list_head *fle, *nfle, *gle, *ngle;

	if (flw_list->num == 0)
		return;

	MCC_LIST_FOR_EACH_SAFE(fle, nfle, flw_list) {
		fe = LE2FLW(fle);

		MCC_LIST_FOR_EACH_SAFE(gle, ngle, &fe->grp_list) {
			ge = LE2GRP(gle);

			if (ge->act_timeout_id)
				(void)timeout_event_remove(context,
							   ge->act_timeout_id);
			if (ge->age_timeout_id)
				(void)timeout_event_remove(context,
							   ge->age_timeout_id);
			/* Remove HW forwarding entry */
			(void)mcc_dev_port_remove(&mcc->dev, fe->flw.port,
						  fe->flw.id, &ge->da);
		}

		mcc_flw_delete(flw_list, fe);
	}
}

/* ======================================================================
 * Capacity / bandwidth
 * ====================================================================== */

/** Get service-level capacity (streams + bandwidth) for port+CVID. */
static void mcc_port_service_capacity_get(struct mcc_ctx *mcc,
					  const uint8_t port_idx,
					  const uint16_t cvid,
					  struct mcc_capacity *cap)
{
	struct mcc_port *port;
	struct mcc_flw_entry *flw;
	struct mcc_grp_entry *grp;
	struct mcc_src_entry *src;
	struct mcc_list_head *flw_le, *flw_nle, *grp_le, *grp_nle,
			     *src_le, *src_nle;

	memset(cap, 0, sizeof(*cap));
	port = &mcc->port[port_idx];

	MCC_LIST_FOR_EACH_SAFE(flw_le, flw_nle, &port->flw_list) {
		flw = LE2FLW(flw_le);
		if (flw->flw.cvid != cvid)
			continue;

		MCC_LIST_FOR_EACH_SAFE(grp_le, grp_nle, &flw->grp_list) {
			grp = LE2GRP(grp_le);

			MCC_LIST_FOR_EACH_SAFE(src_le, src_nle,
					    &grp->src_link_list) {
				src = GRP_LE2SRC(src_le);
				cap->str += 1;
				cap->ibw += src->ibw;
				if (src->ibw_any)
					break;
			}
		}
	}
}

/** Get total capacity (streams + bandwidth) for a port across all flows. */
static void mcc_port_total_capacity_get(struct mcc_ctx *mcc,
					const uint8_t port_idx,
					struct mcc_capacity *cap)
{
	struct mcc_port *port;
	struct mcc_flw_entry *flw;
	struct mcc_grp_entry *grp;
	struct mcc_src_entry *src;
	struct mcc_list_head *flw_le, *flw_nle, *grp_le, *grp_nle,
			     *src_le, *src_nle;

	memset(cap, 0, sizeof(*cap));
	port = &mcc->port[port_idx];

	MCC_LIST_FOR_EACH_SAFE(flw_le, flw_nle, &port->flw_list) {
		flw = LE2FLW(flw_le);

		MCC_LIST_FOR_EACH_SAFE(grp_le, grp_nle, &flw->grp_list) {
			grp = LE2GRP(grp_le);

			MCC_LIST_FOR_EACH_SAFE(src_le, src_nle,
					    &grp->src_link_list) {
				src = GRP_LE2SRC(src_le);
				cap->str += 1;
				cap->ibw += src->ibw;
				if (src->ibw_any)
					break;
			}
		}
	}
}

/** Get maximum imputed bandwidth across all groups/sources on a port. */
uint32_t mcc_port_ibw_max_get(const struct mcc_port *port)
{
	struct mcc_flw_entry *flw;
	struct mcc_grp_entry *grp;
	struct mcc_src_entry *src;
	struct mcc_list_head *flw_le, *flw_nle, *grp_le, *grp_nle,
			     *src_le, *src_nle;
	uint32_t max = 0;

	MCC_LIST_FOR_EACH_SAFE(flw_le, flw_nle, &port->flw_list) {
		flw = LE2FLW(flw_le);

		MCC_LIST_FOR_EACH_SAFE(grp_le, grp_nle, &flw->grp_list) {
			grp = LE2GRP(grp_le);

			MCC_LIST_FOR_EACH_SAFE(src_le, src_nle,
					    &grp->src_link_list) {
				src = GRP_LE2SRC(src_le);
				max = MCC_MAX(src->ibw, max);
				if (src->ibw_any)
					break;
			}
		}
	}

	return max;
}

/* ======================================================================
 * Forwarding source list operations (fwd_le linkage)
 * ====================================================================== */

static void mcc_fwd_slist_intersect(struct mcc_list *list1,
				    const struct mcc_list *list2)
{
	struct mcc_src_entry *e1, *e2;
	struct mcc_list_head *l1e, *nl1e, *l2e, *nl2e;
	union mcc_ip_addr sa;
	bool intersect, any = false;

	if (list2->num == 0)
		return;

	if (list1->num == 0) {
		mcc_list_init(list1);
		MCC_LIST_FOR_EACH_SAFE(l2e, nl2e, list2) {
			e2 = GRP_LE2SRC(l2e);
			mcc_list_add(&e2->fwd_le, list1->head.prev);
			list1->num++;
		}
		return;
	}

	if (list2->num == 1) {
		memset(&sa, 0, sizeof(sa));
		e2 = GRP_LE2SRC(list2->head.next);
		any = (memcmp(&e2->sa, &sa, sizeof(sa)) == 0) ? true : false;
	}

	MCC_LIST_FOR_EACH_SAFE(l1e, nl1e, list1) {
		e1 = FWD_LE2SRC(l1e);
		intersect = false;

		MCC_LIST_FOR_EACH_SAFE(l2e, nl2e, list2) {
			e2 = GRP_LE2SRC(l2e);
			if (memcmp(&e1->sa, &e2->sa, sizeof(e2->sa)) == 0) {
				intersect = true;
				mcc_list_add(&e2->prt_le, e1->prt_le.prev);
				break;
			}
		}

		if (!intersect) {
			mcc_list_remove(list1, l1e);
		}
	}

	if (any && list1->num == 0) {
		e2 = GRP_LE2SRC(list2->head.next);
		mcc_list_add(&e2->fwd_le, list1->head.prev);
		list1->num++;
	}
}

static void mcc_fwd_slist_subtract(struct mcc_list *list1,
				    const struct mcc_list *list2)
{
	struct mcc_src_entry *e1, *e2;
	struct mcc_list_head *l1e, *nl1e, *l2e, *nl2e;

	if (list1->num == 0 || list2->num == 0)
		return;

	MCC_LIST_FOR_EACH_SAFE(l1e, nl1e, list1) {
		e1 = FWD_LE2SRC(l1e);
		MCC_LIST_FOR_EACH_SAFE(l2e, nl2e, list2) {
			e2 = GRP_LE2SRC(l2e);
			if (memcmp(&e1->sa, &e2->sa, sizeof(e1->sa)) == 0) {
				mcc_list_remove(list1, l1e);
			}
		}
	}
}

static void mcc_fwd_slist_unite(struct mcc_list *list1,
				const struct mcc_list *list2)
{
	struct mcc_src_entry *e1, *e2;
	struct mcc_list_head *l1e, *nl1e, *l2e, *nl2e;
	bool add_new;

	if (list2->num == 0)
		return;

	if (list1->num == 0) {
		mcc_list_init(list1);
		MCC_LIST_FOR_EACH_SAFE(l2e, nl2e, list2) {
			e2 = GRP_LE2SRC(l2e);
			mcc_list_add(&e2->fwd_le, list1->head.prev);
			list1->num++;
		}
		return;
	}

	MCC_LIST_FOR_EACH_SAFE(l2e, nl2e, list2) {
		add_new = true;
		e2 = GRP_LE2SRC(l2e);

		MCC_LIST_FOR_EACH_SAFE(l1e, nl1e, list1) {
			e1 = FWD_LE2SRC(l1e);
			if (memcmp(&e1->sa, &e2->sa, sizeof(e2->sa)) == 0) {
				mcc_list_add(&e1->prt_le, e2->prt_le.prev);
				add_new = false;
				break;
			}
		}

		if (add_new) {
			mcc_list_add(&e2->fwd_le, list1->head.prev);
			list1->num++;
		}
	}
}

/* ======================================================================
 * Forwarding refresh
 * ====================================================================== */

/** Refresh MC forwarding entry for a given group DA across all ports
    on the same bridge. Aggregates per-port group states into a single
    forwarding entry with source filtering and port map. */
static enum omci_error mcc_fwd_refresh(struct mcc_ctx *mcc,
				       const uint8_t lan_port_idx,
				       const uint8_t fid,
				       union mcc_ip_addr *da)
{
	enum omci_error error = OMCI_SUCCESS;
	struct omci_context *context = (struct omci_context *)mcc->ctx_core;
	uint8_t p_idx, port_map = 0;
	uint16_t bridge_id_ref, bridge_id_cur;
	enum mcc_flt_mode fwd_mode = MCC_FLT_MODE_NA;
	struct mcc_grp_entry **grp;
	struct mcc_flw_entry *flw;
	struct mcc_port *port;
	struct mcc_list fwd_slist;
	struct mcc_omci_mc_bridge_info mc_bridge_info;

	mcc_list_init(&fwd_slist);

	/* Get reference bridge ID for this port */
	error = mcc_omci_mc_bridge_info_get(context, lan_port_idx,
					    &mc_bridge_info);
	if (error)
		return error;

	bridge_id_ref = mc_bridge_info.br_id;

	grp = IFXOS_MemAlloc(sizeof(*grp) * mcc->max_ports);
	if (!grp)
		return OMCI_ERROR_MEMORY;

	/* Find the specified group/fid across all ports on the same bridge */
	for (p_idx = 0; p_idx < mcc->max_ports; p_idx++) {
		port = &mcc->port[p_idx];
		grp[p_idx] = NULL;

		error = mcc_omci_mc_bridge_info_get(context, p_idx,
						    &mc_bridge_info);
		if (error != OMCI_SUCCESS)
			continue;

		bridge_id_cur = mc_bridge_info.br_id;
		if (bridge_id_ref != bridge_id_cur)
			continue;

		flw = mcc_flw_find(&port->flw_list, fid);
		if (flw == NULL)
			continue;

		grp[p_idx] = mcc_grp_find(&flw->grp_list, da);
		if (grp[p_idx] == NULL)
			continue;

		port_map |= 1 << p_idx;

		if (grp[p_idx]->fmode == MCC_FLT_MODE_INCLUDE)
			fwd_mode = MCC_FLT_MODE_INCLUDE;
		if (grp[p_idx]->fmode == MCC_FLT_MODE_EXCLUDE)
			fwd_mode = MCC_FLT_MODE_EXCLUDE;
	}

	if (fwd_mode == MCC_FLT_MODE_EXCLUDE) {
		/* Intersection of EXCLUDE sources across ports */
		for (p_idx = 0; p_idx < mcc->max_ports; p_idx++) {
			if (grp[p_idx] == NULL)
				continue;
			if (grp[p_idx]->fmode == MCC_FLT_MODE_EXCLUDE)
				mcc_fwd_slist_intersect(&fwd_slist,
							&grp[p_idx]->
								src_link_list);
		}
		/* Minus INCLUDE sources */
		for (p_idx = 0; p_idx < mcc->max_ports; p_idx++) {
			if (grp[p_idx] == NULL)
				continue;
			if (grp[p_idx]->fmode == MCC_FLT_MODE_INCLUDE)
				mcc_fwd_slist_subtract(&fwd_slist,
							&grp[p_idx]->
								src_link_list);
		}
	} else if (fwd_mode == MCC_FLT_MODE_INCLUDE) {
		/* Union of sources across all ports */
		for (p_idx = 0; p_idx < mcc->max_ports; p_idx++) {
			if (grp[p_idx] == NULL)
				continue;
			mcc_fwd_slist_unite(&fwd_slist,
					    &grp[p_idx]->src_link_list);
		}
	} else {
		error = mcc_dev_port_remove(&mcc->dev, lan_port_idx, fid, da);
	}

	if (fwd_mode != MCC_FLT_MODE_NA) {
		error = mcc_dev_fwd_update(&mcc->dev, fid,
					   fwd_mode == MCC_FLT_MODE_INCLUDE ?
								true : false,
					   bridge_id_ref, port_map, da,
					   &fwd_slist);
	}

	IFXOS_MemFree(grp);

	return error;
}

/** Update Query forwarding: add general query to all ports. */
static enum omci_error mcc_fwd_qry_update(struct mcc_ctx *mcc,
					  struct mcc_pkt *pkt)
{
	enum omci_error error = OMCI_SUCCESS;
	uint8_t p_idx, is_general_qry, fid;
	union mcc_ip_addr qry_ga, general_qry_ga, qry_da;
	uint16_t svid;

	pkt->info.prot_ctx->ga_get(pkt, &qry_ga);
	memset(&general_qry_ga, 0, sizeof(general_qry_ga));

	is_general_qry = memcmp(&qry_ga, &general_qry_ga,
				sizeof(qry_ga)) == 0 ? 1 : 0;

	if (is_general_qry) {
		svid = mcc_pkt_svid_get(&pkt->info);

		error = mcc_pkt_da_get(pkt, &qry_da);
		if (error)
			return error;

		for (p_idx = 0; p_idx < mcc->max_ports; p_idx++) {
			error = mcc_dev_fid_get(&mcc->dev, svid, &fid);
			if (error)
				return error;

			error = mcc_dev_port_add(&mcc->dev, MCC_DIR_DS,
						 p_idx, fid, &qry_da);
			if (error)
				return error;
		}
	}

	return error;
}

/** Update Report forwarding: add report to upstream port. */
static enum omci_error mcc_fwd_rep_update(struct mcc_ctx *mcc,
					  struct mcc_pkt *pkt)
{
	enum omci_error error = OMCI_SUCCESS;
	uint8_t p_idx = mcc_pkt_port_idx_get(&pkt->info), fid;
	union mcc_ip_addr rep_da;
	uint16_t svid;

	RETURN_IF_BOUNDS_ERROR(p_idx, mcc->max_ports - 1);

	svid = mcc_pkt_svid_get(&pkt->info);

	memset(&rep_da, 0, sizeof(rep_da));
	error = mcc_pkt_da_get(pkt, &rep_da);
	if (error)
		return error;

	error = mcc_dev_fid_get(&mcc->dev, svid, &fid);
	if (error)
		return error;

	error = mcc_dev_port_add(&mcc->dev, MCC_DIR_US, p_idx, fid, &rep_da);

	return error;
}

/** Update well-known multicast destination forwarding based on packet type. */
static enum omci_error mcc_fwd_dest_update(struct mcc_ctx *mcc,
					   struct mcc_pkt *pkt)
{
	enum omci_error error = OMCI_SUCCESS;

	switch (pkt->info.pkt_type) {
	case MCC_PKT_TYPE_IGMP_QUERY:
	case MCC_PKT_TYPE_MLD_QUERY:
		error = mcc_fwd_qry_update(mcc, pkt);
		break;
	case MCC_PKT_TYPE_IGMP_V1_REPORT:
		/* No forwarding update needed */
		break;
	case MCC_PKT_TYPE_IGMP_V2_REPORT:
	case MCC_PKT_TYPE_IGMP_V2_LEAVE:
	case MCC_PKT_TYPE_IGMP_V3_REPORT:
	case MCC_PKT_TYPE_MLD_V1_DONE:
	case MCC_PKT_TYPE_MLD_V1_REPORT:
	case MCC_PKT_TYPE_MLD_V2_REPORT:
		error = mcc_fwd_rep_update(mcc, pkt);
		break;
	case MCC_PKT_TYPE_NA:
	default:
		dbg_prn("packet type not detected/handled, transparently pass");
		return error;
	}

	return error;
}

/* ======================================================================
 * Record processing
 * ====================================================================== */

/** Extract multicast record from packet at index rec_idx.
    Fills mcc_rec with flow info, group/client/source addresses, mode. */
static enum omci_error mcc_rec_get(struct mcc_ctx *mcc,
				   struct mcc_pkt *pkt,
				   const uint16_t rec_idx,
				   struct mcc_rec *rec)
{
	enum omci_error error = OMCI_SUCCESS;
	uint8_t s, prot_rec_type;
	void *p_rec = NULL;
	enum mcc_pkt_rec_type rec_type = MCC_PKT_REC_TYPE_NA;
	struct mcc_src_entry *src;
	union mcc_ip_addr sa;
	uint16_t sa_num;

	mcc_src_list_delete(&rec->src_list);
	mcc_list_init(&rec->src_list);

	rec->discard = 0;
	rec->unauth = 0;
	rec->pass_unauth = 0;

	/* Set protocol version */
	switch (pkt->info.pkt_type) {
	case MCC_PKT_TYPE_IGMP_V2_REPORT:
	case MCC_PKT_TYPE_IGMP_V2_LEAVE:
		rec->version = MCC_PROT_VERSION_IGMP_V2;
		break;
	case MCC_PKT_TYPE_IGMP_V3_REPORT:
		rec->version = MCC_PROT_VERSION_IGMP_V3;
		break;
	case MCC_PKT_TYPE_MLD_V1_REPORT:
	case MCC_PKT_TYPE_MLD_V1_DONE:
		rec->version = MCC_PROT_VERSION_MLD_V1;
		break;
	case MCC_PKT_TYPE_MLD_V2_REPORT:
		rec->version = MCC_PROT_VERSION_MLD_V2;
		break;
	default:
		rec->version = MCC_PROT_VERSION_NA;
		break;
	}

	/* Get port index */
	rec->flw.port = mcc_pkt_port_idx_get(&pkt->info);
	RETURN_IF_BOUNDS_ERROR(rec->flw.port, mcc->max_ports - 1);

	/* Get VLAN IDs */
	rec->flw.cvid = mcc_pkt_cvid_get(&pkt->info);
	rec->flw.svid = mcc_pkt_svid_get(&pkt->info);

	/* Get default FID */
	error = mcc_dev_fid_get(&mcc->dev, 0, &rec->flw.id);
	if (error)
		return error;

	/* Get group address */
	error = mcc_pkt_rec_ga_get(pkt, rec_idx, &rec->da);
	if (error)
		return error;

	/* Get client address */
	error = mcc_pkt_rec_ca_get(pkt, &rec->ca);
	if (error)
		return error;

	/* Get protocol-level record */
	p_rec = pkt->info.prot_ctx->rec_get(pkt, rec_idx);
	sa_num = pkt->info.prot_ctx->rec_snum_get(pkt, p_rec);
	prot_rec_type = pkt->info.prot_ctx->rec_type_get(pkt, p_rec);

	/* Map protocol record type to MCC record type */
	switch (prot_rec_type) {
	case MCC_IS_INCLUDE:
	case MCC_CHANGE_TO_INCLUDE:
		rec_type = MCC_PKT_REC_TYPE_INCLUDE;
		break;
	case MCC_IS_EXCLUDE:
	case MCC_CHANGE_TO_EXCLUDE:
		rec_type = MCC_PKT_REC_TYPE_EXCLUDE;
		break;
	case MCC_ALLOW_NEW_SOURCES:
		if (sa_num)
			rec_type = MCC_PKT_REC_TYPE_ALLOW;
		else
			return OMCI_ERROR;
		break;
	case MCC_BLOCK_OLD_SOURCES:
		if (sa_num)
			rec_type = MCC_PKT_REC_TYPE_BLOCK;
		else
			return OMCI_ERROR;
		break;
	default:
		dbg_err("unsupported protocol record type %hhu", prot_rec_type);
		return OMCI_ERROR;
	}

	rec->smode = MCC_SRC_MODE_NA;
	rec->fmode = MCC_FLT_MODE_NA;

	switch (rec_type) {
	case MCC_PKT_REC_TYPE_INCLUDE:
		rec->fmode = MCC_FLT_MODE_INCLUDE;
		break;
	case MCC_PKT_REC_TYPE_EXCLUDE:
		rec->fmode = MCC_FLT_MODE_EXCLUDE;
		break;
	case MCC_PKT_REC_TYPE_ALLOW:
		rec->smode = MCC_SRC_MODE_ALLOW;
		break;
	case MCC_PKT_REC_TYPE_BLOCK:
		rec->smode = MCC_SRC_MODE_BLOCK;
		break;
	default:
		return OMCI_ERROR;
	}

	/* EXCLUDE with no sources → create dummy 0.0.0.0 entry */
	if (rec->fmode == MCC_FLT_MODE_EXCLUDE && sa_num == 0) {
		memset(&sa, 0, sizeof(sa));
		src = mcc_src_create(&rec->src_list, false, NULL, &sa, 0, NULL);
		if (!src)
			return OMCI_ERROR_MEMORY;
	}

	/* Build source list from packet */
	for (s = 0; s < sa_num; s++) {
		error = mcc_pkt_rec_sa_get(pkt, rec_idx, s, &sa);
		if (error)
			return error;

		src = mcc_src_find(&rec->src_list, &sa);
		if (src)
			continue;

		src = mcc_src_create(&rec->src_list, false, NULL, &sa, 0, NULL);
		if (!src)
			return OMCI_ERROR_MEMORY;
	}

	return error;
}

/** Apply whitelist to record: set IBW, filter non-matching sources. */
static enum omci_error mcc_rec_wlist_apply(struct mcc_ctx *mcc,
					   struct mcc_list *wlist,
					   struct mcc_rec *rec)
{
	enum omci_error error = OMCI_SUCCESS;
	union mcc_ip_addr sa;
	struct mcc_src_entry *src, *e;
	struct mcc_list_head *le, *nle;

	if (rec->src_list.num == 0 || wlist->num == 0)
		return error;

	memset(&sa, 0, sizeof(sa)); /* *any* source entry */
	src = mcc_src_find(wlist, &sa);
	if (src) {
		/* Wildcard match — apply to all record sources */
		MCC_LIST_FOR_EACH_SAFE(le, nle, &rec->src_list) {
			e = SRC_LE2SRC(le);
			e->ibw_any = 1;
			e->ibw = src->ibw;
			mcc_src_wlist_id_set(e, &src->wlist_id);
		}
	} else {
		if (rec->fmode == MCC_FLT_MODE_EXCLUDE) {
			/* Convert EXCLUDE → INCLUDE with whitelist sources */
			rec->fmode = MCC_FLT_MODE_INCLUDE;
			mcc_src_list_subtract(wlist, &rec->src_list);
			mcc_src_list_delete(&rec->src_list);
			mcc_list_init(&rec->src_list);
			error = mcc_src_list_create(&rec->src_list, wlist);
			if (error)
				return error;
		} else {
			/* Keep only sources that match the whitelist */
			MCC_LIST_FOR_EACH_SAFE(le, nle, &rec->src_list) {
				e = SRC_LE2SRC(le);
				src = mcc_src_find(wlist, &e->sa);
				if (src) {
					e->ibw = src->ibw;
					mcc_src_wlist_id_set(e, &src->wlist_id);
				} else {
					mcc_src_delete(&rec->src_list, e);
				}
			}
		}
	}

	return error;
}

/** Apply capacity/bandwidth restrictions to record.
    Checks per-service and per-port limits. */
static enum omci_error mcc_rec_restrict(struct mcc_ctx *mcc,
					struct mcc_omci_wlist *wlist,
					struct mcc_rec *rec)
{
	enum omci_error error = OMCI_SUCCESS;
	struct omci_context *context = (struct omci_context *)mcc->ctx_core;
	struct mcc_capacity max_cap, cap, cap_incr = {0, 0};
	uint8_t ibw_enf, bw_exc = 0;
	enum mcc_sa_action action;
	enum mcc_flt_mode fmode = MCC_FLT_MODE_INCLUDE;
	struct mcc_flw_entry *flw = NULL;
	struct mcc_grp_entry *grp = NULL;
	struct mcc_src_entry *e;
	struct mcc_list_head *le, *nle;

	/* Check protocol version */
	if (!(wlist->supported_prot_mask & (1 << rec->version))) {
		rec->discard = 1;
		dbg_prn("protocol version %u is restricted", rec->version);
		return error;
	}

	if (rec->fmode == MCC_FLT_MODE_INCLUDE && rec->src_list.num == 0) {
		/* Leave message, nothing to restrict */
		return error;
	}

	if (wlist->src_list.num == 0) {
		dbg_prn("no DACL match found for DA/VID");
		rec->unauth = 1;
		return error;
	}

	/* Apply whitelist */
	error = mcc_rec_wlist_apply(mcc, &wlist->src_list, rec);
	if (error)
		return error;

	if (rec->src_list.num == 0) {
		dbg_prn("no DACL match found for SA");
		rec->unauth = 1;
		return error;
	}

	flw = mcc_flw_find(&mcc->port[rec->flw.port].flw_list, rec->flw.id);
	if (flw) {
		grp = mcc_grp_find(&flw->grp_list, &rec->da);
		if (grp)
			fmode = grp->fmode;
	}

	action = mcc_src_list_action_get(fmode, rec->smode);
	if (action == MCC_SA_ACTION_REM || action == MCC_SA_ACTION_NA)
		return error;

	/* Calculate capacity increment */
	MCC_LIST_FOR_EACH_SAFE(le, nle, &rec->src_list) {
		e = SRC_LE2SRC(le);
		if (e->ibw_any) {
			if (!grp) {
				cap_incr.str = 1;
				cap_incr.ibw = e->ibw;
			}
			break;
		}
		if (grp) {
			if (mcc_src_find(&grp->src_link_list, &e->sa))
				continue;
		}
		cap_incr.str += 1;
		cap_incr.ibw += e->ibw;
	}

	mcc->port[rec->flw.port].join_msg_cnt++;

	if (cap_incr.str == 0)
		return error;

	error = mcc_omci_port_ibw_enf_get(context, rec->flw.port, &ibw_enf);
	if (error)
		return error;

	/* Check per-service capacity */
	error = mcc_omci_port_service_capacity_get(context, rec->flw.port,
						   rec->flw.cvid, &max_cap);
	if (error)
		return error;

	mcc_port_service_capacity_get(mcc, rec->flw.port, rec->flw.cvid, &cap);
	cap.str += cap_incr.str;
	cap.ibw += cap_incr.ibw;

	if (max_cap.str && cap.str > max_cap.str)
		rec->discard = 1;

	if (max_cap.ibw && cap.ibw > max_cap.ibw) {
		if (ibw_enf)
			rec->discard = 1;
		bw_exc = 1;
	}

	/* Check per-port capacity */
	error = mcc_omci_port_total_capacity_get(context, rec->flw.port,
						 &max_cap);
	if (error)
		return error;

	mcc_port_total_capacity_get(mcc, rec->flw.port, &cap);
	cap.str += cap_incr.str;
	cap.ibw += cap_incr.ibw;

	if (max_cap.str && cap.str > max_cap.str)
		rec->discard = 1;

	if (max_cap.ibw && cap.ibw > max_cap.ibw) {
		if (ibw_enf)
			rec->discard = 1;
		bw_exc = 1;
	}

	if (bw_exc)
		mcc->port[rec->flw.port].exce_msg_cnt++;

	return error;
}

/** Process a single multicast record: apply VLAN mode, check subscriber ME,
    apply whitelist/ACL, create flow/group/client entries, refresh forwarding. */
static enum omci_error mcc_rec_process(struct mcc_ctx *mcc,
				       struct mcc_rec *rec)
{
	enum omci_error error = OMCI_SUCCESS;
	struct omci_context *context = (struct omci_context *)mcc->ctx_core;
	uint16_t svid;
	struct me *port_me = NULL;
	struct mcc_port *port;
	struct mcc_flw_entry *flw;
	struct mcc_grp_entry *grp;
	struct mcc_clt_entry *clt;
	struct mcc_omci_wlist wlist;

	/* Get SVID based on global VLAN mode */
	if (mcc->vlan_mode == MCC_VLAN_MODE_UNAWARE) {
		svid = 0;
	} else if (mcc->vlan_mode == MCC_VLAN_MODE_AWARE) {
		svid = rec->flw.svid;
	} else {
		dbg_err("Invalid VLAN mode %u", mcc->vlan_mode);
		return OMCI_ERROR;
	}

	/* Check if subscriber (port) ME is available */
	error = mcc_omci_port_me_get(context, rec->flw.port,
				     rec->version, &port_me);
	if (error == OMCI_ERROR_ME_NOT_FOUND) {
		/* Unrestricted access */
		dbg_prn("unrestricted access for port %hhu", rec->flw.port);
		error = OMCI_SUCCESS;

		error = mcc_dev_fid_get(&mcc->dev, svid, &rec->flw.id);
		if (error)
			return error;
	} else if (error) {
		return error;
	} else {
		/* Restricted access — get whitelist */
		memset(&wlist, 0, sizeof(wlist));
		mcc_list_init(&wlist.src_list);

		error = mcc_omci_flw_wlist_get(context, port_me,
					       rec->flw.cvid, rec->flw.svid,
					       rec->version, &rec->da,
					       &wlist);
		if (error) {
			mcc_src_list_delete(&wlist.src_list);
			return error;
		}

		if (mcc->vlan_mode == MCC_VLAN_MODE_AWARE) {
			svid = wlist.vid == MCC_VLAN_UNAWARE_SVID ?
								 0 : wlist.vid;
		}

		error = mcc_dev_fid_get(&mcc->dev, svid, &rec->flw.id);
		if (error)
			return error;

		/* Restrict record based on whitelist */
		error = mcc_rec_restrict(mcc, &wlist, rec);
		mcc_src_list_delete(&wlist.src_list);
		if (error)
			return error;

		rec->pass_unauth = wlist.pass_unauth;

		if (rec->discard)
			return error;

		if (rec->unauth) {
			if (omci_iop_mask_isset(context, OMCI_IOP_OPTION_0)) {
				dbg_prn("record unauthorized, force forwarding");
			} else {
				dbg_prn("record unauthorized, skip forwarding");
				return error;
			}
		}
	}

	/* Check against ANI-side MC address table */
	error = mcc_omci_mc_addr_table_match(context, rec->flw.port,
					     rec->version, &rec->da);
	if (error == OMCI_ERROR_DRV) {
		/* Resource not found — no global restriction */
		error = OMCI_SUCCESS;
	} else if (error == OMCI_ERROR_ME_NOT_FOUND) {
		/* Match not found — skip */
		return OMCI_SUCCESS;
	} else if (error) {
		return error;
	}

	port = &mcc->port[rec->flw.port];

	/* Find or create flow */
	flw = mcc_flw_find(&port->flw_list, rec->flw.id);
	if (!flw) {
		flw = mcc_flw_create(&port->flw_list, &rec->flw);
		if (!flw)
			return OMCI_ERROR_MEMORY;
	}

	/* Find or create group */
	grp = mcc_grp_find(&flw->grp_list, &rec->da);
	if (!grp) {
		grp = mcc_grp_create(&flw->grp_list, flw, false, &rec->da);
		if (!grp)
			return OMCI_ERROR_MEMORY;
	}

	/* Find or create client */
	clt = mcc_clt_find(&grp->clt_list, &rec->ca);
	if (!clt) {
		clt = mcc_clt_create(&grp->clt_list, grp, false, &rec->ca);
		if (!clt)
			return OMCI_ERROR_MEMORY;
	}

	mcc_clt_fmode_set(rec->fmode, clt);
	mcc_clt_smode_set(rec->smode, clt);

	/* Refresh client */
	error = mcc_clt_refresh(mcc, &rec->src_list, &grp->clt_list, clt);
	if (error)
		return error;

	/* Refresh group */
	error = mcc_grp_refresh(mcc, flw, grp);
	if (error)
		return error;

	/* Refresh flow */
	if (flw->grp_list.num == 0)
		mcc_flw_delete(&port->flw_list, flw);

	/* Refresh forwarding */
	error = mcc_fwd_refresh(mcc, rec->flw.port, rec->flw.id, &rec->da);

	return error;
}

/* ======================================================================
 * Rate limiting
 * ====================================================================== */

static void mcc_clk_time_get(struct timespec *t)
{
#ifdef LINUX
	clock_gettime(CLOCK_MONOTONIC, t);
#else
	IFX_time_t tv;

	tv = IFXOS_ElapsedTimeSecGet(0);
	t->tv_sec = tv;
	t->tv_nsec = 0;
#endif
}

static long long mcc_clk_elapsed_ms_get(const struct timespec *t2,
					const struct timespec *t1)
{
	long long tmp = (t2->tv_sec - t1->tv_sec) * 1000;

	tmp += ((t2->tv_nsec - t1->tv_nsec) / 1000000);
	return tmp;
}

static struct mcc_rl_entry *mcc_rl_entry_find(const struct mcc_list *rl_list,
					      const enum mcc_rl_type type,
					      const uint16_t cvid)
{
	struct mcc_rl_entry *e;
	struct mcc_list_head *le, *nle;
	uint16_t _cvid;

	switch (type) {
	case MCC_RL_TYPE_SERVICE:
		_cvid = cvid;
		break;
	case MCC_RL_TYPE_PORT:
		_cvid = 0xFFFF;
		break;
	case MCC_RL_TYPE_NA:
	default:
		return NULL;
	}

	if (rl_list->num == 0)
		return NULL;

	MCC_LIST_FOR_EACH_SAFE(le, nle, rl_list) {
		e = LE2RL(le);
		if (e->cvid == _cvid)
			return e;
	}

	return NULL;
}

static struct mcc_rl_entry *mcc_rl_entry_create(struct mcc_list *rl_list,
						const enum mcc_rl_type type,
						const uint16_t cvid,
						const uint32_t rate)
{
	struct mcc_rl_entry *e;
	uint16_t _cvid;

	switch (type) {
	case MCC_RL_TYPE_SERVICE:
		_cvid = cvid;
		break;
	case MCC_RL_TYPE_PORT:
		_cvid = 0xFFFF;
		break;
	case MCC_RL_TYPE_NA:
	default:
		return NULL;
	}

	e = IFXOS_MemAlloc(sizeof(*e));
	if (e == NULL)
		return NULL;

	memset(e, 0, sizeof(*e));
	e->cvid = _cvid;
	e->rate = rate;
	mcc_clk_time_get(&e->ref_ts);

	mcc_list_add_tail(rl_list, &e->le);

	return e;
}

static void mcc_rl_entry_delete(struct mcc_list *rl_list,
				struct mcc_rl_entry *e)
{
	if (rl_list->num == 0)
		return;

	mcc_list_remove(rl_list, &e->le);
	IFXOS_MemFree(e);
}

void mcc_rl_delete(struct mcc_rl *rl)
{
	struct mcc_rl_entry *e;
	struct mcc_list_head *le, *nle;

	if (rl->rl_list.num == 0)
		return;

	MCC_LIST_FOR_EACH_SAFE(le, nle, &rl->rl_list) {
		e = LE2RL(le);
		mcc_rl_entry_delete(&rl->rl_list, e);
	}

	rl->type = MCC_RL_TYPE_NA;
}

static inline void mcc_rl_type_set(struct mcc_rl *rl,
				   const enum mcc_rl_type type)
{
	if (type != MCC_RL_TYPE_NA)
		rl->type = type;
}

static inline enum mcc_rl_type mcc_rl_type_get(struct mcc_rl *rl)
{
	return rl->type;
}

/** Apply rate limiting to an upstream IGMP/MLD packet. */
static enum omci_error mcc_pkt_rate_limit(struct mcc_ctx *mcc,
					  struct mcc_pkt *pkt)
{
	enum omci_error error = OMCI_SUCCESS;
	struct omci_context *context = (struct omci_context *)mcc->ctx_core;
	uint8_t idx = mcc_pkt_port_idx_get(&pkt->info);
	uint16_t cvid = mcc_pkt_cvid_get(&pkt->info);
	struct mcc_port *port;
	struct mcc_rl_entry *rl;
	struct mcc_omci_rl omci_rl;
	struct timespec time;

	RETURN_IF_BOUNDS_ERROR(idx, mcc->max_ports - 1);

	port = &mcc->port[idx];

	rl = mcc_rl_entry_find(&port->rl.rl_list,
			       mcc_rl_type_get(&port->rl), cvid);
	if (rl == NULL) {
		mcc_omci_lock(context);
		error = mcc_omci_rl_get(context, idx, cvid, &omci_rl);
		mcc_omci_unlock(context);
		if (error)
			return error;

		if (omci_rl.type == MCC_RL_TYPE_NA)
			return error;

		mcc_rl_type_set(&port->rl, omci_rl.type);

		rl = mcc_rl_entry_create(&port->rl.rl_list,
					 mcc_rl_type_get(&port->rl),
					 cvid, omci_rl.rate);
		if (!rl)
			return OMCI_ERROR_MEMORY;
	}

	if (rl->rate == 0) /* Value 0 imposes no rate limit */
		return error;

	rl->msg_cnt++;
	mcc_clk_time_get(&time);

	if (mcc_clk_elapsed_ms_get(&time, &rl->ref_ts) > 1000) {
		rl->msg_cnt = 0;
		memcpy(&rl->ref_ts, &time, sizeof(time));
	}

	if (rl->msg_cnt > rl->rate)
		pkt->drop = true;

	return error;
}

/* ======================================================================
 * Top-level packet processing
 * ====================================================================== */

/** Process Query packet: update forwarding and set aging timeouts. */
static enum omci_error mcc_qry_process(struct mcc_ctx *mcc,
				       struct mcc_pkt *pkt)
{
	enum omci_error error = OMCI_SUCCESS;
	struct omci_context *context = (struct omci_context *)mcc->ctx_core;
	uint8_t p_idx, is_general_qry;
	uint32_t aging_to_ms;
	struct mcc_port *port;
	union mcc_ip_addr qry_ga, general_qry_ga;
	struct mcc_flw_entry *flw_e;
	struct mcc_list_head *flw_le, *flw_nle;
	struct mcc_grp_entry *grp_e;
	struct mcc_list_head *grp_le, *grp_nle;

	/* Update destination forwarding */
	error = mcc_fwd_dest_update(mcc, pkt);
	if (error)
		return error;

	/* Get query group address */
	pkt->info.prot_ctx->ga_get(pkt, &qry_ga);
	memset(&general_qry_ga, 0, sizeof(general_qry_ga));
	is_general_qry = memcmp(&qry_ga, &general_qry_ga,
				sizeof(qry_ga)) == 0 ? 1 : 0;

	/* Walk all ports and set aging timers */
	for (p_idx = 0; p_idx < mcc->max_ports; p_idx++) {
		mcc_omci_lock(context);
		IFXOS_LockGet(&mcc->port[p_idx].lock);

		port = &mcc->port[p_idx];
		aging_to_ms = 0;

		MCC_LIST_FOR_EACH_SAFE(flw_le, flw_nle, &port->flw_list) {
			flw_e = LE2FLW(flw_le);

			if (flw_e->grp_list.num == 0)
				continue;

			/* Get GMI from OMCI config */
			error = mcc_omci_flw_gmi_get(context, &flw_e->flw,
						     &aging_to_ms);
			if (error) {
				dbg_err("flw %p GMI get failed", flw_e);
				break;
			}

			MCC_LIST_FOR_EACH_SAFE(grp_le, grp_nle,
					    &flw_e->grp_list) {
				grp_e = LE2GRP(grp_le);

				if (!is_general_qry)
					if (memcmp(&grp_e->da, &qry_ga,
						   sizeof(qry_ga)))
						continue;

				if (grp_e->age_timeout_id) {
					dbg_prn("grp %p aging timer running, skip",
						grp_e);
					continue;
				}

				/* Fall back to packet GMI if no OMCI GMI */
				if (aging_to_ms == 0)
					aging_to_ms = mcc_pkt_gmi_get(pkt);

				if (aging_to_ms == 0) {
					dbg_err("zero GMI, ignoring Query");
					error = OMCI_ERROR;
					break;
				}

				error = timeout_event_add(
						context,
						&grp_e->age_timeout_id,
						(time_t)aging_to_ms,
						mcc_grp_aging_timeout_handler,
						0, 0,
						(unsigned long)flw_e,
						(unsigned long)grp_e,
						0);
				if (error) {
					dbg_err("grp %p aging timeout add failed",
						grp_e);
					break;
				}
			}
			if (error)
				break;
		}

		IFXOS_LockRelease(&mcc->port[p_idx].lock);
		mcc_omci_unlock(context);
		if (error)
			break;
	}

	return error;
}

/** Process Report packet: rate limit, extract records, restrict, forward. */
static enum omci_error mcc_rep_process(struct mcc_ctx *mcc,
				       struct mcc_pkt *pkt)
{
	enum omci_error error = OMCI_SUCCESS;
	struct omci_context *context = (struct omci_context *)mcc->ctx_core;
	uint8_t p_idx = mcc_pkt_port_idx_get(&pkt->info);
	uint8_t pass_unauth = 0;
	uint16_t rec_num, rec_idx, discard_cnt = 0, unauth_cnt = 0;

	RETURN_IF_BOUNDS_ERROR(p_idx, mcc->max_ports - 1);

	/* Rate-limit upstream IGMP/MLD */
	IFXOS_LockGet(&mcc->port[p_idx].lock);
	error = mcc_pkt_rate_limit(mcc, pkt);
	IFXOS_LockRelease(&mcc->port[p_idx].lock);
	if (error)
		return error;

	if (pkt->drop)
		return error;

	rec_num = pkt->info.prot_ctx->rec_num_get(pkt);

	for (rec_idx = 0; rec_idx < rec_num; rec_idx++) {
		error = mcc_rec_get(mcc, pkt, rec_idx, &mcc->rec);
		if (error)
			return error;

		mcc_omci_lock(context);
		IFXOS_LockGet(&mcc->port[p_idx].lock);
		error = mcc_rec_process(mcc, &mcc->rec);
		IFXOS_LockRelease(&mcc->port[p_idx].lock);
		mcc_omci_unlock(context);

		if (error)
			return error;

		if (mcc->rec.discard)
			discard_cnt++;
		if (mcc->rec.unauth)
			unauth_cnt++;
		if (mcc->rec.pass_unauth)
			pass_unauth = 1;
	}

	/* All records unauthorized → check pass/block policy */
	if (unauth_cnt == rec_num) {
		if (omci_iop_mask_isset(context, OMCI_IOP_OPTION_0)) {
			dbg_prn("forced unauthorized passing is ON");
		} else {
			if (pass_unauth)
				dbg_prn("pass unauthorized packet");
			else {
				dbg_prn("block unauthorized packet");
				pkt->drop = true;
			}
		}
	}

	/* All records discarded → drop packet */
	if (discard_cnt == rec_num) {
		pkt->drop = true;
		dbg_prn("all records discarded, packet dropped");
	}

	/* Update forwarding for well-known addresses */
	if (!pkt->drop) {
		error = mcc_fwd_dest_update(mcc, pkt);
		if (error)
			return error;
	}

	return error;
}

/** Top-level packet dispatch: queries → mcc_qry_process,
    reports/leave → mcc_rep_process, v1 → drop. */
static enum omci_error mcc_pkt_process(struct mcc_ctx *mcc,
				       struct mcc_pkt *pkt)
{
	enum omci_error error = OMCI_SUCCESS;

	switch (pkt->info.pkt_type) {
	case MCC_PKT_TYPE_IGMP_QUERY:
	case MCC_PKT_TYPE_MLD_QUERY:
		error = mcc_qry_process(mcc, pkt);
		break;
	case MCC_PKT_TYPE_IGMP_V2_REPORT:
	case MCC_PKT_TYPE_IGMP_V2_LEAVE:
	case MCC_PKT_TYPE_IGMP_V3_REPORT:
	case MCC_PKT_TYPE_MLD_V1_REPORT:
	case MCC_PKT_TYPE_MLD_V1_DONE:
	case MCC_PKT_TYPE_MLD_V2_REPORT:
		error = mcc_rep_process(mcc, pkt);
		break;
	case MCC_PKT_TYPE_IGMP_V1_REPORT:
		pkt->drop = true;
		dbg_prn("IGMP v1 detected, drop as deprecated");
		return error;
	case MCC_PKT_TYPE_NA:
	default:
		dbg_prn("packet type not detected/handled, transparently pass");
		return error;
	}

	return error;
}

/* ======================================================================
 * Packet thread
 * ====================================================================== */

static int mcc_pkt_thread(IFXOS_ThreadParams_t *params)
{
	struct mcc_ctx *mcc = (struct mcc_ctx *)params->nArg1;
	struct omci_context *context = (struct omci_context *)mcc->ctx_core;
	struct mcc_pkt *pkt;

	dbg_prn("MCC: packet thread started");

	/* Allocate packet buffer on heap (too large for stack) */
	pkt = IFXOS_MemAlloc(sizeof(*pkt));
	RETURN_IF_MALLOC_ERROR(pkt);

	while (params->bRunning && !params->bShutDown) {
		memset(pkt, 0, sizeof(*pkt));
		pkt->len = MCC_PKT_MAX_SIZE_BYTE;

		/* Block waiting for packet from exception interface */
		if (mcc_pkt_receive(mcc, pkt)) {
			continue;
		}

		/* When OMCI is in reset we can not lock the MEs any more */
		if (context->mib_reset_in_progress ||
		    context->omci_shutdown_in_progress) {
			continue;
		}

		/* mcc_pkt_receive() could block; re-check thread state */
		if (!params->bRunning || params->bShutDown)
			break;

		/* Process the received packet */
		if (mcc_pkt_process(mcc, pkt)) {
			dbg_wrn("packet process failed");
			continue;
		}

		/* Send packet back to the exception path */
		if (mcc_pkt_send(mcc, pkt))
			dbg_wrn("packet send failed");
	}

	IFXOS_MemFree(pkt);

	dbg_prn("MCC: packet thread exiting");

	return 0;
}

enum omci_error mcc_thread_start(struct mcc_ctx *mcc)
{
	enum omci_error error;

	error = (enum omci_error)IFXOS_ThreadInit(&mcc->pkt_thread_ctrl,
						  "mcc_pkt",
						  mcc_pkt_thread,
						  IFXOS_DEFAULT_STACK_SIZE,
						  IFXOS_THREAD_PRIO_LOWEST,
						  (unsigned long)mcc, 0);
	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}

enum omci_error mcc_thread_stop(struct mcc_ctx *mcc)
{
	/* Cancel blocking receive */
	mcc_dev_pkt_receive_cancel(&mcc->dev);

	/* Wait for thread to exit */
	if (IFXOS_ThreadShutdown(&mcc->pkt_thread_ctrl, 2000)
	    != IFX_SUCCESS) {
		dbg_wrn("MCC: packet thread shutdown timeout");
	}

	return OMCI_SUCCESS;
}

/* ======================================================================
 * Group list clear (for PLOAM state transitions / ME reset)
 * ====================================================================== */

enum omci_error mcc_group_list_clear(struct mcc_ctx *mcc,
				     const uint8_t port_idx)
{
	struct mcc_port *port;

	RETURN_IF_BOUNDS_ERROR(port_idx, mcc->max_ports - 1);

	port = &mcc->port[port_idx];

	IFXOS_LockGet(&port->lock);
	mcc_flw_cleanup(mcc, &port->flw_list);
	mcc_rl_delete(&port->rl);
	port->join_msg_cnt = 0;
	port->exce_msg_cnt = 0;
	IFXOS_LockRelease(&port->lock);

	return OMCI_SUCCESS;
}

/* ======================================================================
 * Static/dynamic flow control from OMCI ME handlers
 * ====================================================================== */

enum omci_error
mcc_port_mc_flow_control(struct mcc_ctx *mcc,
			 const uint8_t port_idx,
			 const bool add,
			 const bool is_static,
			 const struct mcc_mc_flow *flow)
{
	enum omci_error error = OMCI_SUCCESS;
	struct mcc_port *port;
	uint8_t fid;
	uint16_t svid;
	bool src_list_needed, clt_remove_all = false;
	struct mcc_flw mcc_flow;
	struct mcc_flw_entry *flw;
	struct mcc_grp_entry *grp;
	struct mcc_clt_entry *clt;
	struct mcc_src_entry *src;
	struct mcc_list src_list;
	union mcc_ip_addr ip_addr;

	port = &mcc->port[port_idx];

	svid = flow->svid == MCC_VLAN_UNAWARE_SVID ? 0 : flow->svid;

	error = mcc_dev_fid_get(&mcc->dev, svid, &fid);
	if (error)
		return error;

	flw = mcc_flw_find(&port->flw_list, fid);
	if (!flw) {
		if (add) {
			mcc_flow.id   = fid;
			mcc_flow.port = port_idx;
			mcc_flow.cvid = flow->cvid;
			mcc_flow.svid = svid;

			flw = mcc_flw_create(&port->flw_list, &mcc_flow);
			if (!flw)
				return OMCI_ERROR_MEMORY;
		} else {
			return OMCI_ERROR;
		}
	}

	mcc_ip_addr_get(flow->da, &ip_addr);
	grp = mcc_grp_find(&flw->grp_list, &ip_addr);
	if (!grp) {
		if (add) {
			grp = mcc_grp_create(&flw->grp_list, flw,
					     is_static, &ip_addr);
			if (!grp)
				return OMCI_ERROR_MEMORY;
		} else {
			return OMCI_ERROR;
		}
	} else {
		if (grp->is_static != is_static)
			return OMCI_ERROR;
	}

	mcc_ip_addr_get(flow->ca, &ip_addr);
	clt = mcc_clt_find(&grp->clt_list, &ip_addr);
	if (!clt) {
		if (add) {
			clt = mcc_clt_create(&grp->clt_list, grp,
					     is_static, &ip_addr);
			if (!clt)
				return OMCI_ERROR_MEMORY;
		} else {
			if (!mcc_is_ip_any(&ip_addr)) {
				return OMCI_ERROR;
			} else {
				clt = mcc_clt_next(&grp->clt_list, NULL);
				if (!clt)
					return OMCI_ERROR;
				clt_remove_all = true;
			}
		}
	} else {
		if (clt->is_static != is_static)
			return OMCI_ERROR;
	}

do_again:
	src_list.num = 0;
	mcc_list_init(&src_list);

	mcc_ip_addr_get(flow->sa, &ip_addr);
	if (mcc_is_ip_any(&ip_addr)) {
		mcc_clt_fmode_set(add ? MCC_FLT_MODE_EXCLUDE :
					MCC_FLT_MODE_INCLUDE, clt);
		src_list_needed = add ? true : false;
	} else {
		mcc_clt_smode_set(add ? MCC_SRC_MODE_ALLOW :
					MCC_SRC_MODE_BLOCK, clt);
		src_list_needed = true;
	}

	if (src_list_needed) {
		src = mcc_src_create(&src_list, true, clt, &ip_addr, 0, NULL);
		if (!src)
			return OMCI_ERROR_MEMORY;
	}

	do {
		error = mcc_clt_refresh(mcc, &src_list, &grp->clt_list, clt);
		if (error != OMCI_SUCCESS)
			break;

		error = mcc_grp_refresh(mcc, flw, grp);
		if (error != OMCI_SUCCESS)
			break;

		if (flw->grp_list.num == 0)
			mcc_flw_delete(&port->flw_list, flw);

		mcc_ip_addr_get(flow->da, &ip_addr);
		error = mcc_fwd_refresh(mcc, port_idx, fid, &ip_addr);
		if (error != OMCI_SUCCESS)
			break;
	} while (0);

	mcc_src_list_delete(&src_list);

	if (clt_remove_all) {
		clt = mcc_clt_next(&grp->clt_list, clt);
		if (clt)
			goto do_again;
	}

	return error;
}

enum omci_error
mcc_port_mc_flow_range_delete(struct mcc_ctx *mcc,
			      const uint8_t port_idx,
			      const bool is_static,
			      const struct mcc_mc_flow_range *flow_range)
{
	enum omci_error error = OMCI_SUCCESS;
	struct mcc_port *port;
	uint8_t fid;
	uint16_t svid;
	struct mcc_flw_entry *flw;
	union mcc_ip_addr da_s, da_e;
	struct mcc_grp_entry *e;
	struct mcc_list_head *le, *nle;
	struct mcc_mc_flow flow;

	port = &mcc->port[port_idx];

	svid = flow_range->svid == MCC_VLAN_UNAWARE_SVID ? 0 : flow_range->svid;

	error = mcc_dev_fid_get(&mcc->dev, svid, &fid);
	if (error)
		return error;

	flw = mcc_flw_find(&port->flw_list, fid);
	if (!flw)
		return OMCI_ERROR;

	if (flw->grp_list.num == 0)
		return OMCI_ERROR;

	mcc_ip_addr_get(flow_range->ip_range.da_s, &da_s);
	mcc_ip_addr_get(flow_range->ip_range.da_e, &da_e);

	MCC_LIST_FOR_EACH_SAFE(le, nle, &flw->grp_list) {
		e = LE2GRP(le);

		if (memcmp(&e->da, &da_s, sizeof(da_s)) < 0 ||
		    memcmp(&e->da, &da_e, sizeof(da_e)) > 0)
			continue;

		memset(&flow, 0, sizeof(flow));
		flow.cvid = flow_range->cvid;
		flow.svid = flow_range->svid;
		memcpy(flow.ca, flow_range->ip_range.ca, sizeof(flow.ca));
		memcpy(flow.sa, flow_range->ip_range.sa, sizeof(flow.sa));

		if (mcc_is_ipv6(&e->da))
			memcpy(flow.da, e->da.ipv6, sizeof(e->da.ipv6));
		else
			memcpy(&flow.da[12], e->da.ipv4, sizeof(e->da.ipv4));

		(void)mcc_port_mc_flow_control(mcc, port_idx, false,
					       is_static, &flow);
	}

	return error;
}
