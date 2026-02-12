/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_api_mcc.c
   IGMP demonstration code.
*/

#ifdef LINUX

#include "omci_api_common.h"
#include "omci_api_debug.h"

#ifdef INCLUDE_OMCI_API_MCC

#include <linux/sockios.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "omci_api_usock.h"

#include "mcc/omci_api_mcc.h"
#include "omci_api_mcc_common.h"

/** \defgroup OMCI_API_MCC Multicast Control
    Demonstration application for IGMP handling on a FALC ON-based GPON ONU.
    This is a preliminary version, based on the FS4 software release.

    Added functionality compared with FS3:
      - IGMPv1 control packet dropping.
      - IGMP/MLD control packet rate filtering.
      - Adding/removing UNI ports to/from existing multicast groups.

    The following restrictions apply:
      - No support of IGMP query messages.
      - No support of IGMPv3 source filtering.
      - No support of OMCI-controlled functionality.
      - No support of MLD (IPv6).
   @{
*/

/** Time in ms to wait for interface to become 'up' */
#define MCC_IF_WAIT_TIMEOUT			5000

/** Debug level control, set this as required.
	Values from 0 to 4 are used.
*/
static uint8_t mcc_dbg_level = 4;

static uint8_t mcc_subscr_idx_get(struct mcc_ctx *mcc,
				  const uint8_t lan_port);
static uint32_t mcc_subscr_max_mc_bw_get(struct mcc_ctx *mcc,
					 const uint8_t s_idx);
static bool mcc_subscr_bw_enf_get(struct mcc_ctx *mcc, const uint8_t s_idx);
static uint8_t mcc_profile_idx_get(struct mcc_ctx *mcc, const uint8_t s_idx);

/* until HW is working provide a SW fix */
static uint32_t us_igmp_rate = 0;

/** Locking function to allow multithreading.
*/
static void mcc_locked_memcpy(void *to, const void *from, const size_t size,
			      IFXOS_lock_t *lock)
{
	IFXOS_LockGet(lock);
	memcpy(to, from, size);
	IFXOS_LockRelease(lock);
}

static void mcc_locked_memset(void *dest, const uint8_t fill, const size_t size,
			      IFXOS_lock_t *lock)
{
	IFXOS_LockGet(lock);
	memset(dest, fill, size);
	IFXOS_LockRelease(lock);
}

/** Convert an IP muticast address into a MAC multicast address.

	\param addr IP multicast group address.

	\return mac Ethernet MAC multicast address.
*/
static void mcc_igmp_addr2mac(const uint32_t addr, uint8_t mac[6])
{
	mac[0] = 0x01;
	mac[1] = 0x00;
	mac[2] = 0x5E;
	mac[3] = (uint8_t)((addr >> 16) & 0x7F);
	mac[4] = (uint8_t)((addr >> 8) & 0xFF);
	mac[5] = (uint8_t)(addr & 0xFF);
}

/** This function is used to add/remove IPv4 multicast group to/from a LAN/UNI
    port.

	\param mcc MCC context.
	\param add function control (add or remove).
	\param lan_port UNI/LAN port index.
	\param fid Flow ID
	\param ip IPv4 multicast address, index 0 holds the first byte "AA" of a
		  IP address AA.BB.CC.DD

	\return Return value as follows:
	- OMCI_API_SUCCESS The function has successfully returned.
	- Others in case of errors.
*/
static enum omci_api_return mcc_short_fwd_port_ctrl(struct mcc_ctx *mcc,
						    const bool add,
						    const uint8_t lan_port,
						    const uint8_t fid,
						    const uint8_t ip[4])
{
	enum omci_api_return ret;
	struct gpe_ipv4_mc_port mc_port;

	memcpy(mc_port.ip, ip, 4);
	mc_port.fid = fid;
	mc_port.lan_port_index = lan_port;
	mc_port.igmp = 1;

	ret = dev_ctl(mcc->remote, mcc->onu_fd,
		      add ? FIO_GPE_SHORT_FWD_IPV4_MC_PORT_ADD :
			    FIO_GPE_SHORT_FWD_IPV4_MC_PORT_DELETE,
		      &mc_port, sizeof(mc_port));
	if (ret == OMCI_API_SUCCESS) {
		DBG(OMCI_API_MSG, ("MCC IPv4 MC port %u %s: "
				"%u.%u.%u.%u\n",
				   lan_port,
				   add ? "added" : "removed",
				   ip[0], ip[1], ip[2], ip[3]));
	}

	return ret;
}

/** Modify multicast forwarding table entries (add or delete).
    This function is used to add or remove a multicast forwarding entry to/from
    the multicast forwarding table.

    Adding/removing ports to/from existing multicast groups is done on-the-fly.

	\param mcc MCC context.
	\param add Controls, if the entry shall be added or deleted.
	\param bridge_idx This selects the bridge (one of 8 bridges)
	\param port_map This bit map defines, to which bridge ports a multicast
	                packet shall be replicated.
	\param mac MAC multicast address, index 0 holds the first byte "AA" of a
	           MAC address AA:BB:CC:DD:EE:FF

	\return Return value as follows:
	- OMCI_API_SUCCESS The function has successfully returned.
	- Others in case of errors.
*/
static enum omci_api_return mcc_short_fwd_entry_ctrl(struct mcc_ctx *mcc,
						     const bool add,
						     const uint8_t bridge_idx,
						     const uint16_t port_map,
						     const uint8_t mac[6])
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	memset(&entry, 0x00, sizeof(entry));

	entry.data.short_fwd_table_mac_mc.mac_address_high =
			mac[0] << 8 | mac[1];
	entry.data.short_fwd_table_mac_mc.mac_address_low =
			mac[2] << 24 | mac[3] << 16 | mac[4] << 8 | mac[5];

	entry.data.short_fwd_table_mac_mc.bridge_index = bridge_idx;
	entry.data.short_fwd_table_mac_mc.port_map = port_map;
	entry.data.short_fwd_table_mac_mc.key_code = 0;
	entry.data.short_fwd_table_mac_mc.fid = ONU_GPE_CONSTANT_VAL_DEFAULT_FID;
	entry.data.short_fwd_table_mac_mc.include_enable = 1;
	entry.data.short_fwd_table_mac_mc.msf_enable = 0;
	entry.data.short_fwd_table_mac_mc.dynamic_enable = 0;
	entry.data.short_fwd_table_mac_mc.zero_limitation = 0;
	entry.data.short_fwd_table_mac_mc.one_port_map_indicator = 1;
	entry.data.short_fwd_table_mac_mc.igmp = 1; /* set IGMP flag*/

	ret = dev_ctl(mcc->remote, mcc->onu_fd,
		      add ? FIO_GPE_SHORT_FWD_ADD : FIO_GPE_SHORT_FWD_DELETE,
		      &entry,
		      TABLE_ENTRY_SIZE(entry.data.short_fwd_table_mac_mc));
	if (ret == OMCI_API_SUCCESS) {
		DBG(OMCI_API_MSG, ("MCC MAC MC entry %s: "
				"0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n",
				   add ? "added" : "removed",
					mac[0], mac[1], mac[2],
					mac[3], mac[4], mac[5]));
	}

	return ret;
}

/** Add well-known multicast MAC addresses to the multicast forwarding table.
    Certain multicast addresses can be pre-configured to allow IGMP control
    packets to be forwarded.
    The addresses are hard-coded in this fuction and can be modified as needed.

	\param mcc MCC context.
	\param add Controls if the entries are added or removed.

	\return Return value as follows:
	- OMCI_API_SUCCESS The function has successfully returned.
	- Others in case of errors.
*/
static enum omci_api_return
mcc_short_fwd_unknown_mac_flooding_ctrl(struct mcc_ctx *mcc, const bool add)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t i, j;
	uint8_t mac_tbl[][6] = {
		{0x01, 0x00, 0x5E, 0x00, 0x00, 0x16},
		{0x01, 0x00, 0x5E, 0x00, 0x00, 0x02},
		{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}
	};

	/* set well-known adresses for all 8 bridges with port_map = 0x3F*/
	for (i = 0; i < ONU_GPE_MAX_BRIDGES; i++) {
		for (j = 0; j < sizeof(mac_tbl)/sizeof(mac_tbl[0]); j++) {
			ret = mcc_short_fwd_entry_ctrl(mcc, add, i,
						       0x1F, &mac_tbl[j][0]);
			if (ret != OMCI_API_SUCCESS) {
				DBG(OMCI_API_ERR, ("MCC MAC MC entry add failed "
						   "bridge_idx=%u, ret=%d\n",
						   i, ret));
				return ret;
			}
		}
	}

	return ret;
}

/** Remove all group entries from the subscriber list.

	\param mcc MCC context.
	\param s_idx Subscriber index.

	\return Return value as follows:
	- OMCI_API_SUCCESS The function has successfully returned.
	- Others in case of errors.
*/
static enum omci_api_return
mcc_subscr_group_entries_clear(struct mcc_ctx *mcc, const uint8_t s_idx)
{
	enum omci_api_return err;
	struct mcc_added_groups_list *groups_list;
	struct mcc_added_groups_list_entry *list_entry;
	struct mcc_added_groups_list_entry *next_list_entry;

	groups_list = s_idx == MCC_SUBSCR_NULL ?
				&mcc->unassigned_groups_list :
				&mcc->added_groups_list[s_idx];

	IFXOS_LockGet(&mcc->groups_list_lock);

	MCC_DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				&groups_list->list_head) {

		/* remove Layer-2 forwarding entry */
		err = mcc_short_fwd_port_ctrl(mcc, false,
					      list_entry->entry.lan_port,
					      list_entry->entry.fid,
					      (uint8_t*)&(list_entry->entry.group.g_addr));
		if (err != OMCI_API_SUCCESS && err != GPE_STATUS_NOT_AVAILABLE) {
			DBG(OMCI_API_ERR, ("MCC IPv4 entry remove failed, "
				           "ret=%d\n", err));
			return err;
		}

		MCC_DLIST_REMOVE(list_entry);

		--groups_list->entries_num;

		IFXOS_MemFree(list_entry);
		list_entry = NULL;
	}

	IFXOS_LockRelease(&mcc->groups_list_lock);

	return OMCI_API_SUCCESS;
}

static uint32_t
mcc_subscr_group_entries_bw_total_get(struct mcc_ctx *mcc, const uint8_t s_idx)
{
	struct mcc_added_groups_list *groups_list;
	struct mcc_added_groups_list_entry *list_entry;
	struct mcc_added_groups_list_entry *next_list_entry;
	uint32_t bw_total = 0;

	groups_list = s_idx == MCC_SUBSCR_NULL ?
				&mcc->unassigned_groups_list :
				&mcc->added_groups_list[s_idx];

	IFXOS_LockGet(&mcc->groups_list_lock);

	MCC_DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				&groups_list->list_head) {
		bw_total += list_entry->entry.bw;
	}

	IFXOS_LockRelease(&mcc->groups_list_lock);

	return bw_total;
}

/** Get best effort estimate of the actual bandwidth currently being delivered
    to subscriber port over all dynamic multicast groups. */
static uint32_t
mcc_subscr_group_entries_bw_curr_get(struct mcc_ctx *mcc, const uint8_t s_idx)
{
	struct mcc_added_groups_list *groups_list;
	struct mcc_added_groups_list_entry *list_entry;
	struct mcc_added_groups_list_entry *next_list_entry;
	uint32_t bw_best = 0;

	groups_list = s_idx == MCC_SUBSCR_NULL ?
				&mcc->unassigned_groups_list :
				&mcc->added_groups_list[s_idx];

	IFXOS_LockGet(&mcc->groups_list_lock);

	MCC_DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				&groups_list->list_head) {
		bw_best = MAX(bw_best, list_entry->entry.bw);
	}

	IFXOS_LockRelease(&mcc->groups_list_lock);

	return bw_best;
}

/** Update group entries for the specified subscriber. Entries with no multicast
    activity are marked as "lost".

	\param mcc MCC context.

	\return Return value as follows:
	- OMCI_API_SUCCESS The function has successfully returned.
	- Others in case of errors.
*/
static enum omci_api_return
mcc_subscr_group_entries_update(struct mcc_ctx *mcc)
{
	struct mcc_added_groups_list *groups_list;
	struct mcc_added_groups_list_entry *list_entry;
	struct mcc_added_groups_list_entry *next_list_entry;
	struct timespec t_val;
	uint8_t s_idx;

	if (clock_gettime(CLOCK_MONOTONIC, &t_val) != 0)
		return OMCI_API_ERROR;

	IFXOS_LockGet(&mcc->groups_list_lock);

	for (s_idx = 0; s_idx < OMCI_API_MCC_MAX_SUBSCRIBERS + 1; s_idx++) {
		groups_list = s_idx < OMCI_API_MCC_MAX_SUBSCRIBERS ?
				&mcc->added_groups_list[s_idx] :
				&mcc->unassigned_groups_list;

		if (!groups_list->entries_num)
			continue;

		MCC_DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
					&groups_list->list_head) {
			if (list_entry->entry.lost)
				continue;

			if (t_val.tv_sec - list_entry->entry.last_update <
						MCC_LOST_GROUPS_UPDATE_TIME_SEC)
				continue;

			list_entry->entry.last_update = t_val.tv_sec;

			/** \todo read HW MC forwarding table and update loss flag
				  depending on the MC activity bit.
			*/

			/** \todo remove lost group only for the unassigned
			          group list */
		}
	}


	IFXOS_LockRelease(&mcc->groups_list_lock);

	return OMCI_API_SUCCESS;
}

/** Add group entry for the specified subscriber.

	\param mcc MCC context.
	\param s_idx Subscriber index.
	\param entry Group entry

	\return Return value as follows:
	- OMCI_API_SUCCESS The function has successfully returned.
	- Others in case of errors.
*/
static enum omci_api_return
mcc_subscr_group_entry_add(struct mcc_ctx *mcc,
			   const uint8_t s_idx,
			   const struct mcc_added_group *entry)
{
	enum omci_api_return err;
	struct mcc_added_groups_list *groups_list;
	struct mcc_added_groups_list_entry *list_entry;
	struct mcc_added_groups_list_entry *next_list_entry;

	groups_list = s_idx == MCC_SUBSCR_NULL ?
				&mcc->unassigned_groups_list :
				&mcc->added_groups_list[s_idx];

	/* add/remove Layer-3 forwarding entry */
	err = mcc_short_fwd_port_ctrl(mcc, true, entry->lan_port, entry->fid,
				      (uint8_t*)&(entry->group.g_addr));
				      
	if (err != OMCI_API_SUCCESS && err != GPE_STATUS_NOT_AVAILABLE) {
		DBG(OMCI_API_ERR, ("MCC IPv4 MAC entry add failed, ret=%d\n",
									err));
		return err;
	}

	IFXOS_LockGet(&mcc->groups_list_lock);

	/* check if entry already exists*/
	MCC_DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				&groups_list->list_head) {
		if (list_entry->entry.group.g_addr == entry->group.g_addr) {
			list_entry->entry.last_update = entry->last_update;
			IFXOS_LockRelease(&mcc->groups_list_lock);
			return OMCI_API_SUCCESS;
		}
	}

	list_entry = IFXOS_MemAlloc(sizeof(*list_entry));
	if (!list_entry)
		return OMCI_API_NO_MEMORY;

	memcpy(list_entry, entry, sizeof(*entry));
	++groups_list->entries_num;

	MCC_DLIST_ADD_TAIL(list_entry, &groups_list->list_head);

	IFXOS_LockRelease(&mcc->groups_list_lock);

	return OMCI_API_SUCCESS;
}

/** Remove specified subscriber group entry.

	\param mcc MCC context.
	\param s_idx Subscriber index.
	\param entry Group entry

	\return Return value as follows:
	- OMCI_API_SUCCESS The function has successfully returned.
	- Others in case of errors.
*/
static enum omci_api_return
mcc_subscr_group_entry_rem(struct mcc_ctx *mcc,
			   const uint8_t s_idx,
			   const struct mcc_added_group *entry)
{
	enum omci_api_return err;
	struct mcc_added_groups_list *groups_list;
	struct mcc_added_groups_list_entry *list_entry;
	struct mcc_added_groups_list_entry *next_list_entry;

	groups_list = s_idx == MCC_SUBSCR_NULL ?
				&mcc->unassigned_groups_list :
				&mcc->added_groups_list[s_idx];

	/* remove Layer-3 forwarding entry */
	err = mcc_short_fwd_port_ctrl(mcc, false, entry->lan_port, entry->fid,
				      (uint8_t*)&(entry->group.g_addr));
	if (err != OMCI_API_SUCCESS && err != GPE_STATUS_NOT_AVAILABLE) {
		DBG(OMCI_API_ERR, ("MCC IPv4 MAC entry remove failed, ret=%d\n",
									err));
		return err;
	}

	IFXOS_LockGet(&mcc->groups_list_lock);

	MCC_DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				&groups_list->list_head) {
		if (list_entry->entry.group.g_addr != entry->group.g_addr)
			continue;
		if (list_entry->entry.group.vlan.tci != entry->group.vlan.tci)
			continue;

		MCC_DLIST_REMOVE(list_entry);

		--groups_list->entries_num;

		IFXOS_MemFree(list_entry);
		list_entry = NULL;
	}

	IFXOS_LockRelease(&mcc->groups_list_lock);

	return OMCI_API_SUCCESS;
}

/** Find group entry for the specified subscriber.

	\param mcc MCC context.
	\param s_idx Subscriber index.
	\param entry Group entry

	\return Return value as follows:
	- OMCI_API_SUCCESS The function has successfully returned, entry matched
	- OMCI_API_NOT_FOUND Entry not found
	- Others in case of errors.
*/
static enum omci_api_return
mcc_subscr_group_entry_match_find(struct mcc_ctx *mcc,
				  const uint8_t s_idx,
				  const struct mcc_added_group *entry,
				  struct mcc_added_group *entry_matched)
{
	enum omci_api_return err;
	struct mcc_added_groups_list *groups_list;
	struct mcc_added_groups_list_entry *list_entry;
	struct mcc_added_groups_list_entry *next_list_entry;

	groups_list = s_idx == MCC_SUBSCR_NULL ?
				&mcc->unassigned_groups_list :
				&mcc->added_groups_list[s_idx];

	memset(entry_matched, 0, sizeof(*entry_matched));

	IFXOS_LockGet(&mcc->groups_list_lock);

	MCC_DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				&groups_list->list_head) {
		if (list_entry->entry.group.g_addr != entry->group.g_addr)
			continue;
		if (list_entry->entry.group.vlan.tci != entry->group.vlan.tci)
			continue;

		memcpy(entry_matched, &list_entry->entry,
		       sizeof(struct mcc_added_group));

		IFXOS_LockRelease(&mcc->groups_list_lock);
		return OMCI_API_SUCCESS;
	}

	IFXOS_LockRelease(&mcc->groups_list_lock);

	return OMCI_API_NOT_FOUND;
}

/** Add source addresses to the existing group entry.

	\param mcc MCC context.
	\param s_idx Subscriber index.
	\param entry Group entry

	\return Return value as follows:
	- OMCI_API_SUCCESS The function has successfully returned.
	- Others in case of errors.
*/
static enum omci_api_return
mcc_subscr_group_entry_src_add(struct mcc_ctx *mcc,
			       const uint8_t s_idx,
			       const struct mcc_added_group *entry)
{
	enum omci_api_return err = OMCI_API_SUCCESS;
	struct mcc_added_groups_list *groups_list;
	struct mcc_added_groups_list_entry *list_entry;
	struct mcc_added_groups_list_entry *next_list_entry;
	uint32_t i, j;
	const uint32_t *new_sa;
	uint32_t *old_sa;
	bool duplicate;

	groups_list = s_idx == MCC_SUBSCR_NULL ?
				&mcc->unassigned_groups_list :
				&mcc->added_groups_list[s_idx];

	IFXOS_LockGet(&mcc->groups_list_lock);

	MCC_DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				&groups_list->list_head) {
		if (list_entry->entry.group.g_addr != entry->group.g_addr)
			continue;
		if (list_entry->entry.group.vlan.tci != entry->group.vlan.tci)
			continue;

		list_entry->entry.group.s_addr_list_state =
						entry->group.s_addr_list_state;

		new_sa = entry->group.s_addr_list.s_addr;
		old_sa = list_entry->entry.group.s_addr_list.s_addr;

		for (i = 0; i < entry->group.s_addr_list.s_addr_num; i++) {
			duplicate = false;
			for (j = 0; j < list_entry->entry.group.s_addr_list.s_addr_num; j++) {
				if (new_sa[i] == old_sa[j]) {
					duplicate = true;
					break;
				}
			}
			if (duplicate)
				continue; /* skip duplicate entry*/

			if (list_entry->entry.group.s_addr_list.s_addr_num >=
				MCC_IGMP_SOURCE_ADDR_LIST_COUNT_MAX) {
				/* no free space left */
				err = OMCI_API_ERROR;
				break;
			}

			/* add new source address */
			old_sa[list_entry->entry.group.s_addr_list.s_addr_num] =
								      new_sa[i];
			list_entry->entry.group.s_addr_list.s_addr_num++;
		}

	}

	IFXOS_LockRelease(&mcc->groups_list_lock);

	return err;
}

/** Remove source addresses from the existing group entry.

	\param mcc MCC context.
	\param s_idx Subscriber index.
	\param entry Group entry

	\return Return value as follows:
	- OMCI_API_SUCCESS The function has successfully returned.
	- Others in case of errors.
*/
static enum omci_api_return
mcc_subscr_group_entry_src_rem(struct mcc_ctx *mcc,
			       const uint8_t s_idx,
			       const struct mcc_added_group *entry)
{
	enum omci_api_return err = OMCI_API_SUCCESS;
	struct mcc_added_groups_list *groups_list;
	struct mcc_added_groups_list_entry *list_entry;
	struct mcc_added_groups_list_entry *next_list_entry;
	uint32_t i, j, next_idx;
	const uint32_t *new_sa;
	uint32_t *old_sa;

	groups_list = s_idx == MCC_SUBSCR_NULL ?
				&mcc->unassigned_groups_list :
				&mcc->added_groups_list[s_idx];

	IFXOS_LockGet(&mcc->groups_list_lock);

	MCC_DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				&groups_list->list_head) {
		if (list_entry->entry.group.g_addr != entry->group.g_addr)
			continue;
		if (list_entry->entry.group.vlan.tci != entry->group.vlan.tci)
			continue;

		list_entry->entry.group.s_addr_list_state =
						entry->group.s_addr_list_state;

		new_sa = entry->group.s_addr_list.s_addr;
		old_sa = list_entry->entry.group.s_addr_list.s_addr;

		for (i = 0; i < entry->group.s_addr_list.s_addr_num; i++) {
			for (j = 0; j < list_entry->entry.group.s_addr_list.s_addr_num; j++) {
				if (new_sa[i] != old_sa[j])
					continue;

				next_idx = i + 1;
				if (next_idx == list_entry->entry.group.s_addr_list.s_addr_num) {
					old_sa[i] = 0;
					/* last entry, just update the count */
					list_entry->entry.group.s_addr_list.s_addr_num--;
				} else {
					/* remove matched source address */
					memmove(&old_sa[j], &old_sa[next_idx],
						sizeof(old_sa[next_idx]) *
						(list_entry->entry.group.
						s_addr_list.s_addr_num - j - 1)
					);
					list_entry->entry.group.s_addr_list.s_addr_num--;
				}
			}

			/* remove group entry completely if there are no
			   sources left */
			/** \todo crosscheck if this is a valid handling.
			*/
			if (list_entry->entry.group.s_addr_list.s_addr_num == 0) {
				/* remove Layer-3 forwarding entry */
				err = mcc_short_fwd_port_ctrl(mcc, false,
						list_entry->entry.lan_port,
						list_entry->entry.fid,
						(uint8_t*)&(list_entry->entry.group.g_addr));
				if (err != OMCI_API_SUCCESS && err != GPE_STATUS_NOT_AVAILABLE) {
					DBG(OMCI_API_ERR, ("MCC IPv4 MAC entry remove failed, ret=%d\n",
												err));
					return err;
				}

				MCC_DLIST_REMOVE(list_entry);
				--groups_list->entries_num;
				IFXOS_MemFree(list_entry);
				list_entry = NULL;
			}
		}
	}

	IFXOS_LockRelease(&mcc->groups_list_lock);

	return err;
}

/** This function checks if a subsscriber has already reached the maximum number
    of allowed  simultaneous groups.

	\param mcc MCC context.
	\param s_idx Subscriber index.

	\return Return value as follows:
	- true The limit has been reached.
	- false The limit has not been reached.
*/
static bool mcc_subscr_is_groups_limit_reached(struct mcc_ctx *mcc,
					       const uint8_t s_idx)
{
	bool ret = false;

	if (s_idx != MCC_SUBSCR_NULL) {
		if (mcc->subscr[s_idx].max_simultaneous_groups &&
			mcc->added_groups_list[s_idx].entries_num >=
				mcc->subscr[s_idx].max_simultaneous_groups) {
			ret = true;
		}
	}

	return ret;
}

/** Receive an IGMP control packet from the exception interface.

	\param s t.b.d.
	\param pkt Received IGMP packet information

	\return Return value as follows:
	- 0 The function has successfully returned.
	- -1 Packet receive error.
*/
static int mcc_pkt_rcv(const int s, struct mcc_pkt *pkt)
{
	int len;

	/* Here we receive only one RAW packet per call.
	   Nice Linux feature... */
	len = recvfrom(s, pkt->data, sizeof(pkt->data), 0, NULL, NULL);
	if (len <= 0)
		return -1;

	pkt->len = (uint32_t)len;

	pkt->drop = false;

	return 0;
}

/** Send an IGMP control packet to the exception interface.

	\param s t.b.d.
	\param sll Socket address
	\param pkt Received IGMP packet information

	\return Return value as follows:
	- 0 The function has successfully returned.
	- -1 Packet transmit error.
*/
static int mcc_pkt_snd(const int s, struct sockaddr_ll *sll,
		       struct mcc_pkt *pkt)
{
	if (pkt->drop)
		return 0;
	if (sendto(s, pkt->data, pkt->len, 0,
		   (struct sockaddr *)sll, sizeof(*sll)) <= 0)
		return -1;
	return 0;
}

/** Get the contents of an IGMP contol packet.

	\param pkt Received IGMP packet information

	\return Return value as follows:
	- 0 The function has successfully returned.
	- 1 No IP header found in the packet.
	- 2 Unsupported IP version found in the packet.
	- 3 Unsupported IP protocol found in the packet.
*/
static int mcc_pkt_info_update(struct mcc_pkt *pkt)
{
	uint8_t *p;
	uint32_t len;
	struct iphdr iphdr;

	memset(&pkt->info, 0, sizeof(pkt->info));

	p = (uint8_t*)pkt->data;

	/* extract exception packet header*/
	pkt->info.exc_hdr.p   = (union u_onu_exception_pkt_hdr*)p;
	len = pkt->info.exc_hdr.p->ext.ext_bytes ?
			sizeof(union u_onu_exception_pkt_hdr) :
			offsetof(union u_onu_exception_pkt_hdr, raw.e[0]);
	pkt->info.exc_hdr.len = len;
	p += len; /* move to the MAC header*/

	switch(((struct mcc_pkt_mac0_hdr*)p)->etype) {
		case MCC_ETH_TYPE_802_1Q:
		case MCC_ETH_TYPE_802_1AD:
		case MCC_ETH_TYPE_Q_IN_Q:
		pkt->info.mac_hdr.mac1_hdr = (struct mcc_pkt_mac1_hdr *)p;
		len = sizeof(struct mcc_pkt_mac1_hdr);
		break;
		default:
		pkt->info.mac_hdr.mac0_hdr = (struct mcc_pkt_mac0_hdr *)p;
		len = sizeof(struct mcc_pkt_mac0_hdr);
		break;
	}
	if(pkt->info.mac_hdr.mac1_hdr) {
		switch(pkt->info.mac_hdr.mac1_hdr->etype) {
			case MCC_ETH_TYPE_802_1Q:
			case MCC_ETH_TYPE_802_1AD:
			case MCC_ETH_TYPE_Q_IN_Q:
			pkt->info.mac_hdr.mac1_hdr = NULL;
			pkt->info.mac_hdr.mac2_hdr = (struct mcc_pkt_mac2_hdr *)p;
			len = sizeof(struct mcc_pkt_mac2_hdr);
			break;
		}
	}
	if(pkt->info.mac_hdr.mac2_hdr) {
		switch(pkt->info.mac_hdr.mac2_hdr->etype) {
			case MCC_ETH_TYPE_802_1Q:
			case MCC_ETH_TYPE_802_1AD:
			case MCC_ETH_TYPE_Q_IN_Q:
			pkt->info.mac_hdr.mac2_hdr = NULL;
			pkt->info.mac_hdr.mac3_hdr = (struct mcc_pkt_mac3_hdr *)p;
			len = sizeof(struct mcc_pkt_mac3_hdr);
			break;
		}
	}
	pkt->info.mac_hdr.len = len;

	p += len; /* move to the IP header */

	memcpy(&iphdr, p, sizeof(iphdr));
	if (iphdr.version == 4) {
		memcpy(&pkt->info.ip_hdr.ipv4, p, sizeof(struct iphdr));
		/* IP header length*/
		len = iphdr.ihl * sizeof(uint32_t);
	} else if (iphdr.version == 6) {
		DBG(OMCI_API_ERR, ("MCC IPv6 is not supported yet!\n"));
		return 1;
	} else {
		DBG(OMCI_API_MSG, ("MCC unsupported IP version %u\n",
						((struct iphdr*)p)->version));
		return 2;
	}
	pkt->info.ip_hdr.len = len;

	p += len; /* move to the IP packet payload */

	/* Check IPv4*/
	if (pkt->info.ip_hdr.ipv4.version == 4) {
		/* Check if we have IGMP packet */
		if (pkt->info.ip_hdr.ipv4.protocol == MCC_IP_PROTO_IGMP) {
			pkt->info.igmp.p = (struct mcc_pkt_igmp_hdr*)p;
			len = pkt->info.ip_hdr.ipv4.tot_len -
						pkt->info.ip_hdr.ipv4.ihl;
			pkt->info.igmp.len = len;
		} else {
			DBG(OMCI_API_MSG, ("MCC unsupported IP proto %u\n",
					      pkt->info.ip_hdr.ipv4.protocol));
			return 3;
		}
	}

	return 0;
}

/** Extract the received outer VLAN tag.

	\param info IGMP packet information.

	\return VLAN tag
*/
static struct mcc_pkt_vlan_tag *
mcc_pkt_outer_vlan_get(const struct mcc_pkt_info *info)
{

	if (info->mac_hdr.mac1_hdr)
		return &(info->mac_hdr.mac1_hdr->tag);
	else if (info->mac_hdr.mac2_hdr)
		return &(info->mac_hdr.mac2_hdr->tag0);
	else if (info->mac_hdr.mac3_hdr)
		return &(info->mac_hdr.mac3_hdr->tag0);
	else
		return NULL;
}

/** Check the IGMP control packet direction.

	\param info IGMP packet information

	\return Data direction
	- false downstream, from ANI to UNI (from server to host(s))
	- true upstream, from UNI to ANI (from host to server)
*/
static bool mcc_pkt_is_upstream(const struct mcc_pkt_info *info)
{
	union u_onu_exception_pkt_hdr *exc_hdr = info->exc_hdr.p;

	if (exc_hdr->ext.ex_side == 0 && exc_hdr->ext.ex_dir == 0)
		return true;
	else
		return false;
}

/** Debug function to display the IP header contents.
	\remark Only IPv4 is supported.

	\param out Output file.
	\param pkt IP packet data.
	\param len IP packet length.
	\param info IP header information.

	\return Data in file.
*/
static void mcc_pkt_ip_dump(FILE *out, const unsigned char *pkt, int len,
			       const struct mcc_pkt_info *info)
{
	char s_addr[16], d_addr[16];
	struct in_addr saddr, daddr;
	(void)pkt;
	(void)len;

	saddr.s_addr = htonl(info->ip_hdr.ipv4.saddr);
	daddr.s_addr = htonl(info->ip_hdr.ipv4.daddr);
	strcpy(s_addr, inet_ntoa(saddr));
	strcpy(d_addr, inet_ntoa(daddr));

	fprintf(out, "\t%6s:  ver=%u, ihl=%u, tos=0x%02X, tol=%u, "
		     "id=%u, foff=0x%02X, ttl=%u, pro=0x%02X, csum=%u, "
		     "ip_src=%s ip_dst=%s\n",
			"ip",
			info->ip_hdr.ipv4.version,
			info->ip_hdr.ipv4.ihl,
			info->ip_hdr.ipv4.tos,
			info->ip_hdr.ipv4.tot_len,
			info->ip_hdr.ipv4.id,
			info->ip_hdr.ipv4.frag_off,
			info->ip_hdr.ipv4.ttl,
			info->ip_hdr.ipv4.protocol,
			info->ip_hdr.ipv4.check,
			s_addr,
			d_addr);
}

/** Debug function to display the multicast control packet contents.
	\remark Only IGMP is supported.

	\param out Output file.
	\param pkt IP packet data.
	\param len IP packet length.
	\param info IGMP information.

	\return Data in file.
*/
static void mcc_pkt_mcc_dump(FILE *out, const unsigned char *pkt, int len,
				const struct mcc_pkt_info *info)
{
	(void)pkt;
	(void)len;

	if (info->igmp.p) {
		fprintf(out, "\t%6s:  type=0x%02X, code=0x%02X, csum=%u\n",
				"igmp",
				info->igmp.p->type, info->igmp.p->code,
				info->igmp.p->checksum);
	}
}

/** Debug function to display the packet contents as hexadecimal dump.

	\param out Output file.
	\param pkt IP packet data.
	\param len IP packet length.

	\return Data in file.
*/
static void mcc_pkt_hex_dump(FILE *out, const unsigned char *pkt, int len)
{
	int i = 0, bytes = len, stamp = 0;
	char line[MCC_HEX_CHARS_PER_LINE], *s;

	s = line;
	while (--bytes >= 0) {
		snprintf(s, MCC_HEX_CHARS_PER_BYTE + 1, " %02X", *pkt++);
		s += MCC_HEX_CHARS_PER_BYTE;
		i++;
		if (i >= MCC_HEX_BYTES_PER_LINE) {
			fprintf(out, "\t0x%04X: %s\n", stamp, line);
			i = 0;
			s = line;
			stamp += MCC_HEX_BYTES_PER_LINE;
		}
	}
	if (i) {
		*s = '\0';
		fprintf(out, "\t0x%04X: %s\n", stamp, line);
	}
}

/** Debug control function to display the packet's contents.

	\param mcc MCC context.
	\param prn_prefix Printout prefix.
	\param pkt Packet data to be dumped.

	\return None.
*/
static void mcc_pkt_dump(struct mcc_ctx *mcc,
			 const char *prn_prefix,
			 const struct mcc_pkt *pkt)
{
	union u_onu_exception_pkt_hdr *exc_hdr = pkt->info.exc_hdr.p;

	(void)mcc;

	if (mcc_dbg_level == 4)
		return;

	if (mcc_dbg_level < 3)
		fprintf(stdout, "[%s] eqid=0x%02X, lan=%u, fid=0x%02X, gpix=%u,"
				" side=%s, dir=%s, drop=%u, len=%u\n",
				prn_prefix,
				exc_hdr->ext.egress_qid,
				exc_hdr->ext.lan_port_idx,
				exc_hdr->ext.fid, exc_hdr->ext.gpix,
				exc_hdr->ext.ex_side ? "lan" : "wan",
				exc_hdr->ext.ex_dir ? "ingress" : "egress",
				pkt->drop, pkt->len);

	if (mcc_dbg_level <= 2)
		mcc_pkt_ip_dump(stdout, pkt->data, (int)pkt->len, &pkt->info);

	if (mcc_dbg_level <= 1)
		mcc_pkt_mcc_dump(stdout, pkt->data, (int)pkt->len, &pkt->info);

	if (mcc_dbg_level == 0)
		mcc_pkt_hex_dump(stdout, pkt->data, (int)pkt->len);
}

static bool
mcc_profile_dacl_match(struct mcc_ctx *mcc,
	const uint8_t p_idx,
	const struct mcc_mc_group *rec,
	struct omci_api_multicast_operations_profile_acl_entry *dacl_entry)
{
	struct omci_api_multicast_operations_profile_acl_entry *entry;
	uint32_t i, j, count;
	bool match = false;

	memset(dacl_entry, 0, sizeof(*dacl_entry));

	/* no profile is attached - unrestrictive access */
	if (p_idx == MCC_PROFILE_NULL)
		return true;

	/* get dynamic access control list first entry*/
	count = mcc->profile[p_idx].dynamic_acl.count;
	entry = &(mcc->profile[p_idx].dynamic_acl.entry[0]);

	if (count == 0)
		/* list is empty, so no restrictions are specified.
		   Record matches*/
		return true;

	for (i = 0; i < count; i++, entry++) {
		/* match VLAN*/
		if (rec->vlan.tci_bit.vid != entry->vlan_id)
			continue;

		/* match group destination IP */
		if (rec->g_addr < entry->dest_start_ip ||
		    rec->g_addr > entry->dest_end_ip)
			continue;

		/* 0.0.0.0 specifies that source IP is to be ignored */
		if (entry->source_ip == 0) {
			match = true;
			break;
		}

		/* for any sources */
		/** \todo crosscheck if there might be a mix of 0.0.0.0 and 
			  x.x.x.x addresses in a single list
		*/
		if (rec->s_addr_list.s_addr[0] == 0) {
			match = true;
			break;
		}
		
		for (j = 0; j < rec->s_addr_list.s_addr_num; j++) {
			if (entry->source_ip == rec->s_addr_list.s_addr[j]) {
				match = true;
				break;
			}
		}

		if (match)
			break;
	}

	if (match)
		memcpy(dacl_entry, entry, sizeof(*entry));

	return match;
}

static enum omci_api_return mcc_igmp_v2_action_group_do(struct mcc_ctx *mcc,
				    struct mcc_pkt *pkt,
				    struct mcc_igmp_action *action)
{
	enum omci_api_return err;
	uint8_t lan_port = pkt->info.exc_hdr.p->ext.lan_port_idx, s_idx,
		p_idx, fid;
	struct mcc_mc_group *rec;
	struct mcc_added_group group_entry;
	struct omci_api_multicast_operations_profile_acl_entry dacl;
	uint16_t i;
	union mcc_pkt_vlan_tci_u vlan;
	union gpe_vlan_fid_u flow;
	uint32_t max_mc_bw, total_mc_bw;
	struct timespec t_val;
	bool add;
	int action_count = 0;

	s_idx = mcc_subscr_idx_get(mcc, lan_port);
	p_idx = mcc_profile_idx_get(mcc, s_idx);

	for (i = 0; i < action->data.rec_list.count; i++) {
		if (action->data.rec_list.rec[i].g_state == MCC_MC_GROUP_STATE_EXCLUDE)
			add = true;
		else if (action->data.rec_list.rec[i].g_state == MCC_MC_GROUP_STATE_INCLUDE)
			add = false;
		else
			continue; /* no valid state, skip this record */

		vlan.tci = action->data.rec_list.rec[i].vlan.tci;
		rec = &(action->data.rec_list.rec[i]);

		if (add) {
			/* check for dynamic access control list match*/
			if (!mcc_profile_dacl_match(mcc, p_idx, rec, &dacl)) {
				DBG(OMCI_API_MSG, ("MCC no DACL match for dest address 0x%X\n",
					  action->data.rec_list.rec[i].g_addr));
				continue;
			}
		}

		/* Max groups limit check*/
		if (add && mcc_subscr_is_groups_limit_reached(mcc, s_idx)) {
			DBG(OMCI_API_MSG, ("MCC IPv4 MAC entry not added, "
					   "limit reached for subscriber %u\n",
						s_idx));
			continue;
		}

		/* Max bandwidth check */
		if (add) {
			max_mc_bw = mcc_subscr_max_mc_bw_get(mcc, s_idx);
			if (max_mc_bw) {
				/* get total BW for pre-existing groups*/
				total_mc_bw = mcc_subscr_group_entries_bw_total_get(mcc, s_idx);
				/* add current BW for a new group*/
				total_mc_bw += dacl.group_bandwidth;
				if (total_mc_bw > max_mc_bw) {
					if (s_idx != MCC_SUBSCR_NULL)
						mcc->subscr_status[s_idx].bw_exc_cnt++;

					if (mcc_subscr_bw_enf_get(mcc, s_idx)) {
						DBG(OMCI_API_MSG, ("MCC IPv4 MAC entry not added, "
						   "BW limit reached for subscriber %u\n", s_idx));
						continue;
					}
				}
			}
		}

		flow.in.vlan_1 = vlan.tci;
		flow.in.vlan_2 = 0;
		err = dev_ctl(mcc->remote, mcc->onu_fd, FIO_GPE_VLAN_FID_GET,
			      &flow, sizeof(flow));
		if (err != OMCI_API_SUCCESS) {
			if (add) {
				/* Add FID related to the Outer VLAN*/
				flow.in.vlan_1 = vlan.tci;
				flow.in.vlan_2 = 0;
				err = dev_ctl(mcc->remote, mcc->onu_fd,
						  FIO_GPE_VLAN_FID_ADD, &flow,
						  sizeof(flow));
				if (err != OMCI_API_SUCCESS) {
					DBG(OMCI_API_ERR,
						("MCC FID add failed, VLAN=0x%04X\n",
									vlan.tci));
					return err;
				}
			} else {
				DBG(OMCI_API_ERR,
					("MCC FID get failed, VLAN=0x%04X\n",
								vlan.tci));
				return err;
			}
		}

		fid = (uint8_t)flow.out.fid;

		if (clock_gettime(CLOCK_MONOTONIC, &t_val) != 0)
			return OMCI_API_ERROR;

		/* fill group entry */
		memcpy(&group_entry.group, &(action->data.rec_list.rec[i]),
		       sizeof(struct mcc_mc_group));
		group_entry.lan_port = lan_port;
		group_entry.fid = fid;
		group_entry.lost = false;
		group_entry.last_update = t_val.tv_sec;
		group_entry.ts = t_val.tv_sec;
		group_entry.bw = dacl.group_bandwidth;
		
		/* handle group entry list*/
		err = add ? mcc_subscr_group_entry_add(mcc, s_idx, &group_entry) :
			    mcc_subscr_group_entry_rem(mcc, s_idx, &group_entry);
		if (err != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("MCC group entry %s failed, ret=%d\n",
				add ? "add" : "remove", err));
			return err;
		}

		if (add && s_idx != MCC_SUBSCR_NULL) {
			mcc->subscr_status[s_idx].join_msg_cnt++;
			mcc->subscr_status[s_idx].curr_mc_bw =
				mcc_subscr_group_entries_bw_curr_get(mcc, s_idx);
		}

		action_count++;

	}

	if(action_count == 0)
		pkt->drop = true;

	return OMCI_API_SUCCESS;
}

static enum omci_api_return mcc_igmp_v3_action_group_do(struct mcc_ctx *mcc,
				    struct mcc_pkt *pkt,
				    struct mcc_igmp_action *action)
{
	enum omci_api_return ret;
	uint8_t lan_port = pkt->info.exc_hdr.p->ext.lan_port_idx, s_idx,
		p_idx, fid;
	struct mcc_mc_group *rec;
	struct omci_api_multicast_operations_profile_acl_entry dacl;
	uint16_t i;
	union mcc_pkt_vlan_tci_u vlan;
	union gpe_vlan_fid_u flow;
	uint32_t addr, max_mc_bw, total_mc_bw;
	struct mcc_added_group group_entry_new;
	struct mcc_added_group group_entry_matched;
	enum mcc_group_action_type action_type = GROUP_ACTION_NONE;
	struct timespec t_val;
	bool entry_exists;
	int action_count = 0;

	s_idx = mcc_subscr_idx_get(mcc, lan_port);
	p_idx = mcc_profile_idx_get(mcc, s_idx);

	for (i = 0; i < action->data.rec_list.count; i++) {

		action_type = GROUP_ACTION_NONE;

		/* get record from the list */
		rec = &(action->data.rec_list.rec[i]);

		/* check first if MC group entry exists */
		memset(&group_entry_new, 0, sizeof(group_entry_new));
		memcpy(&group_entry_new.group, rec, sizeof(struct mcc_mc_group));
		ret = mcc_subscr_group_entry_match_find(mcc, s_idx,
							&group_entry_new,
							&group_entry_matched);
		if (ret == OMCI_API_NOT_FOUND) {
			DBG(OMCI_API_MSG,
				("MCC MC group entry doesn't exist, g_addr=0x%X\n",
					group_entry_new.group.g_addr));
			entry_exists = false;
		} else if (ret == OMCI_API_SUCCESS) {
			DBG(OMCI_API_MSG,
				("MCC MC group entry exist, g_addr=0x%X\n",
					group_entry_new.group.g_addr));
			entry_exists = true;
		} else {
			DBG(OMCI_API_ERR,
				("MCC MC group match error=%d\n", ret));
			return ret;
		}

		/* handle incoming request according to RFC3376*/
		if (group_entry_new.group.g_state == MCC_MC_GROUP_STATE_INCLUDE &&
		    group_entry_new.group.s_addr_list.s_addr_num == 0) {
			if (entry_exists)
				action_type = GROUP_ACTION_GADDR_REM;
		}

		if (group_entry_new.group.g_state == MCC_MC_GROUP_STATE_EXCLUDE ||
		    group_entry_new.group.s_addr_list.s_addr_num != 0) {
			if (entry_exists) {
				switch (group_entry_new.group.s_addr_list_state) {
				case MCC_SRC_ADDR_LIST_STATE_ALLOW_NEW_SOURCES:
					if (group_entry_matched.group.g_state ==
						MCC_MC_GROUP_STATE_INCLUDE)
						action_type = GROUP_ACTION_SADDR_ADD;
					else
						action_type = GROUP_ACTION_SADDR_REM;
					break;
				case MCC_SRC_ADDR_LIST_STATE_BLOCK_OLD_SOURCES:
					if (group_entry_matched.group.g_state ==
						MCC_MC_GROUP_STATE_INCLUDE)
						action_type = GROUP_ACTION_SADDR_REM;
					else
						action_type = GROUP_ACTION_SADDR_ADD;
					break;
				default:
					break;
				}
			} else {
				/** \todo crosscheck if this condition is valid.
					  The related description was not found
					  under RFC3376.
					  The below condition is required with
					  respect to
					  \ref mcc_subscr_group_entry_src_rem
					  where we remove the complete group
					  entry in case of no sources are were
					  left.
				*/
				if (group_entry_new.group.s_addr_list_state !=
				      MCC_SRC_ADDR_LIST_STATE_BLOCK_OLD_SOURCES)
					action_type = GROUP_ACTION_GADDR_ADD;
			}
		}

		if (action_type == GROUP_ACTION_NONE)
			continue; /* go to the next record*/
		
		addr = action->data.rec_list.rec[i].g_addr;
		vlan.tci = action->data.rec_list.rec[i].vlan.tci;
		
		if (action_type == GROUP_ACTION_GADDR_ADD) {
			/* check for dynamic access control list match*/
			if (!mcc_profile_dacl_match(mcc, p_idx, rec, &dacl)) {
				DBG(OMCI_API_MSG,
					("MCC no DACL match for dest address 0x%X\n", addr));
				continue;
			}
		}

		/* Max groups limit check*/
		if (action_type == GROUP_ACTION_GADDR_ADD &&
		    mcc_subscr_is_groups_limit_reached(mcc, s_idx)) {
			DBG(OMCI_API_MSG, ("MCC IPv4 MAC entry not added, "
					   "limit reached for subscriber %u\n",
						s_idx));
			continue;
		}

		/* Max bandwidth check */
		if (action_type == GROUP_ACTION_GADDR_ADD) {
			max_mc_bw = mcc_subscr_max_mc_bw_get(mcc, s_idx);
			if (max_mc_bw) {
				/* get total BW for pre-existing groups*/
				total_mc_bw = mcc_subscr_group_entries_bw_total_get(mcc, s_idx);
				/* add current BW for a new group*/
				total_mc_bw += dacl.group_bandwidth;
				if (total_mc_bw > max_mc_bw) {
					if (s_idx != MCC_SUBSCR_NULL)
						mcc->subscr_status[s_idx].bw_exc_cnt++;

					if (mcc_subscr_bw_enf_get(mcc, s_idx)) {
						DBG(OMCI_API_MSG, ("MCC IPv4 MAC entry not added, "
						   "BW limit reached for subscriber %u\n", s_idx));
						break;
					}
				}
			}
		}

		if (action_type == GROUP_ACTION_GADDR_ADD ||
		    action_type == GROUP_ACTION_GADDR_REM) {

			flow.in.vlan_1 = vlan.tci;
			flow.in.vlan_2 = 0;
			ret = dev_ctl(mcc->remote, mcc->onu_fd, FIO_GPE_VLAN_FID_GET,
				      &flow, sizeof(flow));
			if (ret != OMCI_API_SUCCESS) {
				if (action_type == GROUP_ACTION_GADDR_ADD) {
					/* Add FID related to the Outer VLAN*/
					flow.in.vlan_1 = vlan.tci;
					flow.in.vlan_2 = 0;
					ret = dev_ctl(mcc->remote, mcc->onu_fd,
							  FIO_GPE_VLAN_FID_ADD, &flow,
							  sizeof(flow));
					if (ret != OMCI_API_SUCCESS) {
						DBG(OMCI_API_ERR,
							("MCC FID add failed, VLAN=0x%04X\n",
										vlan.tci));
						return ret;
					}
				} else {
					DBG(OMCI_API_ERR,
						("MCC FID get failed, VLAN=0x%04X\n",
									vlan.tci));
					return ret;
				}
			}

			fid = (uint8_t)flow.out.fid;

			if (clock_gettime(CLOCK_MONOTONIC, &t_val) != 0)
				return OMCI_API_ERROR;

			/* fill group entry */
			group_entry_new.lan_port = lan_port;
			group_entry_new.fid = fid;
			group_entry_new.lost = false;
			group_entry_new.last_update = t_val.tv_sec;
			group_entry_new.ts = t_val.tv_sec;
			group_entry_new.bw = dacl.group_bandwidth;
		}
		
		if (action_type == GROUP_ACTION_GADDR_ADD) {
			action_count++;
			ret = mcc_subscr_group_entry_add(mcc, s_idx, &group_entry_new);
			if (ret != OMCI_API_SUCCESS) {
				DBG(OMCI_API_ERR, ("MCC group entry add failed,"
						   " ret=%d\n", ret));
				return ret;
			}
		}

		if (action_type == GROUP_ACTION_GADDR_REM) {
			action_count++;
			ret = mcc_subscr_group_entry_rem(mcc, s_idx, &group_entry_new);
			if (ret != OMCI_API_SUCCESS) {
				DBG(OMCI_API_ERR, ("MCC group entry rem failed,"
						   " ret=%d\n", ret));
				return ret;
			}
		}

		if (action_type == GROUP_ACTION_SADDR_ADD) {
			action_count++;
			ret = mcc_subscr_group_entry_src_add(mcc, s_idx, &group_entry_new);
			if (ret != OMCI_API_SUCCESS) {
				DBG(OMCI_API_ERR, ("MCC group entry src addr "
						   "add failed, ret=%d\n",
						   ret));
				return ret;
			}
		}

		if (action_type == GROUP_ACTION_SADDR_REM) {
			action_count++;
			ret = mcc_subscr_group_entry_src_rem(mcc, s_idx, &group_entry_new);
			if (ret != OMCI_API_SUCCESS) {
				DBG(OMCI_API_ERR, ("MCC group entry src addr "
						   "remove failed, ret=%d\n",
						   ret));
				return ret;
			}
		}

		if (action_type == GROUP_ACTION_GADDR_ADD && s_idx != MCC_SUBSCR_NULL) {
			mcc->subscr_status[s_idx].join_msg_cnt++;
			mcc->subscr_status[s_idx].curr_mc_bw =
				mcc_subscr_group_entries_bw_curr_get(mcc, s_idx);
		}
	}

	if(action_count == 0)
		pkt->drop = true;

	return OMCI_API_SUCCESS;
}

/** Get IGMPV2 "report" action.

	\param mcc MCC context.
	\param pkt IGMP packet
	\param action Action to return

	\return 0 - success, error otherwise.
*/
static enum omci_api_return
mcc_igmp_action_v2_report_get(struct mcc_ctx *mcc,
			      struct mcc_pkt *pkt,
			      struct mcc_igmp_action *action)
{
	struct mcc_pkt_igmp_hdr *igmp = pkt->info.igmp.p;
	struct mcc_pkt_vlan_tag *vlan_tag;

	action->data.rec_list.count = 1;
	action->data.rec_list.rec[0].igmp_v = MCC_IGMP_VERSION_2;
	action->data.rec_list.rec[0].g_addr = igmp->group_addr;
	action->data.rec_list.rec[0].g_state = MCC_MC_GROUP_STATE_EXCLUDE;
	vlan_tag = mcc_pkt_outer_vlan_get(&pkt->info);
	action->data.rec_list.rec[0].vlan.tci =
			vlan_tag ? (vlan_tag->u.tci & 0x0FFF) : 0;
			/* use VID only (ignore PCP and DEI) */
	action->data.rec_list.rec[0].c_addr = pkt->info.ip_hdr.ipv4.saddr;
	action->data.rec_list.rec[0].s_addr_list.s_addr_num = 0;
	action->data.rec_list.rec[0].s_addr_list_state =
						MCC_SRC_ADDR_LIST_STATE_NA;

	action->act_do = mcc_igmp_v2_action_group_do;

	return OMCI_API_SUCCESS;
}

/** Get IGMPV2 "leave" action.

	\param mcc MCC context.
	\param pkt IGMP packet
	\param action Action to return

	\return 0 - success, error otherwise.
*/
static enum omci_api_return
mcc_igmp_action_v2_leave_get(struct mcc_ctx *mcc,
			     struct mcc_pkt *pkt,
			     struct mcc_igmp_action *action)
{
	struct mcc_pkt_igmp_hdr *igmp = pkt->info.igmp.p;
	struct mcc_pkt_vlan_tag *vlan_tag;

	action->data.rec_list.count = 1;
	action->data.rec_list.rec[0].igmp_v = MCC_IGMP_VERSION_2;
	action->data.rec_list.rec[0].g_addr = igmp->group_addr;
	action->data.rec_list.rec[0].g_state = MCC_MC_GROUP_STATE_INCLUDE;
	vlan_tag = mcc_pkt_outer_vlan_get(&pkt->info);
	action->data.rec_list.rec[0].vlan.tci =
			vlan_tag ? (vlan_tag->u.tci & 0x0FFF) : 0;
			/* use VID only (ignore PCP and DEI) */
	action->data.rec_list.rec[0].c_addr = pkt->info.ip_hdr.ipv4.saddr;
	action->data.rec_list.rec[0].s_addr_list.s_addr_num = 0;
	action->data.rec_list.rec[0].s_addr_list_state =
						MCC_SRC_ADDR_LIST_STATE_NA;

	action->act_do = mcc_igmp_v2_action_group_do;

	return OMCI_API_SUCCESS;
}

/** Get IGMPV3 "join/leave" action.

	\param mcc MCC context.
	\param pkt IGMP packet
	\param action Action to return

	\return 0 - success, error otherwise.
*/
static enum omci_api_return
mcc_igmp_action_v3_report_get(struct mcc_ctx *mcc,
			      struct mcc_pkt *pkt,
			      struct mcc_igmp_action *action)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint16_t i, j;
	struct mcc_pkt_igmp_v3_report *report =
			(struct mcc_pkt_igmp_v3_report *)pkt->info.igmp.p;
	struct mcc_pkt_igmp_v3_group_record *rec;
	struct mcc_pkt_vlan_tag *vlan_tag;

	if (report->rec_num > MCC_IGMP_GROUP_REC_LIST_COUNT_MAX) {
		DBG(OMCI_API_ERR,
			("MCC group addr list allows max %d entries, "
			 "%u specified in the V3 report\n",
				MCC_IGMP_GROUP_REC_LIST_COUNT_MAX,
				report->rec_num));
		return OMCI_API_ERROR;
	}

	action->data.rec_list.count = 0;
	rec = report->rec;
	for (i = 0; i < report->rec_num; i++) {
		if (rec->s_num > MCC_IGMP_SOURCE_ADDR_LIST_COUNT_MAX) {
			DBG(OMCI_API_ERR,
				("MCC group addr source addr list allows max %d"
				 " entries, %u specified in the V3 report\n",
					MCC_IGMP_SOURCE_ADDR_LIST_COUNT_MAX,
					rec->s_num));
			return OMCI_API_ERROR;
		}

		/* set MC group address */
		action->data.rec_list.rec[i].g_addr = rec->data[0];
		/* set IGMP version */
		action->data.rec_list.rec[i].igmp_v = MCC_IGMP_VERSION_3;
		/* set MC group address default state */
		action->data.rec_list.rec[i].g_state = MCC_MC_GROUP_STATE_INCLUDE;
		/* set Source address list default state */
		action->data.rec_list.rec[i].s_addr_list_state = MCC_SRC_ADDR_LIST_STATE_NA;

		switch (rec->type) {
		case MCC_IGMP_V3_REP_REC_TYPE_CHANGE_TO_INCLUDE:
			action->data.rec_list.rec[i].g_state =
						MCC_MC_GROUP_STATE_INCLUDE;
			break;
		case MCC_IGMP_V3_REP_REC_TYPE_CHANGE_TO_EXCLUDE:
			action->data.rec_list.rec[i].g_state =
						MCC_MC_GROUP_STATE_EXCLUDE;
			break;
		case MCC_IGMP_V3_REP_REC_TYPE_ALLOW_NEW_SOURCES:
			if (report->rec_num == 0)
				continue; /* skip this record */
			action->data.rec_list.rec[i].s_addr_list_state =
						MCC_SRC_ADDR_LIST_STATE_ALLOW_NEW_SOURCES;
			break;
		case MCC_IGMP_V3_REP_REC_TYPE_BLOCK_OLD_SOURCES:
			if (report->rec_num == 0)
				continue; /* skip this record */
			action->data.rec_list.rec[i].s_addr_list_state =
						MCC_SRC_ADDR_LIST_STATE_BLOCK_OLD_SOURCES;
			break;
		default:
			DBG(OMCI_API_ERR,
				("MCC unhandled IGMP V3 report record type %u\n",
				rec->type));
			return OMCI_API_ERROR;
		}

		/* set Source address list */
		action->data.rec_list.rec[i].s_addr_list.s_addr_num = rec->s_num;
		for (j = 0; j < rec->s_num; j++)
			action->data.rec_list.rec[i].s_addr_list.s_addr[j] = rec->data[1+j];

		/* set VLAN info */
		vlan_tag = mcc_pkt_outer_vlan_get(&pkt->info);
		action->data.rec_list.rec[i].vlan.tci =
				vlan_tag ? (vlan_tag->u.tci & 0xFFF): 0;
				/* use VID only (ignore PCP and DEI) */
		/* set Client address */
		action->data.rec_list.rec[i].c_addr = pkt->info.ip_hdr.ipv4.saddr;

		/* Update Record List count */
		action->data.rec_list.count++;

		/* go to the next record*/
		rec++;
		rec += rec->aux_num + rec->s_num;
	}

	action->act_do = mcc_igmp_v3_action_group_do;

	return ret;
}

/** Get action depending on the IGMP message type.

	\param mcc MCC context.
	\param pkt IGMP packet
	\param action Action to return

	\return 0 - success, error otherwise.
*/
static enum omci_api_return mcc_igmp_action_get(struct mcc_ctx *mcc,
						struct mcc_pkt *pkt,
						struct mcc_igmp_action *action)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mcc_pkt_igmp_hdr *igmp = pkt->info.igmp.p;
	bool wan, egress;

	memset(action, 0, sizeof(*action));

	wan = pkt->info.exc_hdr.p->ext.ex_side ? false : true;
	egress = pkt->info.exc_hdr.p->ext.ex_dir ? false : true;

	switch (igmp->type) {
	case MCC_IGMP_TYPE_MEMBERSHIP_QUERY:
		DBG(OMCI_API_MSG, ("MCC Received IGMP Query\n"));
		if (wan && egress)
			pkt->drop = true;
		break;

	case MCC_IGMP_TYPE_V1_MEMBERSHIP_REPORT:
		DBG(OMCI_API_MSG, ("MCC Received IGMP V1 Report\n"));
		/* set drop flag*/
		pkt->drop = true;
		break;

	case MCC_IGMP_TYPE_V2_MEMBERSHIP_REPORT:
		DBG(OMCI_API_MSG, ("MCC Received IGMP V2 Report\n"));
		if (!wan && egress) {
			pkt->drop = true;
			break;
		}
		ret = mcc_igmp_action_v2_report_get(mcc, pkt, action);
		break;

	case MCC_IGMP_TYPE_V3_MEMBERSHIP_REPORT:
		DBG(OMCI_API_MSG, ("MCC Received IGMP V3 Report\n"));
		if (!wan && egress) {
			pkt->drop = true;
			break;
		}
		ret = mcc_igmp_action_v3_report_get(mcc, pkt, action);
		break;

	case MCC_IGMP_TYPE_V2_LEAVE_GROUP:
		DBG(OMCI_API_MSG, ("MCC Received IGMP V2 Leave\n"));
		if (!wan && egress) {
			pkt->drop = true;
			break;
		}
		ret = mcc_igmp_action_v2_leave_get(mcc, pkt, action);
		break;

	default:
		DBG(OMCI_API_WRN, ("MCC packet unknown IGMP type 0x%X\n",
					igmp->type));
		pkt->drop = true;
		ret = OMCI_API_WRN_DEV_NO_DATA;
	}

	return ret;
}

/** IGMP message handler.

	\param mcc MCC context.
	\param pkt IGMP packet

	\return 0 - success, error otherwise.
*/
static int mcc_igmp_handle(struct mcc_ctx *mcc, struct mcc_pkt *pkt)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mcc_igmp_action action;

	ret = mcc_igmp_action_get(mcc, pkt, &action);
	if (ret < 0) {
		DBG(OMCI_API_ERR, ("MCC IGMP action get failed, ret=%d\n", ret));
		return ret;
	}

	if (action.act_do) {
		ret = action.act_do(mcc, pkt, &action);
		if (ret < OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR,
				("MCC IGMP action do failed, ret=%d\n",ret));
			return ret;
		}
	}

	return ret;
}

/** Create Rate Limiter index.

	\param mcc MCC context.
	\param idx Rate Limiter index

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
static enum omci_api_return
mcc_igmp_rate_limiter_create(struct mcc_ctx *mcc, uint32_t *idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_meter meter;

	memset(&meter, 0, sizeof(meter));
	ret = dev_ctl(mcc->remote, mcc->onu_fd, FIO_GPE_METER_CREATE,
		      &meter, sizeof(meter));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("MCC meter create failed, ret=%d\n", ret));
		return ret;
	}

	*idx = meter.index;

	return OMCI_API_SUCCESS;
}

/** Delete Rate Limiter index.

	\param mcc MCC context.
	\param idx Rate Limiter index

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
static enum omci_api_return
mcc_igmp_rate_limiter_delete(struct mcc_ctx *mcc, const uint32_t idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_meter meter;

	meter.index = idx;
	ret = dev_ctl(mcc->remote, mcc->onu_fd, FIO_GPE_METER_DELETE,
		      &meter, sizeof(meter));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("MCC meter delete failed, ret=%d\n", ret));
		return ret;
	}

	return OMCI_API_SUCCESS;
}

/** Set Rate Limiter parameters.

	\param mcc MCC context.
	\param idx Rate Limiter index
	\param enable Enable/disable Rate Limiter
	\param rate Rate Limiter [bytes/s]

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
static enum omci_api_return
mcc_igmp_rate_limiter_set(struct mcc_ctx *mcc,
			  const uint32_t idx,
			  const uint32_t rate)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	union gpe_meter_cfg_get_u meter;

	memset(&meter, 0, sizeof(meter));

	meter.in.index = idx;

	ret = dev_ctl(mcc->remote, mcc->onu_fd, FIO_GPE_METER_CFG_GET,
		      &meter, sizeof(meter));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("MCC meter %u set failed on cfg get, ret=%d\n",
						meter.in.index, ret));
		return ret;
	}

	meter.out.cir = rate * MCC_AVERAGE_IGMP_PACKET_SIZE;
	meter.out.pir = rate * MCC_AVERAGE_IGMP_PACKET_SIZE;
	meter.out.cbs = 10 * MCC_AVERAGE_IGMP_PACKET_SIZE;
	meter.out.pbs = 10 * MCC_AVERAGE_IGMP_PACKET_SIZE;
	meter.out.color_aware = false;

	ret = dev_ctl(mcc->remote, mcc->onu_fd, FIO_GPE_METER_CFG_SET,
		      &meter, sizeof(meter));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("MCC meter %u set failed on cfg set, ret=%d\n",
						meter.in.index, ret));
		return ret;
	}

	return ret;
}

/** Attach Rate Limiter to the specified LAN port.

	\param mcc MCC context.
	\param lan_idx LAN port index
	\param idx Rate Limiter index

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
static enum omci_api_return
mcc_igmp_rate_limiter_attach(struct mcc_ctx *mcc,
			     const uint8_t lan_idx,
			     const uint32_t rate_limiter_idx)
{
	enum omci_api_return ret;
	union gpe_lan_exception_cfg_u exc_cfg;

	/* read LAN port exception config*/
	exc_cfg.in.lan_port_index = lan_idx;
	ret = dev_ctl(mcc->remote, mcc->onu_fd,
		      FIO_GPE_LAN_EXCEPTION_CFG_GET, &exc_cfg, sizeof(exc_cfg));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	exc_cfg.in.lan_port_index = lan_idx;
	exc_cfg.out.igmp_except_meter_id = rate_limiter_idx;
	exc_cfg.out.igmp_except_meter_enable = 1;

	/* write LAN port exception config*/
	ret = dev_ctl(mcc->remote, mcc->onu_fd,
		      FIO_GPE_LAN_EXCEPTION_CFG_SET, &exc_cfg, sizeof(exc_cfg));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return ret;
}

/** Detach Rate Limiter from the specified LAN port.

	\param mcc MCC context.
	\param lan_idx LAN port index

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
static enum omci_api_return
mcc_igmp_rate_limiter_detach(struct mcc_ctx *mcc,
			     const uint8_t lan_idx)
{
	enum omci_api_return ret;
	union gpe_lan_exception_cfg_u exc_cfg;

	/* read LAN port exception config*/
	exc_cfg.in.lan_port_index = lan_idx;
	ret = dev_ctl(mcc->remote, mcc->onu_fd,
		      FIO_GPE_LAN_EXCEPTION_CFG_GET, &exc_cfg, sizeof(exc_cfg));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	exc_cfg.in.lan_port_index = lan_idx;
	exc_cfg.out.igmp_except_meter_enable = 0;

	/* write LAN port exception config*/
	ret = dev_ctl(mcc->remote, mcc->onu_fd,
		      FIO_GPE_LAN_EXCEPTION_CFG_SET, &exc_cfg, sizeof(exc_cfg));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return ret;
}

/** Get multicast profile index for the specified subscribed.

	\param mcc MCC context.
	\param s_idx Subscriber index.

	\return Profile index, \ref MCC_PROFILE_NULL if no profile exists.
*/
static uint8_t mcc_profile_idx_get(struct mcc_ctx *mcc, const uint8_t s_idx)
{
	uint8_t profile_idx;

	if (s_idx >= OMCI_API_MCC_MAX_SUBSCRIBERS)
		return MCC_PROFILE_NULL;

	profile_idx = mcc->subscr[s_idx].profile_idx;

	if (profile_idx >= OMCI_API_MCC_MAX_PROFILES)
		return MCC_PROFILE_NULL;

	return mcc->profile[profile_idx].valid ?
					profile_idx : MCC_PROFILE_NULL;
}

/** Get multicast subscriber index for the specified LAN port.

	\param mcc MCC context.
	\param lan_port LAN port index

	\return Profile index, \ref MCC_SUBSCR_NULL if no subscriber exists.
*/
static uint8_t mcc_subscr_idx_get(struct mcc_ctx *mcc,
				  const uint8_t lan_port)
{
	uint16_t s, gpix, f;
	struct omci_api_mcc_subscr_cfg *subscr;
	bool found = false;

	subscr = mcc->subscr;

	for (s = 0; s < ARRAY_SIZE(mcc->subscr); s++) {
		if (!subscr->valid) {
			subscr++;
			continue;
		}

		if (lan_port != subscr->lan_idx) {
			subscr++;
			continue;
		}

		found = true;
		break;
	}

	return found ? (uint8_t)s : MCC_SUBSCR_NULL;
}

static uint32_t mcc_subscr_max_mc_bw_get(struct mcc_ctx *mcc,
					 const uint8_t s_idx)
{
	if (s_idx == MCC_SUBSCR_NULL)
		return 0;
	return mcc->subscr[s_idx].max_mc_bw;
}

static bool mcc_subscr_bw_enf_get(struct mcc_ctx *mcc, const uint8_t s_idx)
{
	if (s_idx == MCC_SUBSCR_NULL)
		return false;
	return mcc->subscr[s_idx].bw_enforcement ? true : false;
}

/** <description>.

	\param mcc MCC context.
	\param xxx xxx.

	\return xxx xxx.
*/
static int mcc_subscr_vlan_ctrl(struct mcc_ctx *mcc,
				const uint8_t p_idx,
				struct mcc_pkt *pkt,
				const struct mcc_pkt_info *pkt_info)
{
	uint8_t *p_dest = pkt->data, *p_src = pkt->data;
	uint32_t mcount, offset;
	struct mcc_pkt_vlan_tag *vlan_tag, vlan_new;

	if (p_idx == MCC_PROFILE_NULL)
		return 0;

	if (!mcc->profile[p_idx].valid)
		/* no profile attached*/
		return 0;

	switch (mcc->profile[p_idx].us_igmp_tag_ctrl) {
	case 0: /* Pass upstream IGMP traffic transparently*/
		return 0;

	case 2: /* Replace the entire outer TCI*/
	case 3: /* Replace only the VLAN ID*/
		vlan_tag = mcc_pkt_outer_vlan_get(pkt_info);
		if (vlan_tag) {
			vlan_new.u.tci = mcc->profile[p_idx].us_igmp_tci;

			/* replace VID*/
			vlan_tag->u.tci_bit.vid = vlan_new.u.tci_bit.vid;
			if (mcc->profile[p_idx].us_igmp_tag_ctrl == 3)
				break;

			/* replace all*/
			vlan_tag->u.tci = vlan_new.u.tci;
			break;
		}

	case 1: /* Add a VLAN tag*/
		offset = pkt_info->exc_hdr.len +
				offsetof(struct mcc_pkt_mac0_hdr, etype);
		p_src += offset;
		p_dest = p_src + sizeof(vlan_new);

		if (offset < pkt->len)
			mcount = pkt->len - offset;
		else
			return -1;

		/* check if we have enought space to add a tag*/
		if (p_dest + mcount > &pkt->data[MCC_PKT_MAX_SIZE_BYTE - 1])
			return -1;

		/* free room for adding a tag*/
		memmove(p_dest, p_src, mcount);

		vlan_new.tpid = MCC_ETH_TYPE_PROP;
		vlan_new.u.tci  = mcc->profile[p_idx].us_igmp_tci;

		/* add tag */
		memcpy(p_src, &vlan_new, sizeof(vlan_new));
		/* update packet length*/
		pkt->len += sizeof(vlan_new);
		break;

	default:
		DBG(OMCI_API_WRN, ("MCC unknown VLAN tag ctrl %u\n",
				   mcc->profile[p_idx].us_igmp_tag_ctrl));
		return 1;
	}

	return 0;
}

/** Add/remove exception queue for IGMP/MLD packets.

	\param mcc MCC context.
	\param add Add/remove flag.

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
static enum omci_api_return mcc_exc_queue_ctrl(struct mcc_ctx *mcc,
					       const bool add)
{
	enum omci_api_return ret;
	struct gpe_exception_queue_cfg queue_cfg;

	/* setup MCC exception queue*/
	queue_cfg.exception_index = ONU_GPE_EXCEPTION_OFFSET_IGMP_MLD;
	queue_cfg.exception_queue = add ? MCC_EXCEPTION_QID :
					  ONU_GPE_NULL_QUEUE;
	queue_cfg.snooping_enable = 0;
	return dev_ctl(mcc->remote, mcc->onu_fd,
		       FIO_GPE_EXCEPTION_QUEUE_CFG_SET, &queue_cfg,
		       sizeof(queue_cfg));
}

/** Packet handler.

	\param mcc MCC context.
	\param pkt Received IGMP/MLD packet.

	\return 0 - success, error otherwise.
*/
static int mcc_pkt_handle(struct mcc_ctx *mcc, struct mcc_pkt *pkt)
{
	int ret = 0;
	uint8_t s_idx, p_idx;
	struct mcc_pkt_info info;

	/* get packet information*/
	ret = mcc_pkt_info_update(pkt);
	if (ret != 0)
		return ret;

	mcc_pkt_dump(mcc, MCC_RX_DUMP_PREFIX, pkt);

	/* lock handling to avoid subscriber/profile update */
	IFXOS_LockGet(&mcc->lock);

	while (1) {
		/* Handle IGMP message*/
		ret = mcc_igmp_handle(mcc, pkt);
		if (ret != 0)
			break;

		break;
	}

	IFXOS_LockRelease(&mcc->lock);

	mcc_pkt_dump(mcc, MCC_TX_DUMP_PREFIX, pkt);

	return ret;
}

static long long elapsed_time(const struct timespec *t2,
						const struct timespec *t1)
{
	long long tmp = (t2->tv_sec - t1->tv_sec) * 1000;
	tmp += ((t2->tv_nsec - t1->tv_nsec)/1000000);
	return tmp;
}

/** Packet processing thread.

	\param thr_params Thread attached parameters.

	\return 0 - success, error otherwise.
*/
static int32_t mcc_pkt_thread(struct IFXOS_ThreadParams_s *thr_params)
{
	enum omci_api_return ret;
	struct mcc_ctx *ctx = (struct mcc_ctx *)thr_params->nArg1;
	struct timeval tv;
	fd_set rfds;
	int sretval;
	struct timespec t_res, t_current, t_old;
	uint32_t rate = 0;

	DBG(OMCI_API_MSG, ("MCC Packet Thread - Started (tid %d)" CRLF,
								getpid()));

	clock_gettime(CLOCK_MONOTONIC, &t_old);

	while (ctx->run) {
		/* wait for incoming packets */
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(ctx->s, &rfds);
		sretval = select(ctx->s + 1, &rfds, NULL, NULL, &tv);
		if (sretval <= 0) {
			/* timeout */
			if (clock_gettime(CLOCK_MONOTONIC, &t_current) == 0) {
				rate = 0;
				memcpy(&t_old, &t_current, sizeof(struct timespec));
			}
			continue;
		}

		/* receive Multicast Control packet */
		if (mcc_pkt_rcv(ctx->s, &ctx->pkt) < 0) {
			DBG(OMCI_API_ERR, ("MCC packet receive failed\n"));
			continue;
		}

		rate++;
		if (clock_gettime(CLOCK_MONOTONIC, &t_current) == 0) {
			if(elapsed_time(&t_current, &t_old) > 1000) {
				rate = 0;
				memcpy(&t_old, &t_current, sizeof(struct timespec));
			}
		}
		if(us_igmp_rate && (rate > us_igmp_rate))
			continue;

		/* handle Multicast Control packet*/
		if (mcc_pkt_handle(ctx, &ctx->pkt) < 0) {
			DBG(OMCI_API_ERR, ("MCC packet handler failed\n"));
			continue;
		}

		/* send back Multicast Control packet*/
		if (mcc_pkt_snd(ctx->s, &ctx->sll, &ctx->pkt) < 0)
			DBG(OMCI_API_ERR, ("MCC packet send failed\n"));
	}

	return 0;
}

/** Control thread.

	\param thr_params Thread attached parameters.

	\return 0 - success, error otherwise.
*/
static int32_t mcc_ctl_thread(struct IFXOS_ThreadParams_s *thr_params)
{
	enum omci_api_return ret;
	struct mcc_ctx *mcc = (struct mcc_ctx *)thr_params->nArg1;

	DBG(OMCI_API_MSG, ("MCC Control Thread - Started (tid %d)" CRLF,
								getpid()));

	while (mcc->run) {
		/* Update MC groups */
		ret = mcc_subscr_group_entries_update(mcc);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("MCC groups update failed\n"));
			break;
		}

		IFXOS_MSecSleep(1000);
	}

	return ret;
}

/** Start Multicat Control handling.

	\param ctx OMCI API context.

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
enum omci_api_return mcc_start(struct omci_api_ctx *ctx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mcc_ctx *mcc = &ctx->mcc;
	struct ifreq ifr;
	int i, if_index;
	char scmd[32];

	/* open RAW socket*/
	mcc->s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (mcc->s < 0) {
		DBG(OMCI_API_ERR, ("MCC exception socket open failed\n"));
		return OMCI_API_ERROR;
	}

	bzero(&ifr, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, MCC_EXCEPTION_IF_NAME, IFNAMSIZ);

	/* check if exception i/f is available*/
	if (ioctl(mcc->s, SIOCGIFINDEX, &ifr) < 0) {
		DBG(OMCI_API_ERR, ("ioctl SIOCGIFINDEX failed on %s\n",
							MCC_EXCEPTION_IF_NAME));
		return OMCI_API_ERROR;
	}

	if_index = ifr.ifr_ifindex;

	/* bring exception i/f UP */
	snprintf(scmd, sizeof(scmd), "ifconfig %s up", MCC_EXCEPTION_IF_NAME);
	ret = omci_api_scmd_run(ctx, scmd);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("MCC %s i/f up failed\n",
							MCC_EXCEPTION_IF_NAME));
		return ret;
	}

	bzero(&ifr, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, MCC_EXCEPTION_IF_NAME, IFNAMSIZ);

	/* bring exception i/f UP */
	for (i = 0; i < MCC_IF_WAIT_TIMEOUT / 100; i++) {
		if (ioctl(mcc->s, SIOCGIFFLAGS, &ifr) < 0) {
			DBG(OMCI_API_ERR, ("ioctl SIOCGIFFLAGS failed on %s\n",
							MCC_EXCEPTION_IF_NAME));
			return OMCI_API_ERROR;
		}

		if (ifr.ifr_flags & IFF_UP && ifr.ifr_flags & IFF_RUNNING)
			break;

		IFXOS_MSecSleep(100);
	}

	if (!(ifr.ifr_flags & IFF_UP && ifr.ifr_flags & IFF_RUNNING)) {
		DBG(OMCI_API_ERR, ("%s net i/f up wait timeout\n",
							MCC_EXCEPTION_IF_NAME));
		return OMCI_API_ERROR;
	}

	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl(mcc->s, SIOCSIFFLAGS, &ifr) < 0) {
		DBG(OMCI_API_ERR, ("ioctl SIOCSIFFLAGS failed on %s\n",
							MCC_EXCEPTION_IF_NAME));
		return OMCI_API_ERROR;
	}

	/* bind socket */
	memset(&mcc->sll, 0xff, sizeof(mcc->sll));
	mcc->sll.sll_family = AF_PACKET;
	mcc->sll.sll_protocol = htons(ETH_P_ALL);
	mcc->sll.sll_ifindex = if_index;
	mcc->sll.sll_hatype = 1;
	mcc->sll.sll_halen = ETH_ALEN;
	if (bind(mcc->s, (struct sockaddr*)(&mcc->sll),sizeof(mcc->sll)) < 0) {
		DBG(OMCI_API_ERR, ("%s net i/f socket bind error\n",
							MCC_EXCEPTION_IF_NAME));
		return OMCI_API_ERROR;
	}

	mcc->run = true;

	if (IFXOS_ThreadInit(&mcc->mcc_pkt_thread_ctrl, "mcc_pkt",
			     mcc_pkt_thread,
			     IFXOS_DEFAULT_STACK_SIZE,
			     IFXOS_THREAD_PRIO_LOWEST,
			     (unsigned long)mcc,
			     0)) {
		DBG(OMCI_API_ERR, ("Can't start MC packet thread\n"));
		return OMCI_API_ERROR;
	}

	if (IFXOS_ThreadInit(&mcc->mcc_ctl_thread_ctrl, "mcc_ctl",
			     mcc_ctl_thread,
			     IFXOS_DEFAULT_STACK_SIZE,
			     IFXOS_THREAD_PRIO_LOWEST,
			     (unsigned long)mcc,
			     0)) {
		DBG(OMCI_API_ERR, ("Can't start MC control thread\n"));
		return OMCI_API_ERROR;
	}

	return ret;
}

/** Initialize Multicat Control handling.

	\param ctx OMCI API context.

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
enum omci_api_return mcc_init(struct omci_api_ctx *ctx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mcc_ctx *mcc = &ctx->mcc;
	struct gpe_capability gpe_cap;
	int i;

	char dev_onu_name[] = "/dev/" ONU_NAME "0";

	memset(mcc, 0x0, sizeof(*mcc));

	mcc->onu_fd = -1;
	mcc->api_ctx = ctx;
	mcc->remote = ctx->remote;

	/* open ONU device */
	mcc->onu_fd = dev_open(mcc->remote, dev_onu_name);
	if (mcc->onu_fd < 0) {
		DBG(OMCI_API_ERR, ("Can't open %s %d\n", dev_onu_name, mcc->onu_fd));
		return OMCI_API_ERROR;
	}

	/* get ONU capability list*/
	ret = dev_ctl(mcc->remote, mcc->onu_fd, FIO_GPE_CAPABILITY_GET,
		      &gpe_cap, sizeof(gpe_cap));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("MCC ONU device capability get failed, %d\n", ret));
		return ret;
	}
	/* store GPE capabilities internally */
	memcpy(&mcc->gpe_cap, &gpe_cap, sizeof(gpe_cap));

	/* add MCC exception queue*/
	ret = mcc_exc_queue_ctrl(mcc, true);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("MCC exception queue cfg failed, %d\n", ret));
		return ret;
	}

#if 0
	/* add well-known MC MAC entries*/
	ret = mcc_short_fwd_unknown_mac_flooding_ctrl(mcc, true);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("MCC MAC flooding init failed, %d\n", ret));
		return ret;
	}
#endif

	for (i = 0; i < OMCI_API_MCC_MAX_SUBSCRIBERS; i++) {
		/* init added groups list*/
		MCC_DLIST_HEAD_INIT(&mcc->added_groups_list[i].list_head);
		mcc->added_groups_list[i].entries_num = 0;
	}

	/* init unassigned MC groups list*/
	MCC_DLIST_HEAD_INIT(&mcc->unassigned_groups_list.list_head);
	mcc->unassigned_groups_list.entries_num = 0;

	IFXOS_LockInit(&mcc->lock);
	IFXOS_LockInit(&mcc->groups_list_lock);

	return ret;
}

/** Free all Multicat Control resources.

	\param ctx OMCI API context.

	\return OMCI_API_SUCCESS on success, error otherwise.
*/
enum omci_api_return mcc_exit(struct omci_api_ctx *ctx)
{
	uint8_t i;
	struct mcc_ctx *mcc = &ctx->mcc;
	struct ifreq ifr;
	struct mcc_added_groups_list_entry *list_entry;
	struct mcc_added_groups_list_entry *next_list_entry;

	mcc->run = false;

	if (IFXOS_THREAD_INIT_VALID(&mcc->mcc_pkt_thread_ctrl))
		(void)IFXOS_ThreadDelete(&mcc->mcc_pkt_thread_ctrl, 0);

	if (IFXOS_THREAD_INIT_VALID(&mcc->mcc_ctl_thread_ctrl))
		(void)IFXOS_ThreadDelete(&mcc->mcc_ctl_thread_ctrl, 0);

	if (mcc->s >= 0) {
		ioctl(mcc->s, SIOCGIFFLAGS, &ifr);
		ifr.ifr_flags &= ~IFF_PROMISC;
		ioctl(mcc->s, SIOCSIFFLAGS, &ifr);
		close(mcc->s);
	}

	/* remove MCC exception queue */
	(void)mcc_exc_queue_ctrl(mcc, false);

	/* remove added groups list */
	IFXOS_LockGet(&mcc->groups_list_lock);
	for (i = 0; i < OMCI_API_MCC_MAX_SUBSCRIBERS; i++)
		(void)mcc_subscr_group_entries_clear(mcc, i);
	(void)mcc_subscr_group_entries_clear(mcc, MCC_SUBSCR_NULL);
	IFXOS_LockRelease(&mcc->groups_list_lock);

	/* remove allocated locks*/
	IFXOS_LockDelete(&mcc->lock);
	IFXOS_LockDelete(&mcc->groups_list_lock);

	(void)dev_close(mcc->remote, mcc->onu_fd);

	return OMCI_API_SUCCESS;
}

/** For function description please refer to omci_api_mcc.h */
enum omci_api_return omci_api_mcc_cb_register(struct omci_api_ctx *ctx,
					       omci_api_mcc_cb_t *callback)
{
	if (!callback)
		return OMCI_API_ERROR;

	ctx->mcc.callback = callback;
	return OMCI_API_SUCCESS;
}

/** For function description please refer to omci_api_mcc.h */
enum omci_api_return
omci_api_mcc_active_groups_list_get(struct omci_api_ctx *ctx,
				  const uint8_t s_idx,
				  struct omci_api_mcc_active_groups_list *list)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mcc_ctx *mcc;
	struct mcc_added_groups_list *groups_list;
	struct mcc_added_groups_list_entry *list_entry;
	struct mcc_added_groups_list_entry *next_list_entry;
	struct timespec t_val;
	uint32_t count = 0, i, s_addr_num;

	if (ctx == NULL || list == NULL || s_idx >= OMCI_API_MCC_MAX_SUBSCRIBERS)
		return OMCI_API_ERROR;

	mcc = &ctx->mcc;

	list->count = 0;

	if (clock_gettime(CLOCK_MONOTONIC, &t_val) != 0)
		return OMCI_API_ERROR;

	IFXOS_LockGet(&mcc->groups_list_lock);

	groups_list = &mcc->added_groups_list[s_idx];

	MCC_DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				&groups_list->list_head) {
		if (list_entry->entry.lost)
			continue;

		s_addr_num = list_entry->entry.group.s_addr_list.s_addr_num;

		for (i = 0; i < (s_addr_num ? s_addr_num : 1); i++) {
			if (count >= OMCI_API_MAX_AGL_ENTRIES) {
				DBG(OMCI_API_ERR, ("Active Groups List count excess for"
						   " for LAN port %u, ret=%d\n",
						   mcc->subscr[s_idx].lan_idx, ret));
				ret = OMCI_API_ERROR;
				break;
			}
	
			/** \todo crosscheck handling for "best_eff_act_bw_est" */
			list->entry[count].best_eff_act_bw_est = 0;
			list->entry[count].client_ip =
					list_entry->entry.group.c_addr;
			list->entry[count].mc_dest_ip =
					list_entry->entry.group.g_addr;
			list->entry[count].source_ip =
					list_entry->entry.group.s_addr_list.s_addr[i];
			list->entry[count].time_since_join =
					t_val.tv_sec - list_entry->entry.ts;
			list->entry[count].vlan_id =
					list_entry->entry.group.vlan.tci;
	
			count++;
		}

	}

	list->count = count;

	IFXOS_LockRelease(&mcc->groups_list_lock);

	return ret;
}

/** For function description please refer to omci_api_mcc.h */
enum omci_api_return
omci_api_mcc_lost_groups_list_get(struct omci_api_ctx *ctx,
				  const uint8_t idx,
				  struct omci_api_mcc_lost_groups_list *list)
{
	struct mcc_ctx *mcc;
	struct omci_api_multicast_operations_profile_acl *d_acl;
	struct mcc_added_groups_list *groups_list;
	struct mcc_added_groups_list_entry *list_entry;
	struct mcc_added_groups_list_entry *next_list_entry;
	uint32_t count = 0, s_idx, i;

	if (ctx == NULL || list == NULL || idx >= OMCI_API_MCC_MAX_PROFILES)
		return OMCI_API_ERROR;

	mcc = &ctx->mcc;

	list->count = 0;

	IFXOS_LockGet(&mcc->lock);
	IFXOS_LockGet(&mcc->groups_list_lock);

	/* get dynamic access control list*/
	d_acl = &(mcc->profile[idx].dynamic_acl);
	if (!d_acl->count) {
		IFXOS_LockRelease(&mcc->groups_list_lock);
		IFXOS_LockRelease(&mcc->lock);
		return OMCI_API_SUCCESS;
	}

	for (s_idx = 0; s_idx < OMCI_API_MCC_MAX_SUBSCRIBERS; s_idx++) {
		groups_list = &mcc->added_groups_list[s_idx];

		if (mcc->subscr[s_idx].profile_idx != idx)
			continue;

		MCC_DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
					&groups_list->list_head) {
			if (!list_entry->entry.lost)
				continue;

			/* search within DACL for a matched entry*/
			for (i = 0; i < d_acl->count; i++) {
				if (list_entry->entry.group.g_addr < d_acl->entry[i].dest_start_ip ||
				    list_entry->entry.group.g_addr > d_acl->entry[i].dest_end_ip)
					continue;
				if (list_entry->entry.group.vlan.tci_bit.vid != d_acl->entry[i].vlan_id)
					continue;

				list->entry[count].addr =
					list_entry->entry.group.g_addr;
				list->entry[count].vlan_id =
					list_entry->entry.group.vlan.tci_bit.vid;

				count++;
				if (count > OMCI_API_MAX_LGL_ENTRIES - 1 ) {
					IFXOS_LockRelease(&mcc->groups_list_lock);
					IFXOS_LockRelease(&mcc->lock);
					return OMCI_API_NO_MEMORY;
				}
			}
		}
	}

	list->count = count;

	IFXOS_LockRelease(&mcc->groups_list_lock);
	IFXOS_LockRelease(&mcc->lock);

	return OMCI_API_SUCCESS;
}

/** For function description please refer to omci_api_mcc.h */
enum omci_api_return
omci_api_mcc_profile_get(struct omci_api_ctx *ctx,
			 const uint8_t idx,
			 struct omci_api_mcc_profile *profile)
{
	struct mcc_ctx *mcc = &ctx->mcc;

	if (idx >= OMCI_API_MCC_MAX_PROFILES)
		return OMCI_API_ERROR;

	mcc_locked_memcpy(profile, &mcc->profile[idx], sizeof(*profile),
			  &mcc->lock);

	return OMCI_API_SUCCESS;
}

/** For function description please refer to omci_api_mcc.h */
enum omci_api_return
omci_api_mcc_profile_update(struct omci_api_ctx *ctx,
			    const uint8_t idx,
			    const struct omci_api_mcc_profile *profile)
{
	enum omci_api_return ret;
	struct mcc_ctx *mcc = &ctx->mcc;
	uint32_t rl_idx = 0;

	if (idx >= OMCI_API_MCC_MAX_PROFILES)
		return OMCI_API_ERROR;

	if (profile->valid) {
		us_igmp_rate = profile->us_igmp_rate;
		if (mcc->profile_status[idx].igmp_policer_enabled) {
			/* modify IGMP rate limiter*/
			ret = mcc_igmp_rate_limiter_set(mcc,
				mcc->profile_status[idx].igmp_policer_index,
				profile->us_igmp_rate);
			if (ret != OMCI_API_SUCCESS)
				return ret;

			mcc->profile_status[idx].igmp_policer_enabled =
					profile->us_igmp_rate ? true : false;
		} else {
			if (profile->us_igmp_rate) {
				ret = mcc_igmp_rate_limiter_create(mcc, &rl_idx);
				if (ret != OMCI_API_SUCCESS)
					return ret;

				ret = mcc_igmp_rate_limiter_set(mcc,
						rl_idx, profile->us_igmp_rate);
				if (ret != OMCI_API_SUCCESS)
					return ret;

				mcc->profile_status[idx].igmp_policer_enabled =
						profile->us_igmp_rate ? true : false;
				mcc->profile_status[idx].igmp_policer_index = rl_idx;
			}
		}
	} else {
		us_igmp_rate = 0;
		if (mcc->profile_status[idx].igmp_policer_enabled) {
			ret = mcc_igmp_rate_limiter_delete(mcc,
				mcc->profile_status[idx].igmp_policer_index);
			if (ret != OMCI_API_SUCCESS)
				return ret;

			mcc->profile_status[idx].igmp_policer_enabled = false;
		}
	}

	mcc_locked_memcpy(&mcc->profile[idx], profile, sizeof(*profile),
			  &mcc->lock);

	return OMCI_API_SUCCESS;
}

/** For function description please refer to omci_api_mcc.h */
enum omci_api_return
omci_api_mcc_profile_dacl_update(struct omci_api_ctx *ctx,
		 const uint8_t idx,
		 const struct omci_api_multicast_operations_profile_acl *acl)
{
	struct mcc_ctx *mcc = &ctx->mcc;

	if (idx >= OMCI_API_MCC_MAX_PROFILES)
		return OMCI_API_ERROR;

	mcc_locked_memcpy(&(mcc->profile[idx].dynamic_acl), acl, sizeof(*acl),
			  &mcc->lock);

	return OMCI_API_SUCCESS;
}

/** For function description please refer to omci_api_mcc.h */
enum omci_api_return
omci_api_mcc_subscr_get(struct omci_api_ctx *ctx,
		        const uint8_t idx,
		        struct omci_api_mcc_subscr_cfg *subscr)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mcc_ctx *mcc = &ctx->mcc;

	if (idx >= OMCI_API_MCC_MAX_SUBSCRIBERS)
		return OMCI_API_ERROR;

	mcc_locked_memcpy(subscr, &mcc->subscr[idx], sizeof(*subscr),
			  &mcc->lock);

	return ret;
}

/** For function description please refer to omci_api_mcc.h */
enum omci_api_return
omci_api_mcc_subscr_update(struct omci_api_ctx *ctx,
		           const uint8_t idx,
		           const struct omci_api_mcc_subscr_cfg *subscr)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct mcc_ctx *mcc = &ctx->mcc;
	struct mcc_profile_status *p_sts;
	bool valid;

	if (idx >= OMCI_API_MCC_MAX_SUBSCRIBERS)
		return OMCI_API_ERROR;
	if (subscr->profile_idx >= OMCI_API_MCC_MAX_PROFILES &&
	    subscr->profile_idx != MCC_PROFILE_NULL)
		return OMCI_API_ERROR;

	if (mcc->subscr[idx].valid) {
		/* delete existing MCC subscriber first */
		valid = false;
		mcc_locked_memcpy(&(mcc->subscr[idx].valid), &valid,
				  sizeof(valid), &mcc->lock);
		/* remove all added group entries */
		mcc_subscr_group_entries_clear(mcc, idx);
	}

	if (subscr->valid && subscr->profile_idx != MCC_PROFILE_NULL) {
		p_sts = &mcc->profile_status[subscr->profile_idx];
		if (p_sts->igmp_policer_enabled) {
			ret = mcc_igmp_rate_limiter_attach(mcc,
					subscr->lan_idx,
					p_sts->igmp_policer_index);
			if (ret != OMCI_API_SUCCESS) {
				DBG(OMCI_API_ERR, ("IGMP rate limiter attach failed "
						   "for LAN port %u, ret=%d\n",
							subscr->lan_idx, ret));
				return ret;
			}
		}
	} else {
		ret = mcc_igmp_rate_limiter_detach(mcc, subscr->lan_idx);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("IGMP rate limiter detach failed "
					   "for LAN port %u, ret=%d\n",
						subscr->lan_idx, ret));
			return ret;
		}
	}

	mcc_locked_memcpy(&mcc->subscr[idx], subscr, sizeof(*subscr),
			  &mcc->lock);

	return ret;
}

/** For function description please refer to omci_api_mcc.h */
enum omci_api_return
omci_api_mcc_subscr_status_get(struct omci_api_ctx *ctx,
			       const uint8_t idx,
			       struct omci_api_mcc_subscr_status *status)
{
	struct mcc_ctx *mcc = &ctx->mcc;

	if (idx >= OMCI_API_MCC_MAX_SUBSCRIBERS)
		return OMCI_API_ERROR;

	
	mcc_locked_memcpy(status, &(mcc->subscr_status[idx]),
			  sizeof(*status), &mcc->lock);

	return OMCI_API_SUCCESS;
}

/** For function description please refer to omci_api_mcc.h */
enum omci_api_return
omci_api_mcc_subscr_status_reset(struct omci_api_ctx *ctx, const uint8_t idx)
{
	struct mcc_ctx *mcc = &ctx->mcc;

	if (idx >= OMCI_API_MCC_MAX_SUBSCRIBERS)
		return OMCI_API_ERROR;

	mcc_locked_memset(&(mcc->subscr_status[idx]), 0,
			  sizeof(mcc->subscr_status[idx]), &mcc->lock);

	return OMCI_API_SUCCESS;
}

/** For function description please refer to omci_api_mcc.h */
enum omci_api_return omci_api_mcc_debug_level_set(uint8_t level)
{
	switch (level) {
	/* OMCI_DBG_MSG */
	case 0:
	/* OMCI_DBG_PRN */
	case 1:
	/* OMCI_DBG_WRN */
	case 2:
	/* OMCI_DBG_ERR */
	case 3:
	/* OMCI_DBG_OFF */
	case 4:
		break;
	default:
		return OMCI_API_ERROR;
	}

	mcc_dbg_level = level;

	return OMCI_API_SUCCESS;
}

/** For function description please refer to omci_api_mcc.h */
uint8_t omci_api_mcc_debug_level_get(void)
{
	return mcc_dbg_level;
}

#endif /* INCLUDE_OMCI_API_MCC*/
#endif /* LINUX */

/** @} */
