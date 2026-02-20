/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_extended_vlan_config_data.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_extended_vlan_config_data.h"
#include "me/omci_mac_bridge_port_config_data.h"
#include "me/omci_api_extended_vlan_config_data.h"
#include "me/omci_api_extended_vlan_table.h"

/** IOP option bit for US pre-scan (generic vendor path) */
#define OMCI_IOP_OPTION_4  4
/** IOP option bit for zeroing DS treatment_inner_prio/vid (all vendor paths) */
#define OMCI_IOP_OPTION_8  8

/** OLT vendor type for vendor-specific ExtVLAN programming paths */
enum olt_vendor_type {
	OLT_VENDOR_HWTC,
	OLT_VENDOR_ALCL,
	OLT_VENDOR_GENERIC
};

static enum olt_vendor_type get_olt_vendor_type(struct omci_context *ctx)
{
	if (memcmp(ctx->olt_vendor_id, "HWTC", 4) == 0)
		return OLT_VENDOR_HWTC;
	if (memcmp(ctx->olt_vendor_id, "ALCL", 4) == 0)
		return OLT_VENDOR_ALCL;
	return OLT_VENDOR_GENERIC;
}

/** \addtogroup OMCI_ME_EXTENDED_VLAN_CONFIG_DATA
   @{
*/

/** */
struct rx_vlan_oper_table_entry {
	/** Table entry */
	struct omci_rx_vlan_oper_table data;
	/** Entry sorted index*/
	uint32_t idx;
	/** Entry is default*/
	bool def;
};

/** Structure that implements Received frame VLAN tagging operation table */
struct rx_vlan_oper_list_entry {
	/** Table entry */
	struct rx_vlan_oper_table_entry table_entry;

	/** Next entry */
	struct rx_vlan_oper_list_entry *next;

	/** Previous entry */
	struct rx_vlan_oper_list_entry *prev;
};

/** Maximum number of shadow DS tables (= max mappers we can split across) */
#define MAX_SHADOW_DS_TABLES 8

/** Shadow DS table info for dual-VLAN fix */
struct shadow_ds_info {
	uint16_t mapper_me_id;     /**< ME 130 instance used as ext_vlan key */
	uint32_t ext_vlan_idx;     /**< Allocated GPE ExtVLAN table index */
	bool     active;           /**< True if this shadow is in use */
};

/** Internal data */
struct internal_data {
	/** Received frame VLAN tagging operation table (list head) */
	struct rx_vlan_oper_list_entry list_head;

	/** Number of entries in Received frame VLAN tagging operation table */
	size_t entries_num;

	/** Number of default entries in Received frame VLAN tagging
	    operation table */
	size_t def_entries_num;

	/** Shadow DS tables for dual-VLAN DS split fix */
	struct shadow_ds_info shadow_ds[MAX_SHADOW_DS_TABLES];
	uint8_t shadow_ds_count;
};

/** Maximum number of Ext VLAn default rules*/
#define OMCI_ONU_EXT_VLAN_DEFAULT_RULE_MAX	3

/** \todo add endianess handling
*/
struct omci_rx_vlan_oper_table
rx_vlan_def[OMCI_ONU_EXT_VLAN_DEFAULT_RULE_MAX] = {
#if (IFXOS_BYTE_ORDER == IFXOS_BIG_ENDIAN)
	{
		15, 4096,  0, 0,
		15, 4096,  0, 0, 0,
		0,     0, 15, 0, 0,
		0,    15, 0,  0
	},
	{
		15, 4096,  0, 0,
		14, 4096,  0, 0, 0,
		0,     0, 15, 0, 0,
		0,    15,  0, 0
	},
	{
		14, 4096,  0, 0,
		14, 4096,  0, 0, 0,
		0,     0, 15, 0, 0,
		0, 15, 0, 0
	}
#else
	{
		0, 0, 4096,   15,
		0, 0,    0, 4096, 15,
		0, 0,   15,    0,  0,
		0, 0,   15,  0
	},
	{
		0, 0, 4096,   15,
		0, 0,    0, 4096, 14,
		0, 0,   15,    0,  0,
		0, 0,   15,  0
	},
	{
		0, 0, 4096,   14,
		0, 0,    0, 4096, 14,
		0, 0,   15,    0,  0,
		0, 0,   15,  0
	}
#endif
};

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask,
				   const void *data)
{
	struct omci_me_extended_vlan_config_data *upd_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me_class,
	       (void *)exec_mask, (void *)data);

	upd_data = (struct omci_me_extended_vlan_config_data *)data;

	error = default_me_validate(context, me_class, exec_mask, data);
	RETURN_IF_ERROR(error);

	switch (upd_data->association_type) {
	case 0x00:
		error = mib_me_find(context,
				    OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
				    upd_data->associated_me_ptr, NULL);

		break;

	case 0x01:
		error = mib_me_find(context,
				    OMCI_ME_DOT1P_MAPPER_SERVICE_PROFILE,
				    upd_data->associated_me_ptr, NULL);

		break;

	case 0x02:
		error = mib_me_find(context,
				    OMCI_ME_PPTP_ETHERNET_UNI,
				    upd_data->associated_me_ptr, NULL);

		break;

	case 0x03:
		error = mib_me_find(context,
				    OMCI_ME_IP_HOST_CONFIG_DATA,
				    upd_data->associated_me_ptr, NULL);

		break;

	case 0x04:
		/* IPv6 host config data (G.988 Table 9.3.32-1) */
		error = mib_me_find(context,
				    OMCI_ME_IPV6_CONFIG_DATA,
				    upd_data->associated_me_ptr, NULL);

		break;

	case 0x05:
		error = mib_me_find(context,
				    OMCI_ME_GEM_INTERWORKING_TP,
				    upd_data->associated_me_ptr, NULL);

		break;

	case 0x06:
		error = mib_me_find(context,
				    OMCI_ME_MULTICAST_GEM_INTERWORKING_TP,
				    upd_data->associated_me_ptr, NULL);

		break;

	case 0x07:
		error = mib_me_find(context,
				    OMCI_ME_PPTP_MOCA_UNI,
				    upd_data->associated_me_ptr, NULL);

		break;

	case 0x08:
		error = mib_me_find(context,
				    OMCI_ME_PPTP_80211_UNI,
				    upd_data->associated_me_ptr, NULL);

		break;

	case 0x09:
		error = mib_me_find(context,
				    OMCI_ME_ETHERNET_FLOW_TP,
				    upd_data->associated_me_ptr, NULL);

		break;

	case 0x0A:
		/* VEIP (G.988 Table 9.3.32-1, value 10) */
		error = mib_me_find(context,
				    OMCI_ME_VIRTUAL_ETHERNET_INTERFACE_POINT,
				    upd_data->associated_me_ptr, NULL);

		break;

	default:
		error = OMCI_ERROR;
		break;
	}

	if (error) {
		*exec_mask |=
			omci_attr2mask(omci_me_extended_vlan_config_data_association_type);
		*exec_mask |=
			omci_attr2mask(omci_me_extended_vlan_config_data_associated_me_ptr);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static int tbl_entry_uid_cmp(const void *p1, const void *p2)
{
	return memcmp(*(const struct omci_rx_vlan_oper_table **)p1,
		      *(const struct omci_rx_vlan_oper_table **)p2,
		      8);
}

static inline void dump_entry(struct me *me,
			      const char *prefix,
			      struct omci_rx_vlan_oper_table *entry)
{
	me_dbg_prn(me, "%s "
		   "filter_outer_prio=%d,"
		   "filter_outer_vid=%d,"
		   "filter_outer_tpid_de=%d,"
		   "word1_padding=%d "

		   "filter_inner_prio=%d,"
		   "filter_inner_vid=%d,"
		   "filter_inner_tpid_de=%d,"
		   "word2_padding=%d,"
		   "filter_ether_type=%d "

		   "treatment_tags_remove=%d,"
		   "word3_padding=%d,"
		   "treatment_outer_prio=%d,"
		   "treatment_outer_vid=%d,"
		   "treatment_outer_tpid_de=%d "

		   "word4_padding=%d,"
		   "treatment_inner_prio=%d,"
		   "treatment_inner_vid=%d,"
		   "treatment_inner_tpid_de=%d ",
		prefix,

		entry->filter_outer_prio,
		entry->filter_outer_vid,
		entry->filter_outer_tpid_de,
		entry->word1_padding,

		entry->filter_inner_prio,
		entry->filter_inner_vid,
		entry->filter_inner_tpid_de,
		entry->word2_padding,
		entry->filter_ether_type,

		entry->treatment_tags_remove,
		entry->word3_padding,
		entry->treatment_outer_prio,
		entry->treatment_outer_vid,
		entry->treatment_outer_tpid_de,

		entry->word4_padding,
		entry->treatment_inner_prio,
		entry->treatment_inner_vid,
		entry->treatment_inner_tpid_de);
}

/** DS collision group: multiple filter VIDs mapping to the same
    treatment VID in the downstream direction */
struct ds_collision_group {
	uint16_t treatment_vid;       /**< Shared treatment VID */
	uint16_t filter_vids[8];      /**< Conflicting filter VIDs */
	uint16_t mapper_me_ids[8];    /**< Assigned mapper ME 130 instances */
	uint8_t  count;               /**< Number of conflicting VIDs */
};

/** Detect DS many-to-one collisions in the sorted rule array.

   Scans for non-default, non-discard entries where different filter_inner_vid
   values map to the same treatment_inner_vid in the DS direction.

   \param[in]  sort_array   Sorted rule pointers
   \param[in]  entries_num  Number of entries
   \param[out] groups       Output collision groups
   \param[in]  max_groups   Size of groups array
   \return Number of collision groups found
*/
static int detect_ds_collisions(
	struct omci_rx_vlan_oper_table **sort_array,
	size_t entries_num,
	struct ds_collision_group *groups,
	int max_groups)
{
	int num_groups = 0;
	size_t i, j;
	int g, found;

	for (i = 0; i < entries_num && num_groups < max_groups; i++) {
		/* Skip wildcards (vid >= 4095) and discard entries */
		if (sort_array[i]->filter_inner_vid >= 4095)
			continue;
		if (sort_array[i]->treatment_tags_remove == 3)
			continue;

		/* Check if this treatment VID is already in a group */
		found = -1;
		for (g = 0; g < num_groups; g++) {
			if (groups[g].treatment_vid ==
			    sort_array[i]->treatment_inner_vid) {
				found = g;
				break;
			}
		}

		/* See if any later entry has the same treatment VID */
		for (j = i + 1; j < entries_num; j++) {
			if (sort_array[j]->filter_inner_vid >= 4095)
				continue;
			if (sort_array[j]->treatment_tags_remove == 3)
				continue;

			if (sort_array[i]->treatment_inner_vid ==
			    sort_array[j]->treatment_inner_vid &&
			    sort_array[i]->filter_inner_vid !=
			    sort_array[j]->filter_inner_vid) {
				/* Collision found */
				if (found < 0) {
					/* Start new group with entry i */
					if (num_groups >= max_groups)
						break;
					found = num_groups;
					groups[found].treatment_vid =
						sort_array[i]->treatment_inner_vid;
					groups[found].filter_vids[0] =
						sort_array[i]->filter_inner_vid;
					groups[found].count = 1;
					num_groups++;
				}
				/* Add entry j to group if not already there */
				if (groups[found].count < 8) {
					int k, dup = 0;
					for (k = 0; k < groups[found].count; k++) {
						if (groups[found].filter_vids[k] ==
						    sort_array[j]->filter_inner_vid) {
							dup = 1;
							break;
						}
					}
					if (!dup) {
						groups[found].filter_vids[groups[found].count] =
							sort_array[j]->filter_inner_vid;
						groups[found].count++;
					}
				}
			}
		}
	}

	return num_groups;
}

/** Read dual-VLAN config from /tmp/8311_dual_vlan.conf.

   File format:
     "auto" — use instance order heuristic
     "34:0x1102\n35:0x1103\n" — explicit VID:mapper mapping

   \param[out] mapper_me_ids  Output array of mapper ME 130 instances
   \param[out] filter_vids    Output array of filter VIDs (for explicit mapping)
   \param[in]  max_entries    Size of output arrays
   \param[out] is_auto        Set to true if "auto" mode
   \return Number of mapper entries read, or 0 if disabled/error
*/
static int read_dual_vlan_config(uint16_t *mapper_me_ids,
				 uint16_t *filter_vids,
				 int max_entries,
				 bool *is_auto)
{
	FILE *f;
	char line[64];
	int count = 0;
	unsigned int vid, mapper;

	*is_auto = false;

	f = fopen("/tmp/8311_dual_vlan.conf", "r");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f) && count < max_entries) {
		/* Skip comments and empty lines */
		if (line[0] == '#' || line[0] == '\n' || line[0] == '\0')
			continue;

		if (strncmp(line, "auto", 4) == 0) {
			*is_auto = true;
			/* Read remaining lines as mapper ME IDs only */
			while (fgets(line, sizeof(line), f) &&
			       count < max_entries) {
				if (line[0] == '#' || line[0] == '\n')
					continue;
				if (sscanf(line, "0x%x", &mapper) == 1 ||
				    sscanf(line, "%u", &mapper) == 1) {
					mapper_me_ids[count] =
						(uint16_t)mapper;
					count++;
				}
			}
			break;
		}

		/* Explicit format: "vid:0xmapper" */
		if (sscanf(line, "%u:0x%x", &vid, &mapper) == 2 ||
		    sscanf(line, "%u:%u", &vid, &mapper) == 2) {
			filter_vids[count] = (uint16_t)vid;
			mapper_me_ids[count] = (uint16_t)mapper;
			count++;
		}
	}

	fclose(f);
	return count;
}

/** Add/Delete/Clear multicast address table

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] entry   Table entry
   \param[in] ds_mode Downstream mode
   \param[in] def     Default entry
*/
static inline enum omci_error
rx_vlan_oper_table_entry_set(struct omci_context *context,
			     struct me *me,
			     struct omci_rx_vlan_oper_table *entry,
			     uint8_t ds_mode,
			     bool def)
{
	enum omci_error error = OMCI_SUCCESS;
	enum omci_api_return ret;
	struct internal_data *me_internal_data;
	struct rx_vlan_oper_list_entry *list_entry;
	struct rx_vlan_oper_list_entry *next_list_entry;
	bool entry_overridden;
	bool entry_found;
	uint32_t entry_idx = 0, sort_idx, sort_idx_def, sort_num, i;
	struct omci_rx_vlan_oper_table **sort_array;

#if defined(OMCI_SWAP)
	uint32_t data32[4];
#endif
	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)entry);

	me_internal_data = (struct internal_data *) me->internal_data;

#if defined(OMCI_SWAP)
	memcpy(&data32, entry, sizeof(data32));
	data32[0] = ntoh32(data32[0]);
	data32[1] = ntoh32(data32[1]);
	data32[2] = ntoh32(data32[2]);
	data32[3] = ntoh32(data32[3]);
	memcpy(entry, &data32, sizeof(data32));
#endif

	if (entry->treatment_tags_remove == 0x3
	    && entry->word3_padding == 0x3ff
	    && entry->treatment_outer_prio == 0xf
	    && entry->treatment_outer_vid == 0x1fff
	    && entry->treatment_outer_tpid_de == 0x7
	    && entry->word4_padding == 0xfff
	    && entry->treatment_inner_prio == 0xf
	    && entry->treatment_inner_vid == 0x1fff
	    && entry->treatment_inner_tpid_de == 0x7) {
		/* delete entry */
		me_dbg_msg(me, "Delete entry request");

		entry_found = false;
		DLIST_FOR_EACH_SAFE(list_entry,
				    next_list_entry,
				    &me_internal_data->list_head) {
			if (memcmp(&list_entry->table_entry.data, entry, 8) == 0) {
				/* remove entry */
				DLIST_REMOVE(list_entry);

				dump_entry(me, "Delete entry",
					   &list_entry->table_entry.data);

				entry_found = true;
				entry_idx = list_entry->table_entry.idx;

				if (list_entry->table_entry.def)
					--me_internal_data->def_entries_num;

				--me_internal_data->entries_num;

				IFXOS_MemFree(list_entry);
				list_entry = NULL;

				me_dbg_prn(me, "Removed table entry "
					   "(entries num = %lu)",
					   me_internal_data->entries_num);
				break;
			}
		}

		if (!entry_found) {
			dbg_out_ret(__func__, OMCI_ERROR_INVALID_VAL);
			return OMCI_ERROR_INVALID_VAL;
		}

		ret = omci_api_extended_vlan_config_data_tag_oper_table_entry_remove(
			context->api,
			me->instance_id,
			entry_idx,
			ds_mode);

		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't delete table entry",
				   ret);

			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}
	} else {
		/* set entry */
		enum olt_vendor_type vendor = get_olt_vendor_type(context);

		me_dbg_msg(me, "Set entry request");

		if (vendor == OLT_VENDOR_HWTC) {
			/* HWTC: replace semantics — delete matching entry
			   before adding the new one (vs in-place override) */
			DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
					    &me_internal_data->list_head) {
				if (memcmp(&list_entry->table_entry.data,
					   entry, 8) == 0) {
					DLIST_REMOVE(list_entry);
					dump_entry(me, "Replace (remove)",
						   &list_entry->table_entry.data);
					if (list_entry->table_entry.def)
						--me_internal_data->def_entries_num;
					--me_internal_data->entries_num;
					IFXOS_MemFree(list_entry);
					list_entry = NULL;
					break;
				}
			}

			/* Allocate and insert new entry */
			list_entry = IFXOS_MemAlloc(sizeof(*list_entry));
			RETURN_IF_MALLOC_ERROR(list_entry);
			++me_internal_data->entries_num;
			memcpy(&list_entry->table_entry.data, entry,
			       sizeof(list_entry->table_entry.data));
			dump_entry(me, "Add entry",
				   &list_entry->table_entry.data);

			if (def) {
				++me_internal_data->def_entries_num;
				list_entry->table_entry.def = true;
				/* Default: tail insertion */
				DLIST_ADD_TAIL(list_entry,
					       &me_internal_data->list_head);
			} else {
				list_entry->table_entry.def = false;
				/* Non-default: head insertion */
				DLIST_ADD(list_entry,
					  &me_internal_data->list_head);
			}
			me_dbg_prn(me, "Added table entry (entries num = %lu)",
				   me_internal_data->entries_num);

			/* Assign sequential indices from list walk (no sort) */
			sort_idx = 0;
			DLIST_FOR_EACH(list_entry,
				       &me_internal_data->list_head) {
				list_entry->table_entry.idx = sort_idx++;
			}
		} else {
			/* ALCL/generic: override in-place or tail-insert */
			entry_overridden = false;
			DLIST_FOR_EACH(list_entry,
				       &me_internal_data->list_head) {
				if (memcmp(&list_entry->table_entry.data,
					   entry, 8) == 0) {
					dump_entry(me, "Override entry (old)",
						   &list_entry->table_entry.data);
					memcpy(&list_entry->table_entry.data,
					       entry,
					       sizeof(list_entry->table_entry.data));
					dump_entry(me, "Override entry (new)",
						   &list_entry->table_entry.data);
					entry_overridden = true;
					me_dbg_prn(me, "Overridden table entry "
						   "(entries num = %lu)",
						   me_internal_data->entries_num);
					break;
				}
			}

			if (!entry_overridden) {
				list_entry = IFXOS_MemAlloc(sizeof(*list_entry));
				RETURN_IF_MALLOC_ERROR(list_entry);
				++me_internal_data->entries_num;
				memcpy(&list_entry->table_entry.data, entry,
				       sizeof(list_entry->table_entry.data));
				dump_entry(me, "Add entry",
					   &list_entry->table_entry.data);

				if (def) {
					++me_internal_data->def_entries_num;
					list_entry->table_entry.def = true;
				} else {
					list_entry->table_entry.def = false;
				}

				DLIST_ADD_TAIL(list_entry,
					       &me_internal_data->list_head);
				me_dbg_prn(me,
					   "Added table entry (entries num = %lu)",
					   me_internal_data->entries_num);
			}
		}

		/* Build sort_array for programming */
		sort_array = IFXOS_MemAlloc(sizeof(*sort_array) *
					    me_internal_data->entries_num);
		RETURN_IF_MALLOC_ERROR(sort_array);

		if (vendor == OLT_VENDOR_HWTC) {
			/* HWTC: list order, no sort */
			i = 0;
			DLIST_FOR_EACH(list_entry,
				       &me_internal_data->list_head) {
				sort_array[i++] =
					&list_entry->table_entry.data;
			}
		} else {
			/* ALCL/generic: non-defaults first (sorted),
			   defaults at end */
			sort_idx = 0;
			sort_idx_def = 0;
			sort_num = me_internal_data->entries_num -
				   me_internal_data->def_entries_num;
			DLIST_FOR_EACH(list_entry,
				       &me_internal_data->list_head) {
				if (!list_entry->table_entry.def) {
					sort_array[sort_idx] =
						&list_entry->table_entry.data;
					sort_idx++;
				} else {
					sort_array[sort_num + sort_idx_def] =
						&list_entry->table_entry.data;
					sort_idx_def++;
				}
			}

			qsort(sort_array, sort_num, sizeof(*sort_array),
			      tbl_entry_uid_cmp);

			/* Update entry indices from sorted position */
			DLIST_FOR_EACH(list_entry,
				       &me_internal_data->list_head) {
				entry_found = false;
				for (sort_idx = 0;
				     sort_idx < me_internal_data->entries_num;
				     sort_idx++) {
					if (memcmp(&list_entry->table_entry.data,
						   sort_array[sort_idx],
						   8) == 0) {
						list_entry->table_entry.idx =
							sort_idx;
						entry_found = true;
						break;
					}
				}

				if (!entry_found) {
					me_dbg_err(me, "Can't find table entry "
						   "in the sorted list");
					error = OMCI_ERROR_INVALID_VAL;
					break;
				}
			}
		}

		/* Collision detection + clear/reprogram GPE tables */
		if (error == OMCI_SUCCESS) {
			uint32_t us_idx = 0, ds_idx = 0;
			struct ds_collision_group coll_groups[4];
			int num_collisions = 0;
			bool dual_vlan_active = false;
			uint16_t cfg_mappers[MAX_SHADOW_DS_TABLES];
			uint16_t cfg_vids[MAX_SHADOW_DS_TABLES];
			int cfg_count = 0;
			bool cfg_auto = false;
			int s;

			/* Detect DS many-to-one collisions */
			if (ds_mode == 0) {
				num_collisions = detect_ds_collisions(
					sort_array,
					me_internal_data->entries_num,
					coll_groups, 4);

				if (num_collisions > 0) {
					cfg_count = read_dual_vlan_config(
						cfg_mappers, cfg_vids,
						MAX_SHADOW_DS_TABLES,
						&cfg_auto);

					if (cfg_count > 0)
						dual_vlan_active = true;
				}
			}

			/* Clean up previous shadow DS tables */
			for (s = 0; s < me_internal_data->shadow_ds_count;
			     s++) {
				if (me_internal_data->shadow_ds[s].active) {
					ext_vlan_shadow_ds_destroy(
						context->api,
						me_internal_data->shadow_ds[s].mapper_me_id);
					me_internal_data->shadow_ds[s].active = false;
				}
			}
			me_internal_data->shadow_ds_count = 0;

			/* Assign mappers to collision groups */
			if (dual_vlan_active) {
				int g, v;
				for (g = 0; g < num_collisions; g++) {
					for (v = 0; v < coll_groups[g].count &&
					     v < cfg_count; v++) {
						if (cfg_auto) {
							/* Auto: use mapper
							   list in order */
							coll_groups[g].mapper_me_ids[v] =
								cfg_mappers[v];
						} else {
							/* Explicit: match VID
							   to mapper */
							int c;
							coll_groups[g].mapper_me_ids[v] = 0;
							for (c = 0; c < cfg_count; c++) {
								if (cfg_vids[c] ==
								    coll_groups[g].filter_vids[v]) {
									coll_groups[g].mapper_me_ids[v] =
										cfg_mappers[c];
									break;
								}
							}
						}
					}
				}

				/* Create shadow DS tables */
				for (g = 0; g < num_collisions; g++) {
					for (v = 0; v < coll_groups[g].count;
					     v++) {
						uint16_t mme =
							coll_groups[g].mapper_me_ids[v];
						uint32_t sidx;

						if (mme == 0)
							continue;

						ret = ext_vlan_shadow_ds_create_and_link(
							context->api,
							mme, &sidx);
						if (ret != OMCI_API_SUCCESS) {
							me_dbg_err(me,
								"DRV ERR(%d) "
								"shadow create "
								"mapper=0x%04x",
								ret, mme);
							continue;
						}

						if (me_internal_data->shadow_ds_count <
						    MAX_SHADOW_DS_TABLES) {
							int si = me_internal_data->shadow_ds_count;
							me_internal_data->shadow_ds[si].mapper_me_id = mme;
							me_internal_data->shadow_ds[si].ext_vlan_idx = sidx;
							me_internal_data->shadow_ds[si].active = true;
							me_internal_data->shadow_ds_count++;
						}
					}
				}

				me_dbg_msg(me,
					   "DUAL_VLAN: %d collision groups, "
					   "%d shadow DS tables created",
					   num_collisions,
					   me_internal_data->shadow_ds_count);
			}

			/* Clear original GPE tables */
			omci_api_extended_vlan_config_data_tag_oper_table_clear(
				context->api, me->instance_id, ds_mode);

			/* Program rules */
			for (i = 0; i < me_internal_data->entries_num; i++) {
				struct omci_rx_vlan_oper_table *e =
					sort_array[i];
				bool is_colliding = false;
				int coll_g = -1, coll_v = -1;

				/* Check if this entry is in a collision
				   group (for DS split) */
				if (dual_vlan_active) {
					int g, v;
					for (g = 0; g < num_collisions; g++) {
						for (v = 0;
						     v < coll_groups[g].count;
						     v++) {
							if (e->filter_inner_vid ==
							    coll_groups[g].filter_vids[v] &&
							    e->treatment_inner_vid ==
							    coll_groups[g].treatment_vid) {
								is_colliding = true;
								coll_g = g;
								coll_v = v;
								break;
							}
						}
						if (is_colliding)
							break;
					}
				}

				/* US direction — ALL rules go to original
				   US table (no collision in US) */
				ret = omci_api_extended_vlan_config_data_tag_oper_table_entry_add_dir(
					context->api,
					me->instance_id,
					us_idx,
					ds_mode,
					false,
					e->filter_outer_prio,
					e->filter_outer_vid,
					e->filter_outer_tpid_de,
					e->filter_inner_prio,
					e->filter_inner_vid,
					e->filter_inner_tpid_de,
					e->filter_ether_type,
					e->treatment_tags_remove,
					e->treatment_outer_prio,
					e->treatment_outer_vid,
					e->treatment_outer_tpid_de,
					e->treatment_inner_prio,
					e->treatment_inner_vid,
					e->treatment_inner_tpid_de);

				if (ret != OMCI_API_SUCCESS) {
					me_dbg_err(me,
						   "DRV ERR(%d) Can't set US "
						   "ExtVLAN entry", ret);
					error = OMCI_ERROR_DRV;
					break;
				}
				us_idx++;

				/* DS direction (only when ds_mode == 0) */
				if (ds_mode == 0) {
					uint8_t ds_inner_prio =
						e->treatment_inner_prio;
					uint16_t ds_inner_vid =
						e->treatment_inner_vid;

					if (omci_iop_mask_isset(context,
							OMCI_IOP_OPTION_8)) {
						ds_inner_prio = 0;
						ds_inner_vid = 0;
					}

					if (is_colliding &&
					    coll_groups[coll_g].mapper_me_ids[coll_v] != 0) {
						/* Colliding DS: program to
						   shadow DS table instead */
						uint16_t mme =
							coll_groups[coll_g].mapper_me_ids[coll_v];
						uint32_t sidx;
						int omci_idx;
						struct vlan_filter flt;

						ret = ext_vlan_idx_get(
							context->api,
							mme, true, false,
							&sidx);
						if (ret != OMCI_API_SUCCESS) {
							me_dbg_err(me,
								"DRV ERR(%d) "
								"shadow idx_get "
								"mapper=0x%04x",
								ret, mme);
							error = OMCI_ERROR_DRV;
							break;
						}

						flt.filter_outer_priority = e->filter_outer_prio;
						flt.filter_outer_vid = e->filter_outer_vid;
						flt.filter_outer_tpid_de = e->filter_outer_tpid_de;
						flt.filter_inner_priority = e->filter_inner_prio;
						flt.filter_inner_vid = e->filter_inner_vid;
						flt.filter_inner_tpid_de = e->filter_inner_tpid_de;
						flt.filter_ethertype = e->filter_ether_type;
						flt.treatment_tags_to_remove = e->treatment_tags_remove;
						flt.treatment_outer_priority = e->treatment_outer_prio;
						flt.treatment_outer_vid = e->treatment_outer_vid;
						flt.treatment_outer_tpid_de = e->treatment_outer_tpid_de;
						flt.treatment_inner_priority = ds_inner_prio;
						flt.treatment_inner_vid = ds_inner_vid;
						flt.treatment_inner_tpid_de = e->treatment_inner_tpid_de;

						omci_idx = omci_api_find_ext_vlan_rule(&flt, false);
						if (omci_idx >= 0) {
							ret = ext_vlan_rule_add(
								context->api,
								true, sidx,
								0, /* first rule */
								(uint16_t)omci_idx,
								&flt);
							if (ret != OMCI_API_SUCCESS)
								me_dbg_err(me,
									"DRV ERR(%d) "
									"shadow DS add "
									"mapper=0x%04x",
									ret, mme);
						}

						me_dbg_msg(me,
							   "DUAL_VLAN: VID %u -> "
							   "shadow mapper 0x%04x",
							   e->filter_inner_vid,
							   mme);
						/* Skip original DS table for
						   this colliding rule */
						continue;
					}

					/* Non-colliding DS: normal path */

					/* ALCL: inject IOP DS passthrough
					   (VID=0) before each real DS rule */
					if (vendor == OLT_VENDOR_ALCL) {
						ret = omci_api_extended_vlan_config_data_iop_ds_entry_add(
							context->api,
							me->instance_id,
							ds_idx,
							ds_mode);
						if (ret != OMCI_API_SUCCESS) {
							me_dbg_err(me,
								"DRV ERR(%d) "
								"Can't set IOP "
								"DS entry",
								ret);
							error = OMCI_ERROR_DRV;
							break;
						}
						ds_idx++;
					}

					ret = omci_api_extended_vlan_config_data_tag_oper_table_entry_add_dir(
						context->api,
						me->instance_id,
						ds_idx,
						ds_mode,
						true,
						e->filter_outer_prio,
						e->filter_outer_vid,
						e->filter_outer_tpid_de,
						e->filter_inner_prio,
						e->filter_inner_vid,
						e->filter_inner_tpid_de,
						e->filter_ether_type,
						e->treatment_tags_remove,
						e->treatment_outer_prio,
						e->treatment_outer_vid,
						e->treatment_outer_tpid_de,
						ds_inner_prio,
						ds_inner_vid,
						e->treatment_inner_tpid_de);

					if (ret != OMCI_API_SUCCESS) {
						me_dbg_err(me,
							   "DRV ERR(%d) Can't "
							   "set DS ExtVLAN "
							   "entry", ret);
						error = OMCI_ERROR_DRV;
						break;
					}
					ds_idx++;
				}
			}
		}

		IFXOS_MemFree(sort_array);
	}

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error mc_enable_get(struct omci_context *context,
				     const uint8_t association_type,
				     const uint16_t associated_me_ptr,
				     bool *mc)
{
	switch (association_type) {
	case 0:
		/** \todo add handling for the bridge port */
		(void)associated_me_ptr;
		*mc = false;
		break;
	case 2:
		*mc = true;
		break;
	default:
		*mc = false;
		break;
	}

	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	enum omci_error error;
	struct omci_me_extended_vlan_config_data *upd_data;
	struct omci_me_extended_vlan_config_data *me_data;
	struct internal_data *me_internal_data;
	bool mc_enable;
	uint32_t i;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_extended_vlan_config_data *)data;
	me_data = (struct omci_me_extended_vlan_config_data *)me->data;
	me_internal_data = (struct internal_data *) me->internal_data;

	error = mc_enable_get(context, upd_data->association_type,
			      upd_data->associated_me_ptr, &mc_enable);
	RETURN_IF_ERROR(error);

	if (attr_mask &
	    ~omci_attr2mask(omci_me_extended_vlan_config_data_rx_vlan_oper_table)) {

		ret = omci_api_ext_vlan_cfg_data_update(context->api,
							mc_enable,
							upd_data->association_type,
							me->instance_id,
							upd_data->associated_me_ptr,
							upd_data->input_tp_id,
							upd_data->output_tp_id,
							upd_data->dscp_to_pbit_mapping,
							upd_data->ds_mode);

		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't update "
				   "Managed Entity",
				   ret, me->class->class_id,
				   me->instance_id);

			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}
	}

	/* Create default entries*/
	if (!me_internal_data->entries_num) {
		for (i = 0; i < OMCI_ONU_EXT_VLAN_DEFAULT_RULE_MAX; i++) {
			error = rx_vlan_oper_table_entry_set(context, me,
							     &rx_vlan_def[i],
							     upd_data->ds_mode,
							     true);
			RETURN_IF_ERROR(error);
		}
	}

	if (mc_enable) {
		ret = omci_api_extended_vlan_config_data_mc_entries_update(
							       context->api,
							       me->instance_id);
		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't update "
				   "Managed Entity MC VLAN entries",
				   ret, me->class->class_id,
				   me->instance_id);
	
			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}
	}

	if (attr_mask &
	    omci_attr2mask(omci_me_extended_vlan_config_data_rx_vlan_oper_table)) {
		error = rx_vlan_oper_table_entry_set(context, me,
						     &upd_data->
						     rx_vlan_oper_table,
						     upd_data->ds_mode,
						     false);

		RETURN_IF_ERROR(error);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_tbl_copy(struct omci_context *context,
				   struct me *me,
				   unsigned int attr,
				   struct tbl_copy_entry *tbl_copy)
{
	struct internal_data *me_internal_data;
	struct rx_vlan_oper_list_entry *list_entry;
	struct omci_rx_vlan_oper_table *tbl_entry;

#if defined(OMCI_SWAP)
	uint32_t data32[4];
#endif
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %u, 0x%p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	me_internal_data = (struct internal_data *) me->internal_data;

	switch (attr) {
	case omci_me_extended_vlan_config_data_rx_vlan_oper_table:

		tbl_copy->data_size =
			sizeof(struct omci_rx_vlan_oper_table)
			* me_internal_data->entries_num;

		if (!tbl_copy->data_size)
			break;

		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);

		tbl_entry = (struct omci_rx_vlan_oper_table *)
			tbl_copy->data;
		DLIST_FOR_EACH(list_entry, &me_internal_data->list_head) {

			memcpy(&tbl_entry[list_entry->table_entry.idx],
			       &list_entry->table_entry.data,
			       sizeof(*tbl_entry));
#if defined(OMCI_SWAP)
			memcpy(&data32, tbl_entry, sizeof(data32));
			data32[0] = ntoh32(data32[0]);
			data32[1] = ntoh32(data32[1]);
			data32[2] = ntoh32(data32[2]);
			data32[3] = ntoh32(data32[3]);
			memcpy(tbl_entry, &data32, sizeof(data32));
#endif
		}

		error = OMCI_SUCCESS;
		break;

	default:
		error = OMCI_ERROR_INVALID_ME_ATTR;
		break;
	}

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	struct internal_data *me_internal_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	me->internal_data = IFXOS_MemAlloc(sizeof(*me_internal_data));
	RETURN_IF_MALLOC_ERROR(me->internal_data);

	me_internal_data = (struct internal_data *) me->internal_data;

	DLIST_HEAD_INIT(&me_internal_data->list_head);
	me_internal_data->entries_num = 0;
	me_internal_data->def_entries_num = 0;
	me_internal_data->shadow_ds_count = 0;
	memset(me_internal_data->shadow_ds, 0,
	       sizeof(me_internal_data->shadow_ds));

	RETURN_IF_PTR_NULL(init_data);

	error = me_data_write(context, me, init_data, me->class->data_size,
			      ~me->class->inv_attr_mask
			      & ~omci_attr2mask(omci_me_extended_vlan_config_data_rx_vlan_oper_table),
			      suppress_avc);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;
	enum omci_error error;
	struct rx_vlan_oper_list_entry *list_entry;
	struct rx_vlan_oper_list_entry *next_list_entry;
	struct internal_data *me_internal_data;
	struct omci_me_extended_vlan_config_data *me_data;
	bool mc_enable;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	me_internal_data = (struct internal_data *) me->internal_data;
	me_data = (struct omci_me_extended_vlan_config_data *)me->data;

	/* clear RX VLAN operation table */
	DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
			    &me_internal_data->list_head) {
		/* remove entry */
		DLIST_REMOVE(list_entry);

		--me_internal_data->entries_num;
		if (list_entry->table_entry.def)
			--me_internal_data->def_entries_num;

		ret = omci_api_extended_vlan_config_data_tag_oper_table_entry_remove(
			context->api,
			me->instance_id,
			list_entry->table_entry.idx,
			me_data->ds_mode);

		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't delete table entry %u",
					ret, list_entry->table_entry.idx);
		}

		IFXOS_MemFree(list_entry);
		list_entry = NULL;

		me_dbg_prn(me, "Removed table entry (entries num = %lu)",
			   me_internal_data->entries_num);
	}

	/* Destroy shadow DS tables (dual-VLAN fix) */
	{
		int s;
		for (s = 0; s < me_internal_data->shadow_ds_count; s++) {
			if (me_internal_data->shadow_ds[s].active) {
				ext_vlan_shadow_ds_destroy(
					context->api,
					me_internal_data->shadow_ds[s].mapper_me_id);
			}
		}
		me_internal_data->shadow_ds_count = 0;
	}

	IFXOS_MemFree(me->internal_data);

	error = mc_enable_get(context, me_data->association_type,
			      me_data->associated_me_ptr, &mc_enable);
	RETURN_IF_ERROR(error);

	if (mc_enable)
		(void)omci_api_extended_vlan_config_data_mc_entries_clear(
							       context->api,
							       me->instance_id);

	ret = omci_api_ext_vlan_cfg_data_destroy(context->api, me->instance_id);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static uint16_t association_type_cp[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
static uint16_t ds_mode_cp[] = { 0, 1 };

/** Managed Entity class */
struct me_class me_extended_vlan_config_data_class = {
	/* Class ID */
	OMCI_ME_EXTENDED_VLAN_TAGGING_OPERATION_CONFIG_DATA,
	/* Attributes */
	{
		/* 1. Association Type */
		ATTR_ENUM("Association type",
			  ATTR_SUPPORTED,
			  association_type_cp,
			  offsetof(struct omci_me_extended_vlan_config_data,
				   association_type),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 2. Received Frame VLAN Tagging Operation Table
		   Maximum Size */
		ATTR_UINT("RX frame VLAN table max",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_extended_vlan_config_data,
				   rx_vlan_oper_table_size),
			  2,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 3. Input Termination Point ID */
		ATTR_UINT("Input TPID",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_extended_vlan_config_data,
				   input_tp_id),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 4. Output Termination Point ID */
		ATTR_UINT("Output TPID",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_extended_vlan_config_data,
				   output_tp_id),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 5. Downstream Mode */
		ATTR_ENUM("Downstream mode",
			  ATTR_SUPPORTED,
			  ds_mode_cp,
			  offsetof(struct omci_me_extended_vlan_config_data,
				   ds_mode),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 6. Received Frame VLAN Tagging Operation Table */
		ATTR_TBL("RX frame VLAN table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_extended_vlan_config_data,
				  rx_vlan_oper_table),
			 16,	/* size of one table entry */
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 7. Associated Managed Entity Pointer */
		ATTR_PTR("Associated ME ptr",
			 ATTR_SUPPORTED,
			 0x00000000,
			 0xffffffff,
			 offsetof(struct omci_me_extended_vlan_config_data,
				  associated_me_ptr),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 8. DSCP to P-bit Mapping */
		ATTR_STR("DSCP to P-bit mapping",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_extended_vlan_config_data,
				  dscp_to_pbit_mapping),
			 24,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 9-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
	},
	/* Actions */
	{
		NULL, NULL, NULL, NULL,
		/* Create */
		create_action_handle,
		NULL,
		/* Delete */
		delete_action_handle,
		NULL,
		/* Set */
		set_action_handle,
		/* Get */
		get_action_handle,
		NULL,
		/* Get all alarms */
		NULL,
		/* Get all alarms next */
		NULL,
		/* MIB upload */
		NULL,
		/* MIB upload next */
		NULL,
		/* MIB reset */
		NULL,
		/* Alarm */
		NULL,
		/* Attribute value change */
		NULL,
		/* Test */
		NULL,
		/* Start SW download */
		NULL,
		/* Download section */
		NULL,
		/* End SW download */
		NULL,
		/* Activate software */
		NULL,
		/* Commit software */
		NULL,
		/* Synchronize Time */
		NULL,
		/* Reboot */
		NULL,
		/* Get next */
		get_next_action_handle,
		/* Test result */
		NULL,
		/* Get current data */
		NULL
	},
	/* Init Handler */
	me_init,
	/* Shutdown Handler */
	me_shutdown,
	/* Validate Handler */
	me_validate,
	/* Update Handler */
	me_update,
	/* Table Attribute Copy Handler */
	me_tbl_copy,
	/* Table Attribute Operations Handler */
	NULL,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	NULL,
	/* Thresholds set Handler */
	NULL,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_me_extended_vlan_config_data),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Extended VLAN conf data",
		/* Access */
		ME_CREATED_BY_ONT,
		/* Supported alarms */
		NULL,
		/* Supported alarms count */
		0,
		/* Support */
		ME_SUPPORTED
	},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */
