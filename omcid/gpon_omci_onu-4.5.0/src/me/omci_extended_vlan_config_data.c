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

/** Internal data */
struct internal_data {
	/** Received frame VLAN tagging operation table (list head) */
	struct rx_vlan_oper_list_entry list_head;

	/** Number of entries in Received frame VLAN tagging operation table */
	size_t entries_num;

	/** Number of default entries in Received frame VLAN tagging
	    operation table */
	size_t def_entries_num;
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
		error = mib_me_find(context,
				    OMCI_ME_PPTP_XDSL_UNI_1,
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
		me_dbg_msg(me, "Set entry request");

		entry_overridden = false;
		DLIST_FOR_EACH(list_entry, &me_internal_data->list_head) {
			if (memcmp(&list_entry->table_entry.data, entry, 8) == 0) {
				/* override entry */

				dump_entry(me, "Override entry (old)",
					   &list_entry->table_entry.data);

				memcpy(&list_entry->table_entry.data,
				       entry, sizeof(list_entry->table_entry.data));

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
			/* insert new entry to the head */
			list_entry = IFXOS_MemAlloc(sizeof(*list_entry));
			RETURN_IF_MALLOC_ERROR(list_entry);

			++me_internal_data->entries_num;

			memcpy(&list_entry->table_entry.data,
			       entry, sizeof(list_entry->table_entry.data));

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

			me_dbg_prn(me, "Added table entry (entries num = %lu)",
				   me_internal_data->entries_num);
		}

		sort_array = IFXOS_MemAlloc(sizeof(*sort_array) *
						me_internal_data->entries_num);
		RETURN_IF_MALLOC_ERROR(sort_array);

		/* fill sort array */
		sort_idx = 0;
		sort_idx_def = 0;
		sort_num = me_internal_data->entries_num -
					me_internal_data->def_entries_num;
		DLIST_FOR_EACH(list_entry, &me_internal_data->list_head) {
			if (!list_entry->table_entry.def) {
				sort_array[sort_idx] =
					&list_entry->table_entry.data;

				sort_idx++;
			} else {
				/* default entry at the end*/
				sort_array[sort_num + sort_idx_def] =
					&list_entry->table_entry.data;

				sort_idx_def++;
			}
		}

		/* sort only non-default entries*/
		qsort(sort_array, sort_num, sizeof(*sort_array),
		      tbl_entry_uid_cmp);

		/* update entries index */
		DLIST_FOR_EACH(list_entry, &me_internal_data->list_head) {
			entry_found = false;
			for (sort_idx = 0; sort_idx < me_internal_data->entries_num; sort_idx++) {
				if (memcmp(&list_entry->table_entry.data,
					   sort_array[sort_idx],
					   8) == 0) {
					list_entry->table_entry.idx = sort_idx;
					entry_found = true;
					break;
				}
			}

			/* this should normally not happen*/
			if (!entry_found) {
				me_dbg_err(me, "Can't find table entry in the sorted list");
				error = OMCI_ERROR_INVALID_VAL;
				break;
			}
		}

		omci_api_extended_vlan_config_data_tag_oper_table_clear(
								context->api,
								me->instance_id,
								ds_mode);

		/* update HW entries */
		for (i = 0; i < me_internal_data->entries_num; i++) {
			ret = omci_api_extended_vlan_config_data_tag_oper_table_entry_add(
				context->api,
				me->instance_id,
				i,
				ds_mode,
				sort_array[i]->filter_outer_prio,
				sort_array[i]->filter_outer_vid,
				sort_array[i]->filter_outer_tpid_de,
				sort_array[i]->filter_inner_prio,
				sort_array[i]->filter_inner_vid,
				sort_array[i]->filter_inner_tpid_de,
				sort_array[i]->filter_ether_type,
				sort_array[i]->treatment_tags_remove,
				sort_array[i]->treatment_outer_prio,
				sort_array[i]->treatment_outer_vid,
				sort_array[i]->treatment_outer_tpid_de,
				sort_array[i]->treatment_inner_prio,
				sort_array[i]->treatment_inner_vid,
				sort_array[i]->treatment_inner_tpid_de);

			if (ret != OMCI_API_SUCCESS) {
				me_dbg_err(me, "DRV ERR(%d) Can't set table entry",
					   ret);
				error = OMCI_ERROR_DRV;
				break;

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

static uint16_t association_type_cp[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
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
