/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_multicast_operations_profile.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_multicast_subscriber_config.h"
#include "me/omci_multicast_operations_profile.h"
#include "me/omci_api_multicast_operations_profile.h"
#include "mcc/omci_api_mcc.h"

/** \addtogroup OMCI_ME_MULTICAST_OPERATIONS_PROFILE
   @{
*/

/** Structure that implements Dynamic/Static ACL table */
struct acl_list_entry {
	/** Table entry */
	struct omci_acl_table table_entry;

	/** Next entry */
	struct acl_list_entry *next;

	/** Previous entry */
	struct acl_list_entry *prev;
};

/** Internal data */
struct internal_data {
	/** Multicast Address table (list head) */
	struct acl_list_entry dynamic_list_head;

	/** Number of entries in Multicast Address table */
	size_t dynamic_entries_num;

	/** Multicast Address table (list head) */
	struct acl_list_entry static_list_head;

	/** Number of entries in Multicast Address table */
	size_t static_entries_num;
};

/** Add/Delete/Clear dynamic ACL table

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] entry   Table entry
*/
static inline enum omci_error dynamic_acl_table_entry_set(struct omci_context
							  *context,
							  struct me *me,
							  struct
							  omci_acl_table
							  *entry)
{
	enum omci_api_return ret;
	struct internal_data *me_internal_data;
	struct acl_list_entry *list_entry;
	struct acl_list_entry *next_list_entry;
	bool entry_overridden;
	bool entry_found;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)entry);

	me_internal_data = (struct internal_data *)me->internal_data;

	/* swap entry */
#if defined(OMCI_SWAP)
	entry->index = ntoh16(entry->index);
	entry->gem_port_id = ntoh16(entry->gem_port_id);
	entry->vlan_id = ntoh16(entry->vlan_id);
	entry->group_bandwidth = ntoh32(entry->group_bandwidth);
#endif

	if (entry->index & OMCI_ACL_TABLE_ENTRY_DELETE
	    && entry->index & OMCI_ACL_TABLE_ENTRY_SET) {
		me_dbg_msg(me, "Table clear");

		DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				    &me_internal_data->dynamic_list_head) {
			DLIST_REMOVE(list_entry);

			--me_internal_data->dynamic_entries_num;

			IFXOS_MemFree(list_entry);
			list_entry = NULL;

			me_dbg_prn(me, "Removed table entry "
				   "(entries num = %lu)",
				   me_internal_data->dynamic_entries_num);
		}

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	} else if (entry->index & OMCI_ACL_TABLE_ENTRY_DELETE) {
		/* delete entry */
		me_dbg_msg(me, "Entry delete");

		entry->index &= ~(OMCI_ACL_TABLE_ENTRY_SET
				  | OMCI_ACL_TABLE_ENTRY_DELETE);

		entry_found = false;
		DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				    &me_internal_data->dynamic_list_head) {
			if (list_entry->table_entry.index == entry->index) {
				/* remove entry */
				DLIST_REMOVE(list_entry);

				--me_internal_data->dynamic_entries_num;

				IFXOS_MemFree(list_entry);
				list_entry = NULL;

				entry_found = true;

				me_dbg_prn(me, "Removed table entry "
					   "(entries num = %lu)",
					   me_internal_data->
					   dynamic_entries_num);
			}
		}

		if (!entry_found) {
			dbg_out_ret(__func__, OMCI_ERROR_INVALID_VAL);
			return OMCI_ERROR_INVALID_VAL;
		}

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	} else if (entry->index & OMCI_ACL_TABLE_ENTRY_SET) {
		/* set entry */
		me_dbg_msg(me, "Entry set");

		entry->index &= ~(OMCI_ACL_TABLE_ENTRY_SET
				  | OMCI_ACL_TABLE_ENTRY_DELETE);

		entry_overridden = false;
		DLIST_FOR_EACH(list_entry,
			       &me_internal_data->dynamic_list_head) {
			if (list_entry->table_entry.index == entry->index) {
				/* override entry */

				memcpy(&list_entry->table_entry,
				       entry, sizeof(list_entry->table_entry));

				entry_overridden = true;

				me_dbg_prn(me, "Overridden table entry "
					   "(entries num = %lu)",
					   me_internal_data->
					   dynamic_entries_num);
			}
		}

		if (!entry_overridden) {
			/* insert new entry to the head */

			list_entry = IFXOS_MemAlloc(sizeof(*list_entry));
			RETURN_IF_MALLOC_ERROR(list_entry);

			++me_internal_data->dynamic_entries_num;

			memcpy(&list_entry->table_entry,
			       entry, sizeof(list_entry->table_entry));

			DLIST_ADD_TAIL(list_entry,
				       &me_internal_data->dynamic_list_head);

			me_dbg_prn(me, "Added table entry (entries num = %lu)",
				   me_internal_data->dynamic_entries_num);
		}

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	} else {
		dbg_out_ret(__func__, OMCI_ERROR_INVALID_VAL);
		return OMCI_ERROR_INVALID_VAL;
	}
}

/** Add/Delete/Clear static ACL table

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] entry   Table entry
*/
static inline enum omci_error static_acl_table_entry_set(struct omci_context
							 *context,
							 struct me *me,
							 struct
							 omci_acl_table
							 *entry)
{
	enum omci_api_return ret;
	struct internal_data *me_internal_data;
	struct acl_list_entry *list_entry;
	struct acl_list_entry *next_list_entry;
	bool entry_overridden;
	bool entry_found;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)entry);

	me_internal_data = (struct internal_data *)me->internal_data;

	/* swap entry */
#if defined(OMCI_SWAP)
	entry->index = ntoh16(entry->index);
	entry->gem_port_id = ntoh16(entry->gem_port_id);
	entry->vlan_id = ntoh16(entry->vlan_id);
	entry->group_bandwidth = ntoh32(entry->group_bandwidth);
#endif

	if (entry->index & OMCI_ACL_TABLE_ENTRY_DELETE
	    && entry->index & OMCI_ACL_TABLE_ENTRY_SET) {
		me_dbg_msg(me, "Table clear");

		DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				    &me_internal_data->static_list_head) {
			DLIST_REMOVE(list_entry);

			--me_internal_data->static_entries_num;

			ret = omci_api_multicast_operations_profile_static_acl_table_entry_remove(
				context->api,
				me->instance_id, list_entry->table_entry.index);

			if (ret != OMCI_API_SUCCESS) {
				me_dbg_err(me, "DRV ERR(%d) Can't remove "
					   "table entry", ret);

				IFXOS_MemFree(list_entry);

				dbg_out_ret(__func__, OMCI_ERROR_DRV);
				return OMCI_ERROR_DRV;
			}

			IFXOS_MemFree(list_entry);
			list_entry = NULL;

			me_dbg_prn(me, "Removed table entry (entries num = %lu)",
				   me_internal_data->static_entries_num);
		}

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	} else if (entry->index & OMCI_ACL_TABLE_ENTRY_DELETE) {
		/* delete entry */
		me_dbg_msg(me, "Entry delete");

		entry->index &= ~(OMCI_ACL_TABLE_ENTRY_SET
				  | OMCI_ACL_TABLE_ENTRY_DELETE);

		ret = omci_api_multicast_operations_profile_static_acl_table_entry_remove(
			context->api,
			me->instance_id, entry->index);

		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't remove "
				   "table entry", ret);

			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}

		entry_found = false;
		DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				    &me_internal_data->static_list_head) {
			if (list_entry->table_entry.index == entry->index) {
				/* remove entry */
				DLIST_REMOVE(list_entry);

				--me_internal_data->static_entries_num;

				IFXOS_MemFree(list_entry);
				list_entry = NULL;

				entry_found = true;

				me_dbg_prn(me, "Removed table entry "
					   "(entries num = %lu)",
					   me_internal_data->
					   static_entries_num);
			}
		}

		if (!entry_found) {
			dbg_out_ret(__func__, OMCI_ERROR_INVALID_VAL);
			return OMCI_ERROR_INVALID_VAL;
		}

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	} else if (entry->index & OMCI_ACL_TABLE_ENTRY_SET) {
		/* set entry */
		me_dbg_msg(me, "Entry set");

		entry->index &= ~(OMCI_ACL_TABLE_ENTRY_SET
				  | OMCI_ACL_TABLE_ENTRY_DELETE);

		ret = omci_api_multicast_operations_profile_static_acl_table_entry_add(
			context->api,
			me->instance_id, entry->index, entry->gem_port_id,
			entry->vlan_id, entry->source_ip, entry->dest_start_ip,
			entry->dest_end_ip, entry->group_bandwidth);

		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't set "
				   "table entry", ret);

			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}

		entry_overridden = false;
		DLIST_FOR_EACH(list_entry,
			       &me_internal_data->static_list_head) {
			if (list_entry->table_entry.index == entry->index) {
				/* override entry */

				memcpy(&list_entry->table_entry,
				       entry, sizeof(list_entry->table_entry));

				entry_overridden = true;

				me_dbg_prn(me, "Overridden table entry "
					   "(entries num = %lu)",
					   me_internal_data->
					   static_entries_num);
			}
		}

		if (!entry_overridden) {
			/* insert new entry to the head */

			list_entry = IFXOS_MemAlloc(sizeof(*list_entry));
			RETURN_IF_MALLOC_ERROR(list_entry);

			++me_internal_data->static_entries_num;

			memcpy(&list_entry->table_entry,
			       entry, sizeof(list_entry->table_entry));

			DLIST_ADD_TAIL(list_entry,
				       &me_internal_data->static_list_head);

			me_dbg_prn(me, "Added table entry (entries num = %lu)",
				   me_internal_data->static_entries_num);
		}

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	} else {
		dbg_out_ret(__func__, OMCI_ERROR_INVALID_VAL);
		return OMCI_ERROR_INVALID_VAL;
	}
}

static enum omci_error dacl_table_fill(struct me *me,
				       struct omci_api_multicast_operations_profile_acl *acl)
{
	struct internal_data *me_internal_data;
	struct acl_list_entry *list_entry;
	struct acl_list_entry *next_list_entry;
	uint32_t i = 0;

	me_internal_data = (struct internal_data *)me->internal_data;

	if (me_internal_data->dynamic_entries_num >= ARRAY_SIZE(acl->entry)) {

		me_dbg_err(me, "Can't update "
			   "Managed Entity, number of DACL entries exceed");
		return OMCI_ERROR;
	}

	/* clear dynamic ACL table */
	DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
			    &me_internal_data->dynamic_list_head) {

		acl->entry[i].gem_port_id = list_entry->table_entry.gem_port_id;
		acl->entry[i].vlan_id = list_entry->table_entry.vlan_id;
		acl->entry[i].source_ip =
			*((uint32_t*)&list_entry->table_entry.source_ip[0]);
		acl->entry[i].dest_start_ip =
			*((uint32_t*)&list_entry->table_entry.dest_start_ip[0]);
		acl->entry[i].dest_end_ip =
			*((uint32_t*)&list_entry->table_entry.dest_end_ip[0]);
		acl->entry[i].group_bandwidth;

		i++;
	}
	acl->count = i;

	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	enum omci_error error;
	struct omci_me_multicast_operations_profile *upd_data;
	struct omci_me_multicast_operations_profile *me_data;
	struct omci_api_multicast_operations_profile_acl dacl;
	struct me *subscr[OMCI_API_MCC_MAX_SUBSCRIBERS];
	size_t subscr_num, i;
	uint16_t profile;
	

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_multicast_operations_profile *) data;
	me_data = (struct omci_me_multicast_operations_profile *) me->data;

	if (attr_mask &
	    omci_attr2mask(omci_me_multicast_operations_profile_dynamic_acl_table)) {
		error = dynamic_acl_table_entry_set(context, me,
						    &upd_data->
						    dynamic_acl_table);

		RETURN_IF_ERROR(error);

		/* fill OMCI API dynamic access control list */
		error = dacl_table_fill(me, &dacl);
		RETURN_IF_ERROR(error);

		ret = omci_api_multicast_operations_profile_dynamic_acl_table_update(
				context->api, me->instance_id, &dacl);
		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't update "
				   "Managed Entity", ret);

			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}
	} else if (attr_mask &
		   omci_attr2mask
		   (omci_me_multicast_operations_profile_static_acl_table)) {
		error = static_acl_table_entry_set(context, me,
						   &upd_data->static_acl_table);

		RETURN_IF_ERROR(error);
	} else {
		ret = omci_api_multicast_operations_profile_update(
				context->api,
				me->instance_id,
				upd_data->igmp_version,
				upd_data->igmp_function,
				upd_data->immediate_leave,
				upd_data->us_igmp_tag_ctrl_info,
				upd_data->us_igmp_tag_ctrl,
				upd_data->us_igmp_rate,
				upd_data->robustness,
				upd_data->querier_ip_addr,
				upd_data->query_interval,
				upd_data->query_max_rsp_time,
				upd_data->last_member_query_interval,
				*((uint16_t*)&(upd_data->ds_igmp_mc_tci[1])),
				upd_data->ds_igmp_mc_tci[0]);

		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't update "
				   "Managed Entity", ret);

			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}
	}

	if (attr_mask &
	    (omci_attr2mask(omci_me_multicast_operations_profile_us_igmp_tag_ctrl_info) |
	     omci_attr2mask(omci_me_multicast_operations_profile_us_igmp_tag_ctrl) |
	     omci_attr2mask(omci_me_multicast_operations_profile_ds_igmp_mc_tci))) {

		/* Find All subscribers with this profile */
		profile = me->instance_id;
		error = mib_me_find_where(context,
					  OMCI_ME_MULTICAST_SUBSCRIBER_CONFIG_INFO,
					  omci_me_multicast_subscriber_config_mc_ops_profile_ptr,
					  &profile, sizeof(profile),
					  subscr, sizeof(subscr),
					  &subscr_num);
		if (error) {
			dbg_out_ret(__func__, OMCI_SUCCESS);
			return OMCI_SUCCESS;
		}
	
		if (subscr_num > ARRAY_SIZE(subscr)) {
			dbg_err("ERROR(-1) Not enough memory for Subscribers "
				"(Multicast Oper Profile Update)");
			dbg_out_ret(__func__, OMCI_ERROR);
			return OMCI_ERROR;
		}

		/* refresh all Subscribers */
		for (i = 0; i < subscr_num; i++) {
			me_lock(context, subscr[i]);
			error = me_refresh(context, subscr[i]);
			me_unlock(context, subscr[i]);
			if (error != OMCI_SUCCESS) {
				me_dbg_err(subscr[i], "Refresh error %d", error);
				continue;
			}
		}
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_tbl_copy(struct omci_context *context,
				   struct me *me,
				   unsigned int attr,
				   struct tbl_copy_entry *tbl_copy)
{
	enum omci_api_return ret;
	unsigned int i;
	unsigned int lost_group_table_entries_num;
	struct omci_api_multicast_operations_profile_lost_group_list_table_entry
		*lost_group_table;
	struct omci_lost_groups_table *lost_group_table_entry;
	struct internal_data *me_internal_data;
	struct acl_list_entry *list_entry;
	struct omci_acl_table *tbl_entry;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	me_internal_data = (struct internal_data *)me->internal_data;

	switch (attr) {
	case omci_me_multicast_operations_profile_dynamic_acl_table:
		tbl_copy->data_size = sizeof(struct omci_acl_table)
		    * me_internal_data->dynamic_entries_num;

		if (!tbl_copy->data_size)
			break;

		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);

		tbl_entry = (struct omci_acl_table *)tbl_copy->data;
		DLIST_FOR_EACH(list_entry,
			       &me_internal_data->dynamic_list_head) {
			tbl_entry->index =
				hton16(list_entry->table_entry.index);

			tbl_entry->gem_port_id =
				hton16(list_entry->table_entry.gem_port_id);

			tbl_entry->vlan_id =
				hton16(list_entry->table_entry.vlan_id);

			tbl_entry->group_bandwidth =
				hton32(list_entry->table_entry.
				       group_bandwidth);

			memcpy(tbl_entry->source_ip,
			       list_entry->table_entry.source_ip,
			       sizeof(tbl_entry->source_ip));

			memcpy(tbl_entry->dest_start_ip,
			       list_entry->table_entry.dest_start_ip,
			       sizeof(tbl_entry->dest_start_ip));

			memcpy(tbl_entry->dest_end_ip,
			       list_entry->table_entry.dest_end_ip,
			       sizeof(tbl_entry->dest_end_ip));

			tbl_entry->reserved = 0;

			++tbl_entry;
		}

		error = OMCI_SUCCESS;
		break;

	case omci_me_multicast_operations_profile_static_acl_table:
		tbl_copy->data_size = sizeof(struct omci_acl_table)
		    * me_internal_data->static_entries_num;

		if (!tbl_copy->data_size)
			break;

		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);

		tbl_entry = (struct omci_acl_table *)tbl_copy->data;
		DLIST_FOR_EACH(list_entry,
			       &me_internal_data->static_list_head) {
			tbl_entry->index =
				hton16(list_entry->table_entry.index);

			tbl_entry->gem_port_id =
				hton16(list_entry->table_entry.gem_port_id);

			tbl_entry->vlan_id =
				hton16(list_entry->table_entry.vlan_id);

			tbl_entry->group_bandwidth =
				hton32(list_entry->table_entry.
				       group_bandwidth);

			memcpy(tbl_entry->source_ip,
			       list_entry->table_entry.source_ip,
			       sizeof(tbl_entry->source_ip));

			memcpy(tbl_entry->dest_start_ip,
			       list_entry->table_entry.dest_start_ip,
			       sizeof(tbl_entry->dest_start_ip));

			memcpy(tbl_entry->dest_end_ip,
			       list_entry->table_entry.dest_end_ip,
			       sizeof(tbl_entry->dest_end_ip));

			tbl_entry->reserved = 0;

			++tbl_entry;
		}

		error = OMCI_SUCCESS;
		break;

	case omci_me_multicast_operations_profile_lost_groups_table:
		ret = omci_api_multicast_operations_profile_lost_group_list_table_get(
			context->api,
			me->instance_id, &lost_group_table_entries_num,
			&lost_group_table);

		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't get "
				   "Lost groups list table", ret);

			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}

		if (lost_group_table_entries_num && !lost_group_table) {
			me_dbg_err(me, "DRV ERR Can't get "
				   "Lost groups list table, "
				   "NULL table pointer");

			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}

		tbl_copy->data_size =
			sizeof(struct omci_lost_groups_table)
			* lost_group_table_entries_num;

		if (!tbl_copy->data_size)
			break;

		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		if (!tbl_copy->data) {
			IFXOS_MemFree(lost_group_table);

			RETURN_IF_MALLOC_ERROR(tbl_copy->data);
		}

		lost_group_table_entry =
			(struct omci_lost_groups_table *)tbl_copy->data;

		for (i = 0; i < lost_group_table_entries_num; i++) {
			lost_group_table_entry[i].vlan_id =
				hton16(lost_group_table[i].vlan_id);

			memcpy(lost_group_table_entry[i].source_ip,
			       lost_group_table[i].src_ip_addr,
			       sizeof(lost_group_table_entry[i].source_ip));

			memcpy(lost_group_table_entry[i].dest_ip,
			       lost_group_table[i].mc_dest_ip_addr,
			       sizeof(lost_group_table_entry[i].dest_ip));
		}

		IFXOS_MemFree(lost_group_table);
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
	enum omci_error error;
	struct internal_data *me_internal_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	me->internal_data = IFXOS_MemAlloc(sizeof(*me_internal_data));
	RETURN_IF_MALLOC_ERROR(me->internal_data);

	me_internal_data = (struct internal_data *)me->internal_data;

	DLIST_HEAD_INIT(&me_internal_data->dynamic_list_head);
	me_internal_data->dynamic_entries_num = 0;

	DLIST_HEAD_INIT(&me_internal_data->static_list_head);
	me_internal_data->static_entries_num = 0;

	error = me_data_write(context, me, init_data, me->class->data_size,
			      me->class->sbc_attr_mask, suppress_avc);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;
	struct internal_data *me_internal_data;
	struct acl_list_entry *list_entry;
	struct acl_list_entry *next_list_entry;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	me_internal_data = (struct internal_data *)me->internal_data;

	/* clear dynamic ACL table */
	DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
			    &me_internal_data->dynamic_list_head) {
		DLIST_REMOVE(list_entry);

		--me_internal_data->dynamic_entries_num;

		IFXOS_MemFree(list_entry);
		list_entry = NULL;
	}

	/* clear static ACL table */
	DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
			    &me_internal_data->static_list_head) {
		DLIST_REMOVE(list_entry);

		--me_internal_data->static_entries_num;

		ret = omci_api_multicast_operations_profile_static_acl_table_entry_remove(
			context->api,
			me->instance_id, list_entry->table_entry.index);

		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't remove table entry",
				   ret);
		}

		IFXOS_MemFree(list_entry);
		list_entry = NULL;

		me_dbg_prn(me, "Removed table entry (entries num = %lu)",
			   me_internal_data->static_entries_num);
	}

	IFXOS_MemFree(me->internal_data);

	ret = omci_api_multicast_operations_profile_destroy(context->api,
							    me->instance_id);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't shutdown "
			   "Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static uint16_t igmp_version_cp[] = {
	1,
	2,
	3
};

static uint16_t us_igmp_tag_ctrl_cp[] = {
	0,
	1,
	2,
	3
};

/** Managed Entity class */
struct me_class me_multicast_operations_profile_class = {
	/* Class ID */
	OMCI_ME_MULTICAST_OPERATIONS_PROFILE,
	/* Attributes */
	{
		/* 1. IGMP version */
		ATTR_ENUM("IGMP version",
			  ATTR_SUPPORTED,
			  igmp_version_cp,
			  offsetof(struct omci_me_multicast_operations_profile,
				   igmp_version),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR
			  | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 2. IGMP function */
		ATTR_UINT("IGMP function",
			  ATTR_SUPPORTED,
			  0,
			  3,
			  offsetof(struct omci_me_multicast_operations_profile,
				   igmp_function),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR
			  | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 3. Immediate leave */
		ATTR_BOOL("Immediate leave",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_multicast_operations_profile,
				   immediate_leave),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR
			  | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 4. Upstream IGMP TCI */
		ATTR_UINT("Upstream IGMP TCI",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_multicast_operations_profile,
				   us_igmp_tag_ctrl_info),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR
			  | OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 5. Upstream IGMP tag control */
		ATTR_ENUM("Upstream IGMP tag ctrl",
			  ATTR_SUPPORTED,
			  us_igmp_tag_ctrl_cp,
			  offsetof(struct omci_me_multicast_operations_profile,
				   us_igmp_tag_ctrl),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR
			  | OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 6. Upstream IGMP rate */
		ATTR_UINT("Upstream IGMP rate",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_multicast_operations_profile,
				   us_igmp_rate),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR
			  | OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 7. Dynamic access control list table */
		ATTR_TBL("Dynamic ACL table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_multicast_operations_profile,
				  dynamic_acl_table),
			 24,	/* size of one table entry */
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 8. Static access control list table */
		ATTR_TBL("Static ACL table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_multicast_operations_profile,
				  static_acl_table),
			 24,	/* size of one table entry */
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 9. Lost groups list table */
		ATTR_TBL("Lost groups list table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_multicast_operations_profile,
				  lost_groups_table),
			 10,	/* size of one table entry */
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 10. Robustness */
		ATTR_UINT("Robustness",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_multicast_operations_profile,
				   robustness),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 11. Querier IP address */
		ATTR_STR("Querier IP address",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_multicast_operations_profile,
				  querier_ip_addr),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL |
			 OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 12. Query interval */
		ATTR_UINT("Query interval",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_multicast_operations_profile,
				   query_interval),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL |
			 OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 13. Query max response time */
		ATTR_UINT("Query max response time",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_multicast_operations_profile,
				   query_max_rsp_time),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL |
			 OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 14. Last member query interval */
		ATTR_UINT("Last member query int",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_multicast_operations_profile,
				   last_member_query_interval),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 15. Unauthorized join request behavior */
		ATTR_UINT("Unauth. join req. beh.",
			  ATTR_SUPPORTED,
			  0,
			  1,
			  offsetof(struct omci_me_multicast_operations_profile,
				   unauthorized_join_request_behavior),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 16. Downstream IGMP and multicast TCI */
		ATTR_STR("Downstream IGMP/MC TCI",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_multicast_operations_profile,
				  ds_igmp_mc_tci),
			 3,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
			 NULL)
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
	default_me_validate,
	/* Update Handler */
	me_update,
	/* Table Attribute Copy Handler */
	me_tbl_copy,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	NULL,
	/* Thresholds set Handler */
	NULL,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_me_multicast_operations_profile),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Multicast oper profile",
		/* Access */
		ME_CREATED_BY_OLT,
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
