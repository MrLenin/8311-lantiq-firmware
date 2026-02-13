/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_mac_bridge_port_filter_table_data.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_mac_bridge_port_filter_table_data.h"
#include "me/omci_mac_bridge_port_config_data.h"
#include "me/omci_api_mac_bridge_port_filter_table_data.h"

/** \addtogroup OMCI_ME_MAC_BRIDGE_PORT_FILTER_TABLE_DATA
    @{
*/

/** Structure that implements MAC filter table */
struct mac_filter_list_entry {
	/** Table entry */
	struct omci_mac_filter_table table_entry;

	/** Next entry */
	struct mac_filter_list_entry *next;

	/** Previous entry */
	struct mac_filter_list_entry *prev;
};

/** Internal data */
struct internal_data {
	/** MAC filter table (list head) */
	struct mac_filter_list_entry list_head;

	/** Number of entries in MAC filter table */
	size_t entries_num;
};

/** Add/Delete/Clear dynamic ACL table

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] entry   Table entry
*/
static inline enum omci_error mac_filter_table_entry_set(struct omci_context
							 *context,
							 struct me *me,
							 struct
							 omci_mac_filter_table
							 *entry)
{
	enum omci_api_return ret;
	struct internal_data *me_internal_data;
	struct mac_filter_list_entry *list_entry;
	struct mac_filter_list_entry *next_list_entry;
	bool entry_overridden;
	bool entry_found, clear_all;
	uint16_t bridge_me_id;
	uint8_t idx;
	struct me *bridge_port_me;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)entry);

	error = mib_me_find(context, OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
			    me->instance_id,
			    &bridge_port_me);
	RETURN_IF_ERROR(error);

	me_lock(context, bridge_port_me);
	error = me_attr_read(context, bridge_port_me,
			     omci_me_mac_bridge_port_config_data_bridge_id_ptr,
			     &bridge_me_id,
			     sizeof(bridge_me_id));
	me_unlock(context, bridge_port_me);
	RETURN_IF_ERROR(error);

	me_internal_data = (struct internal_data *) me->internal_data;

	if ((entry->filter_byte & (1 << 7)) &&
	    (entry->filter_byte & (1 << 6))) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	if (entry->filter_byte & (1 << 7)) {
		/* set entry */
		me_dbg_msg(me, "Entry set");

		entry_overridden = false;
		DLIST_FOR_EACH(list_entry, &me_internal_data->list_head) {
			if (list_entry->table_entry.index == entry->index) {
				/* override entry */
				memcpy(&list_entry->table_entry,
				       entry, sizeof(list_entry->table_entry));

				entry_overridden = true;

				me_dbg_prn(me, "Overridden table entry "
					   "(entries num = %lu)",
					   me_internal_data->entries_num);
			}
		}

		if (!entry_overridden) {
			/* insert new entry to the head */

			list_entry = IFXOS_MemAlloc(sizeof(*list_entry));
			RETURN_IF_MALLOC_ERROR(list_entry);

			++me_internal_data->entries_num;

			memcpy(&list_entry->table_entry,
			       entry, sizeof(list_entry->table_entry));

			DLIST_ADD_TAIL(list_entry,
				       &me_internal_data->list_head);

			me_dbg_prn(me, "Added table entry (entries num = %lu)",
				   me_internal_data->entries_num);
		}

		ret = omci_api_mac_bridge_port_filter_table_data_mac_filter_table_entry_add(
			context->api,
			me->instance_id,
			bridge_me_id,
			entry->index,
			entry->filter_byte,
			entry->mac_address);

		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't set table entry",
				   ret);

			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}
	} else {
		/* delete entry */
		me_dbg_msg(me, "Entry delete");

		entry_found = false;
		clear_all = (entry->filter_byte & (1 << 6)) ? true : false;
		idx = 0;
		DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				    &me_internal_data->list_head) {
			if ((list_entry->table_entry.index == entry->index) || clear_all) {

				idx = clear_all ? idx : list_entry->table_entry.index;

				ret = omci_api_mac_bridge_port_filter_table_data_mac_filter_table_entry_remove(
					context->api,
					me->instance_id,
					bridge_me_id,
					idx);
				
				if (ret != OMCI_API_SUCCESS) {
					me_dbg_err(me, "DRV ERR(%d) Can't delete "
						   "table entry", ret);
				
					dbg_out_ret(__func__, OMCI_ERROR_DRV);
					return OMCI_ERROR_DRV;
				}
				idx++;

				/* remove entry */
				DLIST_REMOVE(list_entry);

				--me_internal_data->entries_num;

				IFXOS_MemFree(list_entry);
				list_entry = NULL;

				entry_found = true;

				me_dbg_prn(me, "Removed table entry "
					   "(entries num = %lu)",
					   me_internal_data->entries_num);
			}
		}

		if (!entry_found) {
			dbg_out_ret(__func__, OMCI_ERROR_INVALID_VAL);
			return OMCI_ERROR_INVALID_VAL;
		}
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	struct omci_me_mac_bridge_port_filter_table_data *upd_data;
	struct omci_me_mac_bridge_port_filter_table_data *me_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_mac_bridge_port_filter_table_data *)data;
	me_data = (struct omci_me_mac_bridge_port_filter_table_data *)
		me->data;

	if (attr_mask &
	    omci_attr2mask
	    (omci_me_mac_bridge_port_filter_table_data_mac_filter_table)) {
		error = mac_filter_table_entry_set(context, me,
						   &upd_data->mac_filter_table);

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
	struct mac_filter_list_entry *list_entry;
	struct omci_mac_filter_table *tbl_entry;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);
	me_internal_data = (struct internal_data *)me->internal_data;

	switch (attr) {
	case omci_me_mac_bridge_port_filter_table_data_mac_filter_table:
		tbl_copy->data_size =
			sizeof(struct omci_mac_filter_table)
			* me_internal_data->entries_num;

		if (!tbl_copy->data_size)
			break;

		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);

		tbl_entry = (struct omci_mac_filter_table *)tbl_copy->data;
		DLIST_FOR_EACH(list_entry, &me_internal_data->list_head) {
			*tbl_entry = list_entry->table_entry;
			++tbl_entry;
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
	enum omci_api_return ret;
	struct internal_data *me_internal_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	me->internal_data = IFXOS_MemAlloc(sizeof(*me_internal_data));
	RETURN_IF_MALLOC_ERROR(me->internal_data);

	me_internal_data = (struct internal_data *)me->internal_data;

	DLIST_HEAD_INIT(&me_internal_data->list_head);
	me_internal_data->entries_num = 0;

	ret = omci_api_mac_bridge_port_filter_table_data_create(context->api,
							       me->instance_id);
	if (ret != OMCI_API_SUCCESS) {
		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;
	struct internal_data *me_internal_data;
	struct mac_filter_list_entry *list_entry;
	struct mac_filter_list_entry *next_list_entry;
	uint16_t bridge_me_id;
	struct me *bridge_port_me;
	enum omci_error error;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	error = mib_me_find(context, OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
			    me->instance_id,
			    &bridge_port_me);
	RETURN_IF_ERROR(error);

	me_lock(context, bridge_port_me);
	error = me_attr_read(context, bridge_port_me,
			     omci_me_mac_bridge_port_config_data_bridge_id_ptr,
			     &bridge_me_id,
			     sizeof(bridge_me_id));
	me_unlock(context, bridge_port_me);
	RETURN_IF_ERROR(error);

	me_internal_data = (struct internal_data *)me->internal_data;

	DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
			    &me_internal_data->list_head) {
		/* remove entry */
		DLIST_REMOVE(list_entry);

		--me_internal_data->entries_num;

		ret = omci_api_mac_bridge_port_filter_table_data_mac_filter_table_entry_remove(
			context->api,
			me->instance_id,
			bridge_me_id,
			list_entry->table_entry.index);

		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't delete table entry",
				   ret);
		}

		IFXOS_MemFree(list_entry);
		list_entry = NULL;

		me_dbg_prn(me, "Removed table entry (entries num = %lu)",
			   me_internal_data->entries_num);
	}

	IFXOS_MemFree(me->internal_data);

	ret = omci_api_mac_bridge_port_filter_table_data_destroy(context->api,
							       me->instance_id);
	if (ret != OMCI_API_SUCCESS) {
		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_mac_bridge_port_filter_table_data_class = {
	/* Class ID */
	OMCI_ME_MAC_BRIDGE_PORT_FILTER_TABLE_DATA,
	/* Attributes */
	{
		/* 1. MAC Filter Table */
		ATTR_TBL("MAC filter table",
			 ATTR_SUPPORTED,
			 offsetof(struct
				  omci_me_mac_bridge_port_filter_table_data,
				  mac_filter_table),
			 8,	/* size of one table entry */
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 2-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
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
		NULL,
		NULL,
		/* Delete */
		NULL,
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
	sizeof(struct omci_me_mac_bridge_port_filter_table_data),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Bridge port filter table",
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
