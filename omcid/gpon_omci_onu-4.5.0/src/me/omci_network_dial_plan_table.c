/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_network_dial_plan_table.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_network_dial_plan_table.h"

#ifdef INCLUDE_OMCI_ONU_VOIP

/** \addtogroup OMCI_ME_NETWORK_DIAL_PLAN_TABLE
   @{
*/

/** Structure that implements Network Dial Plpan table */
struct network_dial_plan_table_list_entry {
	/** Table entry */
	struct omci_dial_plan_table table_entry;

	/** Next entry */
	struct network_dial_plan_table_list_entry *next;

	/** Previous entry */
	struct network_dial_plan_table_list_entry *prev;
};

/** Internal data */
struct internal_data {
	/** Network Dial Plan Table (list head) */
	struct network_dial_plan_table_list_entry list_head;

	/** Number of entries in Network Dial Plan Table */
	size_t entries_num;
};


/** Add/Remove Network Dial Plan Table Entry

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] entry   Table entry
*/
static inline enum omci_error network_dial_plan_table_entry_set(
				struct omci_context *context,
				struct me *me,
				struct omci_dial_plan_table *entry)
{
	struct internal_data *me_internal_data;
	struct network_dial_plan_table_list_entry *list_entry;
	struct network_dial_plan_table_list_entry *next_list_entry;
	bool entry_found;
	uint32_t entry_idx = 0;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)entry);

	me_internal_data = (struct internal_data *) me->internal_data;

	if (entry->action == 0) {
		/* delete entry */
		me_dbg_msg(me, "Entry delete");

		entry_found = false;
		DLIST_FOR_EACH_SAFE(list_entry,
				    next_list_entry,
				    &me_internal_data->list_head) {
			if (list_entry->table_entry.dial_plan_id == 
							entry->dial_plan_id) {
				/* remove entry */
				DLIST_REMOVE(list_entry);

				--me_internal_data->entries_num;

				IFXOS_MemFree(list_entry);
				list_entry = NULL;

				entry_found = true;

				me_dbg_prn(me, "Removed table entry "
					   "(entries num = %lu)",
					   me_internal_data->entries_num);
				break;
			}
			entry_idx++;
		}

		if (!entry_found) {
			dbg_out_ret(__func__, OMCI_ERROR_INVALID_VAL);
			return OMCI_ERROR_INVALID_VAL;
		}
	} else if (entry->action == 1) {
		/* add entry */
		me_dbg_msg(me, "Entry add");

		if (me_internal_data->entries_num >=
					OMCI_NETWORK_DIAL_PLAN_TABLE_MAX_SIZE) {
			dbg_out_ret(__func__, OMCI_ERROR_INVALID_VAL);
			return OMCI_ERROR_INVALID_VAL;
		}

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
	} else {
		dbg_out_ret(__func__, OMCI_ERROR_INVALID_VAL);
		return OMCI_ERROR_INVALID_VAL;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error dial_plan_number_get(struct omci_context *context,
					    struct me *me, void *data,
					    size_t data_size)
{
	struct internal_data *me_internal_data;

	assert(data_size == 2);

	me_internal_data = (struct internal_data *) me->internal_data;

	*((uint16_t*)data) = (uint16_t)me_internal_data->entries_num;

	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_error error;
	struct omci_me_network_dial_plan_table *upd_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_network_dial_plan_table *)data;

	if (attr_mask &
	    omci_attr2mask(omci_me_network_dial_plan_table_dial_plan_table)) {
		error = network_dial_plan_table_entry_set(
				context, me, &upd_data->dial_plan_table);

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
	struct network_dial_plan_table_list_entry *list_entry;
	struct omci_dial_plan_table *tbl_entry;

	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %u, 0x%p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	me_internal_data = (struct internal_data *) me->internal_data;

	switch (attr) {
	case omci_me_network_dial_plan_table_dial_plan_table:

		tbl_copy->data_size =
			sizeof(struct omci_dial_plan_table)
			* me_internal_data->entries_num;

		if (!tbl_copy->data_size)
			break;

		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);

		tbl_entry = (struct omci_dial_plan_table *)tbl_copy->data;
		DLIST_FOR_EACH(list_entry, &me_internal_data->list_head) {
			memcpy(tbl_entry, &list_entry->table_entry,
			       sizeof(*tbl_entry));
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
	struct internal_data *me_internal_data;
	struct omci_me_network_dial_plan_table *me_init_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	me->internal_data = IFXOS_MemAlloc(sizeof(*me_internal_data));
	RETURN_IF_MALLOC_ERROR(me->internal_data);

	me_internal_data = (struct internal_data *) me->internal_data;

	DLIST_HEAD_INIT(&me_internal_data->list_head);
	me_internal_data->entries_num = 0;

	RETURN_IF_PTR_NULL(init_data);

	me_init_data = (struct omci_me_network_dial_plan_table *)init_data;

	if (me_init_data->dial_plan_tbl_max_size >
					OMCI_NETWORK_DIAL_PLAN_TABLE_MAX_SIZE) {
		error = OMCI_ERROR_INVALID_VAL;
		RETURN_IF_ERROR(error);
	}

	error = me_data_write(context, me, init_data, me->class->data_size,
			      me->class->sbc_attr_mask, suppress_avc);

	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	struct network_dial_plan_table_list_entry *list_entry;
	struct network_dial_plan_table_list_entry *next_list_entry;
	struct internal_data *me_internal_data;
	uint32_t entry_idx = 0;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	me_internal_data = (struct internal_data *) me->internal_data;

	/* clear table */
	DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
			    &me_internal_data->list_head) {
		/* remove entry */
		DLIST_REMOVE(list_entry);

		--me_internal_data->entries_num;

		entry_idx = me_internal_data->entries_num;


		IFXOS_MemFree(list_entry);
		list_entry = NULL;

		me_dbg_prn(me, "Removed table entry (entries num = %lu)",
			   me_internal_data->entries_num);
	}

	IFXOS_MemFree(me->internal_data);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_network_dial_plan_table_class = {
	/* Class ID */
	OMCI_ME_NETWORK_DIAL_PLAN_TABLE,
	/* Attributes */
	{
		ATTR_UINT("Dial plan number",
			  ATTR_SUPPORTED,
			  0x0000,
			  OMCI_NETWORK_DIAL_PLAN_TABLE_MAX_SIZE,
			  offsetof(struct omci_me_network_dial_plan_table,
				   dial_plan_number),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  dial_plan_number_get),
		ATTR_UINT("Dial plan tbl max size",
			  ATTR_SUPPORTED,
			  0x0000,
			  OMCI_NETWORK_DIAL_PLAN_TABLE_MAX_SIZE,
			  offsetof(struct omci_me_network_dial_plan_table,
				   dial_plan_tbl_max_size),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_SBC |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		ATTR_UINT("Critical dial timeout",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_network_dial_plan_table,
				   critical_dial_timeout),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		ATTR_UINT("Partial dial timeout",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_network_dial_plan_table,
				   partial_dial_timeout),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		ATTR_UINT("Dial plan format",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_network_dial_plan_table,
				   dial_plan_format),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		ATTR_TBL("Dial plan table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_network_dial_plan_table,
				  dial_plan_table),
			 30,	/* size of one table entry */
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
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
	sizeof(struct omci_me_network_dial_plan_table),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Network dial plan table",
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
#endif
