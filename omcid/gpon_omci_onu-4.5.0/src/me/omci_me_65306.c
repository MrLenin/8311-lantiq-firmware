/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_me_65306.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_me_65306.h"

/** \addtogroup OMCI_ME_65306
   @{
*/

/** Structure that implements attr1 table */
struct attr1_list_entry {
	/** Table entry */
	struct omci_me_65306_attr1 table_entry;
	/** Next entry */
	struct attr1_list_entry *next;
	/** Previous entry */
	struct attr1_list_entry *prev;
};

/** Internal data */
struct internal_data {
	/** Attr1 table (list head) */
	struct attr1_list_entry list_head;
	/** Number of entries in attr1 table */
	size_t entries_num;
};

static enum omci_error attr1_table_entry_set(struct omci_context *context,
					     struct me *me,
					     struct omci_me_65306_attr1 *entry)
{
	enum omci_api_return ret;
	struct internal_data *me_internal_data;
	struct attr1_list_entry *list_entry;
	struct attr1_list_entry *next_list_entry;
	bool entry_overridden;
	bool entry_found;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)entry);

	me_internal_data = (struct internal_data *)me->internal_data;

	/* swap entry */
#if defined(OMCI_SWAP)
	entry-v1 = ntoh16(entry-v1);
	entry-v2 = ntoh32(entry-v2);
	entry-v3 = ntoh32(entry-v3);
#endif

	if (entry->v1 & OMCI_ME_65306_ATTR1_TABLE_ENTRY_OP) {
		me_dbg_msg(me, "Table add");

		entry_overridden = false;
		DLIST_FOR_EACH(list_entry, &me_internal_data->list_head) {
			if (list_entry->table_entry.v0 == entry->v0) {
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

			DLIST_ADD_TAIL(list_entry,&me_internal_data->list_head);

			me_dbg_prn(me, "Added table entry (entries num = %lu)",
				   me_internal_data->entries_num);
		}

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	} else {
		/* delete entry */
		me_dbg_msg(me, "Entry delete");

		entry_found = false;
		DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				    &me_internal_data->list_head) {
			if (list_entry->table_entry.v0 == entry->v0) {
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

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}
}

static enum omci_error me_tbl_copy(struct omci_context *context,
				   struct me *me,
				   unsigned int attr,
				   struct tbl_copy_entry *tbl_copy)
{
	enum omci_api_return ret;
	unsigned int i;
	struct internal_data *me_internal_data;
	struct attr1_list_entry *list_entry;
	struct omci_me_65306_attr1 *tbl_entry;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	me_internal_data = (struct internal_data *)me->internal_data;

	switch (attr) {
	case omci_me_65306_attr1:
		tbl_copy->data_size = sizeof(struct omci_me_65306_attr1)
		    * me_internal_data->entries_num;

		if (!tbl_copy->data_size)
			break;

		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);

		tbl_entry = (struct omci_me_65306_attr1 *)tbl_copy->data;
		DLIST_FOR_EACH(list_entry,
			       &me_internal_data->list_head) {
			memcpy(tbl_entry, &list_entry->table_entry,
			       sizeof(tbl_entry));

			tbl_entry->v1 = hton16(tbl_entry->v1);
			tbl_entry->v2 = hton32(tbl_entry->v2);
			tbl_entry->v3 = hton32(tbl_entry->v3);

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

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_error error;
	struct omci_me_65306 *upd_data;
	struct omci_me_65306 *me_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	upd_data = (struct omci_me_65306 *) data;
	me_data = (struct omci_me_65306 *) me->data;

	if (attr_mask & omci_attr2mask(omci_me_65306_attr1)) {
		error = attr1_table_entry_set(context, me, &upd_data->attr1);

		RETURN_IF_ERROR(error);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	struct omci_me_65306 data;
	struct internal_data *me_internal_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)init_data, suppress_avc);

	if (init_data) {
		memcpy(&data, init_data, sizeof(data));
	} else {
		memset(&data, 0x00, sizeof(data));
	}

	me->internal_data = IFXOS_MemAlloc(sizeof(*me_internal_data));
	RETURN_IF_MALLOC_ERROR(me->internal_data);

	me_internal_data = (struct internal_data *)me->internal_data;
	DLIST_HEAD_INIT(&me_internal_data->list_head);
	me_internal_data->entries_num = 0;

	error = me_data_write(context, me, &data, sizeof(data),
			      ~me->class->inv_attr_mask
			      & ~omci_attr2mask(omci_me_65306_attr1),
			      suppress_avc);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	struct internal_data *me_internal_data;
	struct attr1_list_entry *list_entry;
	struct attr1_list_entry *next_list_entry;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	me_internal_data = (struct internal_data *)me->internal_data;

	DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
			    &me_internal_data->list_head) {
		DLIST_REMOVE(list_entry);

		--me_internal_data->entries_num;

		IFXOS_MemFree(list_entry);
		list_entry = NULL;
	}

	IFXOS_MemFree(me->internal_data);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_65306_class = {
	/* Class ID */
	OMCI_ME_65306,
	/* Attributes */
	{
		/* attribute 1 */
		ATTR_TBL("attr1",
			ATTR_SUPPORTED,
			  offsetof(struct omci_me_65306,
				 attr1),
			 19,	/* size of one table entry */
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_OPTIONAL,
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
		NULL,
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
	sizeof(struct omci_me_65306),
	/* Properties */
	OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"ME65306",
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
