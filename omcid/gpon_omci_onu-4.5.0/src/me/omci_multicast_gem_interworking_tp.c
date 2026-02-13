/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_multicast_gem_interworking_tp.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_multicast_gem_interworking_tp.h"
#include "me/omci_api_multicast_gem_interworking_tp.h"
#include "me/omci_gem_port_network_ctp.h"

/* Programming hint:
   The multicast address table must be handled in SW, there is no HW filter
   table. Each time an IGMP join message is snooped, the IP range is compared
   and the multicast table is updated only, if the target IP address is in the
   defined range.
*/

/** \addtogroup OMCI_ME_MULTICAST_GEM_INTERWORKING_TP
   @{
*/

/** Structure that implements Multicast Address table */
struct mc_addr_list_entry {
	/** Table entry */
	struct omci_me_mc_address_table table_entry;

	/** Next entry */
	struct mc_addr_list_entry *next;

	/** Previous entry */
	struct mc_addr_list_entry *prev;

};

/** Internal data */
struct internal_data {
	/** Multicast Address table (list head) */
	struct mc_addr_list_entry list_head;

	/** Number of entries in Multicast Address table */
	size_t entries_num;
};

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask,
				   const void *data)
{
	struct omci_me_multicast_gem_interworking_tp *upd_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me_class,
	       (void *)exec_mask, (void *)data);

	upd_data = (struct omci_me_multicast_gem_interworking_tp *)data;

	error = default_me_validate(context, me_class, exec_mask, data);
	RETURN_IF_ERROR(error);

	error = mib_me_find(context, OMCI_ME_GEM_PORT_NETWORK_CTP,
			    upd_data->gem_port_network_ctp_ptr, NULL);

	if (error) {
		*exec_mask |=
			omci_attr2mask
			(omci_me_multicast_gem_interworking_tp_gem_port_network_ctp_ptr);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Add/Delete/Clear multicast address table

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] entry   Table entry
*/
static inline enum omci_error mc_addr_table_entry_set(struct omci_context
						      *context,
						      struct me *me,
						      struct
						      omci_me_mc_address_table
						      *entry)
{
	enum omci_api_return ret;
	struct internal_data *me_internal_data;
	struct mc_addr_list_entry *list_entry;
	struct mc_addr_list_entry *next_list_entry;
	bool entry_overridden;
	bool entry_found;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)entry);

	me_internal_data = (struct internal_data *)me->internal_data;

	/* swap entry */
#if defined(OMCI_SWAP)
	entry->gem_port_id = ntoh16(entry->gem_port_id);
	entry->secondary_index = ntoh16(entry->secondary_index);
	entry->ip_mc_address_range_start =
		ntoh32(entry->ip_mc_address_range_start);
	entry->ip_mc_address_range_stop =
		ntoh32(entry->ip_mc_address_range_stop);
#endif

	if (entry->ip_mc_address_range_start == 0
	    && entry->ip_mc_address_range_stop == 0) {
		/* delete entry */
		me_dbg_msg(me, "Entry delete");

		ret = omci_api_multicast_gem_interworking_tp_multicast_address_table_entry_remove
			(context->api,
			 me->instance_id, entry->gem_port_id,
			 entry->secondary_index);

		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't delete table entry",
				   ret);

			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}

		entry_found = false;
		DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
				    &me_internal_data->list_head) {
			if (list_entry->table_entry.gem_port_id ==
			    entry->gem_port_id
			    && list_entry->table_entry.secondary_index ==
			    entry->secondary_index) {
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
	} else {
		/* set entry */
		me_dbg_msg(me, "Entry set");

		ret = omci_api_multicast_gem_interworking_tp_multicast_address_table_entry_add(
			context->api,
			me->instance_id, entry->gem_port_id,
			entry->secondary_index,
			entry->ip_mc_address_range_start,
			entry->ip_mc_address_range_stop);

		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't set table entry",
				   ret);

			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}

		entry_overridden = false;
		DLIST_FOR_EACH(list_entry,
			       &me_internal_data->list_head) {
			if (list_entry->table_entry.gem_port_id ==
			    entry->gem_port_id
			    && list_entry->table_entry.secondary_index ==
			    entry->secondary_index) {
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
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	struct omci_me_multicast_gem_interworking_tp *upd_data;
	struct omci_me_multicast_gem_interworking_tp *me_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_multicast_gem_interworking_tp *)data;
	me_data = (struct omci_me_multicast_gem_interworking_tp *)me->data;

	if (attr_mask &
	    omci_attr2mask
	    (omci_me_multicast_gem_interworking_tp_mc_address_table)) {
		error = mc_addr_table_entry_set(context, me,
						&upd_data->mc_address_table);

		RETURN_IF_ERROR(error);
	} else {
		ret = omci_api_multicast_gem_interworking_tp_update(
			context->api,
			me->instance_id,
			upd_data->gem_port_network_ctp_ptr);

		if (ret != OMCI_API_SUCCESS) {
			me_dbg_err(me, "DRV ERR(%d) Can't update "
				   "Managed Entity", ret);

			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
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
	struct internal_data *me_internal_data;
	struct mc_addr_list_entry *list_entry;
	struct omci_me_mc_address_table *tbl_entry;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	me_internal_data = (struct internal_data *)me->internal_data;

	switch (attr) {
	case omci_me_multicast_gem_interworking_tp_mc_address_table:
		tbl_copy->data_size =
			sizeof(struct omci_me_mc_address_table)
			* me_internal_data->entries_num;

		if (!tbl_copy->data_size)
			break;

		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);

		tbl_entry = (struct omci_me_mc_address_table *)
			tbl_copy->data;
		DLIST_FOR_EACH(list_entry, &me_internal_data->list_head) {
			tbl_entry->gem_port_id =
				hton16(list_entry->table_entry.gem_port_id);

			tbl_entry->secondary_index =
				hton16(list_entry->table_entry.secondary_index);

			tbl_entry->ip_mc_address_range_start =
				hton32(list_entry->table_entry.
				       ip_mc_address_range_start);

			tbl_entry->ip_mc_address_range_stop =
				hton32(list_entry->table_entry.
				       ip_mc_address_range_stop);

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
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	/* the value 0xffff is reserved */
	if (me->instance_id == 0xffff) {
		dbg_out_ret(__func__, OMCI_ERROR_INVALID_ME_ID);
		return OMCI_ERROR_INVALID_ME_ID;
	}

	me->internal_data = IFXOS_MemAlloc(sizeof(*me_internal_data));
	RETURN_IF_MALLOC_ERROR(me->internal_data);

	me_internal_data = (struct internal_data *)me->internal_data;

	DLIST_HEAD_INIT(&me_internal_data->list_head);
	me_internal_data->entries_num = 0;

	error = me_update(context, me, init_data, suppress_avc);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, error);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;
	struct mc_addr_list_entry *list_entry;
	struct mc_addr_list_entry *next_list_entry;
	struct internal_data *me_internal_data;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	me_internal_data = (struct internal_data *)me->internal_data;

	/* clear multicast address table */
	DLIST_FOR_EACH_SAFE(list_entry, next_list_entry,
			    &me_internal_data->list_head) {
		/* remove entry */
		DLIST_REMOVE(list_entry);

		--me_internal_data->entries_num;

		ret = omci_api_multicast_gem_interworking_tp_multicast_address_table_entry_remove(
			context->api,
			me->instance_id,
			list_entry->table_entry.gem_port_id,
			list_entry->table_entry.secondary_index);

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

	ret = omci_api_multicast_gem_interworking_tp_destroy(context->api,
							     me->instance_id);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get operational state

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error op_state_get(struct omci_context *context,
					 struct me *me,
					 void *data,
					 size_t data_size)
{
	enum omci_api_return ret;
	enum omci_error error;
	struct me *gem_port_nw_ctp_me;
	uint16_t gem_port_id;
	struct omci_me_multicast_gem_interworking_tp *me_data;
	assert(data_size == 1);

	me_data = (struct omci_me_multicast_gem_interworking_tp *)me->data;

	error = mib_me_find(context, OMCI_ME_GEM_PORT_NETWORK_CTP,
			    me_data->gem_port_network_ctp_ptr,
			    &gem_port_nw_ctp_me);
	RETURN_IF_ERROR(error);

	me_lock(context, gem_port_nw_ctp_me);
	error = me_attr_read(context, gem_port_nw_ctp_me,
			     omci_me_gem_port_network_ctp_gem_port_id,
			     &gem_port_id, sizeof(gem_port_id));
	me_unlock(context, gem_port_nw_ctp_me);
	RETURN_IF_ERROR(error);

	ret =  omci_api_gem_interworking_tp_op_state_get(context->api,
							 me->instance_id,
							 gem_port_id,
							 data);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;

	return OMCI_SUCCESS;
}

static uint16_t interworking_option_cp[] = { 0, 1, 3, 5 };

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
static uint8_t alarm_table[] = { 0 };
#endif

/** Managed Entity class */
struct me_class me_multicast_get_interworking_tp_class = {
	/* Class ID */
	OMCI_ME_MULTICAST_GEM_INTERWORKING_TP,
	/* Attributes */
	{
		/* 1. GEM Port Network CTP Connectivity Pointer */
		ATTR_PTR("GEM port network CTP ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_multicast_gem_interworking_tp,
				  gem_port_network_ctp_ptr),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 2. Interworking Option */
		ATTR_ENUM("Interworking option",
			  ATTR_SUPPORTED,
			  interworking_option_cp,
			  offsetof(struct omci_me_multicast_gem_interworking_tp,
				   interworking_option),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 3. Service Profile Pointer */
		ATTR_PTR("Service profile ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0x0000,
			 offsetof(struct omci_me_multicast_gem_interworking_tp,
				  service_profile_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 4. Interworking Termination Point Pointer */
		ATTR_PTR("Interworking TP ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0x0000,
			 offsetof(struct omci_me_multicast_gem_interworking_tp,
				  interworking_tp_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 5. PPTP Count */
		ATTR_UINT("PPTP counter",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_multicast_gem_interworking_tp,
				   pppt_count),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 6. Operational State */
		ATTR_BOOL("Operational state",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_multicast_gem_interworking_tp,
				   oper_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  op_state_get),
		/* 7. GAL Profile Pointer */
		ATTR_UINT("GAL profile ptr",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,	/* for backward compatibility */
			  offsetof(struct omci_me_multicast_gem_interworking_tp,
				   gal_profile_ptr),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 8. GAL Loopback Configuration */
		ATTR_UINT("GAL loopback config",
			  ATTR_SUPPORTED,
			  0,
			  0,
			  offsetof(struct omci_me_multicast_gem_interworking_tp,
				   gal_loopback_config),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 9. Multicast Address Table */
		ATTR_TBL("Multicast address table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_multicast_gem_interworking_tp,
				  mc_address_table),
			 12,	/* size of one table entry */
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 10-16. Doesn't exist */
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
	sizeof(struct omci_me_multicast_gem_interworking_tp),
	/* Properties */
	OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Multicast GEM TP",
		/* Access */
		ME_CREATED_BY_OLT,
		/* Supported alarms */
		alarm_table,
		/* Supported alarms count */
		sizeof(alarm_table) / sizeof(alarm_table[0]),
		/* Support */
		ME_SUPPORTED
	},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */
