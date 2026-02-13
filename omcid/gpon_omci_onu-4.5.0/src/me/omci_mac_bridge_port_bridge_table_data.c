/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_mac_bridge_port_bridge_table_data.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_mac_bridge_port_bridge_table_data.h"
#include "me/omci_api_mac_bridge_port_bridge_table_data.h"
#include "me/omci_mac_bridge_port_config_data.h"

/** \addtogroup OMCI_ME_MAC_BRIDGE_PORT_BRIDGE_TABLE_DATA
   @{
*/

static enum omci_error me_tbl_copy(struct omci_context *context,
				   struct me *me,
				   unsigned int attr,
				   struct tbl_copy_entry *tbl_copy)
{
	enum omci_api_return ret;
	unsigned int i;
	unsigned int bridge_table_entries_num;
	uint16_t bridge_me_id;
	struct me *bridge_port_me;

	struct omci_api_mac_bridge_port_bridge_table_data_bridge_table_entry
		*bridge_table = NULL;
	struct omci_bridge_table *bridge_table_entry;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	ret = mib_me_find(context, OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
			  me->instance_id,
			  &bridge_port_me);

	if (bridge_port_me == NULL) {
		dbg_out_ret(__func__, ret);
		return ret;
	}

	me_lock(context, bridge_port_me);
	ret = me_attr_read(context, bridge_port_me,
			     omci_me_mac_bridge_port_config_data_bridge_id_ptr,
			     &bridge_me_id,
			     sizeof(bridge_me_id));
	me_unlock(context, bridge_port_me);
	RETURN_IF_ERROR(ret);

	switch (attr) {
	case omci_me_mac_bridge_port_bridge_table_data_bridge_table:
		ret = omci_api_mac_bridge_port_bridge_table_data_bridge_table_get(
			context->api,
			me->instance_id,
			bridge_me_id,
			&bridge_table_entries_num,
			&bridge_table);

		if (ret) {
			me_dbg_err(me, "DRV ERR(%d) Can't get "
				   "Lost groups list table", ret);

			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}

		tbl_copy->data_size = sizeof(struct omci_bridge_table)
			* bridge_table_entries_num;

		if (!tbl_copy->data_size) {
			omci_api_mac_bridge_port_bridge_table_data_bridge_table_free(
				context->api,
				me->instance_id,
				bridge_me_id,
				&bridge_table_entries_num,
				&bridge_table);
			error = OMCI_SUCCESS;
			break;
		}

		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		if (!tbl_copy->data) {
			omci_api_mac_bridge_port_bridge_table_data_bridge_table_free(
				context->api,
				me->instance_id,
				bridge_me_id,
				&bridge_table_entries_num,
				&bridge_table);

			RETURN_IF_MALLOC_ERROR(tbl_copy->data);
		}

		bridge_table_entry =
			(struct omci_bridge_table *)tbl_copy->data;

		for (i = 0; i < bridge_table_entries_num; i++) {
			bridge_table_entry[i].info =
			    hton16(bridge_table[i].information.info_byte);

			memcpy(bridge_table_entry[i].mac_address,
			       bridge_table[i].p_mac_adress,
			       sizeof(bridge_table_entry[i].mac_address));
		}

		omci_api_mac_bridge_port_bridge_table_data_bridge_table_free(
			context->api,
			me->instance_id,
			bridge_me_id,
			&bridge_table_entries_num,
			&bridge_table);
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
	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
		(void *)init_data, suppress_avc);

	/** \todo init table */

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	ret = omci_api_mac_bridge_port_bridge_table_data_destroy(context->api,
								 me->instance_id);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_mac_bridge_port_bridge_table_data_class = {
	/* Class ID */
	OMCI_ME_MAC_BRIDGE_PORT_BRIDGE_TABLE_DATA,
	/* Attributes */
	{
		/* 1. Bridge Table */
		ATTR_TBL("Bridge table",
			 ATTR_SUPPORTED,
			 offsetof(struct
				  omci_me_mac_bridge_port_bridge_table_data,
				  bridge_table),
			 8,	/* size of one table entry */
			 OMCI_ATTR_PROP_RD,
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
	NULL,
	/* Update Handler */
	default_me_update,
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
	sizeof(struct omci_me_mac_bridge_port_bridge_table_data),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Bridge port table data",
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
