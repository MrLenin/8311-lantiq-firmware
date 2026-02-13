/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_multicast_subscriber_monitor.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_mac_bridge_port_config_data.h"
#include "me/omci_multicast_subscriber_monitor.h"
#include "me/omci_api_multicast_subscr_monitor.h"
#include "mcc/omci_mcc.h"

/** \addtogroup OMCI_ME_MULTICAST_SUBSCRIBER_MONITOR
   @{
*/

/** Structure that implements AGL table */
struct agl_list_entry {
	/** Table entry */
	struct omci_agl_table table_entry;

	/** Next entry */
	struct agl_list_entry *next;

	/** Previous entry */
	struct agl_list_entry *prev;
};

/** Internal data */
struct internal_data {
	/** AGL table (list head) */
	struct agl_list_entry agl_list_head;

	/** Number of entries in AGL table */
	size_t agl_entries_num;
};

static enum omci_error current_mc_bw_get(struct omci_context *context,
					 struct me *me,
					 void *data,
					 size_t data_size)
{
	assert(data_size == 4);
	return mcc_port_monitor_data_get(context, me->instance_id,
					 MCC_MONITOR_TYPE_CURRENT_MC_BANDWIDTH,
					 (uint32_t *)data);
}

static enum omci_error join_msg_cnt_get(struct omci_context *context,
					struct me *me,
					void *data,
					size_t data_size)
{
	assert(data_size == 4);
	return mcc_port_monitor_data_get(context, me->instance_id,
					 MCC_MONITOR_TYPE_JOIN_MSG_COUNTER,
					 (uint32_t *)data);
}

static enum omci_error bw_exc_cnt_get(struct omci_context *context,
				      struct me *me,
				      void *data,
				      size_t data_size)
{
	assert(data_size == 4);
	return mcc_port_monitor_data_get(context, me->instance_id,
					 MCC_MONITOR_TYPE_BW_EXCESS_COUNTER,
					 (uint32_t *)data);
}

static enum omci_error me_tbl_copy(struct omci_context *context,
				   struct me *me,
				   unsigned int attr,
				   struct tbl_copy_entry *tbl_copy)
{
	struct omci_ipv4_agl_table *agl = NULL;
	uint32_t agl_num = 0;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	if (attr == omci_me_multicast_subscriber_monitor_agl_table) {
		error = mcc_port_monitor_ipv4_agl_get(context,
						      me->instance_id,
						      &agl, &agl_num);
		if (error != OMCI_SUCCESS) {
			me_dbg_err(me, "MCC ERR(%d) Can't get "
				   "Active group list table", error);
			dbg_out_ret(__func__, error);
			return error;
		}

		/* omci_ipv4_agl_table and omci_agl_table have identical
		 * packed layout (24 bytes each) — use buffer directly */
		tbl_copy->data_size =
			sizeof(struct omci_agl_table) * agl_num;
		tbl_copy->data = agl;
	} else {
		error = OMCI_ERROR_INVALID_ME_ATTR;
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
	struct omci_me_multicast_subscriber_monitor *upd_data = init_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	switch (upd_data->me_type) {
	case 0x00:
		error = mib_me_find(context,
				    OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
				    me->instance_id,
				    NULL);
		break;
#if 0
	/* Not supported yet */
	case 0x01:
		error = mib_me_find(context,
				    OMCI_ME_DOT1P_MAPPER_SERVICE_PROFILE,
				    me->instance_id,
				    NULL);
		break;
#endif
	default:
		error = OMCI_ERROR;
		break;
	}

	RETURN_IF_ERROR(error);

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

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	me_internal_data = (struct internal_data *)me->internal_data;

	IFXOS_MemFree(me->internal_data);

	ret = omci_api_multicast_subscriber_monitor_destroy(context->api,
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

static uint16_t me_type_cp[] = {
	0,
	1
};

/** Managed Entity class */
struct me_class me_multicast_subscriber_monitor_class = {
	/* Class ID */
	OMCI_ME_MULTICAST_SUBSCRIBER_MONITOR,
	/* Attributes */
	{
		/* 1. ME type */
		ATTR_ENUM("ME type",
			  ATTR_SUPPORTED,
			  me_type_cp,
			  offsetof(struct omci_me_multicast_subscriber_monitor,
				   me_type),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR
			  | OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_PARTLY,
			  NULL),
		/* 2. Current multicast bandwidth */
		ATTR_UINT("Current MC bandwidth",
			 ATTR_SUPPORTED,
			 0x00000000,
			 0xffffffff,
			 offsetof(struct omci_me_multicast_subscriber_monitor,
				  current_mc_bw),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			 current_mc_bw_get),
		/* 3. Join messages counter */
		ATTR_UINT("Join msg counter",
			 ATTR_SUPPORTED,
			 0x00000000,
			 0xffffffff,
			 offsetof(struct omci_me_multicast_subscriber_monitor,
				  join_msg_cnt),
			 4,
			 OMCI_ATTR_PROP_RD |OMCI_ATTR_PROP_OPTIONAL,
			 join_msg_cnt_get),
		/* 4. Bandwidth exceeded counter */
		ATTR_UINT("Bandwidth exc counter",
			 ATTR_SUPPORTED,
			 0x00000000,
			 0xffffffff,
			 offsetof(struct omci_me_multicast_subscriber_monitor,
				  bw_exc_cnt),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			 bw_exc_cnt_get),
		/* 5. Active group list table */
		ATTR_TBL("Active group list table",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_multicast_subscriber_monitor,
				   agl_table),
			  24,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 6-16. Doesn't exist */
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
	sizeof(struct omci_me_multicast_subscriber_monitor),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Multicast subscriber mon",
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
