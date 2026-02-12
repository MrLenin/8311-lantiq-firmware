/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_traffic_scheduler.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_traffic_scheduler.h"
#include "me/omci_api_traffic_scheduler.h"

/** \addtogroup OMCI_ME_TRAFFIC_SCHEDULER
    @{
*/

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask,
				   const void *data)
{
	struct omci_me_traffic_scheduler *upd_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me_class,
	       (void *)exec_mask, (void *)data);

	upd_data = (struct omci_me_traffic_scheduler *) data;

	error = default_me_validate(context, me_class, exec_mask, data);
	RETURN_IF_ERROR(error);

	if (!omci_is_ptr_null(upd_data->tcont_ptr)) {
		error = mib_me_find(context, OMCI_ME_TCONT,
				    upd_data->tcont_ptr, NULL);

		if (error) {
			*exec_mask |=
				omci_attr2mask(omci_me_traffic_scheduler_tcont_pointer);
		}
	}

	if (!omci_is_ptr_null(upd_data->traffic_scheduler_ptr)) {
		error = mib_me_find(context, OMCI_ME_TRAFFIC_SCHEDULER,
				    upd_data->traffic_scheduler_ptr, NULL);

		if (error) {
			*exec_mask |=
				omci_attr2mask(omci_me_traffic_scheduler_traffic_scheduler_ptr);
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
	struct omci_me_traffic_scheduler *upd_data;
	struct omci_me_traffic_scheduler *me_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	upd_data = (struct omci_me_traffic_scheduler *) data;
	me_data = (struct omci_me_traffic_scheduler *) me->data;

	if (!me->is_initialized)
		ret = omci_api_traffic_scheduler_create(context->api,
							me->instance_id,
							upd_data->tcont_ptr,
							upd_data->
							traffic_scheduler_ptr,
							upd_data->policy,
							upd_data->
							priority_weight);
	else
		ret = omci_api_traffic_scheduler_update(context->api,
							me->instance_id,
							upd_data->tcont_ptr,
							upd_data->
							traffic_scheduler_ptr,
							upd_data->policy,
							upd_data->
							priority_weight);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't update Managed Entitiy", ret);

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

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	ret = omci_api_traffic_scheduler_destroy(context->api,
						 me->instance_id);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static uint16_t policy_cp[] = { 0, 1, 2 };

/** Managed Entity class */
struct me_class me_traffic_scheduler_class = {
	/* Class ID */
	OMCI_ME_TRAFFIC_SCHEDULER,
	/* Attributes */
	{
		/* 1. T-CONT Pointer */
		ATTR_PTR("T-CONT ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_traffic_scheduler,
				  tcont_ptr),
			 2,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 2. Traffic Scheduler Pointer */
		ATTR_PTR("Traffic scheduler ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_traffic_scheduler,
				  traffic_scheduler_ptr),
			 2,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 3. Traffic Scheduler Policy */
		ATTR_ENUM("Policy",
			  ATTR_SUPPORTED,
			  policy_cp,
			  offsetof(struct omci_me_traffic_scheduler,
				   policy),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 4. Priority or Weight */
		ATTR_UINT("Priority/weight",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_traffic_scheduler,
				   priority_weight),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 5-16. Doesn't exist */
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
		NULL,
		/* Test result */
		NULL,
		/* Get current data */
		NULL
	},
	/* Init Handler */
	default_me_init,
	/* Shutdown Handler */
	me_shutdown,
	/* Validate Handler */
	me_validate,
	/* Update Handler */
	me_update,
	/* Table Attribute Copy Handler */
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
	sizeof(struct omci_me_traffic_scheduler),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Traffic scheduler",
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
