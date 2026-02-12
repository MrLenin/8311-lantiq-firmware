/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_onu_g.c
*/
#include "ifxos_time.h"
#include "ifxos_misc.h"
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_onu_g.h"
#include "me/omci_api_onu_g.h"


/** \addtogroup OMCI_ME_ONU_G
   @{
*/

/** Image store thread priority */
#define ONU_G_TEST_THREAD_PRIO             IFXOS_THREAD_PRIO_LOWEST
/** Image store thread stack size */
#define ONU_G_TEST_THREAD_STACKSIZE        IFXOS_DEFAULT_STACK_SIZE

/** Non-ITU data of the ONU-G Managed Entity */
struct internal_data {
	/** Self test thread control */
	IFXOS_ThreadCtrl_t self_test_thr_ctrl;
};

/** Self test thread

   \param[in] thr_params IFXOS_ThreadParams_t structure
*/
static int32_t self_test_thread(struct IFXOS_ThreadParams_s *thr_params)
{
	struct omci_context *context;
	union omci_msg msg;

#ifdef LINUX
	dbg_msg("SelftestThread (tid %d)", (int)getpid());
#endif

	context = (struct omci_context *)thr_params->nArg1;

	/* we are "executing" test :) */
	IFXOS_SecSleep(1);

	memset(&msg, 0, sizeof(msg));

	msg.onu_g.header.tci = (uint16_t)thr_params->nArg2;
	msg.onu_g.header.type = 0;
	omci_msg_type_mt_set(&msg, OMCI_MT_TEST_RESULT);
	msg.onu_g.header.dev_id = OMCI_FORMAT_BASELINE;
	msg.onu_g.header.class_id = hton16(OMCI_ME_ONU_G);
	msg.onu_g.header.instance_id = hton16(0);

	msg.onu_g.result = 2;	/* not completed */

	return (int32_t)omci_msg_send(context, &msg);
}

static enum omci_error test_action_handle(struct omci_context *context,
					  struct me *me,
					  const union omci_msg *msg,
					  union omci_msg *rsp)
{
	struct internal_data *me_internal_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	me_internal_data = (struct internal_data *) me->internal_data;

	if (msg->test_onu_g.test == 0x07) {
		if (IFXOS_THREAD_INIT_VALID
		    (&me_internal_data->self_test_thr_ctrl))
			(void)IFXOS_ThreadDelete(&me_internal_data->
						 self_test_thr_ctrl, 0);

		error = (enum omci_error)
			IFXOS_ThreadInit(&me_internal_data->self_test_thr_ctrl,
					 "tstontg", self_test_thread,
					 ONU_G_TEST_THREAD_STACKSIZE,
					 ONU_G_TEST_THREAD_PRIO,
					 (unsigned long)context,
					 (unsigned long)msg->msg.header.tci);

		RETURN_IF_ERROR(error);
	} else {
		/* unsupported test */
		rsp->test_rsp.result = OMCI_MR_PARAM_ERROR;

		dbg_out_ret(__func__, OMCI_ERROR);
		return OMCI_ERROR;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

#ifdef INCLUDE_PM
static enum omci_error sync_time_walker(struct omci_context *context,
					struct me *me,
					void *shared_data)
{
	enum omci_error error;

	(void)shared_data;
	(void)context;

	if ((me->class->prop & OMCI_ME_PROP_PM) == 0)
		return OMCI_SUCCESS;

	if (!me->alarm_bitmap)
		return OMCI_SUCCESS;

	error = alarm_bitmap_clear(me->alarm_bitmap);
	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}
#endif

static enum omci_error sync_time_action_handle(struct omci_context *context,
					       struct me *me,
					       const union omci_msg *msg,
					       union omci_msg *rsp)
{
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

#ifdef INCLUDE_PM
	context_lock(context);
	context->pm.interval_end_time = 0;
	context_unlock(context);

	error = mib_walk(context, sync_time_walker, NULL);
	if (error != OMCI_SUCCESS) {

		dbg_err("ERROR(%d) while cleaning TCA data", error);
	}
#endif

	rsp->sync_time_rsp.result = OMCI_MR_CMD_SUCCESS;

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error serial_number_get(struct omci_context *context,
					  struct me *me,
					  void *data,
					  size_t data_size)
{
	enum omci_api_return ret;

	assert(data_size == 8);

	ret = omci_api_onu_g_serial_number_get(context->api,
					       me->instance_id,
					       (uint8_t *)data);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;

	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	struct omci_me_onu_g *upd_data;
	struct omci_me_onu_g *me_data;
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_onu_g *) data;
	me_data = (struct omci_me_onu_g *) me->data;

#if 0
	/* if the default battery backup value is false don't allow OLT to
	   change it */
	if (me->is_initialized && me_data->battery_backup == false) {
		if (upd_data->battery_backup == true) {
			dbg_out_ret(__func__, OMCI_ERROR);
			return OMCI_ERROR;
		}
	}
#endif

	ret = omci_api_onu_g_update(context->api, me->instance_id,
				    me_data->battery_backup,
				    me_data->traffic_management);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;

	context->traffic_management_opt = me_data->traffic_management;

	/** \todo check if OLT name/version is known and update context->olt */

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	RETURN_IF_PTR_NULL(init_data);

	me->internal_data = IFXOS_MemAlloc(sizeof(struct internal_data));
	RETURN_IF_MALLOC_ERROR(me->internal_data);

	error = me_data_write(context, me, init_data,
			      me->class->data_size,
			      ~me->class->inv_attr_mask, suppress_avc);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	IFXOS_MemFree(me->internal_data);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static uint16_t traffic_management_cp[] = {
	0,
	1
#ifdef INCLUDE_G984_4_AMENDMENT_2
	    ,
	2
#endif
};

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
static uint8_t alarm_table[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
#endif

/** Managed Entity class */
struct me_class me_onu_g_class = {
	/* Class ID */
	OMCI_ME_ONU_G,
	/* Attributes */
	{
		/* 1. Vendor Id */
		ATTR_STR("Vendor id",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_onu_g,
				  vendor_id),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC,
			 NULL),
		/* 2. Version */
		ATTR_STR("Version",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_onu_g,
				  version),
			 14,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC,
			 NULL),
		/* 3. Serial number */
		ATTR_STR("Serial number",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_onu_g,
				  serial_num),
			 8,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC,
			 serial_number_get),
		/* 4. Traffic management option */
		ATTR_ENUM("Traffic management opt",
			  ATTR_SUPPORTED,
			  traffic_management_cp,
			  offsetof(struct omci_me_onu_g,
				   traffic_management),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 5. VP/VC cross-connection function option */
		ATTR_UINT("VP/VC cc function option",
			  ATTR_SUPPORTED,
			  0,
			  0,
			  offsetof(struct omci_me_onu_g,
				   vp_vc),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 6. Battery backup */
		ATTR_BOOL("Battery backup",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_onu_g,
				   battery_backup),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 7. Administrative state */
		ATTR_BOOL("Administrative state",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_onu_g,
				   admin_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 8. Operational state */
		ATTR_BOOL("Operational state",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_onu_g,
				   oper_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
#ifdef INCLUDE_G984_4_AMENDMENT_2
		/* 9. ONU survival time */
		ATTR_UINT("ONU survival time",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_onu_g,
				   survival_time),
			  1,
			  OMCI_ATTR_PROP_RD |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
#else
		/* 11-16. Doesn't exist */
		ATTR_NOT_DEF(),
#endif
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
		test_action_handle,
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
		sync_time_action_handle,
		/* Reboot */
		reboot_acion_handle,
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
	sizeof(struct omci_me_onu_g),
	/* Properties */
	OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"ONU-G",
		/* Access */
		ME_CREATED_BY_ONT,
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
