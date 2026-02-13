/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_call_control_pmhd.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_call_control_pmhd.h"
#include "me/omci_api_call_control_pmhd.h"

#if defined(INCLUDE_PM) && defined(INCLUDE_OMCI_ONU_VOIP)

/** \addtogroup OMCI_CALL_CONTROL_PMHD
   @{
*/

static enum omci_error me_counters_get(struct omci_context *context,
				       struct me *me,
				       enum omci_pm_interval interval)
{
	struct omci_me_call_control_pmhd *me_data;
	uint32_t call_setup_failures, call_setup_timer, call_terminate_failures,
		 analog_port_releases, analog_port_offhook_timer;
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p, %lu", (void *)context, (void *)me, interval);

	me_data = (struct omci_me_call_control_pmhd *)me->data;

	ret = omci_api_call_control_pmhd_cnt_get(context->api,
						 me->instance_id,
						 &call_setup_failures,
						 &call_setup_timer,
						 &call_terminate_failures,
						 &analog_port_releases,
						 &analog_port_offhook_timer);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't get counters", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	me_data->call_setup_failures = call_setup_failures;
	me_data->call_setup_timer = call_setup_timer;
	me_data->call_terminate_failures = call_terminate_failures;
	me_data->analog_port_releases = analog_port_releases;
	me_data->analog_port_offhook_timer = analog_port_offhook_timer;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;

	/* check if related PPTP POTS UNI exists */
	error = mib_me_find(context, OMCI_ME_PPTP_POTS_UNI,
			    me->instance_id, NULL);
	RETURN_IF_ERROR(error);

	error = default_me_init(context, me, init_data, suppress_avc);
	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}

static struct me_tca tca_table[] = {
	/* 1 Call setup failures counter #1 */
	TCA(1, omci_me_call_control_pmhd_call_setup_failures, 1),
	/* 2 Call setup timer counter #2 */
	TCA(2, omci_me_call_control_pmhd_call_setup_timer, 2),
	/* 3 Call terminate failures counter  #3 */
	TCA(3, omci_me_call_control_pmhd_call_terminate_failures, 3),
	/* 4 Analog port releases counter #4 */
	TCA(4, omci_me_call_control_pmhd_analog_port_releases, 4),
	/* 5 Analog port off-hook timer counter #5 */
	TCA(5, omci_me_call_control_pmhd_analog_port_offhook_timer, 5),

	TCA(0, 0, 0)
};

/** Managed Entity class */
struct me_class me_call_control_pmhd_class = {
	/* Class ID */
	OMCI_ME_CALL_CONTROL_PMHD,
	/* Attributes */
	{
		ATTR_UINT("Interval end time",
			ATTR_SUPPORTED,
			0x00,
			0xff,
			offsetof(struct omci_me_call_control_pmhd,
				 interval_end_time),
			1,
			OMCI_ATTR_PROP_RD,
			pm_interval_end_time_get),
		ATTR_UINT("Threshold data",
			ATTR_SUPPORTED,
			0x0000,
			0xffff,
			offsetof(struct omci_me_call_control_pmhd,
				 threshold_data),
			2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			OMCI_ATTR_PROP_SBC,
			NULL),
		ATTR_UINT("Call setup failures",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_call_control_pmhd,
				 call_setup_failures),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Call setup timer",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_call_control_pmhd,
				 call_setup_timer),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Call term failures",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_call_control_pmhd,
				 call_terminate_failures),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Anlg port releases",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_call_control_pmhd,
				 analog_port_releases),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Anlg port off-h timer",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_call_control_pmhd,
				 analog_port_offhook_timer),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
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
		get_current_data_action_handle
	},
	/* Init Handler */
	me_init,
	/* Shutdown Handler */
	NULL,
	/* Validate Handler */
	default_me_validate,
	/* Update Handler */
	default_me_update,
	/* Table Attribute Copy Handler */
	NULL,
	/* Table Attribute Operations Handler */
	NULL,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	me_counters_get,
	/* Thresholds set Handler */
	default_me_thr_set,
#endif
	/* TCA Table */
	tca_table,
	/* Data Size */
	sizeof(struct omci_me_call_control_pmhd),
	/* Properties */
	OMCI_ME_PROP_PM | OMCI_ME_PROP_PM_INTERNAL,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Call ctrl PMHD",
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

#endif

