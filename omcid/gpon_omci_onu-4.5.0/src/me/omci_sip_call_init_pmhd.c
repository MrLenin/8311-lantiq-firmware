/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_sip_call_init_pmhd.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_sip_call_init_pmhd.h"

#ifdef INCLUDE_PM

/** \addtogroup OMCI_SIP_CALL_INIT_PMHD
   @{
*/

static enum omci_error me_counters_get(struct omci_context *context,
				       struct me *me,
				       enum omci_pm_interval interval)
{
	/* No telephony hardware — counters stay at zero */
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;

	/* check if related SIP Agent config data exists */
	error = mib_me_find(context, OMCI_ME_SIP_AGENT_CONFIG_DATA,
			    me->instance_id, NULL);
	RETURN_IF_ERROR(error);

	error = default_me_init(context, me, init_data, suppress_avc);
	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}

static struct me_tca tca_table[] = {
	/* 1 Failed to connect counter #1 */
	TCA(1, omci_me_sip_call_init_pmhd_failed_to_connect, 1),
	/* 2 Faile to validate counter #2 */
	TCA(2, omci_me_sip_call_init_pmhd_failed_to_validate, 2),
	/* 3 Timeout counter  #3 */
	TCA(3, omci_me_sip_call_init_pmhd_timeout, 3),
	/* 4 Failure received counter #4 */
	TCA(4, omci_me_sip_call_init_pmhd_failure_received, 4),
	/* 5 Failed to authenticate counter #5 */
	TCA(5, omci_me_sip_call_init_pmhd_failed_to_auth, 5),

	TCA(0, 0, 0)
};

/** Managed Entity class */
struct me_class me_sip_call_init_pmhd_class = {
	/* Class ID */
	OMCI_ME_SIP_CALL_INITIATION_PMHD,
	/* Attributes */
	{
		ATTR_UINT("Interval end time",
			ATTR_SUPPORTED,
			0x00,
			0xff,
			offsetof(struct omci_me_sip_call_init_pmhd,
				 interval_end_time),
			1,
			OMCI_ATTR_PROP_RD,
			pm_interval_end_time_get),
		ATTR_UINT("Threshold data",
			ATTR_SUPPORTED,
			0x0000,
			0xffff,
			offsetof(struct omci_me_sip_call_init_pmhd,
				 threshold_data),
			2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			OMCI_ATTR_PROP_SBC,
			NULL),
		ATTR_UINT("Failed to connect",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_call_init_pmhd,
				 failed_to_connect),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Failed to validate",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_call_init_pmhd,
				 failed_to_validate),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Timeout",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_call_init_pmhd,
				 timeout),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Failure received",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_call_init_pmhd,
				 failure_received),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Failed to auth",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_call_init_pmhd,
				 failed_to_auth),
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
	sizeof(struct omci_me_sip_call_init_pmhd),
	/* Properties */
	OMCI_ME_PROP_PM | OMCI_ME_PROP_PM_INTERNAL,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"SIP call init PMHD",
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

#endif /* INCLUDE_PM */
