

/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_onu_dyn_pwr_mngmt_ctrl.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_onu_dyn_pwr_mngmt_ctrl.h"
#include "me/omci_api_onu_dyn_pwr_mngmt_ctrl.h"

/** \addtogroup OMCI_ME_ONU_DYN_PWR_MNGMT_CTRL
   @{
*/

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	struct omci_me_onu_dyn_pwr_mngmt_ctrl *upd_data;
	struct omci_me_onu_dyn_pwr_mngmt_ctrl *me_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	upd_data = (struct omci_me_onu_dyn_pwr_mngmt_ctrl *) data;
	me_data = (struct omci_me_onu_dyn_pwr_mngmt_ctrl *) me->data;

	ret = omci_api_onu_dyn_pwr_mngmt_ctrl_update(context->api,
				    me->instance_id,
				    upd_data->pwr_reduction_mngmt_mode,
				    upd_data->max_sleep_interval,
				    upd_data->min_aware_interval,
				    upd_data->min_active_held_interval);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't update Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_onu_dyn_pwr_mngmt_ctrl_class = {
	/* Class ID */
	OMCI_ME_ONU_DYN_PWR_MNGMT_CTRL,
	/* Attributes */
	{
		/* 1. Power reduction management capability */
		ATTR_BF("Pwr reduction mngmt cap",
			 ATTR_SUPPORTED,
			 0x0003,
			 offsetof(struct omci_me_onu_dyn_pwr_mngmt_ctrl,
				  pwr_reduction_mngmt_cap),
			 1,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 2. Power reduction management mode */
		ATTR_BF("Pwr reduction mngmt mode",
			 ATTR_SUPPORTED,
			 0x0003,
			 offsetof(struct omci_me_onu_dyn_pwr_mngmt_ctrl,
				  pwr_reduction_mngmt_mode),
			 1,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 3. Itransinit */
		ATTR_UINT("Itransinit",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu_dyn_pwr_mngmt_ctrl,
				   itransinit),
			  2,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 4. Itxinit */
		ATTR_UINT("Itxinit",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu_dyn_pwr_mngmt_ctrl,
				   itxinit),
			  2,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 5. Maximum sleep interval */
		ATTR_UINT("Max sleep interval",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_onu_dyn_pwr_mngmt_ctrl,
				   max_sleep_interval),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 6. Minimum aware interval */
		ATTR_UINT("Min aware interval",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_onu_dyn_pwr_mngmt_ctrl,
				   min_aware_interval),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 7. Minimum active held interval */
		ATTR_UINT("Min active held interval",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu_dyn_pwr_mngmt_ctrl,
				   min_active_held_interval),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
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
	default_me_shutdown,
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
	sizeof(struct omci_me_onu_dyn_pwr_mngmt_ctrl),
	/* Properties */
	OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"ONU dyn pwr mngmt ctrl",
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
