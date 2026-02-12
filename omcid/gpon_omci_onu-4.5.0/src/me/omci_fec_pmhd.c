/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_fec_pmhd.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_fec_pmhd.h"
#include "me/omci_api_fec_pmhd.h"

#ifdef INCLUDE_PM

/** \addtogroup OMCI_ME_FEC_PMHD
    @{
*/

static enum omci_error me_counters_get(struct omci_context *context,
				       struct me *me,
				       enum omci_pm_interval interval)
{
	struct omci_me_fec_pmhd *me_data;
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p, %lu", (void *)context, (void *)me, interval);

	me_data = (struct omci_me_fec_pmhd *)me->data;

	ret = omci_api_fec_pmhd_cnt_get(context->api,
					me->instance_id,
					false,
					interval == OMCI_PM_INTERVAL_CURR,
					&me_data->corrected_byte_count,
					&me_data->corrected_word_count,
					&me_data->uncorrectable_word_count,
					&me_data->total_word_count,
					&me_data->fec_seconds);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't get counters", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_thr_set(struct omci_context *context,
				  struct me *me,
				  uint32_t thr[PM_THR_NUM])
{
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)thr);

	ret = omci_api_fec_pmhd_thr_set(context->api,
					me->instance_id, thr[0],
					thr[1], thr[2], thr[3], thr[4]);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't set thresholds", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

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

	/* check if related ANI-G exists */
	error = mib_me_find(context, OMCI_ME_ANI_G, me->instance_id, NULL);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	dbg_out_ret(__func__, error);
	return error;
}

static struct me_tca tca_table[] = {
	/* 0 Corrected bytes #1 */
	TCA(0, omci_me_fec_pmhd_corrected_byte_count, 1),
	/* 1 Corrected code words #2 */
	TCA(1, omci_me_fec_pmhd_corrected_word_count, 2),
	/* 2 Uncorrectible code words #3 */
	TCA(2, omci_me_fec_pmhd_uncorrectable_word_count, 3),
	/* 4 FEC seconds #4 */
	TCA(4, omci_me_fec_pmhd_fec_seconds, 4),

	TCA(0, 0, 0)
};

/** Managed Entity class */
struct me_class me_fec_pmhd_class = {
	/* Class ID */
	OMCI_ME_FEC_PMHD,
	/* Attributes */
	{
		/* 1. Interval End Time */
		ATTR_UINT("Interval end time",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_fec_pmhd,
				   interval_end_time),
			  1,
			  OMCI_ATTR_PROP_RD,
			  pm_interval_end_time_get),
		/* 2. Threshold Data 1/2 ID */
		ATTR_PTR("Threshold data 1/2 id",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_fec_pmhd,
				  thr_data_id),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 3. Corrected FEC Byte Count */
		ATTR_UINT("Corrected bytes",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_fec_pmhd,
				   corrected_byte_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 4. Corrected FEC Word Count */
		ATTR_UINT("Corrected code words",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_fec_pmhd,
				   corrected_word_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 5. Uncorrectable FEC Word Count */
		ATTR_UINT("Uncorrectable code words",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_fec_pmhd,
				   uncorrectable_word_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 6. Total FEC Code Word Count  */
		ATTR_UINT("Total code words",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_fec_pmhd,
				   total_word_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 7. FEC Errored Second Count */
		ATTR_UINT("FEC seconds",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_fec_pmhd,
				   fec_seconds),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 8-16. Doesn't exist */
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
	me_shutdown,
	/* Validate Handler */
	default_me_validate,
	/* Update Handler */
	default_me_update,
	/* Table Attribute Copy Handler */
	NULL,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	me_counters_get,
	/* Thresholds set Handler */
	me_thr_set,
#endif
	/* TCA Table */
	tca_table,
	/* Data Size */
	sizeof(struct omci_me_fec_pmhd),
	/* Properties */
	OMCI_ME_PROP_PM | OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"FEC PMHD",
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
