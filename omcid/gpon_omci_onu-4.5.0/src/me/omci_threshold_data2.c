/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_threshold_data2.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_threshold_data1.h"
#include "me/omci_threshold_data2.h"

#ifdef INCLUDE_PM

/** \addtogroup OMCI_ME_THRESHOLD_DATA
   @{
*/

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	struct me *thr1_me;
	struct omci_me_threshold_data1 *thr1_data;

	struct omci_me_threshold_data2 *upd_data;
	struct omci_me_threshold_data2 *me_data;
	uint32_t thr[PM_THR_NUM];

	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	upd_data = (struct omci_me_threshold_data2 *) data;
	me_data = (struct omci_me_threshold_data2 *) me->data;

	thr[7] = upd_data->thr_data8;
	thr[8] = upd_data->thr_data9;
	thr[9] = upd_data->thr_data10;
	thr[10] = upd_data->thr_data11;
	thr[11] = upd_data->thr_data12;
	thr[12] = upd_data->thr_data13;
	thr[13] = upd_data->thr_data14;

	error = mib_me_find(context, OMCI_ME_THRESHOLD_DATA1,
			    me->instance_id, &thr1_me);

	if (error == OMCI_SUCCESS) {
		me_lock(context, thr1_me);

		thr1_data = (struct omci_me_threshold_data1 *)thr1_me->data;

		thr[0] = thr1_data->thr_data1;
		thr[1] = thr1_data->thr_data2;
		thr[2] = thr1_data->thr_data3;
		thr[3] = thr1_data->thr_data4;
		thr[4] = thr1_data->thr_data5;
		thr[5] = thr1_data->thr_data6;
		thr[6] = thr1_data->thr_data7;

		me_unlock(context, thr1_me);
	} else {
		thr[0] = 0xffffffff;
		thr[1] = 0xffffffff;
		thr[2] = 0xffffffff;
		thr[3] = 0xffffffff;
		thr[4] = 0xffffffff;
		thr[5] = 0xffffffff;
		thr[6] = 0xffffffff;
	}

	error = pm_thr_update(context, me, thr);

	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_threshold_data2_class = {
	/* Class ID */
	OMCI_ME_THRESHOLD_DATA2,
	/* Attributes */
	{
		/* 1. Threshold Value 8 */
		ATTR_UINT("Threshold value 8",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data2,
				   thr_data8),
			  4,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 2. Threshold Value 9 */
		ATTR_UINT("Threshold value 9",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data2,
				   thr_data9),
			  4,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 3. Threshold Value 10 */
		ATTR_UINT("Threshold value 10",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data2,
				   thr_data10),
			  4,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 4. Threshold Value 11 */
		ATTR_UINT("Threshold value 11",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data2,
				   thr_data11),
			  4,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 5. Threshold Value 12 */
		ATTR_UINT("Threshold value 12",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data2,
				   thr_data12),
			  4,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 6. Threshold Value 13 */
		ATTR_UINT("Threshold value 13",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data2,
				   thr_data13),
			  4,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 7. Threshold Value 14 */
		ATTR_UINT("Threshold value 14",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data2,
				   thr_data14),
			  4,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
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
		NULL
	},
	/* Init Handler */
	default_me_init,
	/* Shutdown Handler */
	NULL,
	/* Validate Handler */
	NULL,
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
	sizeof(struct omci_me_threshold_data2),
	/* Properties */
	OMCI_ME_PROP_NO_UPLOAD | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Threshold data 2",
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

#endif
