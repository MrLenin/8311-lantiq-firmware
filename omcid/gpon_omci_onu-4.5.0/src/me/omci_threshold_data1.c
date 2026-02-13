/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_threshold_data1.c
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

struct thr_data_walker_data {
	uint16_t thr_data_instance_id;
	uint32_t thr[PM_THR_NUM];
};

static enum omci_error thr_data_walker(struct omci_context *context,
				       struct me *me,
				       void *shared_data)
{
	enum omci_error error;
	uint16_t thr_data;
	struct thr_data_walker_data *walker_data =
		(struct thr_data_walker_data *)shared_data;

	if ((me->class->prop & OMCI_ME_PROP_PM) == 0)
		return OMCI_SUCCESS;

	error = me_attr_read(context, me, omci_me_pm_thr_data_id,
			     &thr_data, sizeof(thr_data));

	RETURN_IF_ERROR(error);

	if (thr_data != walker_data->thr_data_instance_id)
		return OMCI_SUCCESS;

	if (me->class->thr_set)
		error = me->class->thr_set(context, me, walker_data->thr);

	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}

enum omci_error pm_thr_update(struct omci_context *context,
			      struct me *me,
			      uint32_t thr[PM_THR_NUM])
{
	struct thr_data_walker_data walker_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)thr);

	memcpy(walker_data.thr, thr, sizeof(walker_data.thr));

	walker_data.thr_data_instance_id = me->instance_id;
	error = mib_walk(context, thr_data_walker, &walker_data);

	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	struct me *thr2_me;
	struct omci_me_threshold_data2 *thr2_data;

	struct omci_me_threshold_data1 *upd_data;
	struct omci_me_threshold_data1 *me_data;
	uint32_t thr[PM_THR_NUM];

	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	upd_data = (struct omci_me_threshold_data1 *) data;
	me_data = (struct omci_me_threshold_data1 *) me->data;

	thr[0] = upd_data->thr_data1;
	thr[1] = upd_data->thr_data2;
	thr[2] = upd_data->thr_data3;
	thr[3] = upd_data->thr_data4;
	thr[4] = upd_data->thr_data5;
	thr[5] = upd_data->thr_data6;
	thr[6] = upd_data->thr_data7;

	error = mib_me_find(context, OMCI_ME_THRESHOLD_DATA2,
			    me->instance_id, &thr2_me);

	if (error == OMCI_SUCCESS) {
		me_lock(context, thr2_me);

		thr2_data = (struct omci_me_threshold_data2 *)thr2_me->data;

		thr[7] = thr2_data->thr_data8;
		thr[8] = thr2_data->thr_data9;
		thr[9] = thr2_data->thr_data10;
		thr[10] = thr2_data->thr_data11;
		thr[11] = thr2_data->thr_data12;
		thr[12] = thr2_data->thr_data13;
		thr[13] = thr2_data->thr_data14;

		me_unlock(context, thr2_me);
	} else {
		thr[7]  = 0xffffffff;
		thr[8]  = 0xffffffff;
		thr[9]  = 0xffffffff;
		thr[10] = 0xffffffff;
		thr[11] = 0xffffffff;
		thr[12] = 0xffffffff;
		thr[13] = 0xffffffff;
	}

	error = pm_thr_update(context, me, thr);

	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_threshold_data1_class = {
	/* Class ID */
	OMCI_ME_THRESHOLD_DATA1,
	/* Attributes */
	{
		/* 1. Threshold Value 1 */
		ATTR_UINT("Threshold value 1",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data1,
				   thr_data1),
			  4,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 2. Threshold Value 2 */
		ATTR_UINT("Threshold value 2",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data1,
				   thr_data2),
			  4,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 3. Threshold Value 3 */
		ATTR_UINT("Threshold value 3",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data1,
				   thr_data3),
			  4,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 4. Threshold Value 4 */
		ATTR_UINT("Threshold value 4",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data1,
				   thr_data4),
			  4,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 5. Threshold Value 5 */
		ATTR_UINT("Threshold value 5",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data1,
				   thr_data5),
			  4,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 6. Threshold Value 6 */
		ATTR_UINT("Threshold value 6",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data1,
				   thr_data6),
			  4,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 7. Threshold Value 7 */
		ATTR_UINT("Threshold value 7",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_threshold_data1,
				   thr_data7),
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
	sizeof(struct omci_me_threshold_data1),
	/* Properties */
	OMCI_ME_PROP_NO_UPLOAD | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Threshold data 1",
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
