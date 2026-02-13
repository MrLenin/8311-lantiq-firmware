/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_omci.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_omci.h"

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION


/** \addtogroup OMCI_ME_OMCI
    @{
*/

static enum omci_error me_tbl_copy(struct omci_context *context,
				   struct me *me,
				   unsigned int attr,
				   struct tbl_copy_entry *tbl_copy)
{
	uint16_t *data16, tmp16;
	uint8_t *data8;
	unsigned int i;
	size_t required_data_size;

	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	switch (attr) {
	case 1:
		required_data_size = OMCI_ME_TABLE_SIZE * sizeof(uint16_t);
		tbl_copy->data = IFXOS_MemAlloc(required_data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);
		tbl_copy->data_size = required_data_size;

		data16 = (uint16_t *)tbl_copy->data;

		for (i = 0; i < OMCI_ME_TABLE_SIZE; i++) {
			tmp16 = hton16(me_def_class_array[i]->class_id);
			memcpy(&data16[i], &tmp16, sizeof(uint16_t));
		}
		break;

	case 2:
		required_data_size = OMCI_MT_TABLE_SIZE;
		tbl_copy->data = IFXOS_MemAlloc(required_data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);
		tbl_copy->data_size = required_data_size;

		data8 = (uint8_t *)tbl_copy->data;

		data8[0] = OMCI_MT_CREATE;
		data8[1] = OMCI_MT_DELETE;
		data8[2] = OMCI_MT_SET;
		data8[3] = OMCI_MT_GET;
		data8[4] = OMCI_MT_GET_ALL_ALARMS;
		data8[5] = OMCI_MT_GET_ALL_ALARMS_NEXT;
		data8[6] = OMCI_MT_MIB_UPLOAD;
		data8[7] = OMCI_MT_MIB_UPLOAD_NEXT;
		data8[8] = OMCI_MT_MIB_RESET;
		data8[9] = OMCI_MT_ALARM;
		data8[10] = OMCI_MT_AVC;
		data8[11] = OMCI_MT_TEST;
		data8[12] = OMCI_MT_START_SW_DL;
		data8[13] = OMCI_MT_DL_SECTION;
		data8[14] = OMCI_MT_END_SW_DL;
		data8[15] = OMCI_MT_ACTIVATE_SW;
		data8[16] = OMCI_MT_COMMIT_SW;
		data8[17] = OMCI_MT_SYNC_TIME;
		data8[18] = OMCI_MT_REBOOT;
		data8[19] = OMCI_MT_GET_NEXT;
		data8[20] = OMCI_MT_TEST_RESULT;
		data8[21] = OMCI_MT_GET_CURR_DATA;

		break;

	default:
		error = OMCI_ERROR_INVALID_ME_ATTR;
		break;
	}

	dbg_out_ret(__func__, error);
	return error;
}

/** Managed Entity class */
struct me_class me_omci_class = {
	/* Class ID */
	OMCI_ME_OMCI,
	/* Attributes */
	{
		/* 1. Managed Entity Type Table */
		ATTR_TBL("ME type table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_omci,
				  my_type_table),
			 2,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 2. Message Type Table */
		ATTR_TBL("Message type table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_omci,
				  msg_type_table),
			 1,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 3-16. Doesn't exist */
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
		NULL,
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
		/* alarm */
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
	NULL,
	/* Shutdown Handler */
	NULL,
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
	sizeof(struct omci_me_omci),
	/* Properties */
	OMCI_ME_PROP_NO_UPLOAD | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"OMCI",
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
