/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_onu_data.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_onu_data.h"

/** \addtogroup OMCI_ME_ONU_DATA
   @{
*/

/** This timeout event handler is called when the alarm table copy is out of
   date

   \param[in] context OMCI context pointer
   \param[in] timeout timeout descriptor
*/
static enum omci_error alarm_copy_clean_timeout_handle(struct omci_context
						       *context,
						       struct timeout *timeout)
{
	dbg_in(__func__, "%p, %p", (void *)context, (void *)timeout);

	list_lock(&context->alarm_copy.list);

	dbg_prn("Timeout - Clear Alarms copy");

	list_clear(&context->alarm_copy.list);
	context->alarm_copy.timeout_id = 0;

	list_unlock(&context->alarm_copy.list);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** This timeout event handler is called when the MIB copy is out of date.

   \param[in] context OMCI context pointer
   \param[in] timeout timeout descriptor
*/
static enum omci_error mib_copy_clean_timeout_handle(struct omci_context
						     *context,
						     struct timeout *timeout)
{
	dbg_in(__func__, "%p, %p", (void *)context, (void *)timeout);

	list_lock(&context->mib_copy.list);

	dbg_prn("Timeout - Clear MIB copy");

	list_clear(&context->mib_copy.list);
	context->mib_copy.timeout_id = 0;
	context->mib_copy.num = 0;

	list_unlock(&context->mib_copy.list);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error get_all_alarms_action_handle(struct omci_context
						    *context,
						    struct me *me,
						    const union omci_msg *msg,
						    union omci_msg *rsp)
{
	unsigned int inst_num = 0;
	int i;
	struct mib_me_list_entry *me_entry;
	struct alarm_copy_entry *alarm_copy_entry;
	struct list_entry *entry;
	uint8_t arc;

	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	list_lock(&context->alarm_copy.list);

	/* remove old timeout event */
	if (context->alarm_copy.timeout_id) {
		(void)timeout_event_remove(context,
					   context->alarm_copy.timeout_id);

		list_clear(&context->alarm_copy.list);
	}

	/* for each ME instance */
	for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
		for (me_entry = context->mib.me_class_array[i].me_list;
		     me_entry != NULL; me_entry = me_entry->next) {
			/* exclude ME with ARC enabled */
			if (msg->get_all_alarms.mode ==
			    OMCI_GET_ALL_ALARMS_MODE_NO_ARC) {
				if (me_entry->me.arc_context != NULL) {
					error = me_attr_read(context,
							     &me_entry->me,
							     me_entry->me.
							     arc_context->
							     arc_attr,
							     &arc,
							     sizeof(arc));

					if (error == OMCI_SUCCESS)
						if (arc == OMCI_ARC_ENABLED)
							continue;
				}
			}

			if (me_entry->me.alarm_bitmap == NULL)
				continue;

			if (me_entry->me.class->
			    prop & OMCI_ME_PROP_PM)
				continue;

			if (is_alarm_bitmap_empty(me_entry->me.alarm_bitmap) ==
			    false) {
				entry = list_entry_alloc(&context->alarm_copy.
							 list);
				if (!entry) {
					list_unlock(&context->alarm_copy.list);
					continue;
				}

				alarm_copy_entry = list_entry_data(entry);

				alarm_copy_entry->class_id =
					me_entry->me.class->class_id;
				alarm_copy_entry->instance_id =
					me_entry->me.instance_id;

				list_entry_add_tail(&context->alarm_copy.list,
						    entry);

				/* copy alarm bitmap */
				memcpy(alarm_copy_entry->alarm_bitmap,
				       me_entry->me.alarm_bitmap,
				       OMCI_ALARM_BITMAP_SIZE);

				inst_num++;
			}
		}
	}

	rsp->get_all_alarms_rsp.seq_num = hton16(inst_num);

	/* reset alarm sequence number */
	context_lock(context);
	context->mib.alarm_seq_num = 0;
	context_unlock(context);

	/* set new timeout */
	error = timeout_event_add(context, &context->alarm_copy.timeout_id,
				  OMCI_ONUDATA_GET_ALL_ALARMS_TIMEOUT,
				  alarm_copy_clean_timeout_handle,
				  me->class->class_id,
				  me->instance_id,
				  0, 0, 0);

	if (error != OMCI_SUCCESS) {
		list_unlock(&context->alarm_copy.list);

		dbg_out_ret(__func__, error);
		return error;
	}

	list_unlock(&context->alarm_copy.list);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error get_all_alarms_next_action_handle(struct omci_context
							 *context,
							 struct me *me,
							 const union
							 omci_msg *msg,
							 union omci_msg *rsp)
{
	unsigned int inst_num = 0;
	unsigned int seq_num;
	struct list_entry *entry, *tmp_entry;
	struct alarm_copy_entry *alarm_copy_entry;

	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	list_lock(&context->alarm_copy.list);

	if (is_list_empty(&context->alarm_copy.list)) {
		dbg_prn("Get all alarms next timeout");

		list_unlock(&context->alarm_copy.list);

		rsp->msg_rsp.result = OMCI_MR_CMD_SUCCESS;

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	seq_num = ntoh16(msg->get_all_alarms_next.seq_num);

	foreach_list_entry_safe(&context->alarm_copy.list, entry, tmp_entry) {
		if (inst_num != seq_num) {
			inst_num++;
			continue;
		}

		alarm_copy_entry = list_entry_data(entry);

		/* copy alarm bitmap */
		memcpy(rsp->get_all_alarms_next_rsp.alarm_bitmap,
		       alarm_copy_entry->alarm_bitmap,
		       OMCI_ALARM_BITMAP_SIZE);

		rsp->get_all_alarms_next_rsp.class_id =
			hton16(alarm_copy_entry->class_id);

		rsp->get_all_alarms_next_rsp.instance_id =
			hton16(alarm_copy_entry->instance_id);

		/* remove old timeout event */
		if (context->alarm_copy.timeout_id)
			(void)timeout_event_remove(context,
						   context->alarm_copy.
						   timeout_id);

		/* add new timeout event */
		error = timeout_event_add(context,
					  &context->alarm_copy.timeout_id,
					  OMCI_ONUDATA_GET_ALL_ALARMS_TIMEOUT,
					  alarm_copy_clean_timeout_handle,
					  me->class->class_id,
					  me->instance_id,
					  0, 0, 0);

		if (error != OMCI_SUCCESS) {
			list_unlock(&context->alarm_copy.list);

			dbg_out_ret(__func__, error);
			return error;
		}

		inst_num++;
	}

	/* sequence number is out of range */
	if (inst_num > seq_num) {
		/* message should be cleared, don't clear again */
	}

	list_unlock(&context->alarm_copy.list);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error mib_upload_action_handle(struct omci_context *context,
						struct me *me,
						const union omci_msg *msg,
						union omci_msg *rsp)
{
	unsigned int inst_num = 0;
	enum omci_error error;
	uint8_t seq=0;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	list_lock(&context->mib_copy.list);

	mib_seq_num_get(context, &seq);
	if (seq != 0) {
		if (mib_copy(context) != OMCI_SUCCESS) {
			/* don't send RSP */
			omci_msg_type_ak_set(rsp, 0);
		}
	}

	/* insert sequence number */
	rsp->mib_upload_rsp.seq_num = hton16(context->mib_copy.num);

	if(rsp->mib_upload_rsp.seq_num == 0) {
		list_unlock(&context->mib_copy.list);

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

	if (context->mib_copy.timeout_id)
			(void)timeout_event_remove(context,
						   context->mib_copy.
						   timeout_id);

	/* set new timeout */
	error = timeout_event_add(context, &context->mib_copy.timeout_id,
				  OMCI_ONUDATA_MIB_UPLOAD_TIMEOUT,
				  mib_copy_clean_timeout_handle,
				  me->class->class_id,
				  me->instance_id,
				  0, 0, 0);

	if (error != OMCI_SUCCESS) {
		list_unlock(&context->mib_copy.list);

		dbg_out_ret(__func__, error);
		return error;
	}

	list_unlock(&context->mib_copy.list);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error mib_upload_next_action_handle(struct omci_context
						     *context,
						     struct me *me,
						     const union omci_msg *msg,
						     union omci_msg *rsp)
{
	struct mib_copy_entry *mib_copy_entry = NULL;
	struct list_entry *entry, *tmp_entry;
	unsigned int inst_num = 0;
	unsigned int seq_num;

	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	list_lock(&context->mib_copy.list);

	/* check if message sequence was terminated */
	if (is_list_empty(&context->mib_copy.list)) {
		dbg_prn(__func__, "MIB upload next timeout");

		list_unlock(&context->mib_copy.list);

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	seq_num = ntoh16(msg->mib_upload_next.seq_num);

	foreach_list_entry_safe(&context->mib_copy.list, entry, tmp_entry) {
		mib_copy_entry = list_entry_data(entry);

		/* found nth entry */
		if (inst_num == seq_num) {
			rsp->mib_upload_next_rsp.class_id =
				hton16(mib_copy_entry->class_id);

			rsp->mib_upload_next_rsp.instance_id =
				hton16(mib_copy_entry->instance_id);

			rsp->mib_upload_next_rsp.attr_mask =
				hton16(mib_copy_entry->attr_mask);

			memcpy(rsp->mib_upload_next_rsp.values,
			       mib_copy_entry->values,
			       MIB_UPLOAD_NEXT_RSP_VALUES_SIZE);

			/* remove old timeout event */
			if (context->mib_copy.timeout_id)
				(void)timeout_event_remove(context,
							   context->mib_copy.
							   timeout_id);

			/* add new timeout event */
			error = timeout_event_add(context,
						  &context->mib_copy.timeout_id,
						  OMCI_ONUDATA_MIB_UPLOAD_TIMEOUT,
						  mib_copy_clean_timeout_handle,
						  me->class->class_id,
						  me->instance_id,
						  0, 0, 0);

			if (error != OMCI_SUCCESS) {
				list_unlock(&context->mib_copy.list);

				dbg_out_ret(__func__, error);
				return error;
			}

			break;
		}

		inst_num++;
	}

	/* sequence number is out of range */
	if (inst_num > seq_num) {
		/* message is clear, don't clear again */
	}

	list_unlock(&context->mib_copy.list);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error mib_reset_action_handle(struct omci_context *context,
					       struct me *me,
					       const union omci_msg *msg,
					       union omci_msg *rsp)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	error = mib_reset(context, false);
	if (error != OMCI_SUCCESS) {
		rsp->mib_reset_rsp.result = OMCI_MR_CMD_ERROR;

		dbg_out_ret(__func__, error);
		return error;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_onu_data_class = {
	/* Class ID */
	OMCI_ME_ONU_DATA,
	/* Attributes */
	{
		/* 1. MIB data sync */
		ATTR_UINT("MIB data sync",
			  ATTR_SUPPORTED,
			  0,
			  255,
			  offsetof(struct omci_me_onu_data,
				   mib_data_sync),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 2-16. Doesn't exist */
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
		get_all_alarms_action_handle,
		/* Get all alarms next */
		get_all_alarms_next_action_handle,
		/* MIB upload */
		mib_upload_action_handle,
		/* MIB upload next */
		mib_upload_next_action_handle,
		/* MIB reset */
		mib_reset_action_handle,
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
	default_me_update,
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
	sizeof(struct omci_me_onu_data),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"ONU data",
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
