/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE OMCI_DBG_MODULE_CORE

#include "omci_core.h"
#include "omci_debug.h"

/** \addtogroup OMCI_ALARM
   @{
*/

enum omci_error alarm_copy_init(struct omci_context *context)
{
	enum omci_error error;

	dbg_in(__func__, "%p", (void *)context);

	memset(&context->alarm_copy, 0, sizeof(struct alarm_copy));

	error = list_init(&context->alarm_copy.list,
			  sizeof(struct alarm_copy_entry));
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error alarm_copy_shutdown(struct omci_context *context)
{
	dbg_in(__func__, "%p", (void *)context);

	list_delete(&context->alarm_copy.list);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

bool is_alarm_bitmap_empty(const uint8_t alarm_bitmap[OMCI_ALARM_BITMAP_SIZE])
{
	unsigned int i;

	if (alarm_bitmap == NULL)
		return true;

	for (i = 0; i < OMCI_ALARM_BITMAP_SIZE; i++)
		if (alarm_bitmap[i] != 0)
			return false;

	return true;
}

enum omci_error alarm_set(uint8_t alarm_bitmap[OMCI_ALARM_BITMAP_SIZE],
			  uint8_t alarm,
			  bool active)
{
	RETURN_IF_PTR_NULL(alarm_bitmap);

	if (alarm > OMCI_ALARMS_NUM - 1)
		return OMCI_ERROR_BOUNDS;

	if (active == true)
		alarm_bitmap[alarm / 8] |= 1 << (7 - alarm % 8);
	else
		alarm_bitmap[alarm / 8] &= ~(uint8_t)(1 << (7 - alarm % 8));

	return OMCI_SUCCESS;
}

enum omci_error alarm_bitmap_clear(uint8_t alarm_bitmap[OMCI_ALARM_BITMAP_SIZE])
{
	RETURN_IF_PTR_NULL(alarm_bitmap);

	memset(alarm_bitmap, 0, OMCI_ALARM_BITMAP_SIZE);

	return OMCI_SUCCESS;
}

enum omci_error alarm_get(const uint8_t *alarm_bitmap,
			  uint8_t alarm,
			  bool *active)
{
	RETURN_IF_PTR_NULL(alarm_bitmap);

	if (alarm > OMCI_ALARMS_NUM - 1)
		return OMCI_ERROR_BOUNDS;

	if (alarm_bitmap[alarm / 8] & (1 << (7 - alarm % 8)))
		*active = true;
	else
		*active = false;

	return OMCI_SUCCESS;
}

enum omci_error alarm_bitmap_alloc(struct me *me)
{
	if (me->alarm_bitmap != NULL) {
		/* suppose that during reinit of ME it can already
		   have alarm bitmap */
		memset(me->alarm_bitmap, 0, OMCI_ALARM_BITMAP_SIZE);
		return OMCI_SUCCESS;
	}

	me->alarm_bitmap = IFXOS_MemAlloc(OMCI_ALARM_BITMAP_SIZE);
	RETURN_IF_MALLOC_ERROR(me->alarm_bitmap);

	memset(me->alarm_bitmap, 0, OMCI_ALARM_BITMAP_SIZE);

	return OMCI_SUCCESS;
}

enum omci_error alarm_bitmap_free(struct me *me)
{
	if (me->alarm_bitmap == NULL)
		return OMCI_SUCCESS;

	IFXOS_MemFree(me->alarm_bitmap);
	me->alarm_bitmap = NULL;

	return OMCI_SUCCESS;
}

enum omci_error arc_context_alloc(struct me *me)
{
	if (me->arc_context != NULL) {
		memset(me->arc_context, 0, sizeof(struct me_arc_context));
		return OMCI_SUCCESS;
	}

	me->arc_context = IFXOS_MemAlloc(sizeof(struct me_arc_context));
	RETURN_IF_MALLOC_ERROR(me->arc_context);

	memset(me->arc_context, 0, sizeof(struct me_arc_context));

	return OMCI_SUCCESS;
}

enum omci_error arc_context_free(struct me *me)
{
	if (me->arc_context == NULL)
		return OMCI_SUCCESS;

	IFXOS_MemFree(me->arc_context);
	me->arc_context = NULL;

	return OMCI_SUCCESS;
}

enum omci_error arc_interval_set(struct omci_context *context,
				 struct me *me,
				 const uint8_t *data,
				 size_t data_size)
{
	uint8_t *arc;
	uint8_t *attr_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %lu",
	       (void *)context, (void *)me, (void *)data, data_size);

	assert(data_size == 1);

	/* remove old timeout */
	if (me->arc_context->timeout_id) {
		error = timeout_event_remove(context,
					     me->arc_context->timeout_id);
		me->arc_context->timeout_id = 0;
		RETURN_IF_ERROR(error);
	}

	/* read ARC status */
	arc = (uint8_t *)me->data
	    + me_attr_offset_get(me->class, me->arc_context->arc_attr);

	if (*arc == OMCI_ARC_ENABLED && *data > 0 && *data != 255) {
		/* add AVC expired timeout event */
		error = timeout_event_add(context,
					  &me->arc_context->timeout_id,
					  *data * 60 * 1000,
					  arc_interval_exp_timeout_handler,
					  me->class->class_id,
					  me->instance_id,
					  me->class->class_id,
					  me->instance_id, 0);
		RETURN_IF_ERROR(error);
	}

	/* store ARC_interval in the MIB */
	attr_data = (uint8_t *)me->data
		+ me_attr_offset_get(me->class,
				     me->arc_context->arc_interval_attr);

	*attr_data = *data;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error arc_interval_exp_timeout_handler(struct omci_context *context,
						 struct timeout *timeout)
{
	uint16_t class_id;
	uint16_t instance_id;
	struct me *me;
	enum omci_error error;
	uint8_t arc = OMCI_ARC_DISABLED;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)timeout);

	dbg_prn("timeout - ARC interval is expired");

	/* extract data from the timeout event */
	class_id = (uint16_t)timeout->arg1;
	instance_id = (uint16_t)timeout->arg2;

	mib_lock_read(context);

	/* find ME */
	error = mib_me_find(context, class_id, instance_id, &me);
	if (error)
		goto unlock_mib;

	me_lock(context, me);

	/* write ARC = DISABLED */
	error = me_attr_write(context, me, me->arc_context->arc_attr, &arc,
			      sizeof(arc), false);
	if (error)
		goto unlock_me;

	/* send AVC */
	error = avc_send(context, me, me->arc_context->arc_attr);
	if (error)
		goto unlock_me;

	me_unlock(context, me);

	mib_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;

unlock_me:
	me_unlock(context, me);

unlock_mib:
	mib_unlock(context);

	dbg_out_ret(__func__, error);
	return error;
}

/** @} */
