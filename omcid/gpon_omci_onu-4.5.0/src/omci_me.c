/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_memory_alloc.h"
#include "ifxos_time.h"

#define OMCI_DBG_MODULE OMCI_DBG_MODULE_CORE

#include "omci_core.h"
#include "omci_debug.h"

/** \addtogroup OMCI_MIB
   @{
*/

enum omci_error me_data_read(struct omci_context *context,
			     struct me *me,
			     void *data,
			     size_t data_size,
			     enum omci_pm_interval interval)
{
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(context && me && data);
	assert(data_size >= me->class->data_size);

	if ((me->class->inv_attr_mask | me->class->opt_attr_mask) == 0xffff) {
		memset(data, 0, data_size);

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

#ifdef INCLUDE_PM
	(void)pm_me_interval_set(context, me, interval);
#endif

	error = me_data_fetch(context, me,
			      ~(me->class->inv_attr_mask
				| me->class->opt_attr_mask),
			      me->data, data_size,
			      ~me->class->inv_attr_mask, data);

	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Check for new AVCs and send notification */
static enum omci_error me_avc_send(struct omci_context *context,
				   struct me *const me,
				   uint16_t attr_mask,
				   uint16_t suppress_avc,
				   uint16_t upd_attr_mask)
{
	unsigned int attr;

	if (me->class->avc_attr_mask & attr_mask & upd_attr_mask &
	    ~suppress_avc)
		for (attr = 1; attr <= 16; attr++)
			if (omci_attr2mask(attr) & me->class->avc_attr_mask &
			    upd_attr_mask)
				(void)avc_send(context, me, attr);
	return OMCI_SUCCESS;
}

enum omci_error me_data_write(struct omci_context *context,
			      struct me *const me,
			      void *data,
			      size_t data_size,
			      uint16_t attr_mask,
			      uint16_t suppress_avc)
{
	uint16_t exec_mask = 0;
	enum omci_error error;
	uint16_t upd_attr_mask;

	dbg_in(__func__, "%p, %p, %p, %lu, 0x%04x, 0x%04x", (void *)context,
	       (void *)me, (void *)data, data_size, attr_mask, suppress_avc);

	assert(context && me && data);
	assert(data_size == me->class->data_size);

	upd_attr_mask = 0;

	if (is_data_updated(context, me, data, attr_mask, &upd_attr_mask)
	    == false) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	if (me->class->validate) {
		error = me->class->validate(context, me->class, &exec_mask,
					    data);

		if (exec_mask) {
			me_attr_update_print(context, me->class,
					     me->instance_id,
					     attr_mask,
					     data, data_size,
					     "Can't set",
					     exec_mask &
					     (attr_mask));

			dbg_out_ret(__func__, OMCI_ERROR_INVALID_ME_ATTR);
			return OMCI_ERROR_INVALID_ME_ATTR;
		}
	}

	if (me->active)
		error = me->class->update(context, me, data, attr_mask);
	else {
		omci_hook(context, "update", me->class->class_id, me->instance_id);
		error = 0;
		me_dbg_wrn(me, "Skip update handler");
	}

	if (error) {
		me_attr_update_print(context, me->class, me->instance_id,
				     attr_mask,
				     data, data_size,
				     "Can't set (update)",
				     exec_mask & (attr_mask));

		RETURN_IF_ERROR(error);
	}

	memcpy(me->data, data, me->class->data_size);

	me_attr_update_print(context, me->class, me->instance_id,
			     attr_mask, data,
			     data_size,
			     "set", attr_mask & ~me->class->vol_attr_mask);

#ifdef INCLUDE_PM
	if (me->class->prop & OMCI_ME_PROP_PM)
		if (upd_attr_mask & omci_attr2mask(omci_me_pm_thr_data_id))
			(void)pm_me_thr_set(context, me);
#endif

	error = me_avc_send(context, me, attr_mask,
			    suppress_avc, upd_attr_mask);

	dbg_out_ret(__func__, error);
	return error;
}

void _me_lock(struct omci_context *context,
	      struct me *me,
	      const char *file,
	      int line)
{
	enum omci_error error;

#ifndef NDEBUG
	if (mib_is_locked(context) == false) {
		dbg_err("Attempt to lock ME without MIB locked at %s:%d! "
			"Aborting...\n", file, line);
		/*abort();*/
	}
#endif

	me_dbg_msg(me, "{ LOCK   ME     (%p)", (void *)&me);

	error = recursive_lock_get(&me->lock);
	if (error != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't lock ME", error);
		abort();
	}
}

void _me_unlock(struct omci_context *context,
		struct me *me,
		const char *file,
		int line)
{
	enum omci_error error;

	if (me == NULL)
		return;

#ifndef NDEBUG
	if (mib_is_locked(context) == false) {
		dbg_err("Attempt to unlock ME without MIB locked at %s:%d! "
			"Aborting...\n",
			file, line);
		/*abort();*/
	}
#endif

	me_dbg_msg(me, "} UNLOCK ME     (%p)", (void *)&me);

	error = recursive_lock_release(&me->lock);
	if (error != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't unlock ME", error);
		abort();
	}
}

enum omci_error me_lock_init(struct me *me)
{
	return recursive_lock_init(&me->lock);
}

enum omci_error me_lock_delete(struct me *me)
{
	return recursive_lock_delete(&me->lock);
}

enum omci_error me_class_data_fetch(struct omci_context *context,
				    const struct me_class *me_class,
				    uint16_t attr_mask,
				    const void *data,
				    size_t data_size,
				    void *fetched_data)
{
	unsigned int attr;
	size_t attr_size;
	unsigned int attr_data_offset;
	unsigned int offset = 0;

	dbg_in(__func__, "%p, %p, 0x%04x, %p, %lu, %p", (void *)context,
	       (void *)me_class, attr_mask, (void *)data, data_size,
	       (void *)fetched_data);

	assert(context && me_class && attr_mask && data && fetched_data);

	memset(fetched_data, 0, me_class->data_size);

	for (attr = 1; attr <= OMCI_ATTRIBUTES_NUM; attr++) {
		if (!(attr_mask & omci_attr2mask(attr)))
			continue;

		attr_data_offset = me_attr_offset_get(me_class, attr);
		attr_size = me_attr_size_get(me_class, attr);

		if (offset + attr_size > data_size) {
			dbg_err("ME class attribute size mismatch attr num:%d, "
				"offset:%d, attr size:%d, data size:%d ",
				attr, offset, attr_size, data_size);
			dbg_out_ret(__func__, OMCI_ERROR_BOUNDS);
			return OMCI_ERROR_BOUNDS;
		}

		memcpy((uint8_t *)fetched_data + attr_data_offset,
		       (uint8_t *)data + offset, attr_size);
		offset += attr_size;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error me_data_fetch(struct omci_context *context,
			      struct me *me,
			      uint16_t attr_mask,
			      const void *data,
			      size_t data_size,
			      uint16_t data_attr_mask,
			      void *fetched_data)
{
	unsigned int attr;
	size_t attr_size;
	unsigned int attr_data_offset;
	unsigned int offset = 0;
	enum omci_error error;
	me_get_handler *attr_get_handler;

	dbg_in(__func__, "%p, %p, 0x%04x, %p, %lu, 0x%04x, %p", (void *)context,
	       (void *)me, attr_mask, (void *)data, data_size, data_attr_mask,
	       (void *)fetched_data);

	assert(context && me && attr_mask && fetched_data);

	if (me->data)
		memcpy(fetched_data, me->data, me->class->data_size);
	else
		memset(fetched_data, 0, me->class->data_size);

	for (attr = 1; attr <= OMCI_ATTRIBUTES_NUM; attr++) {
		attr_size = me_attr_size_get(me->class, attr);

		if (!(attr_mask & omci_attr2mask(attr))) {
			if (data_attr_mask & omci_attr2mask(attr))
				offset += attr_size;

			continue;
		}

		attr_data_offset = me_attr_offset_get(me->class, attr);

		if (offset + attr_size > data_size) {
			me_dbg_err(me, "ME attribute size mismatch "
				   "attr num:%d, offset:%d, attr size:%d, "
				   "data size:%d",
				   attr, offset, attr_size, data_size);
			dbg_out_ret(__func__, OMCI_ERROR_BOUNDS);
			return OMCI_ERROR_BOUNDS;
		}

		attr_get_handler = me_attr_get_handler_get(me->class,
							   attr);
		if (attr_get_handler) {
			error = attr_get_handler(context, me,
						 (uint8_t *)fetched_data +
						 attr_data_offset,
						 attr_size);

			if (error) {
				me_dbg_err(me, "ME attribute get handler error "
					   "(%d) attr num:%d", error, attr);

				dbg_out_ret(__func__, error);
				return error;
			}
		} else {
			if (data)
				memcpy((uint8_t *)fetched_data +
				       attr_data_offset,
				       (uint8_t *)data + offset, attr_size);
			else
				memset((uint8_t *)fetched_data +
				       attr_data_offset,
				       0, attr_size);
		}

		if (data_attr_mask & omci_attr2mask(attr))
			offset += attr_size;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error me_action_handler_get(const struct me_class *me_class,
				      unsigned int action,
				      me_action_handler **me_action_handler)
{
	dbg_in(__func__, "%p, %u, %p", (void *)me_class, action,
	       (void *)me_action_handler);

	assert(me_class);
	assert(me_action_handler);

	if (action < 1 || action > 28) {
		dbg_out_ret(__func__, OMCI_ERROR_INVALID_ME_ACTION);
		return OMCI_ERROR_INVALID_ME_ACTION;
	}

	*me_action_handler = me_class->actions[action];

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

bool is_me_attr_exist(const struct me_class *me_class, unsigned int attr)
{
	if (attr < 1 || attr > OMCI_ATTRIBUTES_NUM)
		return false;

	if ((me_attr_prop_get(me_class, attr) & OMCI_ATTR_PROP_NOT_SUPPORTED)
	    || me_attr_prop_get(me_class, attr) == OMCI_ATTR_PROP_NONE)
		return false;

	return true;
}

enum omci_error me_attr_read_with_interval(struct omci_context *context,
					   struct me *me,
					   unsigned int attr,
					   void *buff,
					   size_t buff_size,
					   enum omci_pm_interval interval)
{
	uint8_t data[OMCI_ME_DATA_SIZE_MAX];
	size_t attr_size;
	unsigned int attr_off;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %u, %p, %lu", (void *)context, (void *)me,
	       attr, (void *)buff, buff_size);

	assert(context && me);

	attr_size = me_attr_size_get(me->class, attr);
	attr_off = me_attr_offset_get(me->class, attr);

	assert(attr_size == buff_size);

	error = me_data_read(context, me, data, me->class->data_size, interval);
	RETURN_IF_ERROR(error);

	memcpy(buff, data + attr_off, buff_size);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error me_attr_read(struct omci_context *context,
			     struct me *me,
			     unsigned int attr,
			     void *buff,
			     size_t buff_size)
{
	return me_attr_read_with_interval(context, me, attr, buff, buff_size,
					  OMCI_PM_INTERVAL_CURR);
}

enum omci_error me_attr_write(struct omci_context *context,
			      struct me *const me,
			      unsigned int attr,
			      const void *buff,
			      size_t buff_size,
			      bool suppress_avc)
{
	uint8_t data[OMCI_ME_DATA_SIZE_MAX];
	size_t attr_size;
	unsigned int attr_off;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %u, %p, %lu, %u", (void *)context, (void *)me,
	       attr, (void *)data, buff_size, (unsigned int)suppress_avc);

	assert(context && me && buff);

	attr_size = me_attr_size_get(me->class, attr);
	attr_off = me_attr_offset_get(me->class, attr);

	assert(attr_size == buff_size);

	error = me_data_read(context, me, data, me->class->data_size,
			     OMCI_PM_INTERVAL_CURR);
	RETURN_IF_ERROR(error);

	memcpy(data + attr_off, buff, buff_size);

	error = me_data_write(context, me, data, me->class->data_size,
			      omci_attr2mask(attr), suppress_avc);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error me_alarm_set(struct omci_context *context,
			     struct me *me,
			     uint8_t alarm,
			     bool active)
{
	uint8_t arc;
	uint8_t arc_interval;
	bool avc_enabled = false;
	bool alarm_curr_status;
	enum omci_error error;
	uint8_t alarm_seq_num;
	uint8_t tca_bitmap[OMCI_ALARM_BITMAP_SIZE] = { 0 };

	dbg_in(__func__, "%p, %p, %u, %u", (void *)context, (void *)me, alarm,
		(unsigned int)active);

	/* check if the alarm is already in the current state */
	error = alarm_get(me->alarm_bitmap, alarm, &alarm_curr_status);
	RETURN_IF_ERROR(error);

	if (alarm_curr_status == active) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	if (active == true) {
		error = alarm_set(me->alarm_bitmap, alarm, true);
		RETURN_IF_ERROR(error);

		/* read ARC & ARC_interval */
		if (me->arc_context != NULL) {
			error = me_attr_read(context, me,
					     me->arc_context->arc_attr, &arc,
					     sizeof(arc));
			RETURN_IF_ERROR(error);

			error = me_attr_read(context, me,
					     me->arc_context->
					     arc_interval_attr,
					     &arc_interval, sizeof(arc));
			RETURN_IF_ERROR(error);

			if (arc == OMCI_ARC_ENABLED) {
				avc_enabled = true;

				if (arc_interval == 0) {
					arc = OMCI_ARC_DISABLED;

					/* write ARC = DISABLED */
					error = me_attr_write(context, me,
							      me->arc_context->
							      arc_attr, &arc,
							      sizeof(arc),
							      false);
					RETURN_IF_ERROR(error);
				}
			}
		}
	} else {
		error = alarm_set(me->alarm_bitmap, alarm, false);
		RETURN_IF_ERROR(error);
	}

#ifdef INCLUDE_PM
	/** \todo check if this code is used */

	if (me->class->prop & OMCI_ME_PROP_PM) {
		me_dbg_prn(me, "TCA #%u is %s", alarm, (active) ? "on" : "off");

		error = alarm_set(tca_bitmap, alarm, true);
		RETURN_IF_ERROR(error);

		error = tca_send(context, me, tca_bitmap);
		RETURN_IF_ERROR(error);
	} else
#endif
	{
		me_dbg_prn(me, "Alarm #%u is %s", alarm,
			   (active) ? "on" : "off");

		if (avc_enabled == false) {
			context_lock(context);
			alarm_seq_num = context->mib.alarm_seq_num;
			context_unlock(context);

			if (alarm_seq_num == 255)
				alarm_seq_num = 1;
			else
				alarm_seq_num++;

			context_lock(context);
			context->mib.alarm_seq_num = alarm_seq_num;
			context_unlock(context);

			error = alarm_send(context, me);
			RETURN_IF_ERROR(error);
		}
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error me_alarm_get(struct omci_context *context,
			     struct me *me,
			     uint8_t alarm,
			     bool *alarm_active)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me,
	       alarm, (void *)alarm_active);

	error = alarm_get(me->alarm_bitmap, alarm, alarm_active);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

void me_attr_update_print(struct omci_context *context,
			  const struct me_class *me_class,
			  uint16_t instance_id,
			  uint16_t attr_mask,
			  const void *values,
			  size_t values_size,
			  const char *prefix,
			  uint16_t attr_print_mask)
{
	unsigned int attr;
	const uint8_t *attr_data;
	size_t attr_size = 0;
	size_t attr_size_sum = 0;
	unsigned int i;
	uint16_t tmp16;
	uint32_t tmp32;

	(void)context;

	for (attr = 1; attr <= 16; attr++) {
		if (!(attr_mask & omci_attr2mask(attr)))
			continue;

		attr_size = me_attr_size_get(me_class, attr);

		if (!attr_size)
			continue;

		attr_data = (uint8_t *)values + attr_size_sum;
		attr_size_sum += attr_size;

		if (attr_size_sum > values_size)
			return; /* don't indicate error */

		if (!(attr_print_mask & omci_attr2mask(attr)))
			continue;

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
		dbg(OMCI_DBG_PRN,
		    "%u@%u %s %-25.25s = ", me_class->class_id,
		    instance_id, prefix,
		    me_attr_name_get(me_class, attr));
#else
		dbg(OMCI_DBG_PRN,
		    "%u@%u %s #%u = ", me_class->class_id,
		    instance_id, prefix, attr);
#endif

		if (me_attr_type_get(me_class, attr) == OMCI_ATTR_TYPE_STR) {
			for (i = 0; i < me_attr_size_get(me_class, attr); i++) {
				dbg_naked(OMCI_DBG_PRN,
					  OMCI_DBG_MODULE,
					  "%02x ", attr_data[i]);
			}

			dbg_naked(OMCI_DBG_PRN, OMCI_DBG_MODULE, "\"");

			for (i = 0; i < me_attr_size_get(me_class, attr); i++) {
				dbg_naked(OMCI_DBG_PRN,
					  OMCI_DBG_MODULE, "%c",
							    attr_data[i]);
			}

			dbg_naked(OMCI_DBG_PRN, OMCI_DBG_MODULE, "\"");
		} else {
			switch (attr_size) {
			case sizeof(uint8_t):
				dbg_naked(OMCI_DBG_PRN,
					  OMCI_DBG_MODULE,
					  "0x%02x (%u)",
					   *(uint8_t *)attr_data,
					   *(uint8_t *)attr_data);
				break;

			case sizeof(uint16_t):
				memcpy(&tmp16, attr_data, sizeof(uint16_t));
				dbg_naked(OMCI_DBG_PRN,
					  OMCI_DBG_MODULE,
					  "0x%04x (%u)",
					   tmp16,
					   tmp16);
				break;

			case sizeof(uint32_t):
				memcpy(&tmp32, attr_data, sizeof(uint32_t));
				dbg_naked(OMCI_DBG_PRN,
					  OMCI_DBG_MODULE,
					  "0x%08x (%u)",
					   tmp32,
					   tmp32);
				break;

			case 5: /* copy to long long and printout ?! */

			default:
				for (i = 0; i < attr_size; i++) {
					dbg_naked(OMCI_DBG_PRN,
						  OMCI_DBG_MODULE,
						  "%02x ", attr_data[i]);
				}
			}
		}

		dbg_naked(OMCI_DBG_PRN, OMCI_DBG_MODULE, "\n");
	}
}

bool is_data_updated(struct omci_context *context,
		     const struct me *me,
		     const void *upd_data,
		     uint16_t attr_mask,
		     uint16_t *upd_attr_mask)
{
	unsigned int attr;
	enum omci_attr_prop attr_prop;
	uint8_t *attr_data;
	size_t attr_size;
	unsigned int attr_data_offset;

	(void)context;

	/* let update handler be called from init handler anyway */
	if (me->is_initialized == false) {
		if (upd_attr_mask)
			*upd_attr_mask = ~me->class->inv_attr_mask;

		return true;
	}

	for (attr = 1; attr <= 16; attr++) {
		if (omci_attr2mask(attr) & attr_mask) {
			attr_prop = me_attr_prop_get(me->class, attr);

			/* table attributes always marked as updated */
			if (attr_prop & OMCI_ATTR_PROP_TABLE) {
				if (upd_attr_mask)
					*upd_attr_mask |= omci_attr2mask(attr);
				else
					return true;

				continue;
			}

			attr_data = (uint8_t *)me->data
				+ me_attr_offset_get(me->class, attr);
			attr_size = me_attr_size_get(me->class, attr);
			attr_data_offset =
				me_attr_offset_get(me->class, attr);

			if (memcmp((uint8_t *)upd_data + attr_data_offset,
				   attr_data, attr_size) != 0) {
				if (upd_attr_mask)
					*upd_attr_mask |= omci_attr2mask(attr);
				else
					return true;
			}
		}
	}

	if (upd_attr_mask) {
		if (*upd_attr_mask)
			return true;
		else
			return false;
	} else {
		return false;
	}
}

enum omci_error me_tbl_data_read(struct omci_context *context,
				 struct me *me,
				 unsigned int attr,
				 void **data,
				 size_t *data_size)
{
	enum omci_error error = OMCI_SUCCESS;
	struct tbl_copy_entry tbl_copy;

	dbg_in(__func__, "%p, %p, %u, %p, %p", (void *)context, (void *)me,
	       attr, (void *)data, (void *)data_size);

	assert(context && me && data && data_size);

	if ((me_attr_prop_get(me->class, attr) & OMCI_ATTR_PROP_TABLE) == 0)
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);

	*data = NULL;
	*data_size = 0;

	memset(&tbl_copy, 0x00, sizeof(tbl_copy));

	if (me->class->tbl_copy == NULL)
		RETURN_IF_ERROR(OMCI_ERROR_INVALID_ME_ATTR);

	error = me->class->tbl_copy(context, me, attr, &tbl_copy);
	RETURN_IF_ERROR(error);

	*data_size = tbl_copy.data_size;
	*data = IFXOS_MemAlloc(*data_size);
	memcpy(*data, tbl_copy.data, *data_size);

	if (tbl_copy.free_data)
		IFXOS_MemFree(tbl_copy.data);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error me_refresh(struct omci_context *context,
			   struct me *me)
{
	enum omci_error error = OMCI_SUCCESS;
	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	assert(context && me);

	if (me->active)
		error = me->class->update(context, me, me->data,
					  ~me->class->inv_attr_mask);
	else
		omci_hook(context, "update", me->class->class_id,
			  me->instance_id);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return error;
}

/** @} */
