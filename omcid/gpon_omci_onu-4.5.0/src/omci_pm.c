/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_memory_alloc.h"
#include "ifxos_time.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_PM

#ifdef LINUX
#include <unistd.h>
#endif

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_list.h"
#include "me/omci_threshold_data1.h"
#include "me/omci_threshold_data2.h"

#ifdef INCLUDE_PM

/** PM thread shutdown wait time */
#define PM_THREAD_SHUTDOWN_WAIT			1000

/** PM thread polling time (in milliseconds) */
#define PM_POLLING_TIME				(60 * 1000)

/** PM thread priority */
#define PM_THREAD_PRIO				IFXOS_THREAD_PRIO_HIGH

/** PM thread stack size */
#define PM_THREAD_STACKSIZE			IFXOS_DEFAULT_STACK_SIZE

/** \addtogroup OMCI_PM
   @{
*/

static uint64_t attr_data_get(void *data, unsigned int off, int size)
{
	void *p = (uint8_t *)data + off;
	uint8_t data8;
	uint16_t data16;
	uint32_t data32;

	switch (size) {
	case 1:
		memcpy(&data8, p, sizeof(data8));
		return (uint64_t)data8;
	case 2:
		memcpy(&data16, p, sizeof(data16));
		return (uint64_t)data16;
	case 4:
		memcpy(&data32, p, sizeof(data32));
		return (uint64_t)data32;
	default:
		dbg_err("Unsupported data size = %d", size);
		return 0;
	}
}

static void attr_data_set(void *data, unsigned int off, int size, uint64_t val)
{
	void *p = (uint8_t *)data + off;
	uint8_t data8;
	uint16_t data16;
	uint32_t data32;

	switch (size) {
	case 1:
		data8 = (uint8_t)val;
		memcpy(p, &data8, sizeof(data8));
		break;
	case 2:
		data16 = (uint16_t)val;
		memcpy(p, &data16, sizeof(data16));
		break;
	case 4:
		data32 = (uint32_t)val;
		memcpy(p, &data32, sizeof(data32));
		break;
	default:
		dbg_err("Unsupported data size = %d", size);
	}
}

static uint64_t attr_sub(uint64_t lhs, uint64_t rhs, int size)
{
	switch (size) {
	case 1:
		if ((uint8_t)lhs < (uint8_t)rhs)
			return 0xFF - rhs + lhs + 1;
		break;
	case 2:
		if ((uint16_t)lhs < (uint16_t)rhs)
			return 0xFFFF - rhs + lhs + 1;
		break;
	case 4:
		if ((uint32_t)lhs < (uint32_t)rhs)
			return 0xFFFFFFFF - rhs + lhs + 1;
		break;
	default:
		dbg_err("Unsupported data size = %d", size);
		return 0;
	}

	return lhs - rhs;
}

static uint64_t attr_add(uint64_t lhs, uint64_t rhs, int size)
{
	switch (size) {
	case 1:
		if ((uint8_t)(lhs + rhs) < (uint8_t)lhs)
			return 0xFF;
		break;
	case 2:
		if ((uint16_t)(lhs + rhs) < (uint16_t)lhs) {
			return 0xFFFF;
		}
		break;
	case 4:
		if ((uint32_t)(lhs + rhs) < (uint32_t)lhs)
			return 0xFFFFFFFF;
		break;
	default:
		dbg_err("Unsupported data size = %d", size);
		return 0;
	}

	return lhs + rhs;
}

enum omci_error pm_interval_end_time_get(struct omci_context *context,
					 struct me *me,
					 void *data,
					 size_t data_size)
{
	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
		(void *)data, data_size);

	if (data_size < 1) {
		dbg_out_ret(__func__, OMCI_ERROR_BOUNDS);
		return OMCI_ERROR_BOUNDS;
	}

	context_lock(context);
	context->pm.interval_end_time = *(uint8_t *)data;
	context_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_thr_fill(struct omci_context *context,
				   struct me *me,
				   uint8_t tca_bitmap[OMCI_ALARM_BITMAP_SIZE])
{
	enum omci_error error = OMCI_SUCCESS;
	unsigned int attr, thr_attr, tca;
	size_t attr_size;
	unsigned int attr_off;
	void *cur_me_data = me->pm->interval[OMCI_PM_INTERVAL_CURR];
	uint64_t attr_data, thr;
	int i;
	const struct me_tca *const tca_table = me->class->tca_table;

	for (i = 0;
	     tca_table[i].thr_num != 0 &&
	     tca_table[i].attr_num != 0 &&
	     tca_table[i].thr_attr_num != 0;
	     i++) {
		tca = tca_table[i].thr_num,
		attr = tca_table[i].attr_num;
		thr_attr = tca_table[i].thr_attr_num;

		me_dbg_prn(me,
			   "check threshold #%u (for attr #%u, thr_attr #%u)",
			   tca, attr, thr_attr);

		attr_size = me_attr_size_get(me->class, attr);
		attr_off = me_attr_offset_get(me->class, attr);

		attr_data = attr_data_get(cur_me_data, attr_off, attr_size);
		thr = me->pm->thr[thr_attr - 1];

		me_dbg_prn(me, "attr_data = 0x%llx", attr_data);
		me_dbg_prn(me, "thr = 0x%llx", thr);

		/* don't trigger TCA for zero */
		if (thr == 0)
			continue;

		if (attr_data > thr) {
			me_dbg_prn(me, "TCA for #%u", attr);

			error = alarm_set(tca_bitmap, tca, true);
			RETURN_IF_ERROR(error);
		}
	}
	return OMCI_SUCCESS;
}

static enum omci_error me_thr_check(struct omci_context *context,
				    struct me *me)
{
	uint16_t thr_inst;
	uint8_t tca_bitmap[OMCI_ALARM_BITMAP_SIZE] = { 0 };
	bool new_tca;
	unsigned int i;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p", context, me);

	thr_inst = ((struct pm_me_data *)me->data)->thr_data_id;

	error = me_thr_fill(context, me, tca_bitmap);
	RETURN_IF_ERROR(error);

	new_tca = false;
	for (i = 0; i < OMCI_ALARM_BITMAP_SIZE; i++) {
		/* exclude previously crossed thresholds */
		tca_bitmap[i] = (tca_bitmap[i] ^ me->pm->tca_bitmap[i]) &
			tca_bitmap[i];

		/* check if any new threshold was crossed */
		if (tca_bitmap[i])
			new_tca = true;

		/* add new crossed threshold to Managed Entity instance */
		me->pm->tca_bitmap[i] |= tca_bitmap[i];
	}

	if (new_tca)
		error = tca_send(context, me, tca_bitmap);

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error counters_update(struct omci_context *context,
				       struct me *me,
				       void *old_me_data)
{
	enum omci_error error = OMCI_SUCCESS;
	unsigned int attr;
	size_t attr_size;
	unsigned int attr_off;
	void *cur_me_data = me->pm->interval[OMCI_PM_INTERVAL_CURR];
	void *abs_me_data = me->pm->interval[OMCI_PM_INTERVAL_ABS];
	uint64_t new_attr_data, old_attr_data, cur_attr_data, diff;

	dbg_in(__func__, "%p, %p, %p", context, me, old_me_data);

	for (attr = omci_me_pm_counter_1;
	     attr < omci_me_pm_counter_max;
	     attr++) {
		if (!is_me_attr_exist(me->class, attr))
			continue;

		me_dbg_prn(me, "Update counter #%u", attr);

		attr_size = me_attr_size_get(me->class, attr);
		attr_off = me_attr_offset_get(me->class, attr);

		new_attr_data = attr_data_get(abs_me_data, attr_off, attr_size);
		old_attr_data = attr_data_get(old_me_data, attr_off, attr_size);
		cur_attr_data = attr_data_get(cur_me_data, attr_off, attr_size);

		diff = attr_sub(new_attr_data, old_attr_data, attr_size);

		me_dbg_prn(me, "new_attr_data = %llu", new_attr_data);
		me_dbg_prn(me, "old_attr_data = %llu", old_attr_data);
		me_dbg_prn(me, "diff = %llu", diff);
		me_dbg_prn(me, "cur_attr_data = %llu (before)", cur_attr_data);

		cur_attr_data = attr_add(cur_attr_data, diff, attr_size);

		me_dbg_prn(me, "cur_attr_data = %llu (after)", cur_attr_data);

		attr_data_set(cur_me_data, attr_off, attr_size, cur_attr_data);
	}

	dbg_out_ret(__func__, error);
	return error;
}

void pm_me_interval_set(struct omci_context *context,
			struct me *me,
			enum omci_pm_interval interval)
{
	if (me->class->prop & OMCI_ME_PROP_PM_INTERNAL)
		me->data = me->pm->interval[interval];
	else if (me->class->prop & OMCI_ME_PROP_PM)
		(void)pm_me_counters_get(context, me, interval);
}

enum omci_error pm_me_counters_get(struct omci_context *context,
				   struct me *me,
				   enum omci_pm_interval interval)
{
	uint8_t old_data[OMCI_ME_DATA_SIZE_MAX];
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %d", (void *)context, (void *)me, interval);

	me_dbg_msg(me, "Update counters for interval %u", interval);

	if (me->class->counters_get) {
		if (me->class->prop & OMCI_ME_PROP_PM_INTERNAL) {
			memcpy(&old_data,
			       me->pm->interval[OMCI_PM_INTERVAL_ABS],
			       me->class->data_size);

			pm_me_interval_set(context, me, OMCI_PM_INTERVAL_ABS);
		}

		error = me->class->counters_get(context, me, interval);

		if (me->class->prop & OMCI_ME_PROP_PM_INTERNAL) {
			error = counters_update(context, me, old_data);

			if (error != OMCI_SUCCESS) {
				me_dbg_err(me, "Can't update counters for "
					   "interval #%lu", interval);
			}

			if (interval == OMCI_PM_INTERVAL_ABS ||
			    interval == OMCI_PM_INTERVAL_END)
				pm_me_interval_set(context, me,
						   OMCI_PM_INTERVAL_CURR);
			else
				pm_me_interval_set(context, me, interval);
		}

		if (error != OMCI_SUCCESS) {
			me_dbg_err(me, "Can't get counters for interval #%lu",
				   interval);

			goto exit;
		}
	}

	if (me->class->thr_set && me->class->prop & OMCI_ME_PROP_PM_INTERNAL) {
		error = me_thr_check(context, me);
		if (error) {
			me_dbg_err(me, "PmThread - Managed Entity "
				   "thresholds check error (%d)",
				   error);

			goto exit;
		}
	}

exit:
	dbg_out_ret(__func__, error);
	return error;
}

/** PM handling thread

   \param[in] thr_params IFXOS_ThreadParams_t structure
*/
static int32_t pm_thread_main(struct IFXOS_ThreadParams_s *thr_params)
{
	struct omci_context *context = (struct omci_context *)thr_params->nArg1;
	time_t start_time;
	time_t delta_time = 0;
	struct list_entry *entry;
	struct pm_list_entry *pm_entry;

	enum omci_error error;

	dbg_in(__func__, "%p", thr_params);
#ifdef LINUX
	dbg_msg("PmThread - Started (tid %d)", getpid());
#endif

	/* while thread is running */
	while (thr_params->bRunning == IFX_TRUE &&
	       thr_params->bShutDown == IFX_FALSE) {
		dbg_msg("PmThread - Sleep for %u msec...",
			PM_POLLING_TIME - delta_time);

		IFXOS_MSecSleep(PM_POLLING_TIME - (IFX_time_t)delta_time);

		/* check if we are shutting down */
		if (thr_params->bShutDown == IFX_TRUE
		    || thr_params->bRunning == IFX_FALSE) {
			dbg_msg("PmThread - Shutting down...");
			break;
		}

		dbg_msg("PmThread - Woke up, update counters...");

		start_time = IFXOS_ElapsedTimeMSecGet(0);

		mib_lock_read(context);

		/* update counters for each PM entry in the list */
		list_lock(&context->pm.list);

		foreach_list_entry(&context->pm.list, entry) {
			pm_entry = list_entry_data(entry);

			me_lock(context, pm_entry->me);
			error = pm_me_counters_get(context, pm_entry->me,
						   OMCI_PM_INTERVAL_ABS);
			me_unlock(context, pm_entry->me);
			if (error) {
				me_dbg_err(pm_entry->me,
					   "PmThread - Managed Entity "
					   "counters update error (%d)",
					   error);
			}
		}

		list_unlock(&context->pm.list);

		mib_unlock(context);

		delta_time = IFXOS_ElapsedTimeMSecGet((IFX_time_t) start_time);

		if (delta_time > PM_POLLING_TIME) {
			dbg_err("PmThread - Handling is too slow ( > %u ms)",
				PM_POLLING_TIME);

			delta_time = 0;
		}
	}

	dbg_msg("PmThread - Bye");

	return 0;
}

/** Start PM thread

   \param[in] context OMCI context pointer
*/
static enum omci_error pm_thread_start(struct omci_context *context)
{
	enum omci_error error;

	dbg_in(__func__, "%p", context);

	error = (enum omci_error)IFXOS_ThreadInit(&context->pm.thread_ctrl,
						  "omcipm",
						  pm_thread_main,
						  PM_THREAD_STACKSIZE,
						  PM_THREAD_PRIO,
						  (unsigned long)context, 0);
	if (error) {
		dbg_out_ret(__func__, error);
		return error;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Stop PM thread

   \param[in] context OMCI context pointer
*/
static enum omci_error pm_thread_stop(struct omci_context *context)
{
   dbg_in(__func__, "%p", context);

   (void)IFXOS_ThreadDelete(&context->pm.thread_ctrl,
                            PM_THREAD_SHUTDOWN_WAIT);

   dbg_out_ret(__func__, OMCI_SUCCESS);
   return OMCI_SUCCESS;
}

enum omci_error pm_init(struct omci_context *context)
{
	enum omci_error error;

	dbg_in(__func__, "%p", context);

	list_init(&context->pm.list, sizeof(struct pm_list_entry));

	error = pm_thread_start(context);
	if (error) {
		dbg_out_ret(__func__, error);
		return error;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error pm_shutdown(struct omci_context *context)
{
	dbg_in(__func__, "%p", context);

	(void)pm_thread_stop(context);

	list_delete(&context->pm.list);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error default_me_thr_set(struct omci_context *context,
				   struct me *me,
				   uint32_t thr[PM_THR_NUM])
{
	int i;

	if ((me->class->prop & OMCI_ME_PROP_PM_INTERNAL) == 0) {
		me_dbg_wrn(me, "Setting %s for external PM ME doesn't make "
			   "any sense", __func__);
		return OMCI_SUCCESS;
	}

	for (i = 0; i < PM_THR_NUM; i++)
		me->pm->thr[i] = thr[i];

	return OMCI_SUCCESS;
}

static enum omci_error interval_end_walker(struct omci_context *context,
					   struct me *me,
					   void *shared_data)
{
	enum omci_error error;
	void *tmp_interval;

	(void)shared_data;

	if ((me->class->prop & OMCI_ME_PROP_PM) == 0)
		return OMCI_SUCCESS;

	if (me->alarm_bitmap) {
		if (is_alarm_bitmap_empty(me->alarm_bitmap) == false) {
			error = tca_send(context, me, me->alarm_bitmap);
			RETURN_IF_ERROR(error);

			error = alarm_bitmap_clear(me->alarm_bitmap);
			RETURN_IF_ERROR(error);
		}
	}

	if (me->class->prop & OMCI_ME_PROP_PM_INTERNAL) {
		me_dbg_prn(me, "Save history");

		error = pm_me_counters_get(context, me,
					   OMCI_PM_INTERVAL_END);
		if (error != OMCI_SUCCESS)
			me_dbg_err(me, "Failed to execute counters update "
				   "with OMCI_PM_INTERVAL_END");

		tmp_interval = me->pm->interval[OMCI_PM_INTERVAL_HIST];
		me->pm->interval[OMCI_PM_INTERVAL_HIST] =
			me->pm->interval[OMCI_PM_INTERVAL_CURR];
		me->pm->interval[OMCI_PM_INTERVAL_CURR] = tmp_interval;

		memset(tmp_interval, 0, me->class->data_size);

		/* copy back non-counters values from the history */
		memcpy(tmp_interval, me->pm->interval[OMCI_PM_INTERVAL_HIST],
		       1 + 2 /* interval end time + thr data id */);

		/* clear TCAs */
		memset(me->pm->tca_bitmap, 0, sizeof(me->pm->tca_bitmap));
	}

	return OMCI_SUCCESS;
}

enum omci_error pm_interval_end(struct omci_context *context,
				uint8_t interval_end_time)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %u", (void *)context, interval_end_time);

	RETURN_IF_PTR_NULL(context);

	context_lock(context);
	context->pm.interval_end_time = interval_end_time;
	context_unlock(context);

	mib_lock_write(context);

	error = mib_walk(context, interval_end_walker, NULL);
	if (error != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) while cleaning TCA data", error);
	}

	mib_unlock(context);

	dbg_prn("#%u 15-min interval has been passed", interval_end_time);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error pm_me_context_alloc(struct me *me)
{
	enum omci_error error;

	dbg_in(__func__, "%p", me);

	if ((me->class->prop & OMCI_ME_PROP_PM_INTERNAL) == 0) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	me->pm = IFXOS_MemAlloc(sizeof(*me->pm));
	if (!me->pm)
		return OMCI_ERROR_MEMORY;

	me->pm->interval[OMCI_PM_INTERVAL_CURR] = me->data;
	me->pm->interval[OMCI_PM_INTERVAL_HIST] =
		IFXOS_MemAlloc(me->class->data_size);
	me->pm->interval[OMCI_PM_INTERVAL_ABS] =
		IFXOS_MemAlloc(me->class->data_size);

	if (!me->pm->interval[OMCI_PM_INTERVAL_CURR] ||
	    !me->pm->interval[OMCI_PM_INTERVAL_HIST] ||
	    !me->pm->interval[OMCI_PM_INTERVAL_ABS]) {
		error = OMCI_ERROR_MEMORY;

		goto free_pm_context;
	}

	memset(me->pm->interval[OMCI_PM_INTERVAL_CURR], 0,
	       me->class->data_size);
	memset(me->pm->interval[OMCI_PM_INTERVAL_HIST], 0,
	       me->class->data_size);
	memset(me->pm->interval[OMCI_PM_INTERVAL_ABS], 0,
	       me->class->data_size);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;

free_pm_context:
	(void)pm_me_context_free(me);
	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error pm_me_context_free(struct me *me)
{
	dbg_in(__func__, "%p", me);

	if ((me->class->prop & OMCI_ME_PROP_PM_INTERNAL) == 0) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	IFXOS_MemFree(me->pm->interval[OMCI_PM_INTERVAL_HIST]);
	IFXOS_MemFree(me->pm->interval[OMCI_PM_INTERVAL_ABS]);
	IFXOS_MemFree(me->pm);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error pm_me_add(struct omci_context *context,
			  struct me *me)
{
	enum omci_error error = OMCI_SUCCESS;
	struct list_entry *entry;
	struct pm_list_entry *pm_entry;

	dbg_in(__func__, "%p, %p", context, me);

	if ((me->class->prop & OMCI_ME_PROP_PM_INTERNAL) == 0) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	list_lock(&context->pm.list);
	entry = list_entry_alloc(&context->pm.list);
	if (!entry) {
		list_unlock(&context->pm.list);
		error = OMCI_ERROR_MEMORY;
		dbg_out_ret(__func__, error);
		return error;
	}

	pm_entry = list_entry_data(entry);
	pm_entry->me = me;

	list_entry_add_tail(&context->pm.list, entry);

	list_unlock(&context->pm.list);
	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error pm_me_remove(struct omci_context *context,
			     struct me *me)
{
	struct list_entry *entry, *next_entry;
	struct pm_list_entry *pm_entry;

	dbg_in(__func__, "%p, %p", context, me);

	if ((me->class->prop & OMCI_ME_PROP_PM_INTERNAL) == 0) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	list_lock(&context->pm.list);

	foreach_list_entry_safe(&context->pm.list, entry, next_entry) {
		pm_entry = list_entry_data(entry);

		if (pm_entry->me == me) {
			list_entry_free(&context->pm.list, entry);
			break;
		}
	}

	list_unlock(&context->pm.list);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error pm_me_thr_set(struct omci_context *context,
			     struct me *me)
{
	uint16_t thr_data;
	struct me *thr1, *thr2;
	enum omci_error error;
	uint32_t thr[PM_THR_NUM] = { 0 };
	struct omci_me_threshold_data1 thr1_data;
	struct omci_me_threshold_data2 thr2_data;

	error = me_attr_read(context, me, omci_me_pm_thr_data_id,
			     &thr_data, sizeof(thr_data));
	RETURN_IF_ERROR(error);

	error = mib_me_find(context, OMCI_ME_THRESHOLD_DATA1, thr_data, &thr1);
	if (error == OMCI_SUCCESS) {
		me_lock(context, thr1);
		error = me_data_read(context, thr1, &thr1_data,
				     sizeof(thr1_data), OMCI_PM_INTERVAL_CURR);
		me_unlock(context, thr1);
		RETURN_IF_ERROR(error);

		thr[0] = thr1_data.thr_data1;
		thr[1] = thr1_data.thr_data2;
		thr[2] = thr1_data.thr_data3;
		thr[3] = thr1_data.thr_data4;
		thr[4] = thr1_data.thr_data5;
		thr[5] = thr1_data.thr_data6;
		thr[6] = thr1_data.thr_data7;
	}

	error = mib_me_find(context, OMCI_ME_THRESHOLD_DATA2, thr_data, &thr2);
	if (error == OMCI_SUCCESS) {
		me_lock(context, thr2);
		error = me_data_read(context, thr2, &thr2_data,
				     sizeof(thr2_data), OMCI_PM_INTERVAL_CURR);
		me_unlock(context, thr2);
		RETURN_IF_ERROR(error);

		thr[8] = thr2_data.thr_data8;
		thr[9] = thr2_data.thr_data9;
		thr[10] = thr2_data.thr_data10;
		thr[11] = thr2_data.thr_data11;
		thr[12] = thr2_data.thr_data12;
		thr[13] = thr2_data.thr_data13;
		thr[14] = thr2_data.thr_data14;
	}

	if (me->class->thr_set)
		me->class->thr_set(context, me, thr);

	return error;
}

/** @} */

#endif
