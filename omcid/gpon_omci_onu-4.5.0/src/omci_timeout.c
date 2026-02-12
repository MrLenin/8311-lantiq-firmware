/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_memory_alloc.h"
#include "ifxos_time.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_CORE

#ifdef LINUX
#include <unistd.h>
#endif

#include "omci_core.h"
#include "omci_debug.h"

/** \addtogroup OMCI_TIMEOUT
   @{
*/

/** timeout thread poll time (in milliseconds) */
#define TIMEOUT_THREAD_POLL_TIME	100

/** timeout thread priority */
#define TIMEOUT_THREAD_PRIO		IFXOS_THREAD_PRIO_NORMAL

/** timeout thread stack size */
#define TIMEOUT_THREAD_STACK_SIZE	IFXOS_DEFAULT_STACK_SIZE

/** timeout thread shutdown wait */
#define TIMEOUT_THREAD_SHUTDOWN_WAIT	5000

/** Get next timeouted event

   \param[in]  context    OMCI context pointer
   \param[out] timeout    Returns timeout descriptor
   \param[out] timeout_id Returns timeout identifier
*/
static enum omci_error next_active_event_get(struct omci_context *context,
					     struct timeout *timeout,
					     unsigned long *timeout_id)
{
	struct timeout_list_entry *first_entry;

	if (is_list_empty(&context->timeout_list)) {
		return OMCI_ERROR;
	}

	first_entry = list_entry_data(context->timeout_list.used.next);

	if (first_entry->timeout_time <= (time_t)IFXOS_ElapsedTimeMSecGet(0)) {
		*timeout_id = first_entry->timeout_id;
		*timeout = first_entry->timeout;

		return OMCI_SUCCESS;
	}

	return OMCI_ERROR;
}

/** Get next most recent timeouted event

   \param[in]  context    OMCI context pointer
   \param[out] timeout    Returns timeout descriptor
   \param[out] timeout_id Returns timeout identifier
*/
static enum omci_error next_event_get(struct omci_context *context,
				      struct timeout *timeout,
				      unsigned long *timeout_id)
{
	struct timeout_list_entry *first_entry;

	if (is_list_empty(&context->timeout_list)) {
		return OMCI_ERROR;
	}

	first_entry = list_entry_data(context->timeout_list.used.next);

	*timeout_id = first_entry->timeout_id;
	*timeout = first_entry->timeout;

	return OMCI_SUCCESS;
}

/** Lock less version of timeout_event_remove */
static enum omci_error lockless_event_remove(struct omci_context *context,
					     unsigned long timeout_id)
{
	struct list_entry *entry, *tmp_entry;
	struct timeout_list_entry *timeout_entry = NULL;

	if (is_list_empty(&context->timeout_list)) {
		return OMCI_SUCCESS;
	}

	foreach_list_entry_safe(&context->timeout_list, entry, tmp_entry) {
		timeout_entry = list_entry_data(entry);

		if (timeout_entry->timeout_id == timeout_id) {
			dbg_msg("Removed timeout event with id = %lu",
				timeout_id);

			list_entry_free(&context->timeout_list, entry);

			return OMCI_SUCCESS;
		}
	}

	dbg_err("Can't remove timeout event with id = %lu", timeout_id);

	return OMCI_SUCCESS;
}

enum omci_error timeout_init(struct omci_context *context)
{
	enum omci_error error;

	dbg_in(__func__, "%p", (void *)context);

	error = list_init(&context->timeout_list,
			  sizeof(struct timeout_list_entry));
	RETURN_IF_ERROR(error);

	/* start thread */
	error = timeout_thread_start(context);
	if (error) {
		list_delete(&context->timeout_list);

		dbg_out_ret(__func__, error);
		return error;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error timeout_shutdown(struct omci_context *context)
{
	unsigned long timeout_id;
	struct timeout timeout;
	enum omci_error error;

	dbg_in(__func__, "%p", (void *)context);

	(void)timeout_thread_stop(context);

	list_lock(&context->timeout_list);

	/* execute all timeout events */
	while (next_event_get(context, &timeout, &timeout_id) == OMCI_SUCCESS) {
		if (timeout.handler != NULL)
			(void)timeout.handler(context, &timeout);

		error = lockless_event_remove(context, timeout_id);
		if (error != OMCI_SUCCESS) {
			dbg_err("ERROR(%d) Can't delete timeout "
				"with id %lu", error, timeout_id);
		}
	}

	list_unlock(&context->timeout_list);

	list_delete(&context->timeout_list);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Add timeout event

   \param[in]  context      OMCI context pointer
   \param[in]  timeout      Timeout descriptor
   \param[out] timeout_id   Returns generated timeout identifier
   \param[in]  timeout_time Timeout value (in ms)
*/
static enum omci_error event_entry_add(struct omci_context *context,
				       const struct timeout *timeout,
				       unsigned long *timeout_id,
				       time_t timeout_time)
{
	struct list_entry *new_entry, *entry, *tmp_entry;
	struct timeout_list_entry *timeout_entry, *new_timeout_entry;
	bool added = false;

	list_lock(&context->timeout_list);

	new_entry = list_entry_alloc(&context->timeout_list);
	if (!new_entry) {
		list_unlock(&context->timeout_list);
		return OMCI_ERROR_MEMORY;
	}

	new_timeout_entry = list_entry_data(new_entry);

	memcpy(&new_timeout_entry->timeout, timeout,
	       sizeof(struct timeout));

	context->last_timeout_id++;

	if (context->last_timeout_id == 0)
		context->last_timeout_id++;

	new_timeout_entry->timeout_id = context->last_timeout_id;
	new_timeout_entry->timeout_time = IFXOS_ElapsedTimeMSecGet(0)
		+ timeout_time;

	if (timeout_id)
		*timeout_id = new_timeout_entry->timeout_id;

	foreach_list_entry_safe(&context->timeout_list, entry, tmp_entry) {
		timeout_entry = list_entry_data(entry);

		if (timeout_entry->timeout_time >
		    new_timeout_entry->timeout_time) {
			list_entry_add_before(&context->timeout_list, entry,
					      new_entry);

			added = true;
			break;
		}
	}

	if (!added)
		list_entry_add_tail(&context->timeout_list, new_entry);

	dbg_msg("Added timeout event with id = %lu, timeout = %lu ms",
		new_timeout_entry->timeout_id, timeout_time);

	list_unlock(&context->timeout_list);

	return OMCI_SUCCESS;
}

enum omci_error timeout_event_add(struct omci_context *context,
				  unsigned long *timeout_id,
				  time_t timeout_time,
				  timeout_handler *handler,
				  unsigned short class_id,
				  unsigned short instance_id,
				  unsigned long arg1,
				  unsigned long arg2,
				  unsigned long arg3)
{
	struct timeout timeout;

	assert(context && handler);

	timeout.handler = handler;
	timeout.arg1 = arg1;
	timeout.arg2 = arg2;
	timeout.arg3 = arg3;
	timeout.class_id = class_id;
	timeout.instance_id = instance_id;

	return event_entry_add(context, &timeout, timeout_id, timeout_time);
}

enum omci_error timeout_event_remove(struct omci_context *context,
				     unsigned long timeout_id)
{
	enum omci_error error;

	list_lock(&context->timeout_list);
	error = lockless_event_remove(context, timeout_id);
	list_unlock(&context->timeout_list);

	return error;
}

/** timeout events handling thread

   \param[in] thr_params Thread arguments
*/
static int32_t timeout_thread_main(struct IFXOS_ThreadParams_s *thr_params)
{
	struct omci_context *context = (struct omci_context *)thr_params->nArg1;
	unsigned long timeout_id = 0;
	struct timeout timeout;
	enum omci_error error;

	dbg_in(__func__, "%p", (void *)thr_params);

#ifdef LINUX
	dbg_msg("TimeoutThread (tid %d)", (int)getpid());
#endif

	/* while thread is running */
	while (thr_params->bRunning == IFX_TRUE &&
	       thr_params->bShutDown == IFX_FALSE) {
		dbg_msg("Timeout - Waiting for timeout event...");

		/* wait for message in FIFO */
		while (1) {
			list_lock(&context->timeout_list);

			if (next_active_event_get
			    (context, &timeout, &timeout_id) != OMCI_SUCCESS
			    && thr_params->bShutDown == IFX_FALSE
			    && thr_params->bRunning == IFX_TRUE) {

				list_unlock(&context->timeout_list);

				IFXOS_MSecSleep(TIMEOUT_THREAD_POLL_TIME);
			} else {
				list_unlock(&context->timeout_list);
				break;
			}
		}

		/* check if we are shutting down */
		if (thr_params->bShutDown == IFX_TRUE
		    || thr_params->bRunning == IFX_FALSE) {
			dbg_msg("Timeout - Shutting down...");

			break;
		}

		dbg_msg("Timeout - Handle timeout event with id = %lu... %u@%u",
			timeout_id, timeout.class_id, timeout.instance_id);

		if (timeout.handler != NULL) {
			error = timeout.handler(context, &timeout);

			if (error) {
				dbg_msg("Timeout - Got the %d error from the "
					"timeout handler", error);
			}
		} else {
			dbg_err("Timeout - ERROR(%d): found timeout event "
				"without timeout handler", OMCI_DBG_ERR);
		}

		list_lock(&context->timeout_list);
		(void)lockless_event_remove(context, timeout_id);
		list_unlock(&context->timeout_list);
	}

	dbg_msg("Timeout - Bye");

	dbg_out_ret(__func__, 0);
	return 0;
}

enum omci_error timeout_thread_start(struct omci_context *context)
{
	enum omci_error error;

	error = (enum omci_error)IFXOS_ThreadInit(&context->timeout_thread_ctrl,
						  "omcitm",
						  timeout_thread_main,
						  TIMEOUT_THREAD_STACK_SIZE,
						  TIMEOUT_THREAD_PRIO,
						  (unsigned long)context,
						  0);

	return error;
}

enum omci_error timeout_thread_stop(struct omci_context *context)
{
	(void)IFXOS_ThreadDelete(&context->timeout_thread_ctrl,
				 TIMEOUT_THREAD_SHUTDOWN_WAIT);

	return OMCI_SUCCESS;
}

/** @} */
