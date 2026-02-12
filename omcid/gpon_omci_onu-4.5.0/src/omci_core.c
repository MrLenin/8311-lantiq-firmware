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
#include "omci_msg_dump.h"
#include "omci_debug.h"

#ifdef LINUX
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#endif

/** \addtogroup OMCI_CORE
   @{
*/

/** Core thread priority */
#define CORE_THREAD_PRIO		IFXOS_THREAD_PRIO_HIGH

/** Core thread stack size */
#define CORE_THREAD_STACK_SIZE		IFXOS_DEFAULT_STACK_SIZE

/** Core thread shutdown wait time */
#define CORE_THREAD_SHUTDOWN_WAIT	5000

/** Core thread received FIFO polling time (in ms) */
#define CORE_THREAD_POLL_TIME		1

/** Core thread received FIFO event wait timeout (in ms) */
#define CORE_THREAD_MSG_FIFO_TIMEOUT	1000

/** Action thread priority */
#define ACTION_THREAD_PRIO		IFXOS_THREAD_PRIO_HIGH

/** Action thread stack size */
#define ACTION_THREAD_STACK_SIZE	IFXOS_DEFAULT_STACK_SIZE

/** Action thread shutdown wait time */
#define ACTION_THREAD_SHUTDOWN_WAIT	5000

/** Action thread received FIFO polling time (in ms) */
#define ACTION_THREAD_POLL_TIME		1

/** Action thread event wait timeout (in ms) */
#define ACTION_THREAD_TIMEOUT		1000

/** This switch is introduced for disabling AVCs (0 - disabled) */
#define AVC_SEND			1

void context_lock(struct omci_context *context)
{
	dbg_msg("{ LOCK   CTX    (%p)", (void *)&context->lock);
	if (lock_get(&context->lock) != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't lock context (%p)",
			OMCI_ERROR_LOCK,
			(void *)&context->lock);
		abort();
	}
}

void context_unlock(struct omci_context *context)
{
	dbg_msg("} UNLOCK CTX    (%p)", (void *)&context->lock);
	if (lock_release(&context->lock) != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't unlock context (%p)",
			OMCI_ERROR_LOCK,
			(void *)&context->lock);
		abort();
	}
}

void table_copy_lock(struct omci_context *context)
{
	dbg_msg("{ LOCK   ATTRCP (%p)", (void *)&context->tbl_copy.lock);
	if (lock_get(&context->tbl_copy.lock) != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't lock table attribute copy (%p)",
			OMCI_ERROR_LOCK,
			(void *)&context->tbl_copy.lock);
		abort();
	}
}

void table_copy_unlock(struct omci_context *context)
{
	dbg_msg("} UNLOCK ATTRCP (%p)", (void *)&context->tbl_copy.lock);
	if (lock_release(&context->tbl_copy.lock) != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't unlock table attribute copy (%p)",
			OMCI_ERROR_LOCK,
			(void *)&context->tbl_copy.lock);
		abort();
	}
}

/** Check if given OMCI Message is correct

   \param[in] msg OMCI Message pointer

   \return true if message is correct
   \return false otherwise
*/
static inline bool omci_is_msg_correct(const union omci_msg *msg)
{
	if (omci_msg_type_db_get(msg)) {
		dbg_msg("MsgType.Db != 0");

		return false;
	}

	if (omci_msg_type_mt_get(msg) > 28 || omci_msg_type_mt_get(msg) < 4) {
		dbg_msg("MsgType.Mt(0x%02x) is out of range",
			omci_msg_type_mt_get(msg));

		return false;
	}

	if (msg->msg.header.dev_id != OMCI_FORMAT_BASELINE) {
		dbg_msg("Unknown Device identifier (0x%02x != 0x0a)",
			msg->msg.header.dev_id);

		return false;
	}

	return true;
}

/** Free resources associated with temporary Self Description ME */
static void self_desc_me_free(struct omci_context *context,
			      const union omci_msg *msg,
			      struct me *me)
{
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	if (ntoh16(msg->msg.header.class_id) == OMCI_ME_OMCI
	    || ntoh16(msg->msg.header.class_id) == OMCI_ME_MANAGED_ENTITY
	    || ntoh16(msg->msg.header.class_id) == OMCI_ME_ATTRIBUTE) {
		if (me)
			(void)me_lock_delete(me);
	}
#endif
}

/** Allocate new temporary Self Description ME */
static enum omci_error self_desc_me_find(struct omci_context *context,
					 const union omci_msg *msg,
					 union omci_msg *rsp,
					 struct me *sd_me)
{
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	unsigned int i;
	unsigned int attr;
	enum omci_error error;

	if (ntoh16(msg->msg.header.class_id) == OMCI_ME_OMCI) {
		memset(sd_me, 0, sizeof(*sd_me));

		if (ntoh16(msg->msg.header.instance_id) == 0) {
			sd_me->instance_id = 0;
			error = mib_me_class_resolve(context, OMCI_ME_OMCI,
						     &sd_me->class);

			if (error) {
				/* don't send RSP */
				omci_msg_type_ak_set(rsp, 0);

				dbg_out_ret(__func__, OMCI_ERROR_ACTION);
				return OMCI_ERROR_ACTION;
			}

			error = me_lock_init(sd_me);
			if (error) {
				/* don't send RSP */
				omci_msg_type_ak_set(rsp, 0);

				dbg_out_ret(__func__, OMCI_ERROR_ACTION);
				return OMCI_ERROR_ACTION;
			}
		}

		return OMCI_SUCCESS;
	} else if (ntoh16(msg->msg.header.class_id) == OMCI_ME_MANAGED_ENTITY) {
		memset(sd_me, 0, sizeof(*sd_me));

		for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
			if (me_def_class_array[i]->class_id
			    == ntoh16(msg->msg.header.instance_id)) {

				sd_me->instance_id =
					ntoh16(msg->msg.header.instance_id);
				error = mib_me_class_resolve(context,
							     OMCI_ME_MANAGED_ENTITY,
							     &sd_me->class);

				if (error) {
					/* don't send RSP */
					omci_msg_type_ak_set(rsp, 0);

					dbg_out_ret(__func__,
						    OMCI_ERROR_ACTION);
					return OMCI_ERROR_ACTION;
				}

				error = me_lock_init(sd_me);
				if (error) {
					/* don't send RSP */
					omci_msg_type_ak_set(rsp, 0);

					dbg_out_ret(__func__,
						    OMCI_ERROR_ACTION);
					return OMCI_ERROR_ACTION;
				}

				break;
			}
		}

		return OMCI_SUCCESS;
	} else if (ntoh16(msg->msg.header.class_id) == OMCI_ME_ATTRIBUTE) {
		memset(sd_me, 0, sizeof(*sd_me));

		attr = (ntoh16(msg->msg.header.instance_id) & 0xf000) >> 12;

		for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
			if (me_def_class_array[i]->class_id ==
			    (ntoh16(msg->msg.header.instance_id) & 0x0fff)) {
				if (me_def_class_array[i]->attrs[attr].prop
				    == OMCI_ATTR_PROP_NONE) {
					break;
				}

				sd_me->instance_id =
				    ntoh16(msg->msg.header.instance_id);

				error = mib_me_class_resolve(context,
							     OMCI_ME_ATTRIBUTE,
							     &sd_me->class);

				if (error) {
					/* don't send RSP */
					omci_msg_type_ak_set(rsp, 0);

					dbg_out_ret(__func__,
						    OMCI_ERROR_ACTION);
					return OMCI_ERROR_ACTION;
				}

				error = me_lock_init(sd_me);
				if (error) {
					/* don't send RSP */
					omci_msg_type_ak_set(rsp, 0);

					dbg_out_ret(__func__,
						    OMCI_ERROR_ACTION);
					return OMCI_ERROR_ACTION;
				}

				break;
			}
		}

		return OMCI_SUCCESS;
	}
#endif
	return OMCI_ERROR_ME_NOT_FOUND;
}

enum omci_error msg_handle(struct omci_context *context,
			   const union omci_msg *msg,
			   union omci_msg *rsp)
{
	struct me sd_me;
	struct me *me;
	const struct me_class *me_class = NULL;
	me_action_handler *action_handler;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)msg,
	       (void *)rsp);

	/* create empty resp MSG (clear given) to arrived message */
	error = rsp_create(msg, rsp);
	RETURN_IF_ERROR(error);

	/* filter messages with AK = 1 */
	if (omci_msg_type_ak_get(msg)) {
		dbg_msg("Received response message [OMCI_MR_CMD_ERROR]");

		/* don't send RSP */
		omci_msg_type_ak_set(rsp, 0);

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

	/* check message */
	if (omci_is_msg_correct(msg) != true) {
		dbg_msg("Received incorrect message [OMCI_MR_CMD_ERROR]");

		/* don't send RSP */
		omci_msg_type_ak_set(rsp, 0);

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

	/* find target me */
	error = self_desc_me_find(context, msg, rsp, &sd_me);
	if (error == OMCI_SUCCESS)
		me = &sd_me;
	else
		(void)mib_me_find(context, ntoh16(msg->msg.header.class_id),
				  ntoh16(msg->msg.header.instance_id), &me);

	/* ME instance was not found & message type != create; exit */
	if (me == NULL && omci_msg_type_mt_get(msg) != OMCI_MT_CREATE) {
		/* check if we support required Managed Entity class */
		if (mib_me_class_resolve(context,
					 ntoh16(msg->msg.header.class_id), NULL)
		    == OMCI_ERROR_ME_NOT_SUPPORTED) {
			dbg_err("Managed Entity class id = %u not supported",
				ntoh16(msg->msg.header.class_id));

			rsp->msg_rsp.result = OMCI_MR_UNKNOWN_ME;
		} else {
			dbg_err("Managed Entity instance %u@%u was not found",
				ntoh16(msg->msg.header.class_id),
				ntoh16(msg->msg.header.instance_id));

			rsp->msg_rsp.result = OMCI_MR_UNKNOWN_ME_INST;
		}

		error = OMCI_ERROR_ACTION;
		goto exit;
	}

	/* ME instance was not found, resolve class */
	if (me == NULL) {
		/* get ME class from MIB_MeClassResolve */
		error = mib_me_class_resolve(context,
					     ntoh16(msg->msg.header.class_id),
					     &me_class);

		/* check if this ME class is supported */
		if (error == OMCI_ERROR_ME_NOT_SUPPORTED) {
			dbg_err("Managed Entity class id = %u not supported",
				ntoh16(msg->msg.header.class_id));

			rsp->msg_rsp.result = OMCI_MR_UNKNOWN_ME;

			error = OMCI_ERROR_ACTION;
			goto exit;
		}

		if (error != OMCI_SUCCESS)
			goto exit;
	}
	/* get ME class from ME instance ptr */
	else {
		me_class = me->class;
	}

	/* get action handler */
	error = me_action_handler_get(me_class, omci_msg_type_mt_get(msg),
				      &action_handler);
	assert(error != OMCI_ERROR_INVALID_ME_ACTION);

	if (error != OMCI_SUCCESS)
		goto exit;

	/* if this action is NOT allowed for this ME (ME doesn't support this
	   action) */
	if (action_handler == NULL) {
		/* ERR ?! */
		dbg_err("Unsupported action %d for Managed "
			"Entity class id = %u",
			omci_msg_type_mt_get(msg),
			ntoh16(msg->msg.header.class_id));

		rsp->msg_rsp.result = OMCI_MR_CMD_NOT_SUPPORTED;

		error = OMCI_ERROR_ACTION;
		goto exit;
	}

	/* execute action & handle result */

	if (me && omci_msg_type_mt_get(msg) != OMCI_MT_MIB_RESET &&
	    omci_msg_type_mt_get(msg) != OMCI_MT_DELETE)
		me_lock(context, me);

	error = action_handler(context, me, msg, rsp);

	if (me && omci_msg_type_mt_get(msg) != OMCI_MT_MIB_RESET &&
	    omci_msg_type_mt_get(msg) != OMCI_MT_DELETE)
		me_unlock(context, me);

exit:
	self_desc_me_free(context, msg, me);

	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error msg_fifo_init(struct omci_context *context)
{
	unsigned int buff_size;

	dbg_in(__func__, "%p", (void *)context);

	buff_size = sizeof(union omci_msg) * OMCI_RECEIVED_MSG_FIFO_SIZE;
	buff_size += sizeof(long) - (buff_size % sizeof(long));

	/* allocate space for FIFO buffer */
	context->msg_fifo.buf = IFXOS_MemAlloc(buff_size);

	if (context->msg_fifo.buf == NULL) {
		dbg_err("ERROR(%d) Memory allocation error for 'context->"
			"msg_fifo.buf' in %s", OMCI_ERROR_MEMORY, __func__);
		dbg_out_ret(__func__, OMCI_ERROR_MEMORY);
		return OMCI_ERROR_MEMORY;
	}

	/* init FIFO */
	if (IFX_Var_Fifo_Init(&context->msg_fifo.fifo,
			      context->msg_fifo.buf,
			      (unsigned long *)
			      ((uint8_t *)context->msg_fifo.buf + buff_size),
			      sizeof(union omci_msg)) != IFX_SUCCESS) {
		IFXOS_MemFree(context->msg_fifo.buf);

		dbg_err("ERROR(%d) FIFO (context->msg_fifo.fifo) init error",
			OMCI_ERROR_MEMORY);
		dbg_out_ret(__func__, OMCI_ERROR_MEMORY);
		return OMCI_ERROR_MEMORY;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error msg_fifo_shutdown(struct omci_context *context)
{
	dbg_in(__func__, "%p", (void *)context);

	IFXOS_MemFree(context->msg_fifo.buf);
	context->msg_fifo.buf = NULL;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error tbl_copy_init(struct omci_context *context)
{
	enum omci_error error;

	dbg_in(__func__, "%p", (void *)context);

	memset(&context->tbl_copy, 0, sizeof(struct tbl_copy));

	error = lock_init(&context->tbl_copy.lock);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

long timevaldiff(struct timeval *start, struct timeval *stop)
{
	long msec;
	msec = (stop->tv_sec - start->tv_sec)*1000;
	msec += (stop->tv_usec - start->tv_usec)/1000;
	return msec;
}

enum omci_error tbl_copy_shutdown(struct omci_context *context)
{
	dbg_in(__func__, "%p", (void *)context);

	(void)lock_delete(&context->tbl_copy.lock);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Remember response to the incoming message */
static void rsp_remember(struct omci_context *context,
			 const uint16_t tci,
			 union omci_msg *rsp)
{
	uint8_t prio = tci & 0x8000 ? 1 : 0;

	context->retransmit.data[prio].rsp = *rsp;
	context->retransmit.data[prio].tci = tci;
	context->retransmit.data[prio].valid = true;
}

/** Retransmit message if any */
static bool rsp_retransmit(struct omci_context *context,
			   const uint16_t tci,
			   union omci_msg *rsp)
{
	uint8_t prio = tci & 0x8000 ? 1 : 0;
	bool ret = false;

	context_lock(context);

	if (context->retransmit.data[prio].valid &&
		tci == context->retransmit.data[prio].tci) {
		*rsp = context->retransmit.data[prio].rsp;
		dbg_err("OMCI - retransmit tid 0x%04x", tci);
		ret = true;
	}

	context_unlock(context);

	return ret;
}

void retransmit_flush(struct omci_context *context)
{
	context_lock(context);
	context->retransmit.data[0].valid = false;
	context->retransmit.data[1].valid = false;
	context_unlock(context);
}

int service_busy_device(struct omci_context *context,
			union omci_msg *msg)
{
	enum omci_error error;
	static union omci_msg rsp;
	/*uint8_t mt;*/

	if (msg) {
		(void)rsp_create(msg, &rsp);
		/* doesn't work with Dasan OLT
		mt = omci_msg_type_mt_get(msg);
		if (mt == OMCI_MT_CREATE
			|| mt == OMCI_MT_DELETE
			|| mt == OMCI_MT_MIB_RESET
			|| mt == OMCI_MT_GET
			|| mt == OMCI_MT_SET) {
			rsp.msg_rsp.result = OMCI_MR_DEVICE_BUSY;
		}*/
	}

	error = omci_msg_send(context, &rsp);
	if (error) {
		dbg_err("service_busy_device - Got the %d error from "
			"omci_msg_send", error);
	}

	return 1;
}

int service_delayed_action(struct omci_context *context,
			   union omci_msg *msg)
{
	enum omci_error error;
	union omci_msg rsp;

	context_lock(context);
	if (!context->action.ready) {
		context_unlock(context);
		return 0;
	}

	context->action.ready = false;
	rsp = context->action.rsp;
	context_unlock(context);

	if (omci_msg_type_ak_get(&rsp) == 0) {
		dbg_err("service_delayed_action - Drop message with Ak == 0");
		return 0;
	}

	error = omci_msg_send(context, &rsp);
	if (error) {
		dbg_err("service_delayed_action - Got the %d error from "
			"omci_msg_send", error);
	}

	return 1;
}

int service_retransmission(struct omci_context *context,
			   union omci_msg *msg)
{
	enum omci_error error;
	union omci_msg rsp;
	bool retransmit;

	retransmit = rsp_retransmit(context, msg->msg.header.tci, &rsp);
	if (!retransmit)
		return 0;

	if (omci_msg_type_ak_get(&rsp) == 0) {
		dbg_err("service_retransmission - Drop message with Ak == 0");
		return 0;
	}

	error = omci_msg_send(context, &rsp);
	if (error) {
		dbg_err("service_retransmission - Got the %d error from "
			"omci_msg_send", error);
	}

	return 1;
}

int service_action(struct omci_context *context,
		   union omci_msg *msg)
{
	enum omci_error error;
	union omci_msg rsp;

	(void)rsp_create(msg, &context->action.rsp);

	context->action.msg = *msg;
	context->action.run = true;
	/* Wakeup action event */
	if (IFXOS_EventWakeUp(&context->action_event) < IFX_SUCCESS)
		dbg_err("service_action - action event wakeup failed");

	/* Wait for action thread to signal completion (v7.5.1: event-based) */
	if (IFXOS_EventWait(&context->action_handled_event,
			    context->action_timeout, NULL) < IFX_SUCCESS
	    || context->action.run) {
		return service_busy_device(context, msg);
	}

	context_lock(context);
	context->action.ready = false;
	rsp = context->action.rsp;
	context_unlock(context);

	/* send messages with AK = 1, others are dropped

	   NOTE: If action handler doesn't want to send RSP it should
	   manually (via omci_msg_type_ak_set) set AK to 0!
	   Otherwise message will be sent (even if action handler has
	   returned an error)!
	 */
	if (omci_msg_type_ak_get(&rsp) == 0) {
		dbg_prn("service_action - Drop message with Ak == 0");
		return 0;
	}

	error = omci_msg_send(context, &rsp);
	if (error) {
		dbg_err("service_action - Got the %d error from "
			"omci_msg_send", error);
	}

	return 1;
}

/** Message handling thread

   \param[in] thr_params Thread arguments
*/
static int32_t omci_core_thread_main(struct IFXOS_ThreadParams_s *thr_params)
{
	struct omci_context *context =
		(struct omci_context *)thr_params->nArg1;

#ifndef OMCI_DEBUG_DISABLE
	unsigned long omci_counter;
#endif
	union omci_msg msg;
	union omci_msg *received_msg;

	dbg_in(__func__, "%p", (void *)thr_params);
#ifdef LINUX
	dbg_msg("CoreThread - Started (tid %d)", getpid());
#endif
	/* \note WE DON'T TAKE INTO ACCOUNT MESSAGES PRIORITY!!! */

	/* while thread is running */
	while (thr_params->bRunning == IFX_TRUE &&
	       thr_params->bShutDown == IFX_FALSE) {
		dbg_msg("CoreThread - Waiting for message...");

#if 1
		/* wait while OMCI is disabled */
		while (context->omci_enabled == false
		       && thr_params->bShutDown == IFX_FALSE
		       && thr_params->bRunning == IFX_TRUE) {
			IFXOS_MSecSleep(CORE_THREAD_POLL_TIME);
		}

		if (IFX_Var_Fifo_isEmpty(&context->msg_fifo.fifo)) {
			/* wait for message in FIFO */
			if (IFXOS_EventWait(&context->msg_event,
					    CORE_THREAD_MSG_FIFO_TIMEOUT,
					    NULL) < IFX_SUCCESS)
				continue;
		}
#endif

		/* check if we are shutting down */
		if (thr_params->bShutDown == IFX_TRUE
		    || thr_params->bRunning == IFX_FALSE) {
			dbg_msg("CoreThread - Shutting down...");
			break;
		}

		context_lock(context);

		received_msg = (union omci_msg *)
			IFX_Var_Fifo_readElement(&context->msg_fifo.fifo, NULL);
		/* check if FIFO is not empty */
		if (!received_msg) {
			context_unlock(context);
			continue;
		}

		/* copy message */
		memcpy(&msg, received_msg, sizeof(union omci_msg));

#ifndef OMCI_DEBUG_DISABLE
		omci_counter = ++context->omci_received;
#endif

		context_unlock(context);

		dbg_msg("CoreThread - Received, handle...");

#ifndef OMCI_DEBUG_DISABLE
		msg_dump(context, "RX:", &msg, omci_counter);
#endif

		if (context->action.run) {
			service_busy_device(context, NULL);
		} else {
			if (service_delayed_action(context, &msg) == 0) {
				if (service_retransmission(context, &msg) == 0) {
					service_action(context, &msg);
				}
			}
		}
	}

	dbg_msg("CoreThread - Bye");

	dbg_out_ret(__func__, 0);
	return 0;
}


/** Message handling thread

   \param[in] thr_params Thread arguments
*/
static int32_t action_thread_main(struct IFXOS_ThreadParams_s *thr_params)
{
	struct omci_context *context =
		(struct omci_context *)thr_params->nArg1;
	union omci_msg rsp;
	uint8_t mt;

	dbg_in(__func__, "%p", (void *)thr_params);
#ifdef LINUX
	dbg_msg("ActionThread - Started (tid %d)", getpid());
#endif

	while (thr_params->bRunning == IFX_TRUE &&
	       thr_params->bShutDown == IFX_FALSE) {

		/* wait an action*/
		if (IFXOS_EventWait(&context->action_event,
				    ACTION_THREAD_TIMEOUT, NULL) < IFX_SUCCESS)
			continue;

		mt = omci_msg_type_mt_get(&context->action.msg);

		/* lock MIB */
		if (mt == OMCI_MT_CREATE
			|| mt == OMCI_MT_DELETE
			|| mt == OMCI_MT_MIB_UPLOAD
			|| mt == OMCI_MT_GET_ALL_ALARMS) {
			mib_lock_write(context);
		} else if (mt == OMCI_MT_MIB_RESET) {
		} else {
			mib_lock_read(context);
		}

		context_lock(context);
		context->action.ready = false;
		rsp = context->action.rsp;
		context_unlock(context);

		context->action.handler_error = msg_handle(context,
							   &context->action.msg,
							   &rsp);

		if (context->failsafe && context->action.handler_error
							      != OMCI_SUCCESS) {
			dbg_err("action_thread_main - Got the %d error from "
				"msg_handle (tid = 0x%04x) in failsafe mode",
				context->action.handler_error,
				ntoh16(rsp.msg.header.tci));
			context->action.handler_error = OMCI_SUCCESS;
			(void)rsp_create(&context->action.msg, &rsp);
		}

		/* increment MIB Sequence number */
		if (mt == OMCI_MT_CREATE || mt == OMCI_MT_DELETE
			|| mt == OMCI_MT_SET) {
			if (context->action.handler_error == OMCI_SUCCESS) {
				mib_seq_num_inc(context);
			}
		}

		context_lock(context);
		context->action.rsp = rsp;
		if (omci_msg_type_ak_get(&rsp) == 1)
			rsp_remember(context,
				     context->action.msg.msg.header.tci,
				     &rsp);
		context->action.run = false;
		context->action.ready = true;
		context_unlock(context);

		/* Signal core thread that action is complete (v7.5.1) */
		(void)IFXOS_EventWakeUp(&context->action_handled_event);

		/* unlock MIB */
		if (mt != OMCI_MT_MIB_RESET) {
			mib_unlock(context);
		}
	}

	dbg_msg("ActionThread - Bye");

	dbg_out_ret(__func__, 0);
	return 0;
}

#ifdef LINUX
static void segmentation_fault(int val)
{
	dbg_err("Segmentation fault, thread ID is %d, PID %d",
		(int)IFXOS_ThreadIdGet(), getpid());
	sleep(10000);
}
#endif

void omci_handler_install(void)
{
#ifdef LINUX
	signal(SIGSEGV, segmentation_fault);
	/* ignore broken pipes */
	signal(SIGPIPE, SIG_IGN);
#endif
}

enum omci_error core_thread_start(struct omci_context *context)
{
	enum omci_error error;

	dbg_in(__func__, "%p", (void *)context);

	error = (enum omci_error)
		IFXOS_ThreadInit(&context->core_thread_ctrl,
				 "omcicore",
				 omci_core_thread_main,
				 CORE_THREAD_STACK_SIZE,
				 CORE_THREAD_PRIO,
				 (unsigned long)context, 0);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error core_thread_stop(struct omci_context *context)
{
	dbg_in(__func__, "%p", (void *)context);

	(void)IFXOS_ThreadDelete(&context->core_thread_ctrl,
				 CORE_THREAD_SHUTDOWN_WAIT);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error action_thread_start(struct omci_context *context)
{
	enum omci_error error;

	dbg_in(__func__, "%p", (void *)context);

	error = (enum omci_error)
		IFXOS_ThreadInit(&context->action_thread_ctrl,
				 "omciaction",
				 action_thread_main,
				 ACTION_THREAD_STACK_SIZE,
				 ACTION_THREAD_PRIO,
				 (unsigned long)context, 0);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error action_thread_stop(struct omci_context *context)
{
	dbg_in(__func__, "%p", (void *)context);

	(void)IFXOS_ThreadDelete(&context->action_thread_ctrl,
				 ACTION_THREAD_SHUTDOWN_WAIT);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error rsp_create(const union omci_msg *msg, union omci_msg *rsp)
{
	memset(rsp, 0, sizeof(union omci_msg));

	rsp->msg_rsp.header.tci = msg->msg.header.tci;

	omci_msg_type_ar_set(rsp, 0);
	omci_msg_type_ak_set(rsp, omci_msg_type_ar_get(msg));
	omci_msg_type_mt_set(rsp, omci_msg_type_mt_get(msg));

	rsp->msg_rsp.header.dev_id = OMCI_FORMAT_BASELINE;
	rsp->msg_rsp.header.class_id = msg->msg.header.class_id;
	rsp->msg_rsp.header.instance_id = msg->msg.header.instance_id;

	return OMCI_SUCCESS;
}

enum omci_error avc_send(struct omci_context *context,
			 struct me *me,
			 unsigned int attr)
{
	union omci_msg msg;
	size_t attr_size;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %u", (void *)context, (void *)me, attr);

	assert(context && me);

	if (is_me_attr_exist(me->class, attr) == false) {
		dbg_out_ret(__func__, OMCI_ERROR_INVALID_ME_ATTR);
		return OMCI_ERROR_INVALID_ME_ATTR;
	}

	memset(&msg, 0, sizeof(union omci_msg));

	msg.avc.header.tci = 0x0000;
	omci_msg_type_mt_set(&msg, OMCI_MT_AVC);
	omci_msg_type_ak_set(&msg, 0);
	omci_msg_type_ar_set(&msg, 0);
	omci_msg_type_db_set(&msg, 0);
	msg.avc.header.dev_id = OMCI_FORMAT_BASELINE;
	msg.avc.header.class_id = hton16(me->class->class_id);
	msg.avc.header.instance_id = hton16(me->instance_id);

	msg.avc.attr_mask = omci_attr2mask(attr);
	msg.avc.attr_mask = hton16(msg.avc.attr_mask);

	attr_size = me_attr_size_get(me->class, attr);

	if (attr_size > sizeof(msg.avc.values)) {
		dbg_out_ret(__func__, OMCI_ERROR_BOUNDS);
		return OMCI_ERROR_BOUNDS;
	}

	error = me_attr_read(context, me, attr, msg.avc.values, attr_size);
	RETURN_IF_ERROR(error);

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
# ifndef OMCI_DEBUG_DISABLE
	me_dbg_prn(me, "AVC \"%.25s\" (%u)",
		   me_attr_name_get(me->class, attr), attr);
#  endif
#else
	me_dbg_prn(me, "AVC #%u", attr);
#endif

#if (defined(AVC_SEND) && (AVC_SEND == 1))
	context_lock(context);
	if (context->omci_enabled == true) {
		context_unlock(context);

		/* send AVC */
		error = omci_msg_send(context, &msg);

		if (error) {
			dbg_wrn("WARNING(%d) Can't send AVC message", error);
		}
	} else {
		context_unlock(context);
	}
#endif

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error avc_send_delayed_timeout_handler(struct omci_context
							*context,
							struct timeout *timeout)
{
	enum omci_error error;
	struct me *me;

	mib_lock_read(context);

	error = mib_me_find(context,
			    (uint16_t)timeout->arg1,
			    (uint16_t)timeout->arg2,
			    &me);
	if (error)
		goto exit;

	me_lock(context, me);
	error = avc_send(context, me, timeout->arg3);
	me_unlock(context, me);
	if (error)
		goto exit;

exit:
	mib_unlock(context);

	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}

enum omci_error avc_send_delayed(struct omci_context *context,
				 struct me *me,
				 unsigned int attr,
				 unsigned int timeout)
{
	return timeout_event_add(context, NULL, 3000,
				 avc_send_delayed_timeout_handler,
				 me->class->class_id,
				 me->instance_id,
				 me->class->class_id,
				 me->instance_id, attr);
}

enum omci_error alarm_send(struct omci_context *context,
			   const struct me *me)
{
	union omci_msg msg;
	enum omci_error error;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	RETURN_IF_PTR_NULL(me->alarm_bitmap);

	memset(&msg, 0, sizeof(union omci_msg));
	msg.alarm.header.tci = 0x0000;
	omci_msg_type_mt_set(&msg, OMCI_MT_ALARM);
	omci_msg_type_ak_set(&msg, 0);
	omci_msg_type_ar_set(&msg, 0);
	omci_msg_type_db_set(&msg, 0);
	msg.alarm.header.dev_id = OMCI_FORMAT_BASELINE;
	msg.alarm.header.class_id = hton16(me->class->class_id);
	msg.alarm.header.instance_id = hton16(me->instance_id);

	memcpy(msg.alarm.alarm_bitmap, me->alarm_bitmap,
	       OMCI_ALARM_BITMAP_SIZE);

	context_lock(context);
	msg.alarm.seq_num = context->mib.alarm_seq_num;
	context_unlock(context);

	error = omci_msg_send(context, &msg);

	if (error) {
		dbg_err("ERROR(%d) Can't send alarm message", error);
	}

	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error tca_send(struct omci_context *context,
			 const struct me *me,
			 const uint8_t tca_bitmap[OMCI_ALARM_BITMAP_SIZE])
{
	union omci_msg msg;
	enum omci_error error;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	memset(&msg, 0, sizeof(union omci_msg));
	msg.alarm.header.tci = 0x0000;
	omci_msg_type_mt_set(&msg, OMCI_MT_ALARM);
	omci_msg_type_ak_set(&msg, 0);
	omci_msg_type_ar_set(&msg, 0);
	omci_msg_type_db_set(&msg, 0);
	msg.alarm.header.dev_id = OMCI_FORMAT_BASELINE;
	msg.alarm.header.class_id = hton16(me->class->class_id);
	msg.alarm.header.instance_id = hton16(me->instance_id);

	memcpy(msg.alarm.alarm_bitmap, tca_bitmap, OMCI_ALARM_BITMAP_SIZE);

	error = omci_msg_send(context, &msg);

	if (error) {
		dbg_err("ERROR(%d) Can't send TCA message", error);
	}

	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error me_tbl_copy_empty_get(struct omci_context *context,
				      uint16_t class_id,
				      uint16_t instance_id,
				      unsigned int attr,
				      struct tbl_copy_entry **tbl_copy)
{
	int i;
	struct tbl_copy_entry *entry = NULL;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %p", (void *)context, class_id,
	       instance_id, (void *)tbl_copy);

	/* check if we already created copy */
	for (i = 0; i < OMCI_TABLE_COPY_NUM; i++)
		if (context->tbl_copy.array[i].class_id == class_id
		    && context->tbl_copy.array[i].instance_id == instance_id
		    && context->tbl_copy.array[i].attr == attr) {
			/* found; update timeout and clear data */
			entry = &context->tbl_copy.array[i];

			if (tbl_copy != NULL)
				*tbl_copy = entry;

			entry->class_id = class_id;
			entry->instance_id = instance_id;
			entry->attr = attr;
			entry->data_size = 0;

			if (entry->free_data == true && entry->data) {
				IFXOS_MemFree(entry->data);
				entry->data = NULL;
			}

			entry->valid = true;

			dbg_out_ret(__func__, OMCI_SUCCESS);
			return OMCI_SUCCESS;
		}

	/* not found previous active copy, add new */
	for (i = 0; i < OMCI_TABLE_COPY_NUM; i++)
		if (context->tbl_copy.array[i].valid == false) {
			entry = &context->tbl_copy.array[i];

			if (tbl_copy != NULL)
				*tbl_copy = entry;

			entry->class_id = class_id;
			entry->instance_id = instance_id;
			entry->attr = attr;
			entry->data_size = 0;
			entry->data = NULL;

			entry->valid = true;

			dbg_out_ret(__func__, OMCI_SUCCESS);
			return OMCI_SUCCESS;
		}
#if 0
	/* no more free memory */
	dbg_err("ERROR(%d) Not enough memory for new entry in "
		"context->tbl_copy.array[]", OMCI_ERROR_MEMORY);
#else
	/* OLT has made OMCI_TABLE_COPY_NUM queries for different table
	   attributes in a minute. So we can assume that all previous attributes
	   has been successfully read and we can remove some pending table clear
	   timeout event. */

	for (i = 0; i < OMCI_TABLE_COPY_NUM; i++)
		if (context->tbl_copy.array[i].valid == true) {
			entry = &context->tbl_copy.array[i];

			error = timeout_event_remove(context,
						     entry->timeout_id);
			RETURN_IF_ERROR(error);

			if (entry->free_data == true)
				IFXOS_MemFree(entry->data);

			if (tbl_copy != NULL)
				*tbl_copy = entry;

			entry->class_id = class_id;
			entry->instance_id = instance_id;
			entry->attr = attr;
			entry->data_size = 0;
			entry->data = NULL;

			entry->valid = true;

			dbg_out_ret(__func__, OMCI_SUCCESS);
			return OMCI_SUCCESS;
		}
#endif

	dbg_out_ret(__func__, OMCI_ERROR_MEMORY);
	return OMCI_ERROR_MEMORY;
}

enum omci_error me_tbl_copy_find(struct omci_context *context,
				 uint16_t class_id,
				 uint16_t instance_id,
				 unsigned int attr,
				 struct tbl_copy_entry **tbl_copy)
{
	int i;
	struct tbl_copy_entry *entry = NULL;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %p", (void *)context, class_id,
	       instance_id, (void *)tbl_copy);

	for (i = 0; i < OMCI_TABLE_COPY_NUM; i++)
		if (context->tbl_copy.array[i].class_id == class_id
		    && context->tbl_copy.array[i].instance_id == instance_id
		    && context->tbl_copy.array[i].attr == attr) {
			if (context->tbl_copy.array[i].valid == true)
				entry = &context->tbl_copy.array[i];
			else
				break;
		}

	if (entry == NULL) {
		error = OMCI_ERROR;
	} else {
		error = OMCI_SUCCESS;

		if (tbl_copy != NULL)
			*tbl_copy = entry;
	}

	dbg_out_ret(__func__, error);
	return error;
}

#if defined(OMCI_SWAP)
enum omci_error data_swap(void *data, size_t data_size)
{
	uint8_t byte;
	uint16_t tmp16;
	uint32_t tmp32;

	switch (data_size) {
	case 1:
		return OMCI_SUCCESS;

	case 2:
		memcpy(&tmp16, data, 2);
		tmp16 = ntoh16(tmp16);
		memcpy(data, &tmp16, 2);
		break;
	case 4:
		memcpy(&tmp32, data, 4);
		tmp32 = ntoh32(tmp32);
		memcpy(data, &tmp32, 4);
		break;

	case 5:
		byte = ((uint8_t *)data)[0];
		((uint8_t *)data)[0] = ((uint8_t *)data)[4];
		((uint8_t *)data)[4] = byte;

		byte = ((uint8_t *)data)[1];
		((uint8_t *)data)[1] = ((uint8_t *)data)[3];
		((uint8_t *)data)[3] = byte;

		break;

	default:
		dbg_err("Unexpected size for data swap (= %lu)", data_size);
		return OMCI_ERROR;
	}

	return OMCI_SUCCESS;
}
#endif

#if defined(OMCI_SWAP)
enum omci_error attr_swap(const struct me_class *me_class,
			  void *data,
			  size_t data_size,
			  uint16_t attr_mask)
{
	enum omci_attr_prop attr_prop;
	unsigned int attr;
	void *attr_data;
	size_t attr_size = 0;
	size_t attr_size_sum = 0;
	enum omci_error error;

	for (attr = 1; attr <= 16; attr++) {
		if (!(omci_attr2mask(attr) & attr_mask))
			continue;

		attr_prop = me_attr_prop_get(me_class, attr);
		attr_size = me_attr_size_get(me_class, attr);

		attr_size_sum += attr_size;

		if (attr_size == 1)
			continue;

		if (attr_prop & OMCI_ATTR_PROP_NO_SWAP)
			continue;

		if (attr_size_sum > data_size)
			break;

		attr_data = (uint8_t *)data + attr_size_sum - attr_size;

		error = data_swap(attr_data, attr_size);
		RETURN_IF_ERROR(error);
	}

	return OMCI_SUCCESS;
}
#endif

/** @} */
