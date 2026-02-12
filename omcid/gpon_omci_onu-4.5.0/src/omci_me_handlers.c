/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_me_handlers.h"
#include "omci_debug.h"

#ifdef INCLUDE_PM
#include "me/omci_threshold_data1.h"
#include "me/omci_threshold_data2.h"
#endif

/** \addtogroup OMCI_ME_HANDLERS
   @{
*/

/** The maximum time between two Get Next requests (in milliseconds).
   Please refer to the ITU-T G.984.4 */
#define GET_NEXT_TIMEOUT                          (60 * 1000)

/** This is a timeout event handler.
   It called when get next data is out of date (no more get next messages or
   all messages were proceed and we need to free memory).

   \param[in] context OMCI context pointer
   \param[in] timeout timeout descriptor
*/
static enum omci_error get_next_tbl_copy_clean_timeout_handler(struct
							       omci_context
							       *context,
							       struct timeout
							       *timeout)
{
	uint16_t class_id;
	uint16_t instance_id;
	unsigned int attr;
	struct tbl_copy_entry *tbl_copy;

	enum omci_error error;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)timeout);

	table_copy_lock(context);

	class_id = (uint16_t)timeout->arg1;
	instance_id = (uint16_t)timeout->arg2;
	attr = (unsigned int)timeout->arg3;

	dbg_prn("Timeout - Clear %u@%u #%u attribute table data",
		class_id, instance_id, attr);

	error = me_tbl_copy_find(context, class_id, instance_id, attr,
				 &tbl_copy);
	if (error) {
		table_copy_unlock(context);

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	/* free data */
	if (tbl_copy->free_data == true && tbl_copy->data) {
		IFXOS_MemFree(tbl_copy->data);
		tbl_copy->data = NULL;
	}

	tbl_copy->valid = false;
	tbl_copy->timeout_id = 0;

	table_copy_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error reboot_acion_handle(struct omci_context *context,
				    struct me *me,
				    const union omci_msg *msg,
				    union omci_msg *rsp)
{
	enum omci_error error;
	unsigned int cant_reboot;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	context_lock(context);
	cant_reboot = context->cant_reboot;
	context_unlock(context);

	if (cant_reboot) {
		dbg_wrn("Device busy, can't reboot");

		rsp->reboot_rsp.result = OMCI_MR_DEVICE_BUSY;

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	dbg_wrn("ONU will now reboot...");

	context_lock(context);
	context->cant_reboot++;
	context_unlock(context);

	error = (enum omci_error)omci_api_reboot(REBOOT_TIMEOUT);

	if (error)
		rsp->reboot_rsp.result = OMCI_MR_CMD_ERROR;
	else
		rsp->reboot_rsp.result = OMCI_MR_CMD_SUCCESS;

	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error set_action_handle(struct omci_context *context,
				  struct me *me,
				  const union omci_msg *msg,
				  union omci_msg *rsp)
{
	uint16_t exec_mask = 0;
	uint16_t attr_mask;
	uint8_t upd_data[OMCI_ME_DATA_SIZE_MAX];
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	/* validate and update handler should be set */
	assert(me->class->update);

	attr_mask = ntoh16(msg->set.attr_mask);

	/* check for invalid attributes */
	if (attr_mask & me->class->inv_attr_mask) {
		rsp->set_rsp.result = OMCI_MR_ATTR_FAILED;
		rsp->set_rsp.attr_exec_mask = hton16(attr_mask);
		rsp->set_rsp.opt_attr_mask = hton16((attr_mask &
						     me->class->opt_attr_mask)
						    ^ me->class->opt_attr_mask);

		me_dbg_err(me, "Try to set invalid attribute; "
			   "attr_mask = 0x%04x, inv_attr_mask = 0x%04x",
			   attr_mask, me->class->inv_attr_mask);

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

	/* check for non-supported attributes */
	if (attr_mask & me->class->opt_attr_mask) {
		rsp->set_rsp.result = OMCI_MR_ATTR_FAILED;
		rsp->set_rsp.attr_exec_mask = hton16(attr_mask);
		rsp->set_rsp.opt_attr_mask = hton16((attr_mask &
						     me->class->opt_attr_mask)
						    ^ me->class->opt_attr_mask);

		me_dbg_err(me, "Try to set non-supported optional "
			   "attribute; " "attr_mask = 0x%04x, "
			   "opt_attr_mask = 0x%04x", attr_mask,
			   me->class->opt_attr_mask);

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

	/* check in requested attributes are writable */
	if ((attr_mask ^ me->class->wr_attr_mask) & attr_mask) {
		rsp->set_rsp.result = OMCI_MR_ATTR_FAILED;
		rsp->set_rsp.attr_exec_mask = hton16(attr_mask);
		rsp->set_rsp.opt_attr_mask = hton16((attr_mask &
						     me->class->opt_attr_mask)
						    ^ me->class->opt_attr_mask);

		me_dbg_err(me, "Try to set non-writable attribute; "
			   "attr_mask = 0x%04x, " "wr_attr_mask = 0x%04x",
			   attr_mask, me->class->wr_attr_mask);

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

#if defined(OMCI_SWAP)
	error = attr_swap(me->class, (uint8_t *)msg->set.values,
			  sizeof(msg->set.values), attr_mask);
	RETURN_IF_ERROR(error);
#endif

	/* fetch new data */
	error = me_data_fetch(context, me, attr_mask,
			      msg->set.values,
			      sizeof(msg->set.values),
			      attr_mask, upd_data);

	if (error) {
		rsp->set_rsp.result = OMCI_MR_CMD_ERROR;

		dbg_out_ret(__func__, error);
		return error;
	}

	if (is_data_updated(context, me, upd_data, attr_mask, NULL) == false) {
		rsp->set_rsp.result = OMCI_MR_CMD_SUCCESS;

		me_attr_update_print(context, me->class,
				     me->instance_id, attr_mask,
				     msg->set.values,
				     sizeof(msg->set.values),
				     "set", attr_mask);

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	/* validate new data */
	if (me->class->validate) {
		error = me->class->validate(context, me->class,
					    &exec_mask, upd_data);

		if (error) {
			rsp->set_rsp.result = OMCI_MR_CMD_ERROR;

			dbg_out_ret(__func__, error);
			return error;
		}

		/* requested attribute was failed */
		if (exec_mask & attr_mask) {
			rsp->set_rsp.result = OMCI_MR_PARAM_ERROR;
			rsp->set_rsp.attr_exec_mask =
				hton16(exec_mask & attr_mask);
			rsp->set_rsp.opt_attr_mask =
				hton16((exec_mask & me->class->opt_attr_mask)
				       ^ me->class->opt_attr_mask);

			me_attr_update_print(context, me->class,
					     me->instance_id,
					     attr_mask,
					     msg->set.values,
					     sizeof(msg->set.values),
					     "Can't set",
					     exec_mask & attr_mask);

			dbg_out_ret(__func__, OMCI_ERROR_ACTION);
			return OMCI_ERROR_ACTION;
		}

		/* any other attribute was failed */
		if (exec_mask) {
			me_dbg_err(me, "Non-updated attribute validation "
				   "error; exec_mask = 0x%04x", exec_mask);

			me_dbg_err(me, "OLT tried to set the following "
				   "attributes:");

			me_attr_update_print(context, me->class,
					     me->instance_id,
					     attr_mask,
					     msg->set.values,
					     sizeof(msg->set.values),
					     "Try set", attr_mask);

			me_dbg_err(me, "The snapshot of the Managed Entity:");

			me_attr_update_print(context, me->class,
					     me->instance_id,
					     ~me->class->inv_attr_mask,
					     me->data,
					     me->class->data_size,
					     "",
					     ~me->class->inv_attr_mask);

			rsp->set_rsp.result = OMCI_MR_CMD_ERROR;

			dbg_out_ret(__func__, OMCI_ERROR_ACTION);
			return OMCI_ERROR_ACTION;
		}
	}

	me_attr_update_print(context, me->class,
			     me->instance_id, attr_mask,
			     msg->set.values,
			     sizeof(msg->set.values),
			     "set", attr_mask);

	/* set new data */
	if (me->active) {
		error = me->class->update(context, me, upd_data, attr_mask);
	} else {
		omci_hook(context, "update", me->class->class_id,
			  me->instance_id);
		error = 0;
		me_dbg_wrn(me, "Skip update handler");
	}

#ifdef INCLUDE_PM
	if (me->class->prop & OMCI_ME_PROP_PM)
		if (attr_mask & omci_attr2mask(omci_me_pm_thr_data_id))
			(void)pm_me_thr_set(context, me);
#endif

	if (error) {
		rsp->set_rsp.result = OMCI_MR_PARAM_ERROR;
		rsp->set_rsp.attr_exec_mask = hton16(attr_mask);

		me_dbg_err(me, "Update handler error");

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

	memcpy(me->data, upd_data, me->class->data_size);

	rsp->set_rsp.result = OMCI_MR_CMD_SUCCESS;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error get_action_handle(struct omci_context *context,
				  struct me *me,
				  const union omci_msg *msg,
				  union omci_msg *rsp)
{
	unsigned int i;
	size_t attr_size_sum = 0;
	size_t attr_size = 0;
	enum omci_attr_prop attr_prop = OMCI_ATTR_PROP_NONE;
	uint16_t attr_mask = 0;
	uint16_t attr_exec_mask = 0;
	uint16_t opt_attr_mask = 0;
	uint16_t attr_mask_rsp = 0;
	uint8_t *attr = NULL;
	struct tbl_copy_entry *tbl_copy;
	enum omci_pm_interval interval;

	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	rsp->get_rsp.attr_mask = msg->get.attr_mask;

	/* swap attribute mask */
	attr_mask = ntoh16(msg->get.attr_mask);

	attr = rsp->get_rsp.values;


	if (omci_msg_type_mt_get(msg) == OMCI_MT_GET_CURR_DATA)
		interval = OMCI_PM_INTERVAL_CURR;
	else
		interval = OMCI_PM_INTERVAL_HIST;

#ifdef INCLUDE_PM
	if (me->class->prop & OMCI_ME_PROP_PM &&
	    me->class->prop & OMCI_ME_PROP_PM_INTERNAL) {
		error = pm_me_counters_get(context, me, interval);
		RETURN_IF_ERROR(error);
	}
#endif

	for (i = 1; i <= OMCI_ATTRIBUTES_NUM; i++) {
		/* filter AttrMask */
		if ((attr_mask & omci_attr2mask(i)) == 0)
			continue;

		/* OLT wishes to get attribute at position i */

		/* check if ME have this attribute */
		if (is_me_attr_exist(me->class, i) == false) {
			attr_exec_mask |= omci_attr2mask(i);
			continue;
		}

		/* get size and properties */
		attr_size = me_attr_size_get(me->class, i);
		attr_prop = me_attr_prop_get(me->class, i);

		/* check if optional attribute is not presented */
		if (attr_prop & OMCI_ATTR_PROP_NOT_SUPPORTED) {
			opt_attr_mask = me->class->opt_attr_mask;

			continue;
		}

		/* if attribute is not readable */
		if (!(attr_prop & OMCI_ATTR_PROP_RD)) {
			attr_exec_mask |= omci_attr2mask(i);
			continue;
		}

		/* OLT wishes to get attribute whose size is larger than space
		   available in the one OMCI message
		   \note set action should be handled by the wrapper
		   for each ME */
		if (attr_size > sizeof(rsp->get_rsp.values) ||
		    attr_prop & OMCI_ATTR_PROP_TABLE) {
			/* When the ONT wishes to transfer an attribute whose
			   size is or might be larger than the space available
			   in one OMCI message, the ONT responds with four
			   bytes to indicate the size of that attribute with
			   an appropriate attribute mask. The OLT should then
			   use the get next message in order to retrieve the
			   attribute. */

			/* check whether ME has table attribute handler */
			if (me->class->tbl_copy == NULL) {
				rsp->get_tbl_rsp.result = OMCI_MR_ATTR_FAILED;
				rsp->get_tbl_rsp.attr_exec_mask =
				    omci_attr2mask(i);
				rsp->get_tbl_rsp.attr_exec_mask =
				    hton16(rsp->get_tbl_rsp.attr_exec_mask);
				rsp->get_tbl_rsp.attr_mask = 0;
				memset(rsp->get_tbl_rsp.padding, 0,
				       sizeof(rsp->get_tbl_rsp.padding));

				dbg_out_ret(__func__, OMCI_ERROR_ACTION);
				return OMCI_ERROR_ACTION;
			}

			table_copy_lock(context);

			/* add new item in context */
			error = me_tbl_copy_empty_get(context,
						      me->class->class_id,
						      me->instance_id,
						      i,
						      &tbl_copy);
			if (error) {
				rsp->get_tbl_rsp.result = OMCI_MR_DEVICE_BUSY;
				rsp->get_tbl_rsp.attr_mask = 0;
				memset(rsp->get_tbl_rsp.padding, 0,
				       sizeof(rsp->get_tbl_rsp.padding));

				table_copy_unlock(context);

				dbg_out_ret(__func__, OMCI_ERROR_ACTION);
				return OMCI_ERROR_ACTION;
			}

			tbl_copy->free_data = true;

			/* copy data */
			error = me->class->tbl_copy(context, me, i, tbl_copy);

			if (error) {
				rsp->get_tbl_rsp.result = OMCI_MR_ATTR_FAILED;
				rsp->get_tbl_rsp.attr_exec_mask =
				    omci_attr2mask(i);
				rsp->get_tbl_rsp.attr_exec_mask =
				    hton16(rsp->get_tbl_rsp.attr_exec_mask);
				rsp->get_tbl_rsp.attr_mask = 0;
				memset(rsp->get_tbl_rsp.padding, 0,
				       sizeof(rsp->get_tbl_rsp.padding));

				table_copy_unlock(context);

				dbg_out_ret(__func__, OMCI_ERROR_ACTION);
				return OMCI_ERROR_ACTION;
			}

			/* remove old timeout event */
			if (tbl_copy->timeout_id)
				(void)timeout_event_remove(context,
							   tbl_copy->
							   timeout_id);

			/* set new timeout */
			error = timeout_event_add(context,
						  &tbl_copy->timeout_id,
						  GET_NEXT_TIMEOUT,
						  get_next_tbl_copy_clean_timeout_handler,
						  me->class->class_id,
						  me->instance_id,
						  (unsigned long)me->
						  class->class_id,
						  (unsigned long)me->
						  instance_id,
						  (unsigned long)i);

			if (error) {
				rsp->get_tbl_rsp.result = OMCI_MR_ATTR_FAILED;
				rsp->get_tbl_rsp.attr_exec_mask =
				    omci_attr2mask(i);
				rsp->get_tbl_rsp.attr_exec_mask =
				    hton16(rsp->get_tbl_rsp.attr_exec_mask);
				rsp->get_tbl_rsp.attr_mask = 0;
				memset(rsp->get_tbl_rsp.padding, 0,
				       sizeof(rsp->get_tbl_rsp.padding));

				table_copy_unlock(context);

				dbg_out_ret(__func__, OMCI_ERROR_ACTION);
				return OMCI_ERROR_ACTION;
			}

			/* fill response */
			rsp->get_tbl_rsp.attr_mask = omci_attr2mask(i);
			rsp->get_tbl_rsp.attr_mask =
			    hton16(rsp->get_tbl_rsp.attr_mask);
			memset(rsp->get_tbl_rsp.padding, 0,
			       sizeof(rsp->get_tbl_rsp.padding));

			rsp->get_tbl_rsp.size = hton32(tbl_copy->data_size);
			rsp->get_tbl_rsp.result = OMCI_MR_CMD_SUCCESS;

			table_copy_unlock(context);

			dbg_out_ret(__func__, OMCI_SUCCESS);
			return OMCI_SUCCESS;
		}

		/* count attributes size */
		attr_size_sum += attr_size;

		/* if attributes size exceeds 25 bytes (avail space in MSG) */
		if (attr_size_sum > sizeof(rsp->get_rsp.values)) {
			/* If the OLT asks for too many attributes, and the ONT
			   can respond with however many attributes fit in its
			   25-byte attribute space. The OLT will get the
			   appropriate attribute-present mask and will parse
			   the attributes that were sent correctly. It will ask
			   again later for those attributes that did not fit.
			   While this is the preferred behaviour, an alternate
			   interpretation may be that the ONT would return
			   a "parameter error" code when it receives a get that
			   does not fit in the get Response. */

			/* we use the preferred behaviour! */
			break;
		}

		/* store found attribute */
		error = me_attr_read_with_interval(context, me, i, attr,
						   attr_size, interval);

		if (error) {
			attr_exec_mask |= omci_attr2mask(i);
			continue;
		}
#if defined(OMCI_SWAP)
		/* swap value if needed */
		if (!(attr_prop & OMCI_ATTR_PROP_NO_SWAP)) {
			error = data_swap(attr, attr_size);
		}
#endif

		attr_mask_rsp |= omci_attr2mask(i);
		attr += attr_size;
	}

	if (attr_exec_mask != 0 || opt_attr_mask != 0) {
		if (attr_exec_mask & me->class->inv_attr_mask) {
			rsp->get_rsp.result = OMCI_MR_CMD_ERROR;
			rsp->get_rsp.attr_exec_mask = hton16(0);
			rsp->get_rsp.opt_attr_mask = hton16(0);
			rsp->get_rsp.attr_mask = hton16(0);
			memset(rsp->get_rsp.values, 0,
			       sizeof(rsp->get_rsp.values));
		} else {
			rsp->get_rsp.result = OMCI_MR_ATTR_FAILED;
			rsp->get_rsp.attr_exec_mask =
			    hton16(attr_exec_mask);
			rsp->get_rsp.opt_attr_mask =
			    hton16(opt_attr_mask);
			rsp->get_rsp.attr_mask = hton16(0);
			memset(rsp->get_rsp.values, 0,
			       sizeof(rsp->get_rsp.values));
		}

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	} else {
		rsp->get_rsp.result = OMCI_MR_CMD_SUCCESS;
		rsp->get_rsp.attr_mask = hton16(attr_mask_rsp);

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}
}

enum omci_error get_next_action_handle(struct omci_context *context,
				       struct me *me,
				       const union omci_msg *msg,
				       union omci_msg *rsp)
{
	unsigned int i;
	int attr = -1;
	uint16_t attr_mask = 0;
	size_t offset;
	size_t size;
	struct tbl_copy_entry *tbl_copy;

	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	rsp->get_next_rsp.attr_mask = msg->get_next.attr_mask;

	/* swap attribute mask */
	attr_mask = ntoh16(msg->get_next.attr_mask);

	/* find attribute position by mask and check for errors */
	attr = -1;
	for (i = 1; i <= OMCI_ATTRIBUTES_NUM; i++)
		if (attr_mask & omci_attr2mask(i)) {
			if (attr == -1)
				attr = (int)i;
			else if (attr > 0) {
				attr = -2;
				break;
			}
		}

	/* check for errors */
	if (attr < 1) {
		rsp->get_next_rsp.result = OMCI_MR_PARAM_ERROR;

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

	table_copy_lock(context);

	/* find attribute copy */
	error = me_tbl_copy_find(context, me->class->class_id,
				 me->instance_id, (unsigned int)attr,
				 &tbl_copy);
	if (error) {
		/* error - timeout or get next without get */

		rsp->get_next_rsp.result = OMCI_MR_PARAM_ERROR;

		table_copy_unlock(context);

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

	/* count offset */
	offset = sizeof(rsp->get_next_rsp.values)
		* ntoh16(msg->get_next.seq_num);

	size = sizeof(rsp->get_next_rsp.values);

	if (offset + size > tbl_copy->data_size)
		size = tbl_copy->data_size - offset;

	if (size <= 0 || size > (int)sizeof(rsp->get_next_rsp.values)) {
		rsp->get_next_rsp.result = OMCI_MR_PARAM_ERROR;

		table_copy_unlock(context);

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

	/* copy data */
	if (tbl_copy->data != NULL) {
		memcpy(rsp->get_next_rsp.values,
		       (uint8_t *)tbl_copy->data + offset, (unsigned int)size);
	}

	/* remove old timeout event */
	(void)timeout_event_remove(context, tbl_copy->timeout_id);

	/* set new timeout */
	error = timeout_event_add(context, &tbl_copy->timeout_id,
				  GET_NEXT_TIMEOUT,
				  get_next_tbl_copy_clean_timeout_handler,
				  me->class->class_id,
				  me->instance_id,
				  (unsigned long)me->class->class_id,
				  (unsigned long)me->instance_id,
				  (unsigned long)attr);

	if (error) {
		rsp->get_next_rsp.result = OMCI_MR_PARAM_ERROR;

		table_copy_unlock(context);

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

	table_copy_unlock(context);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

#ifdef INCLUDE_PM
enum omci_error get_current_data_action_handle(struct omci_context *context,
					       struct me *me,
					       const union omci_msg *msg,
					       union omci_msg *rsp)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	error = get_action_handle(context, me, msg, rsp);

	dbg_out_ret(__func__, error);
	return error;
}
#endif

enum omci_error create_action_handle(struct omci_context *context,
				     struct me *me,
				     const union omci_msg *msg,
				     union omci_msg *rsp)
{
	const struct me_class *me_class;
	uint16_t exec_mask = 0;
	uint8_t init_data[OMCI_ME_DATA_SIZE_MAX];
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	/* if OLT tries to create instance that already exists */
	if (me != NULL) {
		dbg_err("OLT tried to create ME %u@%u that already exists",
			ntoh16(msg->msg.header.class_id),
			ntoh16(msg->msg.header.instance_id));

		rsp->msg_rsp.result = OMCI_MR_INST_EXISTS;

		dbg_out_ret(__func__, OMCI_ERROR_ACTION);
		return OMCI_ERROR_ACTION;
	}

	error = mib_me_class_resolve(context,
				     ntoh16(msg->msg.header.class_id),
				     &me_class);
	RETURN_IF_ERROR(error);

#if defined(OMCI_SWAP)
	error = attr_swap(me_class, (uint8_t *)msg->create.values,
			  sizeof(msg->create.values), me_class->sbc_attr_mask);

	RETURN_IF_ERROR(error);
#endif

	/* validate and update handler should be set */
	assert(me_class->update);

	if (me_class->sbc_attr_mask) {
		/* create update data */
		error = me_class_data_fetch(context, me_class,
					    me_class->sbc_attr_mask,
					    msg->create.values,
					    sizeof(msg->create.values),
					    init_data);
		if (error) {
			rsp->create_rsp.result = OMCI_MR_CMD_ERROR;

			dbg_out_ret(__func__, error);
			return error;
		}
	} else {
		memset(init_data, 0, sizeof(init_data));
	}

	/* validate new data */
	if (me_class->validate) {
		error = me_class->validate(context, me_class, &exec_mask,
					   init_data);

		if (error) {
			rsp->create_rsp.result = OMCI_MR_CMD_ERROR;

			dbg_out_ret(__func__, error);
			return error;
		}

		/* set-By-create attribute was failed */
		if (exec_mask & me_class->sbc_attr_mask) {
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
			dbg_err("Can't create \"%.25s\" (%u) with "
				"instance id = %u, "
				"SBC validation error (mask 0x%x)",
				me_class->desc.name,
				me_class->class_id,
				ntoh16(msg->msg.header.instance_id),
				exec_mask & me_class->sbc_attr_mask);
#else
			dbg_err("Can't create ME with class id = %u, "
				"instance id = %u, "
				"SBC validation error (mask 0x%x)",
				me_class->class_id,
				ntoh16(msg->msg.header.instance_id),
				exec_mask & me_class->sbc_attr_mask);
#endif

			me_attr_update_print(context, me_class,
					     ntoh16(msg->msg.header.
						    instance_id),
					     me_class->sbc_attr_mask,
					     msg->create.values,
					     sizeof(msg->create.values),
					     "Can't set",
					     exec_mask);

			rsp->create_rsp.result = OMCI_MR_PARAM_ERROR;
			rsp->create_rsp.attr_exec_mask =
			    hton16(exec_mask & me_class->sbc_attr_mask);

			dbg_out_ret(__func__, OMCI_ERROR_ACTION);
			return OMCI_ERROR_ACTION;
		}

		/* any other attribute was failed */
		if (exec_mask) {
			dbg_err("%u@%u Non-SBC attribute validation "
				"error; exec_mask = 0x%04x, "
				"nSbcMask = 0x%04x",
				me_class->class_id,
				ntoh16(msg->msg.header.instance_id), exec_mask,
				me_class->sbc_attr_mask);

			dbg_err("%u@%u OLT tried to set the "
				"following attributes:",
				me_class->class_id,
				ntoh16(msg->msg.header.instance_id));

			me_attr_update_print(context, me_class,
					     ntoh16(msg->msg.header.
						    instance_id),
					     me_class->sbc_attr_mask,
					     msg->create.values,
					     sizeof(msg->create.values),
					     "Try set",
					     me_class->sbc_attr_mask);

			rsp->create_rsp.result = OMCI_MR_CMD_ERROR;

			dbg_out_ret(__func__, OMCI_ERROR_ACTION);
			return OMCI_ERROR_ACTION;
		}
	}

	/* create me */
	error = mib_me_create(context, true,
			      ntoh16(msg->msg.header.class_id),
			      ntoh16(msg->msg.header.instance_id),
			      &me, init_data, 0x0000);

	/* handle ME create errors */
	if (me == NULL) {
		switch (error) {
		case OMCI_ERROR_MEMORY:
			rsp->msg_rsp.result = OMCI_MR_DEVICE_BUSY;
			break;

		case OMCI_ERROR_ME_NOT_FOUND:
		case OMCI_ERROR_INVALID_ME_ID:
			rsp->msg_rsp.result = OMCI_MR_PARAM_ERROR;
			break;

		default:
			rsp->msg_rsp.result = OMCI_MR_CMD_ERROR;
			break;
		}

		dbg_out_ret(__func__, error);
		return error;
	}
	me_attr_update_print(context, me->class,
			     me->instance_id,
			     me->class->sbc_attr_mask,
			     msg->create.values,
			     sizeof(msg->create.values),
			     "set", me->class->sbc_attr_mask);

	memcpy(me->data, init_data, me_class->data_size);

	rsp->create_rsp.result = OMCI_MR_CMD_SUCCESS;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error delete_action_handle(struct omci_context *context,
				     struct me *me,
				     const union omci_msg *msg,
				     union omci_msg *rsp)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	error = mib_me_delete(context, me);

	if (error) {
		rsp->delete_rsp.result = OMCI_MR_DEVICE_BUSY;

		dbg_out_ret(__func__, error);
		return error;
	}

	rsp->delete_rsp.result = OMCI_MR_CMD_SUCCESS;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error default_me_validate(struct omci_context *context,
				    const struct me_class *me_class,
				    uint16_t *exec_mask,
				    const void *data)
{
	enum omci_attr_type format;
	uint32_t lower_limit;
	uint32_t upper_limit;
	uint32_t bit_field;
	uint16_t *code_points;
	unsigned int code_points_num;
	size_t attr_size;
	unsigned int attr;
	enum omci_attr_prop attr_prop;
	unsigned int attr_data_offset;
	uint8_t *attr_data;
	me_get_handler *get;
	uint16_t tmp16;
	uint32_t tmp32;

	dbg_in(__func__, "%p, %p {%u}, %p, %p",
	       (void *)context, (void *)me_class,
	       me_class->class_id,
	       (void *)exec_mask, (void *)data);

	for (attr = 1; attr <= OMCI_ATTRIBUTES_NUM; attr++) {
		if (is_me_attr_exist(me_class, attr) == false)
			continue;

		attr_prop = me_attr_prop_get(me_class, attr);
		get = me_attr_get_handler_get(me_class, attr);

		if (get && !(attr_prop & OMCI_ATTR_PROP_WR))
			continue;

		attr_size = me_attr_size_get(me_class, attr);
		attr_data_offset = me_attr_offset_get(me_class, attr);
		attr_data = (uint8_t *)data + attr_data_offset;
		format = me_attr_type_get(me_class, attr);

		switch (format) {
		case OMCI_ATTR_TYPE_INT:
		case OMCI_ATTR_TYPE_UINT:
			lower_limit = me_attr_lower_limit_get(me_class,
							      attr);
			upper_limit = me_attr_upper_limit_get(me_class,
							      attr);

			switch (attr_size) {
			case sizeof(uint8_t):
				num_validate(exec_mask, attr,
					     *(uint8_t *) attr_data,
					     lower_limit,
					     upper_limit);
				break;

			case sizeof(uint16_t):
				memcpy(&tmp16, attr_data, sizeof(uint16_t));
				num_validate(exec_mask, attr,
					     tmp16,
					     lower_limit,
					     upper_limit);
				break;

			case sizeof(uint32_t):
				memcpy(&tmp32, attr_data, sizeof(uint32_t));
				num_validate(exec_mask, attr,
					     tmp32,
					     lower_limit,
					     upper_limit);
				break;

			case 5:
				/* just pass 5-byte counters */
				break;

			default:
				dbg_err("ERROR(%d) "
					"%u Invalid size of "
					"numeric value "
					"in attributes "
					"validation; "
					"attribute #%u, "
					"size = %lu",
					me_class->class_id,
					OMCI_ERROR_INVALID_VAL,
					attr, attr_size);
				break;
			}

			break;

		case OMCI_ATTR_TYPE_BF:
			bit_field =
				me_attr_bf_supported_mask_get(me_class,
							      attr);

			switch (attr_size) {
			case sizeof(uint8_t):
				bf_validate(exec_mask, attr,
					    *(uint8_t *) attr_data,
					    bit_field);
				break;

			case sizeof(uint16_t):
				memcpy(&tmp16, attr_data, sizeof(uint16_t));
				bf_validate(exec_mask, attr,
					    tmp16,
					    bit_field);
				break;

			case sizeof(uint32_t):
				memcpy(&tmp32, attr_data, sizeof(uint32_t));
				bf_validate(exec_mask, attr,
					    tmp32,
					    bit_field);
				break;

			default:
				dbg_err("ERROR(%d) "
					"%u Invalid size of "
					"bit field value "
					"in attributes "
					"validation; "
					"attribute #%u, "
					"size = %lu",
					me_class->class_id,
					OMCI_ERROR_INVALID_VAL,
					attr, attr_size);
				break;
			}
			break;

		case OMCI_ATTR_TYPE_ENUM:
			code_points = me_attr_code_points_get(me_class,
							      attr);
			code_points_num =
				me_attr_code_points_num_get(me_class,
							    attr);

			switch (attr_size) {

			case sizeof(uint8_t):
				enum_validate(exec_mask, attr,
					      *(uint8_t *) attr_data,
					      code_points,
					      code_points_num);
				break;

			case sizeof(uint16_t):
				memcpy(&tmp16, attr_data, sizeof(uint16_t));
				enum_validate(exec_mask, attr,
					      tmp16,
					      code_points,
					      code_points_num);
				break;

			default:
				dbg_err("ERROR(%d) "
					"%u Invalid size of "
					"enumeration value "
					"in attributes "
					"validation; "
					"attribute #%u, "
					"size = %lu",
					me_class->class_id,
					OMCI_ERROR_INVALID_VAL,
					attr, attr_size);
				break;
			}

			break;

		case OMCI_ATTR_TYPE_PTR:
		case OMCI_ATTR_TYPE_TBL:
		case OMCI_ATTR_TYPE_STR:
		case OMCI_ATTR_TYPE_UNKNOWN:
			/* no check for such attributes */
			break;
		}
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error default_me_update(struct omci_context *context,
				  struct me *me,
				  void *data,
				  uint16_t attr_mask)
{
#ifdef INCLUDE_PM
	struct me *thr1_me;
	struct me *thr2_me;
	struct omci_me_threshold_data1 *thr1_data;
	struct omci_me_threshold_data2 *thr2_data;
	struct pm_me_data *pm_me_data;
	uint32_t thr[PM_THR_NUM];
	enum omci_error error;
#endif

	dbg_in(__func__, "%p, %p {%u@%u}, %p, 0x%04x",
	       (void *)context,
	       (void *)me,
	       me->class->class_id,
	       me->instance_id,
	       (void *)data, attr_mask);

#ifdef INCLUDE_PM
	if (me->class->prop & OMCI_ME_PROP_PM) {
		pm_me_data = (struct pm_me_data *) data;

		error = mib_me_find(context,
				    OMCI_ME_THRESHOLD_DATA1,
				    pm_me_data->thr_data_id,
				    &thr1_me);

		if (error == OMCI_SUCCESS) {
			thr1_data = (struct omci_me_threshold_data1 *)
				thr1_me->data;

			me_lock(context, thr1_me);

			thr[0] = thr1_data->thr_data1;
			thr[1] = thr1_data->thr_data2;
			thr[2] = thr1_data->thr_data3;
			thr[3] = thr1_data->thr_data4;
			thr[4] = thr1_data->thr_data5;
			thr[5] = thr1_data->thr_data6;
			thr[6] = thr1_data->thr_data7;

			me_unlock(context, thr1_me);
		}

		error = mib_me_find(context,
				    OMCI_ME_THRESHOLD_DATA2,
				    pm_me_data->thr_data_id,
				    &thr2_me);

		if (error == OMCI_SUCCESS) {
			thr2_data = (struct omci_me_threshold_data2 *)
				thr2_me->data;

			me_lock(context, thr2_me);

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

		if (me->class->thr_set) {
			error = me->class->thr_set(context, me, thr);

			RETURN_IF_ERROR(error);
		}
	}
#endif

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error default_me_init(struct omci_context *context,
				struct me *me,
				void *init_data,
				uint16_t suppress_avc)
{
	uint8_t data[OMCI_ME_DATA_SIZE_MAX];
	enum omci_error error;

	dbg_in(__func__, "%p, %p {%u@%u}, %p, 0x%04x",
	       (void *)context,
	       (void *)me,
	       me->class->class_id,
	       me->instance_id,
	       (void *)init_data, suppress_avc);

	if (init_data) {
		memcpy(&data, init_data, me->class->data_size);
	} else {
		memset(&data, 0x00, me->class->data_size);
	}

	error = me_data_write(context, me, &data, me->class->data_size,
			      ~me->class->inv_attr_mask, suppress_avc);

	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
} 

enum omci_error default_me_shutdown(struct omci_context *context,
				   struct me *me)
{
	dbg_in(__func__, "%p, %p {%u@%u}",
	       (void *)context,
	       (void *)me,
	       me->class->class_id,
	       me->instance_id);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** @} */
