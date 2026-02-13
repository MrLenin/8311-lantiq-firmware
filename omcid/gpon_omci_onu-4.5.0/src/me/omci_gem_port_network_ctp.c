/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_gem_port_network_ctp.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_gem_port_network_ctp.h"
#include "me/omci_onu_g.h"
#include "me/omci_tcont.h"
#include "me/omci_onu2_g.h"
#include "me/omci_api_gem_port_network_ctp.h"
#include "me/omci_priority_queue.h"
#include "me/omci_traffic_scheduler.h"
#include "me/omci_traffic_descriptor.h"

/** \addtogroup OMCI_ME_GEM_PORT_NETWORK_CTP
   @{
*/

/** Invalid Port-ID value */
#define OMCI_PORT_ID_INVALID 0xffff

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask,
				   const void *data)
{
	struct omci_me_gem_port_network_ctp *upd_data;
	struct me *onu_g_me;
	enum omci_error error;
	uint8_t traffic_management;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me_class,
	       (void *)exec_mask, (void *)data);

	upd_data = (struct omci_me_gem_port_network_ctp *)data;

	error = default_me_validate(context, me_class, exec_mask, data);
	RETURN_IF_ERROR(error);

	error = mib_me_find(context, OMCI_ME_ONU_G, 0, &onu_g_me);
	RETURN_IF_ERROR(error);

	me_lock(context, onu_g_me);
	error = me_attr_read(context, onu_g_me,
			     omci_me_onu_g_traffic_management,
			     &traffic_management,
			     sizeof(traffic_management));
	me_unlock(context, onu_g_me);
	RETURN_IF_ERROR(error);

	if (upd_data->direction != 2) {
		/* upstream */

		if (upd_data->tcont_ptr) {
			/* check if the pointer is valid */
			error = mib_me_find(context, OMCI_ME_TCONT,
					    upd_data->tcont_ptr, NULL);
			if (error)
				*exec_mask |=
					omci_attr2mask(omci_me_gem_port_network_ctp_tcont_ptr);
		}

		if (traffic_management == 0
#ifdef INCLUDE_G984_4_AMENDMENT_2
		    || traffic_management == 2
#endif
		    ) {
			error = mib_me_find(context,
					    OMCI_ME_PRIORITY_QUEUE,
					    upd_data->traffic_management_ptr_us,
					    NULL);
		} else if (traffic_management == 1) {

			if (upd_data->traffic_management_ptr_us !=
							  upd_data->tcont_ptr) {
				error = OMCI_SUCCESS;
				dbg_wrn("Traffic management pointer US doesn't "
					"redundantly points to the T-CONT, "
					"ignoring attr validate");
			} else {
				error = mib_me_find(context, OMCI_ME_TCONT,
					    upd_data->traffic_management_ptr_us,
					    NULL);
			}
		}

		if (error)
			*exec_mask |=
				omci_attr2mask(omci_me_gem_port_network_ctp_traffic_management_ptr_us);

	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_error error;
	enum omci_api_return ret;
	uint8_t drop_precedence_color_marking = 0, egress_color_marking = 0;
	struct omci_me_gem_port_network_ctp *upd_data;
	struct me *tsched_me;
	struct me *pqueue_me[OMCI_US_PRIORITY_QUEUE_MAX];
	size_t pqueue_num, i;
	uint16_t traffic_management_ptr_us = 0x0000;
	struct map_gem2pqueue *map;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_gem_port_network_ctp *)data;

	if (context->traffic_management_opt == 1 && upd_data->direction == 3) {
		error = mib_me_find_where(context,
					  OMCI_ME_TRAFFIC_SCHEDULER,
					  omci_me_traffic_scheduler_tcont_pointer,
					  &upd_data->tcont_ptr,
					  sizeof(upd_data->tcont_ptr),
					  &tsched_me,
					  sizeof(tsched_me),
					  NULL);
		RETURN_IF_ERROR(error);

		error = mib_me_find_where(context,
					  OMCI_ME_PRIORITY_QUEUE,
					  omci_me_priority_queue_traffic_scheduler_ptr,
					  &tsched_me->instance_id,
					  sizeof(tsched_me->instance_id),
					  &pqueue_me[0],
					  sizeof(pqueue_me),
					  &pqueue_num);
		RETURN_IF_ERROR(error);

		if (pqueue_num > ARRAY_SIZE(pqueue_me)) {
			me_dbg_err(me, "ERR Not enough memory for Priority "
				       "Queues");
			dbg_out_ret(__func__, OMCI_ERROR_MEMORY);
			return OMCI_ERROR_MEMORY;
		}

		map = context->map_gem2pqueue;
		for (i = 0; i < pqueue_num; i++) {
			if (!map[i].mapped) {
				map[i].mapped = true;
				map[i].pqueue_id = pqueue_me[i]->instance_id;
				map[i].gem_port_id = upd_data->gem_port_id;
				traffic_management_ptr_us = map[i].pqueue_id;
				break;
			} else {
				if (map[i].gem_port_id ==
							upd_data->gem_port_id) {
					traffic_management_ptr_us =
							       map[i].pqueue_id;
					break;
				}
			}
		}

		if (i >= pqueue_num) {
			me_dbg_err(me, "ERR Can't map US pqueue to GEM");
	
			dbg_out_ret(__func__, OMCI_ERROR);
			return OMCI_ERROR;
		}
	} else {
		traffic_management_ptr_us = upd_data->traffic_management_ptr_us;
	}

	ret = omci_api_gem_port_network_ctp_update(context->api,
						   me->instance_id,
						   upd_data->gem_port_id,
						   upd_data->tcont_ptr,
						   upd_data->direction,
						   traffic_management_ptr_us,
						   drop_precedence_color_marking,
						   egress_color_marking,
						   upd_data->traffic_descriptor_ptr_us,
						   upd_data->priority_queue_ptr_ds,
						   upd_data->traffic_descriptor_ptr_ds);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't update Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	error = default_me_init(context, me, init_data, suppress_avc);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;
	struct omci_me_gem_port_network_ctp *me_data;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	me_data = (struct omci_me_gem_port_network_ctp *)me->data;
	ret = omci_api_gem_port_network_ctp_destroy(context->api,
						    me->instance_id,
						    me_data->gem_port_id,
						    me_data->traffic_management_ptr_us);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	memset(context->map_gem2pqueue, 0, sizeof(context->map_gem2pqueue));

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static uint16_t direction_cp[] = { 1, 2, 3 };

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
static uint8_t alarm_table[] = { 5 };
#endif

/** Managed Entity class */
struct me_class me_gem_port_network_ctp_class = {
	/* Class ID */
	OMCI_ME_GEM_PORT_NETWORK_CTP,
	/* Attributes */
	{
		/* 1. Port id value */
		ATTR_UINT("Port id value",
			  ATTR_SUPPORTED,
			  0x0000,
			  0x0fff,
			  offsetof(struct omci_me_gem_port_network_ctp,
				   gem_port_id),
			  2,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 2. T-CONT pointer */
		ATTR_PTR("T-CONT ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_gem_port_network_ctp,
				  tcont_ptr),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 3. Direction */
		ATTR_ENUM("Direction",
			  ATTR_SUPPORTED,
			  direction_cp,
			  offsetof(struct omci_me_gem_port_network_ctp,
				   direction),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 4. Traffic management pointer for upstream */
		ATTR_PTR("Traffic manage ptr US",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_gem_port_network_ctp,
				  traffic_management_ptr_us),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 5. Traffic descriptor profile pointer */
		ATTR_PTR("Traffic desc prof ptr US",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_gem_port_network_ctp,
				  traffic_descriptor_ptr_us),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL |
			 OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 6. UNI counter - optional */
		ATTR_UINT("UNI counter",
			  ATTR_UNSUPPORTED,
			  0x00,
			  0x00,
			  offsetof(struct omci_me_gem_port_network_ctp,
				   uni_counter),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_NOT_SUPPORTED |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 7. Priority queue pointer for downstream */
		ATTR_PTR("Priority queue ptr DS",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_gem_port_network_ctp,
				  priority_queue_ptr_ds),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 8. Encryption state - optional */
		ATTR_UINT("Encryption state",
			  ATTR_UNSUPPORTED,
			  0x00,
			  0x00,
			  offsetof(struct omci_me_gem_port_network_ctp,
				   encryption_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_NOT_SUPPORTED |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 9. Traffic Descriptor Profile Pointer Downstream */
		ATTR_PTR("Traffic desc prof ptr DS",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_gem_port_network_ctp,
				  traffic_descriptor_ptr_ds),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 10-16. Doesn't exist */
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
	me_init,
	/* Shutdown Handler */
	me_shutdown,
	/* Validate Handler */
	me_validate,
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
	sizeof(struct omci_me_gem_port_network_ctp),
	/* Properties */
	OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"GEM port network CTP",
		/* Access */
		ME_CREATED_BY_ONT,
		/* Supported alarms */
		alarm_table,
		/* Supported alarms count */
		sizeof(alarm_table) / sizeof(alarm_table[0]),
		/* Support */
		ME_SUPPORTED
	},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */
