/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_priority_queue.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_priority_queue.h"
#include "me/omci_mac_bridge_port_config_data.h"
#include "me/omci_traffic_scheduler.h"
#include "me/omci_api_priority_queue.h"
#include "me/omci_api_mac_bridge_port_config_data.h"
#include "me/omci_api_pptp_ethernet_uni.h"

/** \addtogroup OMCI_ME_PRIORITY_QUEUE
   @{
*/

/** Get Queue configuration option

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error config_option_get(struct omci_context *context,
					 struct me *me,
					 void *data,
					 size_t data_size)
{
#if 0
	enum omci_api_return ret;
#endif

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 1);

#if 0
	ret = OMCI_API_PriorityQueue_QueueConfigurationOptionGet(me->instance_id,
								 data);

	if (ret != OMCI_API_SUCCESS) {
		/** \todo comment error */

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}
#endif

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get Maximum queue size

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error max_size_get(struct omci_context *context,
				    struct me *me,
				    void *data,
				    size_t data_size)
{
#if 0
	enum omci_api_return ret;
#endif

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 2);

#if 0
	ret = OMCI_API_PriorityQueue_MaximumQueueSizeGet(me->instance_id,
							 (uint16_t *)data);

	if (ret != OMCI_API_SUCCESS) {
		/** \todo comment error */

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}
#endif

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask,
				   const void *data)
{
	struct omci_me_priority_queue *upd_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me_class,
	       (void *)exec_mask, (void *)data);

	upd_data = (struct omci_me_priority_queue *) data;

	error = default_me_validate(context, me_class, exec_mask, data);
	RETURN_IF_ERROR(error);

	if (upd_data->allocated_size > upd_data->max_size) {
		*exec_mask |=
			omci_attr2mask(omci_me_priority_queue_allocated_size);
	}

	/** \todo validate queue sizes; attributes from amendment 2 */

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

#ifdef INCLUDE_G984_4_AMENDMENT_2
struct bp_find {
	struct me *bp[OMCI_API_MAC_BRIDGE_PORT_CONFIG_DATA_MAX];
	size_t bp_num;
};

/** Collect only Upstream Queues
*/
static enum omci_error me_walker(struct omci_context *context,
				 struct me *me,
				 void *shared_data)
{
	uint16_t bridge_me_id;
	enum omci_error error;
	struct bp_find *data = (struct bp_find *)shared_data;


	data->bp[data->bp_num] = me;
	data->bp_num += 1;

	if (data->bp_num >= OMCI_API_MAC_BRIDGE_PORT_CONFIG_DATA_MAX)
		return OMCI_ERROR;


	return OMCI_SUCCESS;
}

/** Update all related low-level configurations
*/
static void
drop_precedence_color_marking_refresh(struct omci_context *context,
				      struct me *current_pqueue_me,
				      const uint16_t sched,
				      const uint32_t related_port,
				      uint8_t drop_precedence_color_marking)
{
	enum omci_error error;
	enum omci_api_return ret;
	uint8_t lan_port, lan_start, lan_end;
	bool is_upstream;
	struct bp_find find;
	size_t i;
	uint16_t sched_ptr = sched;

	is_upstream = (current_pqueue_me->instance_id & 0x8000) ? true : false;

	if (is_upstream) {
		lan_start = 0;
		lan_end = OMCI_API_PPPTP_ETHERNET_UNI_MAX - 1;
	} else {
		ret = omci_api_uni2lan(context->api,
				       (related_port >> 16) & 0xFFFF,
				       &lan_start);
		if (ret != OMCI_API_SUCCESS) {
			dbg_err("DRV ERR(%d) UNI2LAN mapping get failed, "
				"(meid=0x%04X)", ret,
						(related_port >> 16) & 0xFFFF);
			return;
		}
		lan_end = lan_start;
	}

	for (lan_port = lan_start; lan_port <= lan_end; lan_port++) {
		ret = omci_api_priority_queue_drop_precedence_color_marking_set(
					is_upstream ?
					   OMCI_API_QUEUE_DIRECTION_UPSTREAM :
					   OMCI_API_QUEUE_DIRECTION_DOWNSTREAM,
					lan_port,
					drop_precedence_color_marking);
		if (ret != OMCI_API_SUCCESS) {
			dbg_err("DRV ERR(%d) Can't set Drop Precedence Color "
				"Marking 0x%02X, LAN(0x%02X)", ret,
						drop_precedence_color_marking,
						lan_port);
			return;
		}
	}


	/* Find all Bridge Ports */
	memset(&find, 0, sizeof(find));
	error = mib_walk_by_class(context,
				  OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
				  me_walker, &find);
	if (error) {
		dbg_err("ERROR(-1) Bridge Ports find failed"
			" (drop precedence color marking refresh)");
		return;
	}

	if (find.bp_num > ARRAY_SIZE(find.bp)) {
		dbg_err("ERROR(-1) Not enough memory for Bridge Ports "
			"(drop precedence color marking refresh)");
		return;
	}

	/* refresh all Bridge Ports */
	for (i = 0; i < find.bp_num; i++) {
		me_lock(context, find.bp[i]);
		error = me_refresh(context, find.bp[i]);
		me_unlock(context, find.bp[i]);
		if (error != OMCI_SUCCESS) {
			me_dbg_err(find.bp[i], "Refresh error %d", error);
			continue;
		}
	}
}
#endif

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_error error;
	enum omci_api_return ret;
	struct omci_me_priority_queue *upd_data;
	struct omci_me_priority_queue *me_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	upd_data = (struct omci_me_priority_queue *) data;
	me_data = (struct omci_me_priority_queue *) me->data;

	if (!me->is_initialized) {
		ret = omci_api_priority_queue_create(context->api,
				me->instance_id,
				upd_data->related_port,
				upd_data->traffic_scheduler_ptr,
				upd_data->allocated_size,
				upd_data->discard_block_counter_reset_interval,
				upd_data->discard_block_thr,
				upd_data->weight,
				upd_data->back_pressure_oper,
				upd_data->back_pressure_time,
				upd_data->back_pressure_occur_thr,
				upd_data->back_pressure_clear_thr,
#ifdef INCLUDE_G984_4_AMENDMENT_2
				upd_data->packet_drop_thr_green_min,
				upd_data->packet_drop_thr_green_max,
				upd_data->packet_drop_thr_yellow_min,
				upd_data->packet_drop_thr_yellow_max,
				upd_data->packet_drop_probability_green,
				upd_data->packet_drop_probability_yellow,
				upd_data->drop_avg_coef,
				upd_data->drop_precedence_color_marking
#else
				0, 0, 0, 0, 0, 0, 0, 0
#endif
				);
	} else {
		ret = omci_api_priority_queue_update(context->api,
				me->instance_id,
				upd_data->allocated_size,
				upd_data->discard_block_counter_reset_interval,
				upd_data->discard_block_thr,
				upd_data->weight,
				upd_data->back_pressure_oper,
				upd_data->back_pressure_time,
				upd_data->back_pressure_occur_thr,
				upd_data->back_pressure_clear_thr,
#ifdef INCLUDE_G984_4_AMENDMENT_2
				upd_data->packet_drop_thr_green_min,
				upd_data->packet_drop_thr_green_max,
				upd_data->packet_drop_thr_yellow_min,
				upd_data->packet_drop_thr_yellow_max,
				upd_data->packet_drop_probability_green,
				upd_data->packet_drop_probability_yellow,
				upd_data->drop_avg_coef,
				upd_data->drop_precedence_color_marking
#else
				0, 0, 0, 0, 0, 0, 0, 0
#endif
				);
	}

#ifdef INCLUDE_G984_4_AMENDMENT_2
	if (attr_mask & omci_attr2mask(omci_me_priority_queue_drop_precedence_color_marking)) {
		drop_precedence_color_marking_refresh(context, me,
				upd_data->traffic_scheduler_ptr,
				upd_data->related_port,
				upd_data->drop_precedence_color_marking);
	}
#endif

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't update Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	ret = omci_api_priority_queue_destroy(context->api,
					      me->instance_id);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete "
			   "Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

#ifdef INCLUDE_G984_4_AMENDMENT_2
static uint16_t drop_precedence[] = {
	0, 1, 2, 3, 4, 5, 6, 7
};
#endif

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
static uint8_t alarm_table[] = { 0 };
#endif

/** Managed Entity class */
struct me_class me_priority_queue_class = {
	/* Class ID */
	OMCI_ME_PRIORITY_QUEUE,
	/* Attributes */
	{
		/* 1. Queue Configuration Option */
		ATTR_UINT("Queue config option",
			  ATTR_SUPPORTED,
			  0,
			  1,
			  offsetof(struct omci_me_priority_queue,
				   config_option),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  config_option_get),
		/* 2. Maximum Queue Size */
		ATTR_UINT("Maximum queue size",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_priority_queue,
				   max_size),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  max_size_get),
		/* 3. Allocated Queue Size */
		ATTR_UINT("Allocated queue size",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_priority_queue,
				   allocated_size),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 4. Discard-block Counter Reset Interval */
		ATTR_UINT("Discard-block cntr reset",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_priority_queue,
				   discard_block_counter_reset_interval),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 5. Threshold Value For Discarded Blocks Due To Buffer
		   Overflow */
		ATTR_UINT("Discarded-block thr",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_priority_queue,
				   discard_block_thr),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 6. Related port */
		ATTR_UINT("Related port",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_priority_queue,
				   related_port),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 7. Traffic Scheduler Pointer */
		ATTR_PTR("Traffic scheduler ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_priority_queue,
				  traffic_scheduler_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 8. Weight */
		ATTR_UINT("Weight",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_priority_queue,
				   weight),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 9. Back Pressure Operation */
		ATTR_BOOL("Back pressure operation",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_priority_queue,
				   back_pressure_oper),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 10. Back Pressure Time */
		ATTR_UINT("Back pressure time",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_priority_queue,
				   back_pressure_time),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 11. Back Pressure Occur Queue Threshold */
		ATTR_UINT("Back pressure occur thr",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_priority_queue,
				   back_pressure_occur_thr),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 12. Back Pressure Clear Queue Threshold */
		ATTR_UINT("Back pressure clear thr",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_priority_queue,
				   back_pressure_clear_thr),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
#ifdef INCLUDE_G984_4_AMENDMENT_2
		/* 13. Packet Drop Thresholds  */
		ATTR_STR("Packet drop queue thr",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_priority_queue,
				  packet_drop_thr_green_min),
			 8,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 14. Packet Drop Probability  */
		ATTR_STR("Packet drop max_p",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_priority_queue,
				  packet_drop_probability_green),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 15. Queue Drop Averaging Coefficients  */
		ATTR_UINT("Queue drop w_q",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_priority_queue,
				   drop_avg_coef),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 16. Drop Precedence Color Marking Mode  */
		ATTR_ENUM("Drop precedence marking",
			  ATTR_SUPPORTED,
			  drop_precedence,
			  offsetof(struct omci_me_priority_queue,
				   drop_precedence_color_marking),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL,
			  NULL)
#else
			/* 13-16. Doesn't exist */
			ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
#endif
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
	me_shutdown,
	/* Validate Handler */
	me_validate,
	/* Update Handler */
	me_update,
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
	sizeof(struct omci_me_priority_queue),
	/* Properties */
	OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Priority queue",
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
