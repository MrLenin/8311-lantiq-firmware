/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_ani_g.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "ifxos_time.h"
#include "ifxos_memory_alloc.h"

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_ani_g.h"
#include "me/omci_api_ani_g.h"


/** \addtogroup OMCI_ME_ANI_G
   @{
*/

/** Self test thread priority */
#define ANI_G_TEST_THREAD_PRIO             IFXOS_THREAD_PRIO_LOWEST
/** Self test thread stack size */
#define ANI_G_TEST_THREAD_STACKSIZE        IFXOS_DEFAULT_STACK_SIZE

/** Non-ITU data of the ANI-G Managed Entity */
struct internal_data {
	/** Self test thread control */
	IFXOS_ThreadCtrl_t self_test_thr_ctrl;
	/** Back-pointer to context (for thread) */
	struct omci_context *context;
	/** Back-pointer to ME (for thread) */
	struct me *me;
};

static enum omci_error sr_indication_get(struct omci_context *context,
					 struct me *me,
					 void *data,
					 size_t data_size)
{
	enum omci_api_return ret;
	assert(data_size == 1);
	ret = omci_api_ani_g_sr_indication_get(context->api,
					       me->instance_id,
					       (uint8_t *)data);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;
	return OMCI_SUCCESS;
}

static enum omci_error total_tcon_num_get(struct omci_context *context,
					  struct me *me,
					  void *data,
					  size_t data_size)
{
	enum omci_api_return ret;
	uint16_t tmp=0;
	assert(data_size == 2);
	ret = omci_api_ani_g_total_tcon_num_get(context->api,
						me->instance_id,
						&tmp);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;
	memcpy(data, &tmp, 2);
	return OMCI_SUCCESS;
}

static enum omci_error optical_signal_level_get(struct omci_context *context,
						struct me *me,
						void *data,
						size_t data_size)
{
	enum omci_api_return ret;
	int16_t tmp=0;
	assert(data_size == 2);
	ret = omci_api_ani_g_optical_signal_level_get(context->api,
						      me->instance_id,
						      &tmp);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;
	memcpy(data, &tmp, 2);
	return OMCI_SUCCESS;
}

static enum omci_error tx_optical_level_get(struct omci_context
					    *context,
					    struct me *me,
					    void *data,
					    size_t data_size)
{
	enum omci_api_return ret;
	int16_t tmp=0;
	assert(data_size == 2);
	ret = omci_api_ani_g_tx_optical_level_get(context->api,
						  me->instance_id,
						  &tmp);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;
	memcpy(data, &tmp, 2);
	return OMCI_SUCCESS;
}

static enum omci_error response_time_get(struct omci_context *context,
					 struct me *me,
					 void *data,
					 size_t data_size)
{
	enum omci_api_return ret;
	uint16_t tmp=0;
	assert(data_size == 2);
	ret = omci_api_ani_g_response_time_get(context->api,
					       me->instance_id,
					       &tmp);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;
	memcpy(data, &tmp, 2);
	return OMCI_SUCCESS;
}

static enum omci_error gem_block_len_get(struct omci_context *context,
					 struct me *me,
					 void *data,
					 size_t data_size)
{
	enum omci_api_return ret;
	uint16_t tmp = 0;
	assert(data_size == 2);
	ret = omci_api_ani_g_gem_block_len_get(context->api,
					       me->instance_id,
					       &tmp);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;
	memcpy(data, &tmp, 2);
	return OMCI_SUCCESS;
}

/** Self test thread — collects optical measurements and sends
    autonomous Test Result message (G.988 Table 9.2.1) */
static int32_t self_test_thread(struct IFXOS_ThreadParams_s *thr_params)
{
	struct internal_data *me_internal_data;
	struct omci_context *context;
	struct me *me;
	union omci_msg msg;
	uint16_t tci;
	int16_t rx_level = 0, tx_level = 0, temperature = 0;
	uint16_t supply_voltage = 0, bias_current = 0;

	me_internal_data = (struct internal_data *)thr_params->nArg1;
	context = me_internal_data->context;
	me = me_internal_data->me;
	tci = (uint16_t)thr_params->nArg2;

	/* Let the test ACK be sent first */
	IFXOS_SecSleep(1);

	/* Collect measurements (best-effort, failures produce 0) */
	(void)omci_api_ani_g_supply_voltage_get(context->api,
						me->instance_id,
						&supply_voltage);
	(void)omci_api_ani_g_optical_signal_level_get(context->api,
						      me->instance_id,
						      &rx_level);
	(void)omci_api_ani_g_tx_optical_level_get(context->api,
						  me->instance_id,
						  &tx_level);
	(void)omci_api_ani_g_laser_bias_current_get(context->api,
						    me->instance_id,
						    &bias_current);
	(void)omci_api_ani_g_laser_temperature_get(context->api,
						   me->instance_id,
						   &temperature);

	/* Build autonomous test result message */
	memset(&msg, 0, sizeof(msg));

	msg.tr_ani_g.header.tci = tci;
	msg.tr_ani_g.header.type = 0;
	omci_msg_type_mt_set(&msg, OMCI_MT_TEST_RESULT);
	msg.tr_ani_g.header.dev_id = OMCI_FORMAT_BASELINE;
	msg.tr_ani_g.header.class_id = hton16(OMCI_ME_ANI_G);
	msg.tr_ani_g.header.instance_id = hton16(me->instance_id);

	/* Type 1: Power feed voltage (20 mV units) */
	msg.tr_ani_g.type1 = 1;
	msg.tr_ani_g.value1 = hton16(supply_voltage);

	/* Type 3: Received optical power (0.002 dBm units) */
	msg.tr_ani_g.type3 = 3;
	msg.tr_ani_g.value3 = hton16((uint16_t)rx_level);

	/* Type 5: Transmitted optical power (0.002 dBm units) */
	msg.tr_ani_g.type5 = 5;
	msg.tr_ani_g.value5 = hton16((uint16_t)tx_level);

	/* Type 9: Laser bias current (2 uA units) */
	msg.tr_ani_g.type9 = 9;
	msg.tr_ani_g.value9 = hton16(bias_current);

	/* Type 12: Temperature (1/256 degree C) */
	msg.tr_ani_g.type12 = 12;
	msg.tr_ani_g.value12 = hton16((uint16_t)temperature);

	return (int32_t)omci_msg_send(context, &msg);
}

static enum omci_error test_action_handle(struct omci_context *context,
					  struct me *me,
					  const union omci_msg *msg,
					  union omci_msg *rsp)
{
	struct internal_data *me_internal_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	me_internal_data = (struct internal_data *)me->internal_data;

	/* G.988: test type 0x07 = self-test / start test */
	if (msg->test_onu_g.test == 0x07) {
		if (IFXOS_THREAD_INIT_VALID
		    (&me_internal_data->self_test_thr_ctrl))
			(void)IFXOS_ThreadDelete(&me_internal_data->
						 self_test_thr_ctrl, 0);

		me_internal_data->context = context;
		me_internal_data->me = me;

		error = (enum omci_error)
			IFXOS_ThreadInit(&me_internal_data->self_test_thr_ctrl,
					 "tstanig", self_test_thread,
					 ANI_G_TEST_THREAD_STACKSIZE,
					 ANI_G_TEST_THREAD_PRIO,
					 (unsigned long)me_internal_data,
					 (unsigned long)msg->msg.header.tci);

		RETURN_IF_ERROR(error);
	} else {
		/* unsupported test */
		rsp->test_rsp.result = OMCI_MR_PARAM_ERROR;

		dbg_out_ret(__func__, OMCI_ERROR);
		return OMCI_ERROR;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	struct omci_me_ani_g *upd_data;
	struct omci_me_ani_g *me_data;
	enum omci_error error;

	upd_data = (struct omci_me_ani_g *)data;
	me_data = (struct omci_me_ani_g *)me->data;

	ret = omci_api_ani_g_update(context->api,
				    me->instance_id,
				    upd_data->gem_block_len,
				    upd_data->sf_thr,
				    upd_data->sd_thr,
				    upd_data->lower_optical_thr,
				    upd_data->upper_optical_thr,
				    upd_data->lower_transmit_power_thr,
				    upd_data->upper_transmit_power_thr);

	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;

	if (attr_mask & omci_attr2mask(omci_me_ani_g_arc)
	    || attr_mask & omci_attr2mask(omci_me_ani_g_arc_interval)) {
		me_data->arc = upd_data->arc;

		error = arc_interval_set(context, me, &upd_data->arc_interval,
					 sizeof(upd_data->arc_interval));
		RETURN_IF_ERROR(error);
	}

	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;

	RETURN_IF_PTR_NULL(init_data);

	me->internal_data = IFXOS_MemAlloc(sizeof(struct internal_data));
	RETURN_IF_MALLOC_ERROR(me->internal_data);
	memset(me->internal_data, 0, sizeof(struct internal_data));

	/* setup ARC support */
	me->arc_context->arc_attr = 8;
	me->arc_context->arc_interval_attr = 9;

	error = me_data_write(context, me, init_data, me->class->data_size,
			      ~me->class->inv_attr_mask, suppress_avc);
	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;

	ret = omci_api_ani_g_destroy(context->api, me->instance_id);

	if (me->internal_data) {
		struct internal_data *data =
			(struct internal_data *)me->internal_data;
		if (IFXOS_THREAD_INIT_VALID(&data->self_test_thr_ctrl))
			(void)IFXOS_ThreadDelete(&data->self_test_thr_ctrl, 0);
		IFXOS_MemFree(me->internal_data);
		me->internal_data = NULL;
	}

	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;

	return OMCI_SUCCESS;
}

static uint16_t piggyback_dba_cp[] = {
	0,
	1,
#ifndef INCLUDE_G984_4_AMENDMENT_2
	2,
	3,
#endif
	4
};

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
static uint8_t alarm_table[] = { 1, 3, 5 };
#endif

/** Managed Entity class */
struct me_class me_ani_g_class = {
	/* Class ID */
	OMCI_ME_ANI_G,
	/* Attributes */
	{
		/* 1. Status Reporting Indication */
		ATTR_BOOL("SR indication",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_ani_g, sr_indication),
			  1,
			  OMCI_ATTR_PROP_RD,
			  sr_indication_get),
		/* 2. Total T-CONT Number */
		ATTR_UINT("Total T-CONT number",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_ani_g, total_tcon_num),
			  2,
			  OMCI_ATTR_PROP_RD,
			  total_tcon_num_get),
		/* 3. GEM Block Length */
		ATTR_UINT("GEM block length",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_ani_g, gem_block_len),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  gem_block_len_get),
		/* 4. Piggy-back Dynamic Bandwidth Allocation */
		ATTR_ENUM("Piggyback DBA reporting",
			  ATTR_SUPPORTED,
			  piggyback_dba_cp,
			  offsetof(struct omci_me_ani_g, piggyback_dba),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 5. Whole ONT DBA Reporting */
		ATTR_UINT("Whole ONT DBA reporting",
			  ATTR_SUPPORTED,
			  0x00,
			  0x00,
			  offsetof(struct omci_me_ani_g,
				   whole_ont_dba_reporting),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 6. Signal Fail Threshold */
		ATTR_UINT("SF threshold",
			  ATTR_SUPPORTED,
			  3,
			  8,
			  offsetof(struct omci_me_ani_g, sf_thr),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 7. Signal Degrade Threshold */
		ATTR_UINT("SD threshold",
			  ATTR_SUPPORTED,
			  4,
			  10,
			  offsetof(struct omci_me_ani_g, sd_thr),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 8. Alarm Reporting Control */
		ATTR_BOOL("ARC",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_ani_g, arc),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_AVC |
			  OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 9. Alarm Reporting Interval */
		ATTR_UINT("ARC interval",
			  ATTR_SUPPORTED,
			  0,
			  255,
			  offsetof(struct omci_me_ani_g, arc_interval),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 10. Optical Signal Level Downstream */
		ATTR_INT("Optical signal level",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_ani_g,
				   optical_signal_level),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  optical_signal_level_get),
		/* 11. Lower optical threshold */
		ATTR_UINT("Lower optical threshold",
			  ATTR_SUPPORTED,
			  0,
			  255,
			  offsetof(struct omci_me_ani_g, lower_optical_thr),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_PARTLY | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 12. Upper optical threshold */
		ATTR_UINT("Upper optical threshold",
			  ATTR_SUPPORTED,
			  0,
			  255,
			  offsetof(struct omci_me_ani_g, upper_optical_thr),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_PARTLY | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 13. ONT response time */
		ATTR_UINT("ONT response time",
			  ATTR_SUPPORTED,
			  34000,
			  36000,
			  offsetof(struct omci_me_ani_g, ont_response_time),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  response_time_get),
		/* 14. Transmit optical level */
		ATTR_INT("Transmit optical level",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_ani_g,
				   transmit_optical_level),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  tx_optical_level_get),
		/* 15. Lower transmit power threshold */
		ATTR_INT("Lower transmit power thr",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_ani_g,
				   lower_transmit_power_thr),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_PARTLY | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 16. Upper transmit power threshold */
		ATTR_INT("Upper transmit power thr",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_ani_g,
				   upper_transmit_power_thr),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_PARTLY | OMCI_ATTR_PROP_OPTIONAL,
			  NULL)
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
		test_action_handle,
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
	default_me_validate,
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
	sizeof(struct omci_me_ani_g),
	/* Properties */
	OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_HAS_ARC | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"ANI-G",
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
