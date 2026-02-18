/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_pptp_ethernet_uni.c
*/
#include "ifxos_time.h"
#include <stdio.h>

#define DLOG(fmt, ...) do { \
	FILE *_f = fopen("/tmp/8311_me11.log", "a"); \
	if (_f) { fprintf(_f, fmt "\n", ##__VA_ARGS__); fclose(_f); } \
} while (0)

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_pptp_ethernet_uni.h"
#include "me/omci_api_pptp_ethernet_uni.h"
#include "me/omci_api_dot1x_port_ext_pkg.h"

/** \addtogroup OMCI_ME_PPTP_ETHERNET_UNI
   @{
*/

static enum omci_error sensed_type_get(struct omci_context *context,
				       struct me *me,
				       void *data,
				       size_t data_size)
{
	enum omci_api_return ret;
	uint8_t tmp = 0;
	assert(data_size == 1);
	ret = omci_api_pptp_ethernet_uni_sensed_type_get(context->api,
							 me->instance_id,
							 &tmp);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;
	memcpy(data, &tmp, 1);
	return OMCI_SUCCESS;
}

static enum omci_error oper_state_get(struct omci_context *context,
				      struct me *me,
				      void *data,
				      size_t data_size)
{
	enum omci_api_return ret;
	uint8_t tmp = 0;
	assert(data_size == 1);
	ret = omci_api_pptp_ethernet_uni_oper_state_get(context->api,
							me->instance_id,
							&tmp);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;
	memcpy(data, &tmp, 1);
	return OMCI_SUCCESS;
}

static enum omci_error config_ind_get(struct omci_context *context,
				      struct me *me,
				      void *data,
				      size_t data_size)
{
	enum omci_api_return ret;
	uint8_t tmp = 0;
	assert(data_size == 1);
	ret = omci_api_pptp_ethernet_uni_configuration_ind_get(context->api,
							       me->instance_id,
							       &tmp);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;
	memcpy(data, &tmp, 1);
	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	struct omci_me_pptp_ethernet_uni *upd_data;
	struct omci_me_pptp_ethernet_uni *me_data;
	enum omci_error error;

	upd_data = (struct omci_me_pptp_ethernet_uni *)data;
	me_data = (struct omci_me_pptp_ethernet_uni *)me->data;

	/* v7.5.1: skip if only read-only attrs changed (sensed_type,
	   oper_state, config_ind).  Mask 0xb9ff = all writable attrs. */
	if ((~(omci_attr2mask(omci_me_pptp_ethernet_uni_config_ind) |
	       omci_attr2mask(omci_me_pptp_ethernet_uni_sensed_type) |
	       omci_attr2mask(omci_me_pptp_ethernet_uni_oper_state))
	     & attr_mask) == 0)
		return OMCI_SUCCESS;

	ret = omci_api_pptp_ethernet_uni_update(context->api,
						me->instance_id,
						upd_data->expected_type,
						upd_data->auto_detect_config,
						upd_data->ether_loopback_config,
						upd_data->max_frame_size,
						upd_data->dte_dce_ind,
						upd_data->pause_time,
						upd_data->bridged_ip_ind,
						upd_data->pppoe_filter,
						upd_data->power_control);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't update Managed Entity", ret);
		return OMCI_ERROR_DRV;
	}

	/* v7.5.1: after _config, call _enabled to set GPE table valid bit
	   and enable the LAN port hardware.  Stock binary calls this from
	   the me_update path (0x421d1a). */
	ret = omci_api_pptp_ethernet_uni_enabled(context->api,
						 me->instance_id);
	if (ret != OMCI_API_SUCCESS)
		me_dbg_err(me, "DRV ERR(%d) _enabled failed", ret);

	/* ARC handling */
	if (attr_mask & omci_attr2mask(omci_me_pptp_ethernet_uni_arc)
	    || attr_mask &
	    omci_attr2mask(omci_me_pptp_ethernet_uni_arc_interval)) {
		me_data->arc = upd_data->arc;

		error = arc_interval_set(context, me,
					 &upd_data->arc_interval,
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
	enum omci_api_return ret;
	enum omci_error error;
	struct omci_me_pptp_ethernet_uni *me_data;

	DLOG("ME11 me_init ENTERED: id=0x%04x init_data=%p",
	     me->instance_id, init_data);

	RETURN_IF_PTR_NULL(init_data);

	/* setup ARC support */
	me->arc_context->arc_attr = 12;
	me->arc_context->arc_interval_attr = 13;

	me_data = (struct omci_me_pptp_ethernet_uni *)init_data;

	DLOG("ME11 me_init: id=0x%04x exp=%u auto=%u "
	     "loop=%u mfs=%u admin=%u",
	     me->instance_id, me_data->expected_type,
	     me_data->auto_detect_config, me_data->ether_loopback_config,
	     me_data->max_frame_size, me_data->admin_state);

	/* v7.5.1 stock ME create handler (0x421eee) sequence:
	   1. _create(me_id) — mapping only (uni2port + explicit_map)
	   2. me_data_write — stores MIB data, triggers _update → _config
	      (me_update calls _config then _enabled)
	   3. 802.1x auth set to OPEN (dot1x_enable=0, action=3) */
	ret = omci_api_pptp_ethernet_uni_create(context->api,
						me->instance_id);

	DLOG("ME11 me_init: create ret=%d", ret);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) init: mapping failed", ret);
		return OMCI_SUCCESS;
	}

	/* me_data_write stores init_data and triggers me_update callback
	   which calls _config (port settings) + _enabled (LAN_PORT_ENABLE
	   + GPE table valid bit). */
	error = me_data_write(context, me, init_data, me->class->data_size,
			      ~me->class->inv_attr_mask, suppress_avc);

	DLOG("ME11 me_init: me_data_write ret=%d", error);

	if (error != OMCI_SUCCESS)
		me_dbg_err(me, "DRV ERR(%d) init: data write failed", error);

	/* v7.5.1: set 802.1x to OPEN after data write.
	   Stock calls omci_api_dotx_port_ext_pkg_pptp(me_id, 0, 3).
	   Our API: dot1x_enable=0, action_register=3 → OPEN. */
	ret = omci_api_dot1x_port_ext_pkg_update(context->api,
						  me->instance_id,
						  0, 3);
	DLOG("ME11 me_init: 802.1x auth OPEN ret=%d", ret);

	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;
	(void)context;

	ret = omci_api_pptp_ethernet_uni_destroy(context->api,
						 me->instance_id);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);
		return OMCI_ERROR_DRV;
	}

	return OMCI_SUCCESS;
}

static uint16_t expected_type_cp[] = {
	OMCI_CIRCUIT_PACK_TYPE_NO_LIM,
	OMCI_CIRCUIT_PACK_TYPE_10BASET,
	OMCI_CIRCUIT_PACK_TYPE_100BASET,
	OMCI_CIRCUIT_PACK_TYPE_10100BASET,
	OMCI_CIRCUIT_PACK_TYPE_101001000BASET,
	OMCI_CIRCUIT_PACK_TYPE_GPON1244155,
	OMCI_CIRCUIT_PACK_TYPE_GPON1244622,
	OMCI_CIRCUIT_PACK_TYPE_GPON12441244,
	OMCI_CIRCUIT_PACK_TYPE_GPON2488155,
	OMCI_CIRCUIT_PACK_TYPE_GPON2488622,
	OMCI_CIRCUIT_PACK_TYPE_GPON24881244,
	OMCI_CIRCUIT_PACK_TYPE_GPON24882488
};

static uint16_t auto_detect_config_cp[] = {
	0x00,
	0x01,
	0x02,
	0x03,
	0x04,
	0x10,
	0x11,
	0x12,
	0x13,
	0x14,
	0x20,
	0x30
};

static uint16_t ether_loopback_config_cp[] = { 0, 3 };

static uint16_t config_ind_cp[] = {
	0x00,
	0x01,
	0x02,
	0x03,
	0x11,
	0x12,
	0x13
};

static uint16_t dte_dce_ind_cp[] = { 0, 1 };

static uint16_t bridged_or_ip_ind_cp[] = { 0, 1, 2 };

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
static uint8_t alarm_table[] = {
	omci_me_pptp_ethernet_uni_alarm_lan_los
};
#endif

/** Managed Entity class */
struct me_class me_pptp_ethernet_uni_class = {
	/* Class ID */
	OMCI_ME_PPTP_ETHERNET_UNI,
	/* Attributes */
	{
		/* 1. Expected type */
		ATTR_ENUM("Expected type",
			  ATTR_SUPPORTED,
			  expected_type_cp,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   expected_type),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 2. Sensed type */
		ATTR_ENUM("Sensed type",
			  ATTR_SUPPORTED,
			  expected_type_cp,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   sensed_type),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			  OMCI_ATTR_PROP_TEMPLATE,
			  sensed_type_get),
		/* 3. Auto detection configuration */
		ATTR_ENUM("Auto detection config",
			  ATTR_SUPPORTED,
			  auto_detect_config_cp,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   auto_detect_config),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 4. Ethernet loopback configuration */
		ATTR_ENUM("Ethernet loopback config",
			  ATTR_SUPPORTED,
			  ether_loopback_config_cp,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   ether_loopback_config),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 5. Administrative state */
		ATTR_BOOL("Administrative state",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   admin_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 6. Operational state */
		ATTR_BOOL("Operational state",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   oper_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			  OMCI_ATTR_PROP_TEMPLATE | OMCI_ATTR_PROP_OPTIONAL,
			  oper_state_get),
		/* 7. Configuration ind */
		ATTR_ENUM("Configuration ind",
			  ATTR_SUPPORTED,
			  config_ind_cp,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   config_ind),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  config_ind_get),
		/* 8. Max frame size */
		ATTR_UINT("Max frame size",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   max_frame_size),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 9. DTE or DCE ind */
		ATTR_ENUM("DTE or DCE ind",
			  ATTR_SUPPORTED,
			  dte_dce_ind_cp,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   dte_dce_ind),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 10. Pause time */
		ATTR_UINT("Pause time",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   pause_time),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 11. Bridged or IP ind */
		ATTR_ENUM("Bridged or IP ind",
			  ATTR_SUPPORTED,
			  bridged_or_ip_ind_cp,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   bridged_ip_ind),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 12. Alarm Reporting Control */
		ATTR_BOOL("ARC",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   arc),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_AVC | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 13. Alarm Reporting Interval */
		ATTR_UINT("ARC interval",
			  ATTR_SUPPORTED,
			  0,
			  255,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   arc_interval),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 14. PPPoE filter */
		ATTR_BOOL("PPPoE filter",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   pppoe_filter),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 15. Power control */
		ATTR_BOOL("Power control",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_pptp_ethernet_uni,
				   power_control),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 16. Doesn't exist */
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
	sizeof(struct omci_me_pptp_ethernet_uni),
	/* Properties */
	OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_HAS_ARC |
	OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"PPTP Ethernet UNI",
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
