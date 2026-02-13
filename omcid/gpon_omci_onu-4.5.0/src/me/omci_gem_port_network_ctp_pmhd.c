/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_gem_port_network_ctp_pmhd.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_gem_port_network_ctp_pmhd.h"
#include "me/omci_gem_port_network_ctp.h"
#include "me/omci_api_gem_port_pmhd.h"

#ifdef INCLUDE_PM

/** \addtogroup OMCI_ME_GEM_PORT_NETWORK_CTP_PMHD
    @{
*/

static enum omci_error me_counters_get(struct omci_context *context,
				       struct me *me,
				       enum omci_pm_interval interval)
{
	struct omci_me_gem_port_network_ctp_pmhd *me_data;
	enum omci_api_return ret;

	uint64_t tx_gem_frames;
	uint64_t rx_gem_frames;

	dbg_in(__func__, "%p, %p, %lu", (void *)context, (void *)me, interval);

	me_data = (struct omci_me_gem_port_network_ctp_pmhd *)me->data;

	ret = omci_api_gem_port_pmhd_cnt_get(context->api,
					     me->instance_id,
					     false,
					     interval == OMCI_PM_INTERVAL_CURR,
					     &tx_gem_frames,
					     &rx_gem_frames,
					     &me_data->rx_payload_bytes,
					     &me_data->tx_payload_bytes,
					     NULL);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't get counters", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	me_data->tx_gem_frames = uint64_lo(tx_gem_frames);
	me_data->rx_gem_frames = uint64_lo(rx_gem_frames);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_thr_set(struct omci_context *context,
				  struct me *me,
				  uint32_t thr[PM_THR_NUM])
{
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)thr);

	ret = omci_api_gem_port_pmhd_thr_set(context->api,
					     me->instance_id,
					     thr[0], thr[1],
					     thr[2], thr[3], 0);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't set thresholds", ret);

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

	/* check if related GEM Port Network CTP exists */
	error = mib_me_find(context, OMCI_ME_GEM_PORT_NETWORK_CTP,
			    me->instance_id, NULL);

	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	dbg_out_ret(__func__, error);
	return error;
}

/** Managed Entity class */
struct me_class me_gem_port_network_ctp_pmhd_class = {
	/* Class ID */
	OMCI_ME_GEM_PORT_NETWORK_CTP_PMHD,
	/* Attributes */
	{
		/* 1. Interval End Time */
		ATTR_UINT("Interval end time",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_gem_port_network_ctp_pmhd,
				   interval_end_time),
			  1,
			  OMCI_ATTR_PROP_RD,
			  pm_interval_end_time_get),
		/* 2. Threshold Data 1/2 ID */
		ATTR_PTR("Threshold data 1/2 id",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_gem_port_network_ctp_pmhd,
				  thr_data_id),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 3. Transmitted GEM frames */
		ATTR_UINT("Transmitted GEM frames",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_gem_port_network_ctp_pmhd,
				   tx_gem_frames),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 4. Received GEM frames */
		ATTR_UINT("Received GEM frames",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_gem_port_network_ctp_pmhd,
				   rx_gem_frames),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 5. Received payload bytes */
		ATTR_UINT("Received payload bytes",
			  ATTR_SUPPORTED,
			  ULL_CONST(0x0000000000000000),
			  ULL_CONST(0xffffffffffffffff),
			  offsetof(struct omci_me_gem_port_network_ctp_pmhd,
				   rx_payload_bytes),
			  8,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 6. Transmitted payload bytes */
		ATTR_UINT("Transmitted payload bytes",
			  ATTR_SUPPORTED,
			  ULL_CONST(0x0000000000000000),
			  ULL_CONST(0xffffffffffffffff),
			  offsetof(struct omci_me_gem_port_network_ctp_pmhd,
				   tx_payload_bytes),
			  8,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 7-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
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
		get_current_data_action_handle
	},
	/* Init Handler */
	me_init,
	/* Shutdown Handler */
	me_shutdown,
	/* Validate Handler */
	default_me_validate,
	/* Update Handler */
	default_me_update,
	/* Table Attribute Copy Handler */
	NULL,
	/* Table Attribute Operations Handler */
	NULL,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	me_counters_get,
	/* Thresholds set Handler */
	me_thr_set,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_me_gem_port_network_ctp_pmhd),
	/* Properties */
	OMCI_ME_PROP_PM | OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"GEM port network CTP PMHD",
		/* Access */
		ME_CREATED_BY_OLT,
		/* Supported alarms */
		NULL,
		/* Supported alarms count */
		0,
		/* Support */
		ME_SUPPORTED},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */

#endif
