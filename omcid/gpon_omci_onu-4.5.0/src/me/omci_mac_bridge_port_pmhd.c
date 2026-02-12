/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_mac_bridge_port_pmhd.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_mac_bridge_port_pmhd.h"
#include "me/omci_api_mac_bridge_port_pmhd.h"

#ifdef INCLUDE_PM

/** \addtogroup OMCI_ME_MAC_BRIDGE_PORT_PMHD
    @{
*/

static enum omci_error me_counters_get(struct omci_context *context,
				       struct me *me,
				       enum omci_pm_interval interval)
{
	enum omci_api_return ret;
	struct omci_me_mac_bridge_port_pmhd *me_data;
	uint64_t forwarded_frame, delay_exceed_discard,
		mtu_exceed_discard, received_frame, received_and_discarded;

	dbg_in(__func__, "%p, %p, %lu", (void *)context, (void *)me, interval);

	me_data = (struct omci_me_mac_bridge_port_pmhd *)me->data;

	ret = omci_api_mac_bridge_port_pmhd_cnt_get(context->api, me->instance_id,
						interval ==
							OMCI_PM_INTERVAL_CURR,
						false,
						&forwarded_frame,
						&delay_exceed_discard,
						&mtu_exceed_discard,
						&received_frame,
						&received_and_discarded);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't get counters", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	if (interval != OMCI_PM_INTERVAL_ABS) {
		me_data->forwarded_frame_count =
					uint64_lo(forwarded_frame);
		me_data->delay_exceeded_discard_count =
					uint64_lo(delay_exceed_discard);
		me_data->mtu_exceeded_discard_count =
					uint64_lo(mtu_exceed_discard);
		me_data->received_frame_count =
					uint64_lo(received_frame);
		me_data->received_discard_count =
					uint64_lo(received_and_discarded);
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

	/* check if related MAC bridge service profile exists */
	error = mib_me_find(context,
			    OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
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

static struct me_tca tca_table[] = {
	/* 1 Delay exceeded discard #1 */
	TCA(1, omci_me_mac_bridge_port_pmhd_delay_exceeded_discard_count, 1),
	/* 2 MTU exceeded discard #2 */
	TCA(2, omci_me_mac_bridge_port_pmhd_mtu_exceeded_discard_count, 2),
	/* 4 Received and discarded #3 */
	TCA(4, omci_me_mac_bridge_port_pmhd_received_discarded_count, 3),

	TCA(0, 0, 0)
};

/** Managed Entity class */
struct me_class me_mac_bridge_port_pmhd_class = {
	/* Class ID */
	OMCI_ME_MAC_BRIDGE_PORT_PMHD,
	/* Attributes */
	{
		/* 1. Interval End Time */
		ATTR_UINT("Interval end time",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_mac_bridge_port_pmhd,
				   interval_end_time),
			  1,
			  OMCI_ATTR_PROP_RD,
			  pm_interval_end_time_get),
		/* 2. Threshold Data 1/2 ID */
		ATTR_PTR("Threshold data 1/2 id",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_mac_bridge_port_pmhd,
				  thr_data_id),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 3. Forwarded Frame Counter */
		ATTR_UINT("Forwarded frame counter",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_mac_bridge_port_pmhd,
				   forwarded_frame_count),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 4. Delay Exceeded Discard Counter */
		ATTR_UINT("Delay exceeded discard",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_mac_bridge_port_pmhd,
				   delay_exceeded_discard_count),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 5. MTU Exceeded Discard Counter */
		ATTR_UINT("MTU exceeded discard",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_mac_bridge_port_pmhd,
				   mtu_exceeded_discard_count),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 6. Received Frame Counter */
		ATTR_UINT("Received frame counter",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_mac_bridge_port_pmhd,
				   received_frame_count),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 7. Received and Discarded Counter */
		ATTR_UINT("Received and discarded",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_mac_bridge_port_pmhd,
				   received_discard_count),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 8-16. Doesn't exist */
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
#ifdef INCLUDE_PM
	/* Counters get Handler */
	me_counters_get,
	/* Thresholds set Handler */
	default_me_thr_set,
#endif
	/* TCA Table */
	tca_table,
	/* Data Size */
	sizeof(struct omci_me_mac_bridge_port_pmhd),
	/* Properties */
	OMCI_ME_PROP_PM | OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Bridge port PMHD",
		/* Access */
		ME_CREATED_BY_OLT,
		/* Supported alarms */
		NULL,
		/* Supported alarms count */
		0,
		/* Support */
		ME_SUPPORTED
	},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */

#endif
