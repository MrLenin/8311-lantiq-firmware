/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_rtp_pmhd.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_pptp_pots_uni.h"
#include "me/omci_rtp_pmhd.h"
#include "me/omci_api_rtp_pmhd.h"

#if defined(INCLUDE_PM) && defined(INCLUDE_OMCI_ONU_VOIP)

/** \addtogroup OMCI_RTP_PMHD
   @{
*/

static enum omci_error me_counters_get(struct omci_context *context,
				       struct me *me,
				       enum omci_pm_interval interval)
{
	struct omci_me_rtp_pmhd *me_data;
	uint32_t rtp_errors, packet_loss, max_jitter,
		 max_time_between_rtcp_packets, buffer_underflows,
		 buffer_overflows;
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p, %lu", (void *)context, (void *)me, interval);

	me_data = (struct omci_me_rtp_pmhd *)me->data;

	ret = omci_api_rtp_pmhd_cnt_get(context->api,
					me->instance_id,
					&rtp_errors,
					&packet_loss,
					&max_jitter,
					&max_time_between_rtcp_packets,
					&buffer_underflows,
					&buffer_overflows);
	if (ret != OMCI_API_SUCCESS) {
		if (ret == OMCI_API_WRN_DEV_NO_DATA) {
			dbg_out_ret(__func__, OMCI_SUCCESS);
			return OMCI_SUCCESS;
		} else {
			me_dbg_err(me, "DRV ERR(%d) Can't get counters", ret);
	
			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}
	}

	/* This attribute is calculated at the end of the 15-minute interval,
	   and is undefined under the get current data action.*/
	if (interval == OMCI_PM_INTERVAL_END)
		me_data->packet_loss = packet_loss;

	/* This attribute is a high water mark that represents the maximum
	   jitter identified during the measured interval, expressed in RTP
	   timestamp units.*/
	if (max_jitter > me_data->max_jitter)
		me_data->max_jitter = max_jitter;

	me_data->rtp_errors = rtp_errors;
	me_data->max_time_between_rtcp_packets = max_time_between_rtcp_packets;
	me_data->buffer_underflows = buffer_underflows;
	me_data->buffer_overflows = buffer_overflows;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;

	/* check if related PPTP POTS UNI exists */
	error = mib_me_find(context, OMCI_ME_PPTP_POTS_UNI,
			    me->instance_id, NULL);
	RETURN_IF_ERROR(error);

	error = default_me_init(context, me, init_data, suppress_avc);
	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}

static struct me_tca tca_table[] = {
	/* 1 RTP errors #1 */
	TCA(1, omci_me_rtp_pmhd_rtp_errors, 1),
	/* 2 Packet loss #2 */
	TCA(2, omci_me_rtp_pmhd_packet_loss, 2),
	/* 3 Maximum jitter  #3 */
	TCA(3, omci_me_rtp_pmhd_max_jitter, 3),
	/* 4 Max time between RTCP packets #4 */
	TCA(4, omci_me_rtp_pmhd_max_time_between_rtcp_packets, 4),
	/* 5 Buffer underflows #5 */
	TCA(5, omci_me_rtp_pmhd_buffer_underflows, 5),
	/* 6 Buffer overflows #6 */
	TCA(6, omci_me_rtp_pmhd_buffer_overflows, 6),

	TCA(0, 0, 0)
};

/** Managed Entity class */
struct me_class me_rtp_pmhd_class = {
	/* Class ID */
	OMCI_ME_RTP_MONITORING_DATA,
	/* Attributes */
	{
		ATTR_UINT("Interval end time",
			ATTR_SUPPORTED,
			0x00,
			0xff,
			offsetof(struct omci_me_rtp_pmhd,
				 interval_end_time),
			1,
			OMCI_ATTR_PROP_RD,
			pm_interval_end_time_get),
		ATTR_UINT("Threshold data",
			ATTR_SUPPORTED,
			0x0000,
			0xffff,
			offsetof(struct omci_me_rtp_pmhd,
				 threshold_data),
			2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			OMCI_ATTR_PROP_SBC,
			NULL),
		ATTR_UINT("RTP errors",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_rtp_pmhd,
				 rtp_errors),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Pkt loss",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_rtp_pmhd,
				 packet_loss),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Max jitter",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_rtp_pmhd,
				 max_jitter),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Max time between RTCP",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_rtp_pmhd,
				 max_time_between_rtcp_packets),
			4,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			NULL),
		ATTR_UINT("Buffer undeflows",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_rtp_pmhd,
				 buffer_underflows),
			4,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			NULL),
		ATTR_UINT("Buffer overflows",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_rtp_pmhd,
				 buffer_overflows),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
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
	NULL,
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
	sizeof(struct omci_me_rtp_pmhd),
	/* Properties */
	OMCI_ME_PROP_PM | OMCI_ME_PROP_PM_INTERNAL | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"RTP PMHD",
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
