/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_ethernet_pmhd.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_ethernet_pmhd.h"
#include "me/omci_api_ethernet_pmhd.h"

#ifdef INCLUDE_PM

/** \addtogroup OMCI_ME_ETHERNET_PMHD
    @{
*/

static enum omci_error me_counters_get(struct omci_context *context,
				       struct me *me,
				       enum omci_pm_interval interval)
{
	enum omci_api_return ret;
	struct omci_me_ethernet_pmhd *me_data;
	uint64_t fcs_error, excessive_collisions, late_collisions,
		 frames_too_long, rx_buffer_overflow_events,
		 tx_buffer_overflow_events, single_collisions,
		 multiple_collisions, sqe_test, deferred_transmissions,
		 tx_mac_errors, carrier_sense_errors, alignment_error,
		 rx_mac_errors;

	dbg_in(__func__, "%p, %p, %lu", (void *)context, (void *)me, interval);

	me_data = (struct omci_me_ethernet_pmhd *)me->data;

	ret = omci_api_ethernet_pmhd_cnt_get(context->api,
					     me->instance_id,
					     interval == OMCI_PM_INTERVAL_CURR,
					     false,
					     &fcs_error,
					     &excessive_collisions,
					     &late_collisions,
					     &frames_too_long,
					     &rx_buffer_overflow_events,
					     &tx_buffer_overflow_events,
					     &single_collisions,
					     &multiple_collisions,
					     &sqe_test,
					     &deferred_transmissions,
					     &tx_mac_errors,
					     &carrier_sense_errors,
					     &alignment_error,
					     &rx_mac_errors);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't get counters", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	me_data->fcs_error_count =
					uint64_lo(fcs_error);
	me_data->excesive_collision_count =
					uint64_lo(excessive_collisions);
	me_data->late_collision_count =
					uint64_lo(late_collisions);
	me_data->frame_too_long_count =
					uint64_lo(frames_too_long);
	me_data->rx_buffer_overflow_count =
					uint64_lo(rx_buffer_overflow_events);
	me_data->tx_buffer_overflow_count =
					uint64_lo(tx_buffer_overflow_events);
	me_data->single_collision_count =
					uint64_lo(single_collisions);
	me_data->multiple_collision_count =
					uint64_lo(multiple_collisions);
	me_data->signal_quality_error_count =
					uint64_lo(sqe_test);
	me_data->deferred_transmission_count =
					uint64_lo(deferred_transmissions);
	me_data->mac_tx_error_count =
					uint64_lo(tx_mac_errors);
	me_data->carrier_sense_error_count =
					uint64_lo(carrier_sense_errors);
	me_data->aligment_error_count =
					uint64_lo(alignment_error);
	me_data->internal_mac_rx_error_count =
					uint64_lo(rx_mac_errors);

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

	ret = omci_api_ethernet_pmhd_thr_set(context->api, me->instance_id,
					     thr[0], thr[1], thr[2], thr[3],
					     thr[4], thr[5], thr[6], thr[7],
					     thr[8], thr[9], thr[10], thr[11],
					     thr[12], thr[13]);
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

	/* check if related PPTP Eth UNI exists */
	error = mib_me_find(context, OMCI_ME_PPTP_ETHERNET_UNI,
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
	/* 0 FCS errors #1 */
	TCA(0, omci_me_ethernet_pmhd_fcs_error_count, 1),
	/* 1 Excessive collision counter #2 */
	TCA(1, omci_me_ethernet_pmhd_excessive_collision_count, 2),
	/* 2 Late collision counter #3 */
	TCA(2, omci_me_ethernet_pmhd_late_collision_count, 3),
	/* 3 Frames too long #4 */
	TCA(3, omci_me_ethernet_pmhd_frame_too_long_count, 4),
	/* 4 Buffer overflows on receive #5 */
	TCA(4, omci_me_ethernet_pmhd_rx_buffer_overflow_count, 5),
	/* 5 Buffer overflows on transmit #6 */
	TCA(5, omci_me_ethernet_pmhd_tx_buffer_overflow_count, 6),
	/* 6 Single collision frame counter #7 */
	TCA(6, omci_me_ethernet_pmhd_single_collision_count, 7),
	/* 7 Multiple collisions frame counter #8 */
	TCA(7, omci_me_ethernet_pmhd_multiple_collision_count, 8),
	/* 8 SQE counter #9 */
	TCA(8, omci_me_ethernet_pmhd_signal_quality_error_count, 9),
	/* 9 Deferred transmission counter #10 */
	TCA(9, omci_me_ethernet_pmhd_deferred_transmission_count, 10),
	/* 10 Internal MAC transmit error counter #11 */
	TCA(10, omci_me_ethernet_pmhd_mac_tx_error_count, 11),
	/* 11 Carrier sense error counter #12 */
	TCA(11, omci_me_ethernet_pmhd_carrier_sense_error_count, 12),
	/* 12 Alignment error counter #13 */
	TCA(12, omci_me_ethernet_pmhd_alignment_error_count, 13),
	/* 13 Internal MAC receive error counter #14 */
	TCA(13, omci_me_ethernet_pmhd_internal_mac_rx_error_count, 14),

	TCA(0, 0, 0)
};

/** Managed Entity class */
struct me_class me_ethernet_pmhd_class = {
	/* Class ID */
	OMCI_ME_ETHERNET_PMHD,
	/* Attributes */
	{
		/* 1. Interval End Time */
		ATTR_UINT("Interval end time",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   interval_end_time),
			  1,
			  OMCI_ATTR_PROP_RD,
			  pm_interval_end_time_get),
		/* 2. Threshold Data 1/2 ID */
		ATTR_PTR("Threshold data 1/2 id",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_ethernet_pmhd,
				  thr_data_id),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 3. FCS Error Count */
		ATTR_UINT("FCS errors",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   fcs_error_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 4. Excessive Collision Count */
		ATTR_UINT("Excessive collision",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   excesive_collision_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 5. Late Collision Count */
		ATTR_UINT("Late collision counter",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   late_collision_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 6. Frames Too Long Count  */
		ATTR_UINT("Frames too long",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   frame_too_long_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 7. Receive Buffer Overflow Count */
		ATTR_UINT("Buffer overflows on RX",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   rx_buffer_overflow_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 8. Transmit Buffer Overflow Count */
		ATTR_UINT("Buffer overflows on TX",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   tx_buffer_overflow_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 9. Single Collision Count */
		ATTR_UINT("Single collision frame",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   single_collision_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 10. Multiple Collision Count */
		ATTR_UINT("Multiple collision frame",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   multiple_collision_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 11. Signal Quality Error Test Count */
		ATTR_UINT("SQE counter",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   signal_quality_error_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 12. Deferred Transmission Count */
		ATTR_UINT("Deferred TX counter",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   deferred_transmission_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 13. Internal MAC Transmit Error Count */
		ATTR_UINT("Internal MAC TX error",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   mac_tx_error_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 14. Carrier Sense Error Count */
		ATTR_UINT("Carrier sense error",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   carrier_sense_error_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 15. Alignment Error Count */
		ATTR_UINT("Alignment error counter",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   aligment_error_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 16. Internal MAC Receive Error Count */
		ATTR_UINT("Internal MAX RX error",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_pmhd,
				   internal_mac_rx_error_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL)
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
	me_thr_set,
#endif
	/* TCA Table */
	tca_table,
	/* Data Size */
	sizeof(struct omci_me_ethernet_pmhd),
	/* Properties */
	OMCI_ME_PROP_PM | OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Ethernet PMHD",
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
