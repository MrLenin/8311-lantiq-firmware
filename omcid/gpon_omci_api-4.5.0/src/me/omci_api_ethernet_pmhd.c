/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_ethernet_pmhd.h"

/** \addtogroup OMCI_API_ME_ETHERNET_PMHD

@{
*/

enum omci_api_return
omci_api_ethernet_pmhd_cnt_get(struct omci_api_ctx *ctx,
			       uint16_t me_id,
			       bool get_curr,
			       bool reset_cnt,
			       uint64_t *cnt_fcs_error,
			       uint64_t *cnt_excessive_collisions,
			       uint64_t *cnt_late_collisions,
			       uint64_t *cnt_frames_too_long,
			       uint64_t *cnt_rx_buffer_overflow_events,
			       uint64_t *cnt_tx_buffer_overflow_events,
			       uint64_t *cnt_single_collisions,
			       uint64_t *cnt_multiple_collisions,
			       uint64_t *cnt_sqe_test,
			       uint64_t *cnt_deferred_transmissions,
			       uint64_t *cnt_tx_mac_errors,
			       uint64_t *cnt_carrier_sense_errors,
			       uint64_t *cnt_alignment_error,
			       uint64_t *cnt_rx_mac_errors)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	union lan_counter_get_u param;
	uint8_t lan_port;

	ret = omci_api_uni2lan(ctx, me_id, &lan_port);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   get_curr=%u\n"
		  "   reset_cnt=%u\n",
		  __FUNCTION__, me_id, get_curr, reset_cnt));

	memset(&param, 0, sizeof(param));

	param.in.index = lan_port;
	param.in.curr = get_curr;
	param.in.reset_mask = reset_cnt ? 
			(uint64_t)(ONU_LAN_CNT_RST_MASK_RX_FCS_ERR |
				   ONU_LAN_CNT_RST_MASK_EXC_COL |
				   ONU_LAN_CNT_RST_MASK_LATE_COL |
				   ONU_LAN_CNT_RST_MASK_RX_OVSZ_FRAMES |
				   ONU_LAN_CNT_RST_MASK_RX_BUFF_OVERFLOW |
				   ONU_LAN_CNT_RST_MASK_TX_BUFF_OVERFLOW |
				   ONU_LAN_CNT_RST_MASK_SGL_COL |
				   ONU_LAN_CNT_RST_MASK_MUL_COL |
				   ONU_LAN_CNT_RST_MASK_SQE_TST |
				   ONU_LAN_CNT_RST_MASK_TX_DEF |
				   ONU_LAN_CNT_RST_MASK_TX_MAC_ERR |
				   ONU_LAN_CNT_RST_MASK_CAR_SENSE_ERR |
				   ONU_LAN_CNT_RST_MASK_ALGN_ERR |
				   ONU_LAN_CNT_RST_MASK_RX_MAC_ERR) : 0;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_COUNTER_GET,
					     &param, sizeof(param));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	*cnt_fcs_error			= param.out.val.mac.rx_fcs_err;
	*cnt_excessive_collisions	= param.out.val.mac.exc_col;
	*cnt_late_collisions		= param.out.val.mac.late_col;
	*cnt_frames_too_long	    	= param.out.val.rx.rx_oversized_frames;
	*cnt_rx_buffer_overflow_events 	= param.out.val.rx.buffer_overflow;
	*cnt_tx_buffer_overflow_events	= param.out.val.mac.tx_buff_overflow_events;
	*cnt_single_collisions		= param.out.val.mac.sgl_col;
	*cnt_multiple_collisions	= param.out.val.mac.mul_col;
	*cnt_sqe_test			= param.out.val.mac.sqe_test;
	*cnt_deferred_transmissions	= param.out.val.mac.def_trans;
	*cnt_tx_mac_errors		= param.out.val.mac.tx_mac_err;
	*cnt_carrier_sense_errors	= param.out.val.mac.carrier_sense_err;
	*cnt_alignment_error		= param.out.val.mac.algn_err;
	*cnt_rx_mac_errors		= param.out.val.rx.mac_error;

	return ret;
}

enum omci_api_return
omci_api_ethernet_pmhd_thr_set(struct omci_api_ctx *ctx,
			       uint16_t me_id,
			       uint32_t cnt_fcs_error,
			       uint32_t cnt_excessive_collisions,
			       uint32_t cnt_late_collisions,
			       uint32_t cnt_frames_too_long,
			       uint32_t cnt_rx_buffer_overflow_events,
			       uint32_t cnt_tx_buffer_overflow_events,
			       uint32_t cnt_single_collisions,
			       uint32_t cnt_multiple_collisions,
			       uint32_t cnt_sqe_test,
			       uint32_t cnt_deferred_transmissions,
			       uint32_t cnt_tx_mac_errors,
			       uint32_t cnt_carrier_sense_errors,
			       uint32_t cnt_alignment_error,
			       uint32_t cnt_rx_mac_errors)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	union lan_counter_threshold_get_u thr_get;
	struct lan_cnt_threshold thr_set;
	uint8_t lan_port;

	ret = omci_api_uni2lan(ctx, me_id, &lan_port);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   cnt_fcs_error=%u\n"
		  "   cnt_excessive_collisions=%u\n"
		  "   cnt_late_collisions=%u\n"
		  "   cnt_frames_too_long=%u\n"
		  "   cnt_rx_buffer_overflow_events=%u\n"
		  "   cnt_tx_buffer_overflow_events=%u\n"
		  "   cnt_single_collisions=%u\n"
		  "   cnt_multiple_collisions=%u\n"
		  "   cnt_sqe_test=%u\n"
		  "   cnt_deferred_transmissions=%u\n"
		  "   cnt_tx_mac_errors=%u\n"
		  "   cnt_carrier_sense_errors=%u\n"
		  "   cnt_alignment_error=%u\n"
		  "   cnt_rx_mac_errors=%u\n",
		  __FUNCTION__,
		  me_id,
		  cnt_fcs_error,
		  cnt_excessive_collisions,
		  cnt_late_collisions,
		  cnt_frames_too_long,
		  cnt_rx_buffer_overflow_events,
		  cnt_tx_buffer_overflow_events,
		  cnt_single_collisions,
		  cnt_multiple_collisions,
		  cnt_sqe_test,
		  cnt_deferred_transmissions,
		  cnt_tx_mac_errors,
		  cnt_carrier_sense_errors,
		  cnt_alignment_error,
		  cnt_rx_mac_errors));

	memset(&thr_get, 0, sizeof(thr_get));
	thr_get.in.index = lan_port;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_COUNTER_THRESHOLD_GET,
		      &thr_get, sizeof(thr_get));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	thr_get.out.threshold.mac.rx_fcs_err =
				(uint64_t)cnt_fcs_error;
	thr_get.out.threshold.mac.exc_col =
				(uint64_t)cnt_excessive_collisions;
	thr_get.out.threshold.mac.late_col =
				(uint64_t)cnt_late_collisions;
	thr_get.out.threshold.rx.rx_oversized_frames =
				(uint64_t)cnt_frames_too_long;
	thr_get.out.threshold.rx.buffer_overflow =
				(uint64_t)cnt_rx_buffer_overflow_events;
	thr_get.out.threshold.mac.tx_buff_overflow_events =
				(uint64_t)cnt_tx_buffer_overflow_events;
	thr_get.out.threshold.mac.sgl_col =
				(uint64_t)cnt_single_collisions;
	thr_get.out.threshold.mac.mul_col =
				(uint64_t)cnt_multiple_collisions;
	thr_get.out.threshold.mac.sqe_test =
				(uint64_t)cnt_sqe_test;
	thr_get.out.threshold.mac.def_trans =
				(uint64_t)cnt_deferred_transmissions;
	thr_get.out.threshold.mac.tx_mac_err =
				(uint64_t)cnt_tx_mac_errors;
	thr_get.out.threshold.mac.carrier_sense_err =
				(uint64_t)cnt_carrier_sense_errors;
	thr_get.out.threshold.mac.algn_err =
				(uint64_t)cnt_alignment_error;
	thr_get.out.threshold.rx.mac_error =
				(uint64_t)cnt_rx_mac_errors;

	thr_set.index = lan_port;
	memcpy(&thr_set.threshold, &thr_get.out.threshold,
	       sizeof(struct lan_cnt_val));

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_COUNTER_THRESHOLD_SET,
		      &thr_set, sizeof(thr_set));

	return ret;
}
/** @} */
