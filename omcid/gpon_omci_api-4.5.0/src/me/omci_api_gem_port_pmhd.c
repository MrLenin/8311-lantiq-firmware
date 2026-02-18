/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_gem_port_pmhd.h"

/** \addtogroup OMCI_API_ME_GEM_PORT_PMHD

   @{
*/

enum omci_api_return
omci_api_gem_port_pmhd_cnt_get(struct omci_api_ctx *ctx,
			       uint16_t me_id,
			       bool reset_cnt,
			       bool current,
			       uint64_t *tx_gem_frames,
			       uint64_t *rx_gem_frames,
			       uint64_t *rx_payload_bytes,
			       uint64_t *tx_payload_bytes,
			       uint32_t *lost_packets)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t gpix = 0;
	union gtc_counter_get_u gtc_cnt;
	union gpe_gem_counter_get_u gem_cnt;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   current=%u\n"
		  "   reset_cnt=%u\n" ,
		  __FUNCTION__, me_id, current, reset_cnt));

	ret = index_get(ctx, MAPPER_GEMPORTCTP_MEID_TO_IDX, me_id, &gpix);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	gpix = gpix & 0xFFFF;
	memset(&gtc_cnt, 0, sizeof(gtc_cnt));

	gtc_cnt.in.curr = current;
	gtc_cnt.in.reset_mask = reset_cnt ?
				(ONU_GTC_CNT_RST_MASK_RX_GEM_FRAMES_DROPPED) :
				0;
	/* get GTC counters */
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GTC_COUNTER_GET,
		      &gtc_cnt, sizeof(gtc_cnt));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	memset(&gem_cnt, 0, sizeof(gem_cnt));

	gem_cnt.in.gem_port_index = (uint16_t)gpix;
	gem_cnt.in.curr = current;
	gem_cnt.in.reset_mask = reset_cnt ?
				(ONU_GPE_GEM_CNT_RST_MASK_TX_FRAMES |
				 ONU_GPE_GEM_CNT_RST_MASK_RX_FRAMES |
				 ONU_GPE_GEM_CNT_RST_MASK_RX_BYTES |
				 ONU_GPE_GEM_CNT_RST_MASK_TX_BYTES) :
				0;

	/* get GPE GEM counters */
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_GEM_COUNTER_GET,
		      &gem_cnt, sizeof(gem_cnt));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	if (lost_packets)
		*lost_packets = (uint32_t)gtc_cnt.out.val.rx_gem_frames_dropped;
	if (rx_gem_frames)
		*rx_gem_frames = gem_cnt.out.cnt_val.rx.rx_frames;
	if (tx_gem_frames)
		*tx_gem_frames = gem_cnt.out.cnt_val.tx.tx_frames;
	if (rx_payload_bytes)
		*rx_payload_bytes = gem_cnt.out.cnt_val.rx.rx_bytes;
	if (tx_payload_bytes)
		*tx_payload_bytes = gem_cnt.out.cnt_val.tx.tx_bytes;

	return ret;
}

enum omci_api_return
omci_api_gem_port_pmhd_thr_set(struct omci_api_ctx *ctx,
			       uint16_t me_id,
			       uint32_t tx_gem_frames,
			       uint32_t rx_gem_frames,
			       uint32_t rx_payload_bytes,
			       uint32_t tx_payload_bytes,
			       uint32_t lost_packets)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t gpix = 0;
	struct gtc_cnt_value gtc_thr;
	union gpe_gem_counter_threshold_get_u gpe_thr;

	ret = index_get(ctx, MAPPER_GEMPORTCTP_MEID_TO_IDX, me_id, &gpix);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	gpix = gpix & 0xFFFF;
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GTC_COUNTER_THRESHOLD_GET,
		      &gtc_thr, sizeof(gtc_thr));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	gtc_thr.rx_gem_frames_dropped = lost_packets;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GTC_COUNTER_THRESHOLD_SET,
		      &gtc_thr, sizeof(gtc_thr));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	gpe_thr.in.val = gpix;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_GEM_COUNTER_THRESHOLD_GET,
		      &gpe_thr, sizeof(gpe_thr));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	gpe_thr.out.gem_port_index = gpix;
	gpe_thr.out.threshold.rx.rx_frames = rx_gem_frames;
	gpe_thr.out.threshold.tx.tx_frames = tx_gem_frames;
	gpe_thr.out.threshold.rx.rx_bytes = rx_payload_bytes;
	gpe_thr.out.threshold.tx.tx_bytes = tx_payload_bytes;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_GEM_COUNTER_THRESHOLD_SET,
		      &gpe_thr.out, sizeof(gpe_thr.out));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return ret;
}

enum omci_api_return
omci_api_gem_port_pmhd_cnt_reset(struct omci_api_ctx *ctx,
				 uint16_t me_id)
{
	enum omci_api_return ret;
	uint32_t gpix = 0;
	struct gtc_cnt_interval gtc_param;
	struct gpe_gem_cnt_interval gpe_param;

	DBG(OMCI_API_MSG, ("%s me_id=%u\n", __FUNCTION__, me_id));

	ret = index_get(ctx, MAPPER_GEMPORTCTP_MEID_TO_IDX, me_id, &gpix);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	gpix = gpix & 0xFFFF;

	/* Reset GTC counters (lost_packets = rx_gem_frames_dropped) */
	memset(&gtc_param, 0, sizeof(gtc_param));
	gtc_param.reset_mask = ONU_GTC_CNT_RST_MASK_RX_GEM_FRAMES_DROPPED;
	gtc_param.curr = 0;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GTC_COUNTER_RESET,
		      &gtc_param, sizeof(gtc_param));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* Reset GPE GEM counters (tx/rx frames + bytes) */
	memset(&gpe_param, 0, sizeof(gpe_param));
	gpe_param.gem_port_index = gpix;
	gpe_param.reset_mask = ONU_GPE_GEM_CNT_RST_MASK_TX_FRAMES |
			       ONU_GPE_GEM_CNT_RST_MASK_RX_FRAMES |
			       ONU_GPE_GEM_CNT_RST_MASK_RX_BYTES |
			       ONU_GPE_GEM_CNT_RST_MASK_TX_BYTES;
	gpe_param.curr = 0;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_GEM_COUNTER_RESET,
		      &gpe_param, sizeof(gpe_param));

	return ret;
}

enum omci_api_return
omci_api_gem_port_pmhd_total_cnt_get(struct omci_api_ctx *ctx,
				     uint16_t me_id,
				     uint64_t *tx_gem_frames,
				     uint64_t *rx_gem_frames,
				     uint64_t *rx_payload_bytes,
				     uint64_t *tx_payload_bytes,
				     uint32_t *lost_packets)
{
	/* reset_cnt=false, current=true for cumulative */
	return omci_api_gem_port_pmhd_cnt_get(ctx, me_id, false, true,
					      tx_gem_frames,
					      rx_gem_frames,
					      rx_payload_bytes,
					      tx_payload_bytes,
					      lost_packets);
}

/** @} */
