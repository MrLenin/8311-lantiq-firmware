/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_pptp_ethernet_uni.h"
#include "me/omci_api_priority_queue.h"

/** \addtogroup OMCI_API_ME_PRIORITY_QUEUE

   @{
*/

uint8_t drop_precedence_color_marking[2][OMCI_API_PPPTP_ETHERNET_UNI_MAX];

enum omci_api_return
omci_api_priority_queue_drop_precedence_color_marking_set(
				const enum omci_api_queue_direction direction,
				const uint8_t lan_port,
				const uint8_t color_marking)
{
	if (lan_port >= OMCI_API_PPPTP_ETHERNET_UNI_MAX)
		return OMCI_API_NOT_AVAIL;

	if (color_marking > 7) {
		DBG(color_marking, ("Unsupported color marking "
				   "mode 0x%02X\n", color_marking));
		return OMCI_API_ERROR;
	}

	if (direction == OMCI_API_QUEUE_DIRECTION_UPSTREAM) {
		drop_precedence_color_marking[0][lan_port] = color_marking;
	} else if (direction == OMCI_API_QUEUE_DIRECTION_DOWNSTREAM) {
		drop_precedence_color_marking[1][lan_port] = color_marking;
	} else {
		return OMCI_API_NOT_AVAIL;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_priority_queue_drop_precedence_color_marking_get(
				const enum omci_api_queue_direction direction,
				const uint8_t lan_port,
				uint8_t *color_marking)
{
	if (lan_port >= OMCI_API_PPPTP_ETHERNET_UNI_MAX)
		return OMCI_API_NOT_AVAIL;

	if (direction == OMCI_API_QUEUE_DIRECTION_UPSTREAM)
		*color_marking = drop_precedence_color_marking[0][lan_port];
	else if (direction == OMCI_API_QUEUE_DIRECTION_DOWNSTREAM)
		*color_marking = drop_precedence_color_marking[1][lan_port];
	else
		return OMCI_API_NOT_AVAIL;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_priority_queue_create(struct omci_api_ctx *ctx,
			       const uint16_t me_id,
			       const uint32_t related_port,
			       const uint16_t traffic_scheduler_g_ptr,
			       const uint16_t alloc_queue_size,
			       const uint16_t discard_block_cnt_reset_interval,
			       const uint16_t
			       threshold_value_for_discarded_blocks,
			       const uint8_t weight,
			       const uint16_t back_pressure_operation,
			       const uint32_t back_pressure_time,
			       const uint16_t back_pressure_occur_threshold,
			       const uint16_t back_pressure_clear_threshold,
			       const uint16_t
			       packet_drop_queue_threshold_green_min,
			       const uint16_t
			       packet_drop_queue_threshold_green_max,
			       const uint16_t
			       packet_drop_queue_threshold_yellow_min,
			       const uint16_t
			       packet_drop_queue_threshold_yellow_max,
			       const uint8_t packet_drop_probability_green,
			       const uint8_t packet_drop_probability_yellow,
			       const uint8_t queue_drop_averaging_coefficient,
			       const uint8_t drop_precedence_color_marking)
{
	struct gpe_equeue_create equeue_create;
	enum omci_api_return ret = OMCI_API_SUCCESS;
	bool is_upstream = (me_id & 0x8000) ? true : false;
	uint32_t qid = me_id & 0x00ff;
	uint8_t leaf = related_port & 0x07;
	uint8_t sbid = traffic_scheduler_g_ptr & 0x7f;
	uint8_t epn = (related_port >> 16) & 0xFF;
	uint32_t tbs_idx;
	struct gpe_token_bucket_shaper tbs;
 
	DBG(OMCI_API_MSG, ("%s"
		  " me_id=0x%x"
		  " related_port=0x%x"
		  " traffic_scheduler_g_ptr=0x%x\n",
		  __FUNCTION__,
		  me_id,
		  related_port,
		  traffic_scheduler_g_ptr));

	if (is_upstream && traffic_scheduler_g_ptr == 0) {
		/* for direct connection to T-CONT ME use the reserved scheduler */
		sbid = ONU_GPE_SCHEDULER_INDEX_TCONT + epn;
	}

	/* set egress port number */
	memset(&equeue_create, 0, sizeof(equeue_create));
	equeue_create.index = (uint8_t)qid;
	equeue_create.scheduler_input = (sbid << 3) + leaf;
	equeue_create.egress_port_number = epn;

	if (!is_upstream) {
		/*
		 * DS: related port is PPTP Ethernet UNI.
		 * Stock v7.5.1 uses: egress_port = 0x43 - uni2port(uni2lan(me_id))
		 * GPE UNI egress ports are numbered in reverse:
		 *   physical 0 → egress 0x43 (UNI3)
		 *   physical 3 → egress 0x40 (UNI0)
		 * Our uni2lan already returns the physical port index.
		 */
		ret = omci_api_uni2lan(ctx, related_port >> 16, &epn);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		equeue_create.egress_port_number =
			ONU_GPE_UNI3_EGRESS_PORT_NUMBER - epn;
	}

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EGRESS_QUEUE_CREATE,
		      &equeue_create, sizeof(equeue_create));

	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("FIO_GPE_EGRESS_QUEUE_CREATE failed\n"));
		goto err;
	}

	ret = omci_api_priority_queue_update(ctx,
					     me_id,
					     alloc_queue_size,
					     discard_block_cnt_reset_interval,
					     threshold_value_for_discarded_blocks,
					     weight,
					     back_pressure_operation,
					     back_pressure_time,
					     back_pressure_occur_threshold,
					     back_pressure_clear_threshold,
					     packet_drop_queue_threshold_green_min,
					     packet_drop_queue_threshold_green_max,
					     packet_drop_queue_threshold_yellow_min,
					     packet_drop_queue_threshold_yellow_max,
					     packet_drop_probability_green,
					     packet_drop_probability_yellow,
					     queue_drop_averaging_coefficient,
					     drop_precedence_color_marking);
	if (ret != OMCI_API_SUCCESS)
		goto err;

	if (is_upstream) {
		ret = id_map(ctx, MAPPER_PQUEUE_MEID_TO_TBS_IDX,
			     me_id, &tbs_idx);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("Can't get Token bucket shaper index!\n"));
			goto err;
		}

		tbs.index = tbs_idx;
		tbs.tbs_scheduler_block_input = equeue_create.scheduler_input;
		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_GPE_TOKEN_BUCKET_SHAPER_CREATE,
			      &tbs, sizeof(tbs));

		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("Can't create Token bucket shaper!\n"));
			goto err;
		}
	}

err:

	return ret;

}

enum omci_api_return
omci_api_priority_queue_destroy(struct omci_api_ctx *ctx,
				uint16_t me_id)
{
	uint32_t qid = (me_id & 0x7fff);
	union gpe_equeue_get_u equeue;
	struct gpe_equeue destroy;
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t tbs_idx;
	struct gpe_token_bucket_shaper tbs;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	/* delete associated Token Bucket Shaper */
	equeue.in.index = (uint8_t)qid;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EGRESS_QUEUE_GET,
		      &equeue, sizeof(equeue));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("FIO_GPE_EGRESS_QUEUE_CFG_GET failed\n"));
		return ret;
	}

	ret = index_get(ctx, MAPPER_PQUEUE_MEID_TO_TBS_IDX, me_id, &tbs_idx);
	if (ret == OMCI_API_SUCCESS) {
		/* only for US queues */
		tbs.index = tbs_idx;
		tbs.tbs_scheduler_block_input = equeue.out.scheduler_input;
		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_GPE_TOKEN_BUCKET_SHAPER_DELETE,
			      &tbs, sizeof(tbs));
	}

	/* disable queue in driver */
	destroy.index = (uint8_t)qid;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EGRESS_QUEUE_DELETE,
		      &destroy, sizeof(destroy));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("FIO_GPE_EGRESS_QUEUE_DELETE failed\n"));
		return ret;
	}

	return ret;
}

/*
	\todo
	- discard_block_cnt_reset_interval - to be implemented
	- threshold_value_for_discarded_blocks - to be implemented
*/
enum omci_api_return
omci_api_priority_queue_update(struct omci_api_ctx *ctx,
			       const uint16_t me_id,
			       const uint16_t alloc_queue_size,
			       const uint16_t discard_block_cnt_reset_interval,
			       const uint16_t
			       threshold_value_for_discarded_blocks,
			       const uint8_t weight,
			       const uint16_t back_pressure_operation,
			       const uint32_t back_pressure_time,
			       const uint16_t back_pressure_occur_threshold,
			       const uint16_t back_pressure_clear_threshold,
			       const uint16_t
			       packet_drop_queue_threshold_green_min,
			       const uint16_t
			       packet_drop_queue_threshold_green_max,
			       const uint16_t
			       packet_drop_queue_threshold_yellow_min,
			       const uint16_t
			       packet_drop_queue_threshold_yellow_max,
			       const uint8_t packet_drop_probability_green,
			       const uint8_t packet_drop_probability_yellow,
			       const uint8_t queue_drop_averaging_coefficient,
			       const uint8_t drop_precedence_color_marking)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_equeue_cfg update;
	struct gpe_cfg gpe_cfg;
	uint32_t qid = (me_id & 0x7fff);

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   alloc_queue_size=%u\n"
		  "   discard_block_cnt_reset_interval=%u\n"
		  "   threshold_value_for_discarded_blocks=%u\n"
		  "   weight=%u\n"
		  "   back_pressure_operation=%u\n"
		  "   back_pressure_time=%u\n"
		  "   back_pressure_occur_threshold=%u\n"
		  "   back_pressure_clear_threshold=%u\n"
		  "   packet_drop_queue_threshold_green_min=%u\n"
		  "   packet_drop_queue_threshold_green_max=%u\n"
		  "   packet_drop_queue_threshold_yellow_min=%u\n"
		  "   packet_drop_queue_threshold_yellow_max=%u\n"
		  "   packet_drop_probability_green=%u\n"
		  "   packet_drop_probability_yellow=%u\n"
		  "   queue_drop_averaging_coefficient=%u\n"
		  "   drop_precedence_color_marking=%u\n",
		  __FUNCTION__,
		  me_id,
		  alloc_queue_size,
		  discard_block_cnt_reset_interval,
		  threshold_value_for_discarded_blocks,
		  weight,
		  back_pressure_operation,
		  back_pressure_time,
		  back_pressure_occur_threshold,
		  back_pressure_clear_threshold,
		  packet_drop_queue_threshold_green_min,
		  packet_drop_queue_threshold_green_max,
		  packet_drop_queue_threshold_yellow_min,
		  packet_drop_queue_threshold_yellow_max,
		  packet_drop_probability_green,
		  packet_drop_probability_yellow,
		  queue_drop_averaging_coefficient,
		  drop_precedence_color_marking));

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_CFG_GET,
					     &gpe_cfg, sizeof(gpe_cfg));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("FIO_GPE_CFG_GET failed\n"));
		return ret;
	}

	update.index = (uint8_t)qid;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EGRESS_QUEUE_CFG_GET,
		      &update, sizeof(update));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("FIO_GPE_EGRESS_QUEUE_CFG_GET failed\n"));
		return ret;
	}

	update.enable = true;
	/* v7.5.1: sbin_enable = 1 */
	update.sbin_enable = 1;
	update.weight = weight;
	/* v7.5.1: avg_weight clamped to max 14, defaults to 3 if exceeded */
	update.avg_weight = queue_drop_averaging_coefficient;
	if (update.avg_weight > 14)
		update.avg_weight = 3;
	/* v7.5.1: threshold scaling uses gem_blk_len >> 9 (not / 64).
	   With gem_blk_len=48: 5462 * 48 / 512 = 512 (within range)
	   vs v4.5.0:            5462 * 48 / 64  = 4097 (exceeds max 2304) */
	update.drop_threshold_green_min =
		packet_drop_queue_threshold_green_min * gpe_cfg.gem_blk_len >> 9;
	update.drop_threshold_green_max =
		packet_drop_queue_threshold_green_max * gpe_cfg.gem_blk_len >> 9;
	update.drop_threshold_yellow_min =
		packet_drop_queue_threshold_yellow_min * gpe_cfg.gem_blk_len >> 9;
	update.drop_threshold_yellow_max =
		packet_drop_queue_threshold_yellow_max * gpe_cfg.gem_blk_len >> 9;
	update.drop_probability_green = packet_drop_probability_green * 16 +
		(15 * packet_drop_probability_green + 256 - 1) / 256;
	update.drop_probability_yellow = packet_drop_probability_yellow * 16 +
		(15 * packet_drop_probability_yellow + 256 - 1) / 256;
	update.coloring_mode =
			(enum gpe_coloring_mode)drop_precedence_color_marking;
	/* v7.5.1: reservation_threshold = 0x28 (40 segments) */
	update.reservation_threshold = 0x28;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EGRESS_QUEUE_CFG_SET,
		      &update, sizeof(update));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("FIO_GPE_EGRESS_QUEUE_CFG_SET failed\n"));
		return ret;
	}

	return ret;
}

/** @} */
