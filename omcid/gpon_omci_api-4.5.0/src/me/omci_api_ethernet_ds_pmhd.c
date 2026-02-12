/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_ethernet_ds_pmhd.h"

/** \addtogroup OMCI_API_ME_ETHERNET_DS_PMHD

   @{
*/

enum omci_api_return
omci_api_ethernet_ds_pmhd_cnt_get(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  bool get_curr,
				  bool reset_cnt,
				  uint64_t *cnt_drop_events,
				  uint64_t *cnt_octets,
				  uint64_t *cnt_packets,
				  uint64_t *cnt_broadcast_packets,
				  uint64_t *cnt_multicast_packets,
				  uint64_t *cnt_crc_errored_packets,
				  uint64_t *cnt_undersized_packets,
				  uint64_t *cnt_oversized_packets,
				  uint64_t *cnt64_octets_packets,
				  uint64_t *cnt127_octets_packets,
				  uint64_t *cnt255_octets_packets,
				  uint64_t *cnt511_octets_packets,
				  uint64_t *cnt1023_octets_packets,
				  uint64_t *cnt1518_octets_packets)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	union lan_counter_get_u param;
	uint8_t port_index, base_queue_idx, idx, ci;
	uint64_t drop_events = 0;
	union gpe_tmu_counter_get_u tmu_counter_get;
	union gpe_sce_cnt_get_u sce_counter_get;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   get_curr=%u\n"
		  "   reset_cnt=%u\n", __FUNCTION__,
		  me_id, get_curr, reset_cnt));

	ret = omci_api_bridge_port_eth_uni_index_get(ctx, me_id, &port_index);
	if (ret == OMCI_API_NOT_FOUND) {
		*cnt_drop_events = 0;
		*cnt_octets = 0;
		*cnt_packets = 0;
		*cnt_broadcast_packets = 0;
		*cnt_multicast_packets = 0;
		*cnt_crc_errored_packets = 0;
		*cnt_undersized_packets = 0;
		*cnt_oversized_packets = 0;
		*cnt64_octets_packets = 0;
		*cnt127_octets_packets = 0;
		*cnt255_octets_packets = 0;
		*cnt511_octets_packets = 0;
		*cnt1023_octets_packets = 0;
		*cnt1518_octets_packets = 0;
		return OMCI_API_SUCCESS;
	} else if (ret != OMCI_API_SUCCESS) {
		return ret;
	} else {
		memset(&param, 0, sizeof(param));

		param.in.index = port_index;
		param.in.curr = get_curr;
		param.in.reset_mask = reset_cnt ?
			(uint64_t)(ONU_LAN_CNT_RST_MASK_TX_FRAMES |
				   ONU_LAN_CNT_RST_MASK_TX_BYTES |
				   ONU_LAN_CNT_RST_MASK_TX_FRAG |
				   ONU_LAN_CNT_RST_MASK_TX_1519_FRAMES |
				   ONU_LAN_CNT_RST_MASK_TX_64_FRAMES |
				   ONU_LAN_CNT_RST_MASK_TX_65_FRAMES |
				   ONU_LAN_CNT_RST_MASK_TX_128_FRAMES |
				   ONU_LAN_CNT_RST_MASK_TX_256_FRAMES |
				   ONU_LAN_CNT_RST_MASK_TX_512_FRAMES |
				   ONU_LAN_CNT_RST_MASK_TX_1024_FRAMES) : 0;

		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_LAN_COUNTER_GET, &param, sizeof(param));
		if (ret != OMCI_API_SUCCESS)
			return ret;

		ret = omci_api_lan_port_base_queue_get(ctx, port_index,
						       &base_queue_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		for (idx = base_queue_idx; idx < base_queue_idx + 8; idx++) {
			tmu_counter_get.in.index = idx;
			tmu_counter_get.in.cnt_type =
						GPE_TMU_COUNTER_EGRESS_QUEUE;

			ret = dev_ctl(ctx->remote, ctx->onu_fd,
				      FIO_GPE_TMU_COUNTER_GET,
				      &tmu_counter_get,
				      sizeof(tmu_counter_get));
			if (ret != OMCI_API_SUCCESS)
				return ret;

			for (ci = 0; ci < ONU_GPE_QUEUE_MAX_COLOR; ci++)
				drop_events +=
					tmu_counter_get.out.dropped_frames[ci];
		}

		/* Get UNIx Broadcast Counter */
		sce_counter_get.in.cnt_type = GPE_SCE_BROADCAST_EGRESS;
		sce_counter_get.in.index = port_index;
		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_GPE_SCE_COUNTER_GET, &sce_counter_get, sizeof(sce_counter_get));
		if (ret != OMCI_API_SUCCESS)
			return ret;
		*cnt_broadcast_packets = sce_counter_get.out.counter;

		/* Get UNIx Multicast Counter */
		sce_counter_get.in.cnt_type = GPE_SCE_MULTICAST_EGRESS;
		sce_counter_get.in.index = port_index;
		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_GPE_SCE_COUNTER_GET, &sce_counter_get, sizeof(sce_counter_get));
		if (ret != OMCI_API_SUCCESS)
			return ret;
		*cnt_multicast_packets = sce_counter_get.out.counter;

		*cnt_drop_events 	 = drop_events;
		*cnt_octets 		 = param.out.val.tx.tx_bytes;
		*cnt_packets		 = param.out.val.tx.tx_frames;
		/* The number of transmitted broadcast packets is not counted.*/
		/* The number of transmitted multicast packets is not counted.*/
		/* CRC errored packets are never transmitted.
		   This count value is always 0.*/
		*cnt_crc_errored_packets = 0;
		/* Undersized packets are never transmitted.
		   This count value is always 0.*/
		*cnt_undersized_packets  = 0;
		/* Oversized packets are never transmitted.
		   This count value is always 0.*/
		*cnt_oversized_packets 	 = 0;
		*cnt64_octets_packets 	 = param.out.val.tx.tx64;
		*cnt127_octets_packets 	 = param.out.val.tx.tx65;
		*cnt255_octets_packets 	 = param.out.val.tx.tx128;
		*cnt511_octets_packets 	 = param.out.val.tx.tx256;
		*cnt1023_octets_packets  = param.out.val.tx.tx512;
		*cnt1518_octets_packets  = param.out.val.tx.tx1024;
	}

	return ret;
}

enum omci_api_return
omci_api_ethernet_ds_pmhd_thr_set(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint32_t cnt_drop_events,
				  uint32_t cnt_crc_errored_packets,
				  uint32_t cnt_undersized_packets,
				  uint32_t cnt_oversized_packets)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   cnt_drop_events=%u\n"
		  "   cnt_crc_errored_packets=%u\n"
		  "   cnt_undersized_packets=%u\n"
		  "   cnt_oversized_packets=%u\n",
		  __FUNCTION__,
		  me_id,
		  cnt_drop_events,
		  cnt_crc_errored_packets,
		  cnt_undersized_packets,
		  cnt_oversized_packets));

	/* no thresholds to be set */

	return ret;
}
/** @} */
