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
omci_api_ethernet_pmhd3_cnt_get(struct omci_api_ctx *ctx,
		                uint16_t me_id,
			        bool get_curr,
			        bool reset_cnt,
			        uint64_t *cnt_drop_events,
			        uint64_t *cnt_octets,
			        uint64_t *cnt_packets,
			        uint64_t *cnt_broadcast_packets,
			        uint64_t *cnt_multicast_packets,
				uint64_t *cnt_undersized_packets,
			        uint64_t *cnt_fragments,
			        uint64_t *cnt_jabbers,
			        uint64_t *cnt64_octets_packets,
			        uint64_t *cnt127_octets_packets,
			        uint64_t *cnt255_octets_packets,
			        uint64_t *cnt511_octets_packets,
			        uint64_t *cnt1023_octets_packets,
			        uint64_t *cnt1518_octets_packets)
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
			(uint64_t)(ONU_LAN_CNT_RST_MASK_RX_BYTES |
				   ONU_LAN_CNT_RST_MASK_RX_FRAMES |
				   ONU_LAN_CNT_RST_MASK_RX_BC_FRAMES |
				   ONU_LAN_CNT_RST_MASK_RX_MC_FRAMES |
				   ONU_LAN_CNT_RST_MASK_RX_FRAG |
				   ONU_LAN_CNT_RST_MASK_RX_64_FRAMES |
				   ONU_LAN_CNT_RST_MASK_RX_65_FRAMES |
				   ONU_LAN_CNT_RST_MASK_RX_128_FRAMES |
				   ONU_LAN_CNT_RST_MASK_RX_256_FRAMES |
				   ONU_LAN_CNT_RST_MASK_RX_512_FRAMES |
				   ONU_LAN_CNT_RST_MASK_RX_1024_FRAMES) : 0;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_COUNTER_GET,
		      &param, sizeof(param));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	*cnt_drop_events	= (uint32_t)
				 (param.out.val.rx.
						rx_undersized_frames +
				  param.out.val.rx.rx_oversized_frames +
				  param.out.val.mac.rx_fcs_err);
	*cnt_octets		= param.out.val.rx.rx_bytes;
	*cnt_packets		= param.out.val.rx.rx_frames;
	*cnt_broadcast_packets	= param.out.val.sce.rx_bc_frames;
	*cnt_multicast_packets	= param.out.val.sce.rx_mc_frames;
	*cnt_undersized_packets	= param.out.val.rx.rx_undersized_frames;
	*cnt_fragments		= param.out.val.mac.rx_frag;
	*cnt_jabbers		= param.out.val.rx.rx_oversized_frames;
	*cnt64_octets_packets	= param.out.val.rx.rx64;
	*cnt127_octets_packets	= param.out.val.rx.rx65;
	*cnt255_octets_packets	= param.out.val.rx.rx128;
	*cnt511_octets_packets	= param.out.val.rx.rx256;
	*cnt1023_octets_packets	= param.out.val.rx.rx512;
	*cnt1518_octets_packets	= param.out.val.rx.rx1024;

	return ret;
}

enum omci_api_return
omci_api_ethernet_pmhd3_thr_set(struct omci_api_ctx *ctx,
			        uint16_t me_id,
			        uint32_t cnt_drop_events,
			        uint32_t cnt_undersized_packets,
			        uint32_t cnt_fragments,
			        uint32_t cnt_jabbers)
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
		  "   cnt_drop_events=%u\n"
		  "   cnt_undersized_packets=%u\n"
		  "   cnt_fragments=%u\n"
		  "   cnt_jabbers=%u\n",
		  __FUNCTION__,
		  me_id,
		  cnt_drop_events,
		  cnt_undersized_packets,
		  cnt_fragments,
		  cnt_jabbers));

	memset(&thr_get, 0, sizeof(thr_get));
	thr_get.in.index = lan_port;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_COUNTER_THRESHOLD_GET,
		      &thr_get, sizeof(thr_get));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/** \todo add cnt_drop_events handling*/
	/** \todo crosscheck this counter handling in the US/DS PMHD MEs*/
	thr_get.out.threshold.rx.rx_undersized_frames =
					(uint64_t)cnt_undersized_packets;
	thr_get.out.threshold.mac.rx_frag =
					(uint64_t)cnt_fragments;
	thr_get.out.threshold.rx.rx_oversized_frames =
					(uint64_t)cnt_jabbers;

	thr_set.index = lan_port;
	memcpy(&thr_set.threshold, &thr_get.out.threshold,
	       sizeof(struct lan_cnt_val));

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_COUNTER_THRESHOLD_SET,
		      &thr_set, sizeof(thr_set));

	return ret;
}
/** @} */
