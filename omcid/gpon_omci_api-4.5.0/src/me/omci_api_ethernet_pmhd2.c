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
omci_api_ethernet_pmhd2_cnt_get(struct omci_api_ctx *ctx,
			        uint16_t me_id,
			        bool get_curr,
			        bool reset_cnt,
			        uint64_t *cnt_pppoe_filtered_frames)
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
			(uint64_t)(ONU_LAN_CNT_RST_MASK_RX_NON_PPOE_FRAMES) : 0;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_COUNTER_GET,
		      &param, sizeof(param));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	*cnt_pppoe_filtered_frames = param.out.val.sce.rx_non_pppoe_frames;

	return ret;
}

enum omci_api_return
omci_api_ethernet_pmhd2_thr_set(struct omci_api_ctx *ctx,
			        uint16_t me_id,
			        uint32_t cnt_pppoe_filtered_frames)
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
		  "   cnt_pppoe_filtered_frames=%u\n",
		  __FUNCTION__,
		  me_id,
		  cnt_pppoe_filtered_frames));

	memset(&thr_get, 0, sizeof(thr_get));
	thr_get.in.index = lan_port;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_COUNTER_THRESHOLD_GET,
		      &thr_get, sizeof(thr_get));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	thr_get.out.threshold.sce.rx_non_pppoe_frames =
					(uint64_t)cnt_pppoe_filtered_frames;

	thr_set.index = lan_port;
	memcpy(&thr_set.threshold, &thr_get.out.threshold,
	       sizeof(struct lan_cnt_val));

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_COUNTER_THRESHOLD_SET,
		      &thr_set, sizeof(thr_set));

	return ret;
}
/** @} */
