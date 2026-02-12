/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_gal_ethernet_pmhd.h"

/** \addtogroup OMCI_API_ME_GAL_ETHERNET_PMHD

   @{
*/

enum omci_api_return
omci_api_gal_ethernet_pmhd_cnt_get(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   bool get_curr,
				   bool reset_cnt,
				   uint64_t *cnt_discarded_frames)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	union gtc_counter_get_u param;

	DBG(OMCI_API_MSG, ("%s\n me_id=%u\n get_curr=%u\n reset_cnt=%u\n",
		__FUNCTION__, me_id, get_curr, reset_cnt));

	memset(&param, 0x0, sizeof(param));

	param.in.curr = get_curr;
	param.in.reset_mask = reset_cnt ?
					ONU_GTC_CNT_RST_MASK_TOTAL_DROPPED : 0;

	/* me_id is not used, because there is only one structure for all
	   entities in drv. */
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GTC_COUNTER_GET,
		      &param, sizeof(param));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	*cnt_discarded_frames = param.out.val.drop;

	return ret;
}


enum omci_api_return
omci_api_gal_ethernet_pmhd_thr_set(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint32_t cnt_discarded_frames)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gtc_cnt_value thr;
 
	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   cnt_discarded_frames=%u\n",
		  __FUNCTION__,
		  me_id,
		  cnt_discarded_frames));

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GTC_COUNTER_THRESHOLD_GET,
		      &thr, sizeof(thr));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	thr.drop = (uint64_t)cnt_discarded_frames;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GTC_COUNTER_THRESHOLD_SET,
		      &thr, sizeof(thr));
	return ret;
}

/** @} */
