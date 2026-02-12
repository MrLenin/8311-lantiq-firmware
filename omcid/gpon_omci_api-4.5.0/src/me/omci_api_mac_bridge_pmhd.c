/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_mac_bridge_pmhd.h"

/** \addtogroup OMCI_API_ME_MAC_BRIDGE_PMHD

   @{
*/

enum omci_api_return
omci_api_mac_bridge_pmhd_cnt_get(struct omci_api_ctx *ctx,
				 uint16_t me_id,
				 bool reset_cnt,
				 bool current,
				 uint32_t *cnt_bridge_learning_discard)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t bridge_idx;
	union gpe_bridge_counter_get_u param;

	DBG(OMCI_API_MSG, ("%s\n", __FUNCTION__));

	ret = bridge_idx_get(ctx, me_id, &bridge_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	memset(&param, 0, sizeof(param));

	param.in.bridge_index	= bridge_idx;
	param.in.curr		= current;
	param.in.reset_mask	= reset_cnt ?
			ONU_GPE_BRIDGE_CNT_RST_MASK_LEARN_DISCARD : 0;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_BRIDGE_COUNTER_GET,
			&param, sizeof(param));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	*cnt_bridge_learning_discard =
				(uint32_t)param.out.cnt_val.learning_discard;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_mac_bridge_pmhd_thr_set(struct omci_api_ctx *ctx,
				 uint16_t me_id,
				 uint32_t cnt_bridge_learning_discard)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t bridge_idx;
	union gpe_bridge_counter_threshold_get_u param;

	ret = bridge_idx_get(ctx, me_id, &bridge_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	param.in.bridge_index = bridge_idx;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_BRIDGE_COUNTER_THRESHOLD_GET,
		      &param, sizeof(param));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	param.out.bridge_index = bridge_idx;
	param.out.threshold.learning_discard = cnt_bridge_learning_discard;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_BRIDGE_COUNTER_THRESHOLD_SET,
		      &param.out, sizeof(param.out));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

/** @} */
