/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include <assert.h>

#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_pptp_pots_uni.h"

#ifdef INCLUDE_OMCI_API_VOIP

/** \addtogroup OMCI_API_ME_PPTP_POTS_UNI

   @{
*/

enum omci_api_return
omci_api_pptp_pots_uni_update(struct omci_api_ctx *ctx,
			      uint16_t me_id,
			      uint8_t admin_state,
			      uint8_t impedance,
			      uint8_t rx_gain,
			      uint8_t tx_gain)
{
	enum omci_api_return ret;
	uint32_t port_idx = 0;

	ret = index_get(ctx, MAPPER_PPTPPOTSUNI_MEID_TO_IDX, me_id, &port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = fxs_phone_enable(&ctx->voip.fxs, (uint16_t)port_idx,
				admin_state == 0 ? true : false);

	return ret;
}

enum omci_api_return
omci_api_pptp_pots_uni_create(struct omci_api_ctx *ctx,
			      uint16_t me_id)
{
	enum omci_api_return ret;
	uint32_t pots_idx = 0;

	ret = id_map(ctx, MAPPER_PPTPPOTSUNI_MEID_TO_IDX, me_id, &pots_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_pptp_pots_uni_destroy(struct omci_api_ctx *ctx,
			       uint16_t me_id)
{
	enum omci_api_return ret;

	ret = id_remove(ctx, MAPPER_PPTPPOTSUNI_MEID_TO_IDX, me_id);

	return ret;
}

enum omci_api_return
omci_api_pptp_pots_uni_hook_state_get(struct omci_api_ctx *ctx,
				      uint16_t me_id,
				      uint8_t *hook_state)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t port_idx = 0;
	bool off_hook = false;

	ret = index_get(ctx, MAPPER_PPTPPOTSUNI_MEID_TO_IDX, me_id, &port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = fxs_hook_status_get(&ctx->voip.fxs, (uint8_t)port_idx, &off_hook);
	*hook_state = off_hook ? 1 : 0;

	return ret;
}

/** @} */

#endif
