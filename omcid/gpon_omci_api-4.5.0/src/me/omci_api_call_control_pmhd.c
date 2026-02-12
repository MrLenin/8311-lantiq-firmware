/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_call_control_pmhd.h"

#ifdef INCLUDE_OMCI_API_VOIP

/** \addtogroup OMCI_API_ME_CALL_CONTROL_PMHD

   @{
*/

enum omci_api_return
omci_api_call_control_pmhd_cnt_get(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint32_t *call_setup_failures,
				   uint32_t *call_setup_timer,
				   uint32_t *call_terminate_failures,
				   uint32_t *analog_port_releases,
				   uint32_t *analog_port_offhook_timer)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t port_idx = 0;

	DBG(OMCI_API_MSG, ("%s\n"
			   "   me_id=%u\n", __FUNCTION__, me_id));

	ret = index_get(ctx, MAPPER_PPTPPOTSUNI_MEID_TO_IDX, me_id, &port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	*call_setup_failures = 0;
	*call_setup_timer = 0;
	*call_terminate_failures = 0;
	*analog_port_releases = ctx->voip.fxs.abandoned_calls[port_idx];
	*analog_port_offhook_timer =
				ctx->voip.fxs.max_offhook_duration[port_idx];

	return ret;
}

/** @} */

#endif
