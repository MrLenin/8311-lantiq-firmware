/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_sip_call_init_pmhd.h"


#ifdef INCLUDE_OMCI_API_VOIP

/** \addtogroup OMCI_API_ME_SIP_CALL_INIT_PMHD

   @{
*/

enum omci_api_return
omci_api_sip_call_init_pmhd_cnt_get(struct omci_api_ctx *ctx,
			  uint16_t me_id,
			  uint32_t *failed_to_connect,
			  uint32_t *failed_to_validate,
			  uint32_t *timeout,
			  uint32_t *failure_received,
			  uint32_t *failed_to_auth)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct sip_agent_counters cnt;
	uint32_t agt_idx = 0;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n", __FUNCTION__, me_id));
	
	/* Get SIP agent index, currently only one SIP agent allowed*/	
	ret = index_get(ctx, MAPPER_SIP_AGT_TO_IDX, me_id, &agt_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;
	if (agt_idx > 0)
		return OMCI_API_ERROR;

	memset(&cnt, 0, sizeof(cnt));

	ret = omci_api_voip_agent_cnt_get(ctx, &cnt);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	*failed_to_connect = cnt.tx_invite_reqs - cnt.rx_invite_response;
	*failed_to_validate = cnt.sip_init_validate_fail;
	*timeout = cnt.sip_init_timout;
	*failure_received = cnt.sip_init_failure_received;
	*failed_to_auth = cnt.sip_init_auth_fail;

	return ret;
}

/** @} */

#endif
