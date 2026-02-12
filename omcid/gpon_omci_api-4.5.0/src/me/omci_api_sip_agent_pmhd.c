/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_sip_agent_pmhd.h"

#ifdef INCLUDE_OMCI_API_VOIP

/** \addtogroup OMCI_API_ME_SIP_AGENT_PMHD

   @{
*/

enum omci_api_return
omci_api_sip_agent_pmhd_cnt_get(struct omci_api_ctx *ctx,
				uint16_t me_id,
				uint32_t *transactions,
				uint32_t *rx_invite_reqs,
				uint32_t *rx_invite_retrans,
				uint32_t *rx_noninvite_reqs,
				uint32_t *rx_noninvite_retrans,
				uint32_t *rx_response,
				uint32_t *rx_response_retrans,
				uint32_t *tx_invite_reqs,
				uint32_t *tx_invite_retrans,
				uint32_t *tx_noninvite_reqs,
				uint32_t *tx_noninvite_retrans,
				uint32_t *tx_response,
				uint32_t *tx_response_retrans)
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

	memset(&cnt, 0, sizeof(cnt));

	ret = omci_api_voip_agent_cnt_get(ctx, &cnt);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	*transactions 		= 0;
	*rx_invite_reqs 	= cnt.rx_total_invite_reqs;
	*rx_invite_retrans 	= 0;
	*rx_noninvite_reqs 	= cnt.rx_total_noninvite_reqs;
	*rx_noninvite_retrans 	= 0;
	*rx_response 		= cnt.rx_total_response;
	*rx_response_retrans 	= 0;
	*tx_invite_reqs 	= cnt.tx_total_invite_reqs;
	*tx_invite_retrans 	= cnt.tx_total_invite_reqs - cnt.tx_invite_reqs;
	*tx_noninvite_reqs 	= cnt.tx_total_noninvite_reqs;
	*tx_noninvite_retrans 	= cnt.tx_total_noninvite_reqs -
						cnt.tx_noninvite_reqs;
	*tx_response 		= cnt.tx_total_response;
	*tx_response_retrans 	= cnt.tx_total_response - cnt.tx_response;

	return ret;
}

/** @} */

#endif
