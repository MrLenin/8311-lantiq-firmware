/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_rtp_pmhd.h"

#ifdef INCLUDE_OMCI_API_VOIP

/** \addtogroup OMCI_API_ME_RTP_PMHD

   @{
*/

enum omci_api_return
omci_api_rtp_pmhd_cnt_get(struct omci_api_ctx *ctx,
			  uint16_t me_id,
			  uint32_t *rtp_errors,
			  uint32_t *packet_loss,
			  uint32_t *max_jitter,
			  uint32_t *max_time_between_rtcp_packets,
			  uint32_t *buffer_underflows,
			  uint32_t *buffer_overflows)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t port_idx = 0;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n", __FUNCTION__, me_id));
	
	ret = index_get(ctx, MAPPER_PPTPPOTSUNI_MEID_TO_IDX, me_id, &port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* Get RTP Packet loss */
	ret = fxs_rtp_pkt_loss_get(&ctx->voip.fxs, (uint8_t)port_idx,
				   packet_loss);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* Get Jitter Buffer related statistics*/
	ret = fxs_jb_stat_get(&ctx->voip.fxs, (uint8_t)port_idx,
			      rtp_errors, max_jitter, buffer_overflows);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* No implementation in voice firmware and software*/
	*buffer_underflows = 0;
	/* This value is not defined yet (see GPONSW-313 comments) */
	*max_time_between_rtcp_packets = 0;

	return ret;
}

/** @} */
#endif
