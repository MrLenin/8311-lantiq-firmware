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
#include "me/omci_api_voip_voice_ctp.h"

#ifdef INCLUDE_OMCI_API_VOIP

/** \addtogroup OMCI_API_ME_VOIP_VOICE_CTP

   @{
*/

enum omci_api_return
omci_api_voip_voice_ctp_media_update(struct omci_api_ctx *ctx,
				     uint16_t me_id,
				     uint16_t sip_user_me_id,
				     uint8_t code_selection_1,
				     uint8_t code_selection_2,
				     uint8_t code_selection_3,
				     uint8_t code_selection_4)
{
	enum omci_api_return ret;
	uint32_t usr_idx;
	struct sip_user usr;

#if 0
	printf("%s:\n"
	       "\tsip_user_me_id=0x%x\n"
	       "\tcode_selection_1=%hhu\n"
	       "\tcode_selection_2=%hhu\n"
	       "\tcode_selection_3=%hhu\n"
	       "\tcode_selection_4=%hhu\n",
	       __FUNCTION__,
	       sip_user_me_id,
	       code_selection_1,
	       code_selection_2,
	       code_selection_3,
	       code_selection_4);
#endif

	ret = index_get(ctx, MAPPER_SIP_USR_TO_IDX, sip_user_me_id, &usr_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

#if 0
	printf("%s: using usr_idx=%u\n", __FUNCTION__, usr_idx);
#endif

	ret = omci_api_voip_user_cfg_get(ctx, usr_idx, &usr);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	usr.media_codec = (enum voip_codec)code_selection_1;

	/** \todo use other codecs */

	return omci_api_voip_user_cfg_set(ctx, usr_idx, &usr);
}

enum omci_api_return
omci_api_voip_voice_ctp_service_update(struct omci_api_ctx *ctx,
				       uint16_t me_id,
				       uint16_t pptp_pots_me_id,
				       uint8_t announcement_type,
				       uint16_t jitter_target,
				       uint16_t jitter_buffer_max,
				       uint8_t echo_cancel_ind,
				       uint16_t pstn_protocol_variant,
				       uint16_t dtmf_digit_levels,
				       uint16_t dtmf_digit_duration,
				       uint16_t hook_flash_minimum_time,
				       uint16_t hook_flash_maximum_time)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t port_idx;

	DBG(OMCI_API_MSG, ("%s\n"
			   "   me_id=%u\n"
			   "   pptp_pots_me_id=%u\n"
			   "   announcement_type=%u\n"
			   "   jitter_target=%u\n"
			   "   jitter_buffer_max=%u\n"
			   "   echo_cancel_ind=%u\n"
			   "   pstn_protocol_variant=%u\n"
			   "   dtmf_digit_levels=%u\n"
			   "   dtmf_digit_duration=%u\n"
			   "   hook_flash_minimum_time=%u\n"
			   "   hook_flash_maximum_time=%u\n",
			   __FUNCTION__, me_id, pptp_pots_me_id,
			   announcement_type, jitter_target,
			   jitter_buffer_max, echo_cancel_ind,
			   pstn_protocol_variant, dtmf_digit_levels,
			   dtmf_digit_duration, hook_flash_minimum_time,
			   hook_flash_maximum_time));

	ret = index_get(ctx, MAPPER_PPTPPOTSUNI_MEID_TO_IDX, pptp_pots_me_id,
			&port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* configure jitter buffer */
	ret = fxs_jb_cfg_set(&ctx->voip.fxs, (uint8_t) port_idx,
				jitter_target, jitter_buffer_max);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* setup echo canceller*/
	ret = fxs_phone_lec_enable(&ctx->voip.fxs, (uint8_t) port_idx,
				   (bool)echo_cancel_ind);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* setup DTMF*/
	ret = fxs_dtmf_cfg_set(&ctx->voip.fxs, (uint8_t) port_idx,
				dtmf_digit_levels, dtmf_digit_duration);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* set hook flash time*/
	ret = fxs_hook_flash_cfg_set(&ctx->voip.fxs, (uint8_t) port_idx,
				     hook_flash_minimum_time,
				     hook_flash_maximum_time);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return ret;
}

enum omci_api_return
omci_api_voip_voice_ctp_rtp_update(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint16_t local_port_min,
				   uint16_t local_port_max,
				   uint8_t dscp_mark,
				   uint8_t piggyback_events,
				   uint8_t tone_events,
				   uint8_t dtmf_events,
				   uint8_t cas_events)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t usr_idx;
	struct sip_user usr;

	DBG(OMCI_API_MSG, ("%s\n"
			   "   me_id=%u\n"
			   "   local_port_min=%u\n"
			   "   local_port_max=%u\n"
			   "   dscp_mark=%u\n"
			   "   piggyback_events=%u\n"
			   "   tone_events=%u\n"
			   "   dtmf_events=%u\n"
			   "   cas_events=%u\n",
			   __FUNCTION__, me_id,
			   local_port_min, local_port_max,
			   dscp_mark, piggyback_events, tone_events,
			   dtmf_events, cas_events));

	if (local_port_min > local_port_max && local_port_max) {
		DBG(OMCI_API_ERR, ("RTP port min is greater than max\n"));
		return OMCI_API_ERROR;
	}

	ret = index_get(ctx, MAPPER_SIP_USR_TO_IDX, me_id, &usr_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = omci_api_voip_user_cfg_get(ctx, (uint8_t)usr_idx, &usr);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	usr.user_port = local_port_min + 2*usr_idx;

	if (usr.user_port > local_port_max && local_port_max) {
		DBG(OMCI_API_ERR, ("sip user %u port %u exceeds max val %u\n",
				usr_idx, usr.user_port, local_port_max));
		return OMCI_API_ERROR;
	}

	ret = omci_api_voip_user_cfg_set(ctx, usr_idx, &usr);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = omci_api_voip_user_rtp_tos_set(ctx, usr_idx,
					     (uint8_t)dscp_mark << 2);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return ret;
}

enum omci_api_return
omci_api_voip_voice_ctp_destroy(struct omci_api_ctx *ctx,
				uint16_t me_id)
{
	return OMCI_API_SUCCESS;
}

/** @} */

#endif
