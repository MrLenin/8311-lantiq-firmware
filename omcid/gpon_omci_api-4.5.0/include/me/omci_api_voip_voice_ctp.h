/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_voip_voice_ctp
#define _omci_api_me_voip_voice_ctp

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_VOIP_VOICE_CTP VoIP Voice CTP

    The VoIP voice CTP defines the attributes necessary to associate a
    specified VoIP service (SIP, H.248) with a POTS UNI. This entity is
    conditionally required for ONUs that offer VoIP services. If a non-OMCI
    interface is used to manage VoIP signalling, this ME is unnecessary.

    An instance of this managed entity is created and deleted by the OLT.
    A VoIP voice CTP managed entity is needed for each PPTP POTS UNI
    served by VoIP.

   @{
*/

/** Update VoIP Voice CTP ME media resources

   \param[in] ctx                   OMCI API context pointer
   \param[in] me_id                 Managed Entity identifier
   \param[in] sip_user_me_id        SIP user ME pointer
   \param[in] code_selection_1      Code selection 1
   \param[in] code_selection_2      Code selection 2
   \param[in] code_selection_3      Code selection 3
   \param[in] code_selection_4      Code selection 4
*/
enum omci_api_return
omci_api_voip_voice_ctp_media_update(struct omci_api_ctx *ctx,
				     uint16_t me_id,
				     uint16_t sip_user_me_id,
				     uint8_t code_selection_1,
				     uint8_t code_selection_2,
				     uint8_t code_selection_3,
				     uint8_t code_selection_4);

/** Update VoIP Voice CTP ME service resources

   \param[in] ctx                     OMCI API context pointer
   \param[in] me_id                   Managed Entity identifier
   \param[in] pptp_pots_me_id         PPTP POTS UNI ME pointer
   \param[in] announcement_type       Announcement type
   \param[in] jitter_target           Jitter target
   \param[in] jitter_buffer_max       Jitter maximum buffer
   \param[in] echo_cancel_ind         Echo cancellation off/on
   \param[in] pstn_protocol_variant   POTS signaling protocol variant
   \param[in] dtmf_digit_levels       Power level of DTMF digits
   \param[in] dtmf_digit_duration     Duration of DTMF digits
   \param[in] hook_flash_minimum_time Minimum switchhook flash duration
   \param[in] hook_flash_maximum_time Maximum switchhook flash duration
*/
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
				       uint16_t hook_flash_maximum_time);

/** Update VoIP Voice CTP ME RTP resources

   \param[in] ctx                   OMCI API context pointer
   \param[in] me_id                 Managed Entity identifier
   \param[in] local_port_min        Minimum traffic RTP port
   \param[in] local_port_max        Highest traffic RTP port
   \param[in] dscp_mark             DSCP mark
   \param[in] piggyback_events      Enable/disble RTP piggyback events
   \param[in] tone_events           Enable/disable RTP tone events
   \param[in] dtmf_events           Enable/disable RTP DTMF events
   \param[in] cas_events            Enable/disable RTP CAS events
*/
enum omci_api_return
omci_api_voip_voice_ctp_rtp_update(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint16_t local_port_min,
				   uint16_t local_port_max,
				   uint8_t dscp_mark,
				   uint8_t piggyback_events,
				   uint8_t tone_events,
				   uint8_t dtmf_events,
				   uint8_t cas_events);

/** Clenup VoIP Voice CTP ME resources

   \param[in] ctx                   OMCI API context pointer
   \param[in] me_id                 Managed Entity identifier
*/
enum omci_api_return
omci_api_voip_voice_ctp_destroy(struct omci_api_ctx *ctx,
				uint16_t me_id);

/** @} */

/** @} */

__END_DECLS

#endif
