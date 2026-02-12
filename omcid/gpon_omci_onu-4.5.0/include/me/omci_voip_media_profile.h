/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_voip_media_profile_h
#define _omci_voip_media_profile_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_VOIP_MEDIA_PROFILE VoIP Media Profile

   The VoIP media profile Managed Entity contains settings that apply to VoIP
   voice encoding. This entity is conditionally required for ONUs that offer
   VoIP services. If a non-OMCI interface is used to manage VoIP signalling,
   this ME is unnecessary.
   An instance of this Managed Entity is created and deleted by the OLT. A VoIP
   media profile is needed for each unique set of profile attributes.

    @{
*/

/** This structure hold the attributes of the Voice CTP
    Managed Entity.
*/
struct omci_me_voip_media_profile {
	/** Fax mode
	    Selects the fax mode; value are:
	    - 0 passthru
	    - 1 T.38 */
	uint8_t fax_mode;
	/** Voice service profile pointer
	    Pointer to a voice service profile, which defines parameters such
	    as jitter buffering and echo cancellation */
	uint16_t voice_service_profile_ptr;
	/** Codec selection (1st order)
	    This attribute specifies codec selection as defined by
	    [IETF RFC 3551]. */
	uint8_t code_selection_1;
	/** Packet period selection (1st order)
	    This attribute specifies the packet period selection interval in
	    milliseconds. The recommended default value is 10. Valid values are
	    10..30 ms. */
	uint8_t packet_period_selection_1;
	/** Silence suppression (1st order)
	    This attribute specifies whether silence suppression is on or off.
	    Valid values are 0 = off and 1 = on. */
	uint8_t silence_suppression_1;
	/** Codec selection (2nd order) */
	uint8_t code_selection_2;
	/** Packet period selection (2nd order) */
	uint8_t packet_period_selection_2;
	/** Silence suppression (2nd order) */
	uint8_t silence_suppression_2;
	/** Codec selection (3rd order) */
	uint8_t code_selection_3;
	/** Packet period selection (3rd order) */
	uint8_t packet_period_selection_3;
	/** Silence suppression (3rd order) */
	uint8_t silence_suppression_3;
	/** Codec selection (4th order) */
	uint8_t code_selection_4;
	/** Packet period selection (4th order) */
	uint8_t packet_period_selection_4;
	/** Silence suppression (4th order) */
	uint8_t silence_suppression_4;
	/** OOB DTMF
	    This attribute specifies out-of-band DMTF carriage. When
	    enabled (1), DTMF signals are carried out of band via RTP or the
	    associated signalling protocol. When disabled (0), DTMF tones are
	    carried in the PCM stream. */
	uint8_t oob_dtmf;
	/** RTP profile pointer
	    This attribute points to the associated RTP profile data ME */
	uint16_t rtp_profile_ptr;
} __PACKED__;

/** This enumerator holds the attribute numbers of the VoIP media profile
    Managed Entity. */
enum {
	omci_me_voip_media_profile_fax_mode = 1,
	omci_me_voip_media_profile_voice_service_profile_ptr = 2,
	omci_me_voip_media_profile_code_selection_1 = 3,
	omci_me_voip_media_profile_packet_period_selection_1 = 4,
	omci_me_voip_media_profile_silence_suppression_1 = 5,
	omci_me_voip_media_profile_code_selection_2 = 6,
	omci_me_voip_media_profile_packet_period_selection_2 = 7,
	omci_me_voip_media_profile_silence_suppression_2 = 8,
	omci_me_voip_media_profile_code_selection_3 = 9,
	omci_me_voip_media_profile_packet_period_selection_3 = 10,
	omci_me_voip_media_profile_silence_suppression_3 = 11,
	omci_me_voip_media_profile_code_selection_4 = 12,
	omci_me_voip_media_profile_packet_period_selection_4 = 13,
	omci_me_voip_media_profile_silence_suppression_4 = 14,
	omci_me_voip_media_profile_oob_dtmf = 15,
	omci_me_voip_media_profile_rtp_profile_ptr = 16
};

/** @} */

/** @} */

__END_DECLS

#endif
