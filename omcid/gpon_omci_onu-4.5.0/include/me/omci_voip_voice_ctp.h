/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_voip_voice_ctp_h
#define _omci_voip_voice_ctp_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_VOIP_VOICE_CTP VoIP Voice CTP

    The VoIP voice CTP defines the attributes necessary to associate a specified
    VoIP service (SIP, H.248) with a POTS UNI. This entity is conditionally
    required for ONUs that offer VoIP services.
    If a non-OMCI interface is used to manage VoIP signalling, this ME is
    unnecessary.
    An instance of this Managed Entity is created and deleted by the OLT. A VoIP
    voice CTP Managed Entity is needed for each PPTP POTS UNI served by VoIP.

    @{
*/

/** This structure hold the attributes of the Voice CTP
    Managed Entity.
*/
struct omci_me_voip_voice_ctp {
	/** User protocol pointer
	    This attribute points to signalling protocol data. If the signalling
	    protocol used attribute of the VoIP config data Managed Entity
	    specifies that the ONUs signalling protocol is SIP, this attribute
	    points to a SIP user data ME, which in turn points to a SIP agent
	    config data. If the signalling protocol is H.248, this attribute
	    points directly to an MGC config data ME. */
	uint16_t user_protocol_ptr;
	/** PPTP pointer
	    This attribute points to the PPTP POTS UNI Managed Entity that
	    serves the analogue telephone port. */
	uint16_t pptp_ptr;
	/** VOIP media profile pointer
	    This attribute points to an associated VoIP media profile. */
	uint16_t voip_media_ptr;
	/** Signalling code
	    This attribute specifies the POTS-side signalling:
	    - 1 Loop start
	    - 2 Ground start
	    - 3 Loop reverse battery
	    - 4 Coin first
	    - 5 Dial tone first
	    - 6 Multi-party */
	uint8_t signalling_code;
} __PACKED__;

/** This enumerator holds the attribute numbers of the Voice CTP Managed Entity.
*/
enum {
	omci_me_voip_voice_ctp_user_protocol_ptr = 1,
	omci_me_voip_voice_ctp_pptp_ptr = 2,
	omci_me_voip_voice_ctp_voip_media_ptr = 3,
	omci_me_voip_voice_ctp_signalling_code = 4
};

/** @} */

/** @} */

__END_DECLS

#endif
