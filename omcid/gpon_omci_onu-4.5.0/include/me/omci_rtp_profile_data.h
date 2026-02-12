/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_me_rtp_profile_data_h
#define _omci_me_rtp_profile_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_RTP_PROFILE_DATA RTP profile data Managed Entity

   This managed entity configures RTP. It is conditionally required for ONUs
   that offer VoIP service. If a non-OMCI interface is used to manage VoIP,
   this ME is unnecessary. An instance of this managed entity is created and
   deleted by the OLT. An RTP profile is needed for each unique set of
   attributes.

   @{
*/

/** This structure holds the attributes of the RTP profile data Managed Entity.
*/
struct omci_me_rtp_profile_data {
	/** This attribute defines the base RTP port that should be used for
	    voice traffic. The recommended default is 50 000. */
	uint16_t local_port_min;

	/** This attribute defines the highest RTP port used for voice traffic.
	    The value must be greater than local port min. */
	uint16_t local_port_max;

	/** Diffserv code point to be used for outgoing RTP packets for this
	    profile. The recommended default value is expedited
	    forwarding (EF) = 0x2E. */
	uint8_t dscp_mark;

	/** Enables or disables RTP piggyback events.

	    - 0 Disabled (recommended default)
	    - 1 Enabled */
	uint8_t piggyback_events;

	/** Enables or disables handling of tones via RTP tone events
	    per [IETF RFC 4733] (see also [IETF RFC 4734]).

	    - 0 Disabled (recommended default)
	    - 1 Enabled */
	uint8_t tone_events;

	/** Enables or disables handling of DTMF via RTP DTMF events
	    per [IETF RFC 4733] (see also [IETF RFC 4734]). This attribute is
	    ignored unless the OOB DTMF attribute in the VoIP media profile is
	    enabled.

	    - 0 Disabled
	    - 1 Enabled */
	uint8_t dtmf_events;

	/** Enables or disables handling of CAS via RTP CAS events
	    per [IETF RFC 4733] (see also [IETF RFC 4734]).

	    - 0 Disabled
	    - 1 Enabled */
	uint8_t cas_events;
} __PACKED__;

/** This enumerator holds the attribute numbers of the RTP profile data
    Managed Entity.
*/
enum {
	omci_me_rtp_profile_data_local_port_min = 1,
	omci_me_rtp_profile_data_local_port_max = 2,
	omci_me_rtp_profile_data_dscp_mark = 3,
	omci_me_rtp_profile_data_piggyback_events = 4,
	omci_me_rtp_profile_data_tone_events = 5,
	omci_me_rtp_profile_data_dtmf_events = 6,
	omci_me_rtp_profile_data_cav_events = 7
};

/** @} */

/** @} */

__END_DECLS

#endif
