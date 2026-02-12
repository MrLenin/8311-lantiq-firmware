/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_sip_user_data_h
#define _omci_sip_user_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_SIP_USER_DATA SIP User Data Managed Entity

   The SIP user data defines the user specific configuration attributes
   associated with a specific VoIP CTP. This entity is conditionally required
   for ONUs that offer VoIP SIP services. If a non-OMCI interface is used to
   manage SIP for VoIP, this ME is unnecessary. The non-OMCI interface supplies
   the necessary data, which may be read back to the OLT via the SIP config
   portal ME.

   An instance of this Managed Entity is created and deleted by the OLT.
   A SIP user data instance is required for each POTS UNI port using SIP
   protocol and configured by OMCI.

    @{
*/

/** This structure holds the attributes of the SIP User Data Managed Entity.
*/
struct omci_sip_user_data {
	/** SIP agent pointer
	    This attribute points to the SIP agent config data ME to be used
	    for signalling. */
	uint16_t sip_agent_ptr;
	/** User part AOR
	    This attribute points to a large string that contains the user
	    identification part of the address of record. This can take the form
	    of an alphanumeric string or the subscriber's directory number.
	    A null pointer indicates the absence of an AOR. */
	uint16_t user_part_aor;
	/** SIP display name
	    This ASCII string attribute defines the customer id used for the
	    display attribute in outgoing SIP messages. The default value is
	    null (all zero bytes) */
	uint8_t sip_display_name[25];
	/** Username/password
	    This attribute points to an authentication security method ME that
	    contains the SIP user name and password used for authentication. A
	    null pointer indicates no username/password. */
	uint16_t username_password;
	/** Voicemail server SIP URI
	    This attribute points to a network address ME that contains the
	    name (IP address or URI) of the SIP voicemail server for SIP
	    signalling messages. A null pointer indicates the absence of a SIP
	    voicemail server. */
	uint16_t voicemail_server_sip_uri;
	/** Voicemail subscription expiration time
	    This attribute defines the voicemail subscription expiration time
	    in seconds. If this value is 0, the SIP agent uses an implementation
	    specific value. This attribute is recommended to be set to 3600
	    seconds by default. */
	uint32_t voicemail_subscription_expiration_time;
	/** Network dial plan pointer
	    This attribute points to a network dial plan table. A null pointer
	    indicates the absence of a network dial plan. */
	uint16_t network_dial_plan_ptr;
	/** Application services profile pointer
	    This attribute points to a VoIP application services */
	uint16_t application_services_profile_ptr;
	/** Feature code pointer
	    This attribute points to the VoIP feature access codes ME for this
	    subscriber. A null pointer indicates the absence of a VoIP feature
	    access codes ME. */
	uint16_t feature_code_ptr;
	/** PPTP pointer
	    This attribute points to the PPTP POTS UNI Managed Entity that
	    provides the analogue telephony adaptor (ATA) function. */
	uint16_t pptp_ptr;
	/** Release timer
	    This attribute contains a release timer defined in seconds. The
	    value 0 specifies that the ONU is to use its internal default. The
	    default value of this attribute is 10 seconds. */
	uint8_t release_timer;
	/** ROH timer
	    This attribute defines the time in seconds for the receiver off
	    hook condition before ROH tone is applied. The value 0 disables ROH
	    timing. The default value is 15 seconds. */
	uint8_t roh_timer;
} __PACKED__;

/** This enumerator holds the attribute numbers of the SIP user config data
    Managed Entity.
*/
enum {
	omci_sip_user_data_sip_agent_ptr = 1,
	omci_sip_user_data_user_part_aor = 2,
	omci_sip_user_data_sip_display_name = 3,
	omci_sip_user_data_username_password = 4,
	omci_sip_user_data_voicemail_server_sip_uri = 5,
	omci_sip_user_data_voicemail_subscription_expiration_time = 6,
	omci_sip_user_data_network_dial_plan_ptr = 7,
	omci_sip_user_data_application_services_profile_ptr = 8,
	omci_sip_user_data_feature_code_ptr = 9,
	omci_sip_user_data_pptp_ptr = 10,
	omci_sip_user_data_release_timer = 11,
	omci_sip_user_data_roh_timer = 12
};

/** @} */

/** @} */

__END_DECLS

#endif
