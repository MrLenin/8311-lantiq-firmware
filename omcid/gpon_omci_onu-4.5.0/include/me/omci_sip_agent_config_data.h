/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_sip_agent_config_data_h
#define _omci_sip_agent_config_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_SIP_AGENT_CONFIG_DATA  SIP agent config data ME

    The SIP agent config data Managed Entity models a SIP signalling agent. It
    defines the configuration necessary to establish communication for
    signalling between the SIP user agent and a SIP server.

    Note - If a non-OMCI interface is used to manage SIP for VoIP, this ME is
    unnecessary. The non-OMCI interface supplies the necessary data, which may
    be read back to the OLT via the SIP config portal ME.

    Instances of this Managed Entity are created and deleted by the OLT.

    @{
*/

/** This attribute specifies the tone and text to be presented to the
subscriber upon reception of various SIP messages (normally 4xx, 5xx, 6xx
message codes). The table is a sequence of entries, each of which is defined
as follows */
struct omci_sip_response_table {
	/** SIP response code
	    This field is the value of the SIP message code. It also serves
	    as the index into the SIP response table. When a set operation is
	    performed with the value 0 in this field, the table is cleared. */
	uint16_t sip_response_code;
	/** Tone
	    This field specifies one of the tones in the tone pattern table of
	    the associated voice service profile. The specified tone is played
	    to the subscriber. */
	uint8_t tone;
	/** Text message
	    This field is a pointer to a large string that contains a message
	    to be displayed to the subscriber. If the value of this field is a
	    null pointer, text pre-associated with the tone may be displayed,
	    or no text at all. */
	uint16_t text_message;
} __PACKED__;

/** This structure holds the attributes of the SIP agent config data ME.
*/
struct omci_sip_agent_config_data {
	/** Proxy server address pointer
	    This attribute points to a large string ME that contains the name
	    (IP address or URI) of the SIP proxy server for SIP signalling
	    messages. */
	uint16_t proxy_ptr;
	/** Outbound proxy address pointer
	    An outbound SIP proxy may or may not be required within a given
	    network. If an outbound SIP proxy is used, the outbound proxy
	    address pointer attribute must be set to point to a valid large
	    string ME that contains the name (IP address or URI) of the outbound
	    proxy server for SIP signalling messages. If an outbound SIP proxy
	    is not used, the outbound proxy address pointer attribute must be
	    set to a null pointer. */
	uint16_t outbound_proxy_ptr;
	/** Primary SIP DNS
	    This attribute specifies the primary SIP DNS IP address. If this
	    value is 0, no primary SIP DNS is defined. */
	uint32_t primary_sip_dns;
	/** Secondary SIP DNS
	    This attribute specifies the secondary SIP DNS IP address. If
	    this value is 0, no secondary SIP DNS is defined. */
	uint32_t secondary_sip_dns;
	/** TCP/UDP pointer
	    This pointer associates the SIP agent with the TCP/UDP config
	    data ME to be used for communication with the SIP server. The
	    default value is 0xFFFF, a null pointer. */
	uint16_t tcp_udp_ptr;
	/** SIP reg exp time
	    This attribute specifies the SIP registration expiration time in
	    seconds. If its value is 0, the SIP agent does not add an expiration
	    time to the registration requests and does not perform
	    re-registration.
	    The default value is 3600 seconds */
	uint32_t ip_reg_exp_time;
	/** SIP rereg head start time
	    This attribute specifies the time in seconds prior to timeout that
	    causes the SIP agent to start the re-registration process.
	    The default value is 360 seconds. */
	uint32_t sip_rereg_head_start_time;
	/** Host part URI
	    This attribute points to a large string ME that contains the host
	    or domain part of the SIP address of record for users connected to
	    this ONU. A null pointer indicates that the current address in the
	    IP host config ME is to be used. */
	uint16_t host_part_uri;
	/** SIP status
	    This attribute shows the current status of the SIP agent. Values
	    are as follows:
	    - 0 Ok/initial
	    - 1 Connected
	    - 2 Failed - ICMP error
	    - 3 Failed - Malformed response
	    - 4 Failed - Inadequate info response
	    - 5 Failed - Timeout */
	uint8_t sip_status;
	/** SIP registrar
	    This attribute points to a network address ME that contains the
	    name (IP address or resolved name) of the registrar server for SIP
	    signalling messages. Examples: 10.10.10.10 and proxy.voip.net. */
	uint16_t sip_registrar;
	/** Softswitch
	    This attribute identifies the SIP gateway softswitch vendor.
	    The format is four ASCII coded alphabetic characters [A..Z] as
	    defined in [ATIS-0300220.2005]. A value of four null bytes indicates
	    an unknown or unspecified vendor. */
	uint32_t softswitch;
	/** SIP response table
	    This attribute specifies the tone and text to be presented to the
	    subscriber upon reception of various SIP messages (normally 4xx,
	    5xx, 6xx message codes).
	*/
	struct omci_sip_response_table sip_response;
	/** SIP option transmit control
	    This Boolean attribute specifies that the ONU is (true) or is
	    not (false) enabled to transmit SIP options. The default value is
	    recommended to be false. */
	uint8_t sip_option_transmit_control;
	/** SIP URI format
	    This attribute specifies the format of the URI in outgoing SIP
	    messages. The recommended default value 0 specifies TEL URIs;
	    the value 1 specifies SIP URIs. Other values are reserved. */
	uint8_t sip_uri_format;
} __PACKED__;

/** This enumerator holds the attribute numbers of the SIP agent config data
    Managed Entity.
*/
enum {
	omci_sip_agent_config_data_proxy_ptr = 1,
	omci_sip_agent_config_data_outbound_proxy_ptr = 2,
	omci_sip_agent_config_data_primary_sip_dns = 3,
	omci_sip_agent_config_data_secondary_sip_dns = 4,
	omci_sip_agent_config_data_tcp_udp_ptr = 5,
	omci_sip_agent_config_data_ip_reg_exp_time = 6,
	omci_sip_agent_config_data_sip_rereg_head_start_time = 7,
	omci_sip_agent_config_data_host_part_uri = 8,
	omci_sip_agent_config_data_sip_status = 9,
	omci_sip_agent_config_data_sip_registrar = 10,
	omci_sip_agent_config_data_softswitch = 11,
	omci_sip_agent_config_data_sip_response = 12,
	omci_sip_agent_config_data_sip_option_transmit_control = 13,
	omci_sip_agent_config_data_sip_uri_format = 14
};

/** @} */

/** @} */

__END_DECLS

#endif
