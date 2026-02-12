/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_voip_line_status_h
#define _omci_voip_line_status_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_VOIP_LINE_STATUS VoIP Line Status

   The VoIP line status managed entity contains line status
   information for POTS ports using VoIP service.
   An ONU that supports VoIP automatically creates or deletes
   an instance of this managed entity upon creation or deletion
   of a PPTP POTS UNI.

    @{
*/

/** This structure hold the attributes of the Voice Line Status
    Managed Entity.
*/
struct omci_me_voip_line_status {
	/** Voip codec used
	    Reports the current codec used for a VoIP POTS port.
	    Valid values are taken from [IETF RFC 3551], and are
	    the same as specified in the codec selection attribute
	    of the VoIP media profile */
	uint16_t voip_codec_used;
	/** Voip voice server status
	    Status of the VoIP session for this POTS port */
	uint8_t server_status;
	/** Voip port session type
	    This attribute reports the current state of a VoIP POTS
	    port session */
	uint8_t session_type;
	/** Voip call 1 packet period
	    This attribute reports the packet period for the first
	    call on the VoIP POTS port. The value is defined in
	    milliseconds */
	uint16_t call_1_packet_period;
	/** Voip call 2 packet period
	    This attribute reports the packet period for the second
	    call on the VoIP POTS port. The value is defined in
	    milliseconds */
	uint16_t call_2_packet_period;
	/** Voip call 1 dest addr
	    This attribute reports the destination address for the
	    first call on the VoIP POTS port. The value is an ASCII
	    string. */
	uint8_t call_1_dest_addr[25];
	/** Voip call 2 dest addr
	    This attribute reports the destination address for the
	    second call on the VoIP POTS port. The value is an ASCII
	    string. */
	uint8_t call_2_dest_addr[25];
} __PACKED__;

/** This enumerator holds the attribute numbers of the Voice Line Status Entity.
*/
enum {
	omci_me_voip_line_status_voip_codec_used = 1,
	omci_me_voip_line_status_server_status = 2,
	omci_me_voip_line_status_session_type = 3,
	omci_me_voip_line_status_call_1_packet_period = 4,
	omci_me_voip_line_status_call_2_packet_period = 5,
	omci_me_voip_line_status_call_1_dest_addr = 6,
	omci_me_voip_line_status_call_2_dest_addr = 7
};

/** @} */

/** @} */

__END_DECLS

#endif
