/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_sip_agent_pmhd_h
#define _omci_sip_agent_pmhd_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_SIP_AGENT _PMHD SIP agent Performance Monitoring history data Managed Entity

    This managed entity collects performance monitoring data for the associated
    VoIP SIP agent.
    Instances of this managed entity are created and deleted by the OLT. 

    An instance of this managed entity is associated with a SIP agent config
    data or SIP config portal object. 

    @{
*/


/** This structure holds the attributes of the SIP agent Performance
    Monitoring history data Data Managed Entity. */
struct omci_me_sip_agent_pmhd {
	/** Interval end time
	    This attribute identifies the most recently finished 15-minute 
	    interval.
	*/
	uint8_t interval_end_time;

	/** Threshold data
	    This attribute points to an instance of the threshold data 1 
	    managed entity that contains PM threshold values. Since no 
	    threshold value attribute number exceeds 7, a threshold data 2 
	    ME is optional
	*/
	uint16_t threshold_data;

	/** Transactions
	    This attribute counts the number of new transactions that were
	    initiated.
	*/
	uint32_t transactions;

	/** Rx invite reqs
	    This attribute counts received invite messages, including
	    retransmissions.
	*/
	uint32_t rx_invite_reqs;

	/** Rx invite retrans
	    This attribute counts received invite retransmission messages.
	*/
	uint32_t rx_invite_retrans;

	/** Rx noninvite reqs
	    This attribute counts received non-invite messages, including
	    retransmissions.
	*/
	uint32_t rx_noninvite_reqs;

	/** Rx noninvite retrans
	    This attribute counts received non-invite retransmission messages.
	*/
	uint32_t rx_noninvite_retrans;
	/** Rx response
	    This attribute counts total responses received.
	*/
	uint32_t rx_response;
	/** Rx response retransmissions
	    This attribute counts total response retransmissions received.
	*/
	uint32_t rx_response_retrans;
	/** Tx invite reqs
	    This attribute counts transmitted invite messages, including
	    retransmissions.
	*/
	uint32_t tx_invite_reqs;
	/** Tx invite retrans
	    This attribute counts transmitted invite retransmission messages.
	*/
	uint32_t tx_invite_retrans;
	/** Tx noninvite reqs
	    This attribute counts transmitted non-invite messages, including
	    retransmissions.
	*/
	uint32_t tx_noninvite_reqs;
	/** Tx noninvite retrans
	    This attribute counts transmitted non-invite retransmission
	    messages. */
	uint32_t tx_noninvite_retrans;
	/** Tx response
	    This attribute counts the total responses sent.
	*/
	uint32_t tx_response;
	/** Tx response retransmissions
	    This attribute counts total response retransmissions sent.
	*/
	uint32_t tx_response_retrans;
} __PACKED__;

/** This enumerator holds the attribute numbers of the SIP agent
    Performance Monitoring history data Managed Entity.
*/
enum {
	omci_me_sip_agent_pmhd_interval_end_time = 1,
	omci_me_sip_agent_pmhd_threshold_data = 2,
	omci_me_sip_agent_pmhd_transactions = 3,
	omci_me_sip_agent_pmhd_rx_invite_reqs = 4,
	omci_me_sip_agent_pmhd_rx_invite_retrans = 5,
	omci_me_sip_agent_pmhd_rx_noninvite_reqs = 6,
	omci_me_sip_agent_pmhd_rx_noninvite_retrans = 7,
	omci_me_sip_agent_pmhd_rx_response = 8,
	omci_me_sip_agent_pmhd_rx_response_retrans = 9,
	omci_me_sip_agent_pmhd_tx_invite_reqs = 10,
	omci_me_sip_agent_pmhd_tx_invite_retrans = 11,
	omci_me_sip_agent_pmhd_tx_noninvite_reqs = 12,
	omci_me_sip_agent_pmhd_tx_noninvite_retrans = 13,
	omci_me_sip_agent_pmhd_tx_response = 14,
	omci_me_sip_agent_pmhd_tx_response_retrans = 15
};

/** @} */

/** @} */

__END_DECLS

#endif
