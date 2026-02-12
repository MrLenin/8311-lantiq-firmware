/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_sip_call_init_pmhd_h
#define _omci_sip_call_init_pmhd_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_SIP_CALL_INIT_PMHD SIP call initiation Performance Monitoring history data Managed Entity

    This managed entity collects performance monitoring data related to call
    initiations of a VoIP SIP agent.
    Instances of this managed entity are created and deleted by the OLT. .

    An instance of this managed entity is associated with an instance of the SIP
    agent config data or SIP config portal ME.  

    @{
*/


/** This structure holds the attributes of the SIP call initiation Performance
    Monitoring history data Data Managed Entity. */
struct omci_me_sip_call_init_pmhd {
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

	/** Failed to connect counter
	    This attribute counts the number of times the SIP UA failed to
	    reach/connect its TCP/UDP peer during SIP call initiations.
	*/
	uint32_t failed_to_connect;

	/** Failed to validate counter
	    This attribute counts the number of times the SIP UA failed to
	    validate its peer during SIP call initiations. 
	*/
	uint32_t failed_to_validate;

	/** Timeout counter
	    This attribute counts the number of times the SIP UA timed out
	    during SIP call initiations. 
	*/
	uint32_t timeout;

	/** Failure received counter
	    This attribute counts the number of times the SIP UA received a
	    failure error code during SIP call initiations. 
	*/
	uint32_t failure_received;

	/** Failed to authenticate counter
	    This attribute counts the number of times the SIP UA failed to
	    authenticate itself during SIP call initiations. 
	*/
	uint32_t failed_to_auth;

} __PACKED__;

/** This enumerator holds the attribute numbers of the SIP call initiation
    Performance Monitoring history data Managed Entity.
*/
enum {
	omci_me_sip_call_init_pmhd_interval_end_time = 1,
	omci_me_sip_call_init_pmhd_threshold_data = 2,
	omci_me_sip_call_init_pmhd_failed_to_connect = 3,
	omci_me_sip_call_init_pmhd_failed_to_validate = 4,
	omci_me_sip_call_init_pmhd_timeout = 5,
	omci_me_sip_call_init_pmhd_failure_received = 6,
	omci_me_sip_call_init_pmhd_failed_to_auth = 7
};

/** @} */

/** @} */

__END_DECLS

#endif
