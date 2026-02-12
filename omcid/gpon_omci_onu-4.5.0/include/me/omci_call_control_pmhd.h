/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_call_control_pmhd_h
#define _omci_call_control_pmhd_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_CALL_CONTROL_PMHD Call Control Performance Monitoring history data Managed Entity

    This managed entity collects performance monitoring data related to the call
    control channel.
    Instances of this managed entity are created and deleted by the OLT. 

     An instance of this managed entity is associated with an instance of the
     PPTP POTS UNI managed entity. 

    @{
*/


/** This structure holds the attributes of the Call Control Performance
    Monitoring history data Data Managed Entity. */
struct omci_me_call_control_pmhd {
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

	/** Call setup failures.
	    This attribute counts call setup failures.
	*/
	uint32_t call_setup_failures;

	/** Call setup timer.
	    This attribute is a high water mark that records the longest
	    duration of a single call setup detected during this interval.
	    Time is measured in milliseconds from the time an initial setup was
	    requested by the subscriber until the time at which a response was
	    provided to the subscriber in the form of busy tone, audible ring
	    tone, etc.
	*/
	uint32_t call_setup_timer;

	/** Call terminate failures.
	    This attribute counts the number of calls that were terminated with
	    cause. 
	*/
	uint32_t call_terminate_failures;

	/** Analog port releases.
	    This attribute counts the number of analogue port releases without
	    dialling detected (abandoned calls).
	*/
	uint32_t analog_port_releases;

	/** Analog port off-hook timer.
	    This attribute is a high water mark that records the longest period
	    of a single off-hook detected on the analogue port. Time is measured
	    in milliseconds.
	*/
	uint32_t analog_port_offhook_timer;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Call Control
    Performance Monitoring history data Managed Entity.
*/
enum {
	omci_me_call_control_pmhd_interval_end_time = 1,
	omci_me_call_control_pmhd_threshold_data = 2,
	omci_me_call_control_pmhd_call_setup_failures = 3,
	omci_me_call_control_pmhd_call_setup_timer = 4,
	omci_me_call_control_pmhd_call_terminate_failures = 5,
	omci_me_call_control_pmhd_analog_port_releases = 6,
	omci_me_call_control_pmhd_analog_port_offhook_timer = 7
};

/** @} */

/** @} */

__END_DECLS

#endif
