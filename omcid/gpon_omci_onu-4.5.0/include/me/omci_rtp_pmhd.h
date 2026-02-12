/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_rtp_pmhd_h
#define _omci_rtp_pmhd_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_RTP_PMHD RTP Performance Monitoring history data Managed Entity

    This managed entity collects performance monitoring data related to an RTP
    session. Instances of this managed entity are created and deleted by
    the OLT.

    An instance of this managed entity is associated with an instance of the
    PPTP POTS UNI managed entity. 

    @{
*/


/** This structure holds the attributes of the RTP Performance Monitoring
    history data Data Managed Entity. */
struct omci_me_rtp_pmhd {
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

	/** RTP errors
	    This attribute counts RTP packet errors.
	*/
	uint32_t rtp_errors;

	/** Packet loss
	    This attribute represents the fraction of packets lost.
	    This attribute is calculated at the end of the 15-minute interval,
	    and is undefined under the get current data action. The value 0
	    indicates no packet loss, scaling linearly to 0xFFFF FFFF to
	    indicate 100% packet loss (zero divided by zero is defined to be
	    zero).
	*/
	uint32_t packet_loss;

	/** Maximum jitter
	    This attribute is a high water mark that represents the maximum
	    jitter identified during the measured interval, expressed in RTP
	    timestamp units. 
	*/
	uint32_t max_jitter;

	/** Maximum time between RTCP packets
	    This attribute is a high water mark that represents the maximum time
	    between RTCP packets during the measured interval, in milliseconds. 
	*/
	uint32_t max_time_between_rtcp_packets;

	/** Buffer underflows
	    This attribute counts the number of times the reassembly buffer
	    underflows. In case of continuous underflow caused by a loss of
	    IP packets, a single buffer underflow should be counted. If the
	    interworking function is implemented with multiple buffers, such as
	    a packet level buffer and a bit level buffer, then underflow of
	    either buffer increments this counter.
	*/
	uint32_t buffer_underflows;

	/** Buffer overflows
	    This attribute counts the number of times the reassembly buffer
	    overflows. If the interworking function is implemented with multiple
	    buffers, such as a packet level buffer and a bit level buffer, then
	    overflow of either buffer increments this counter.
	*/
	uint32_t buffer_overflows;
} __PACKED__;

/** This enumerator holds the attribute numbers of the RTP Performance
    Monitoring history data Managed Entity.
*/
enum {
	omci_me_rtp_pmhd_interval_end_time = 1,
	omci_me_rtp_pmhd_threshold_data = 2,
	omci_me_rtp_pmhd_rtp_errors = 3,
	omci_me_rtp_pmhd_packet_loss = 4,
	omci_me_rtp_pmhd_max_jitter = 5,
	omci_me_rtp_pmhd_max_time_between_rtcp_packets = 6,
	omci_me_rtp_pmhd_buffer_underflows = 7,
	omci_me_rtp_pmhd_buffer_overflows = 8
};

/** @} */

/** @} */

__END_DECLS

#endif
