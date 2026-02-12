/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_ip_host_monitoring_data_h
#define _omci_ip_host_monitoring_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_IP_HOST_MONITORING_DATA IP Host Monitoring Data Managed Entity

    This Managed Entity collects performance monitoring data related to an IP 
    host. Instances of this Managed Entity are created and deleted by the OLT.

    An instance of this Managed Entity is associated with an instance of the 
    IP host Managed Entity.

    @{
*/


/** This structure holds the attributes of the IP Host Monitoring Data Managed
   Entity. */
struct omci_me_ip_host_monitoring_data {
	/** Interval end time
	    This attribute identifies the most recently finished 15-minute 
	    interval.
	*/
	uint8_t interval_end_time;

	/** Threshold data
	    This attribute points to an instance of the threshold data 1 
	    Managed Entity that contains PM threshold values. Since no 
	    threshold value attribute number exceeds 7, a threshold data 2 
	    ME is optional
	*/
	uint16_t threshold_data;

	/** ICMP errors
	    This attribute counts ICMP errors received.
	*/
	uint32_t icmp_errors;

	/** DNS errors
	    This attribute counts DNS errors received.
	*/
	uint32_t dns_errors;

	/** DHCP timeouts
	    This attribute counts DHCP timeouts.
	*/
	uint16_t dhcp_timeouts;

	/** IP address conflict
	    This attribute is incremented whenever the ONU detects a 
	    conflicting IP address on the network. A conflicting IP 
	    address is one that has the same value as the one currently 
	    assigned to the ONU.
	*/
	uint16_t ip_address_conflict;

	/** Out of memory
	    This attribute is incremented whenever the ONU encounters 
	    an out of memory condition in the IP stack.
	*/
	uint16_t out_of_memory;

	/** Internal error
	    This attribute is incremented whenever the ONU encounters 
	    an internal error condition such as a driver interface 
	    failure in the IP stack.
	*/
	uint16_t internal_error;

} __PACKED__;

/** This enumerator holds the attribute numbers of the IP Host Monitoring Data
   Managed Entity.
*/
enum {
	omci_me_ip_host_monitoring_data_interval_end_time = 1,
	omci_me_ip_host_monitoring_data_threshold_data = 2,
	omci_me_ip_host_monitoring_data_icmp_errors = 3,
	omci_me_ip_host_monitoring_data_dns_errors = 4,
	omci_me_ip_host_monitoring_data_dhcp_timeouts = 5,
	omci_me_ip_host_monitoring_data_ip_address_conflict = 6,
	omci_me_ip_host_monitoring_data_out_of_memory = 7,
	omci_me_ip_host_monitoring_data_internal_error = 8
};

/** @} */

/** @} */

__END_DECLS

#endif
