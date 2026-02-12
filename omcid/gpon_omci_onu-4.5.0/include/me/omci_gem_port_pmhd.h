/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_gem_port_pmhd_h
#define _omci_gem_port_pmhd_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_GEM_PORT_PMHD GEM Port Performance Monitoring History Data Managed Entity

    This Managed Entity collects performance monitoring data associated with a
    GEM port network CTP.
    Instances of this Managed Entity are created and deleted by the OLT.

    @{
*/

/** This structure holds the attributes of the GEM Port Monitoring History
    Data Managed Entity.
*/
struct omci_me_gem_port_pmhd {
	/** Interval End Time

	    This attribute identifies the most recently finished 15-minute
	    interval. The sequence of 15-minute intervals is initiated by the
	    synchronize time action, issued by the OLT. The counter is
	    incremented every 15 minutes autonomously by the ONU and rolls over
	    from 255 to 0.

	    This attribute is read-only by the OLT.
	*/
	uint8_t interval_end_time;

	/** Threshold Data 1/2 ID

	    This attribute points to an instance of the threshold data 1 Managed
	    Entity that contains PM threshold values.
	    Since no threshold value attribute number exceeds 7, a threshold
	    data 2 Managed Entity is optional.

	    This attribute is readable and writable by the OLT.
	*/
	uint16_t thr_data_id;

	/** Lost Packet Count

	    This attribute counts downstream GEM frame loss. It does not
	    distinguish between packets lost because of header bit errors or
	    buffer overflows, it records only loss of information.
	*/
	uint32_t lost_packets;

	/** Misinserted Packet Count

	    This attribute is read-only by the OLT.

	    \remarks This type of error detection is not supported by the GTC
	    hardware. The counter value is always 0x0000.
	*/
	uint32_t misinserted_packets;

	/** Received Packet Count

	    This attribute counts downstream GEM frames that were received
	    correctly at the monitored GEM port.

	    This attribute is read-only by the OLT.

	    \note This is the high byte of the Received Packet Count attribute
	*/
	uint8_t received_packets_hi;

	/** Received Packet Count

	    \note This is the low 4 bytes of the Received Packet Count attribute
	*/
	uint32_t received_packets_lo;

	/** Received Block Count

	    This attribute counts downstream GEM blocks or partial blocks that
	    were received correctly at the monitored GEM port.

	    This attribute is read-only by the OLT.

	    \note This is the high byte of the Received Block Count attribute
	*/
	uint8_t received_blocks_hi;

	/** Received Block Count

	    \note This is the low 4 bytes of the Received Block Count attribute
	*/
	uint32_t received_blocks_lo;

	/** Transmitted Block Count

	    This attribute counts GEM blocks or partial blocks that have been
	    transmitted to the OLT.

	    This attribute is read-only by the OLT.

	    \note This is the high byte of the Transmitted Block Count attribute
	*/
	uint8_t transmitted_blocks_hi;

	/** Transmitted Block Count

	    \note This is the low 4 bytes of the Transmitted Block Count
	    attribute
	*/
	uint32_t transmitted_blocks_lo;

	/** Impaired Block Count

	    This severely errored data block counter is incremented whenever the
	    number of lost packets reaches its threshold. The threshold value is
	    defined by the application.

	    This attribute is read-only by the OLT.
	*/
	uint32_t impaired_blocks;

} __PACKED__;

/** This enumerator holds the attribute numbers of the GEM Port Monitoring
   History Data Managed Entity.
*/
enum {
	omci_me_gem_port_pmhd_interval_end_time = 1,
	omci_me_gem_port_pmhd_thr_data_id = 2,
	omci_me_gem_port_pmhd_lost_packets = 3,
	omci_me_gem_port_pmhd_misinserted_packets = 4,
	omci_me_gem_port_pmhd_received_packets_hi = 5,
	omci_me_gem_port_pmhd_received_blocks_hi = 6,
	omci_me_gem_port_pmhd_transmitted_blocks_hi = 7,
	omci_me_gem_port_pmhd_impaired_blocks = 8
};

/** @} */

/** @} */

__END_DECLS

#endif
