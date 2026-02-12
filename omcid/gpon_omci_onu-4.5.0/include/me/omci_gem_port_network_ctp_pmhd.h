/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_gem_port_network_ctp_pmhd_h
#define _omci_gem_port_network_ctp_pmhd_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_GEM_PORT_NETWORK_CTP_PMHD PMHD GEM Port Network CTP Performance Monitoring History Data Managed Entity

    This Managed Entity collects performance monitoring data associated with a
    GEM port network CTP.
    Instances of this Managed Entity are created and deleted by the OLT.

    @{
*/

/** This structure holds the attributes of the GEM Port Network CTP Monitoring History
    Data Managed Entity.
*/
struct omci_me_gem_port_network_ctp_pmhd {
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

	/** Transmitted GEM frames

	    This attribute counts GEM frames transmitted on the
	    monitored GEM port.
	*/
	uint32_t tx_gem_frames;

	/** Received GEM frames

	    This attribute counts GEM frames received correctly on the
	    monitored GEM port. A correctly received GEM frame is one that
	    contains no uncorrectable errors and a valid HEC.
	*/
	uint32_t rx_gem_frames;

	/** Received payload bytes

	    This attribute counts user payload bytes received on the monitored
	    GEM port.
	*/
	uint64_t rx_payload_bytes;

	/** Transmitted payload bytes

	    This attribute counts user payload bytes transmitted on the
	    monitored GEM port.
	*/
	uint64_t tx_payload_bytes;
} __PACKED__;

/** This enumerator holds the attribute numbers of the GEM Port Network CTP
   Monitoring History Data Managed Entity.
*/
enum {
	omci_me_gem_port_network_ctp_pmhd_interval_end_time = 1,
	omci_me_gem_port_network_ctp_pmhd_thr_data_id = 2,
	omci_me_gem_port_network_ctp_pmhd_tx_gem_frames = 3,
	omci_me_gem_port_network_ctp_pmhd_rx_gem_frames = 4,
	omci_me_gem_port_network_ctp_pmhd_rx_payload_bytes = 5,
	omci_me_gem_port_network_ctp_pmhd_tx_payload_bytes = 6
};

/** @} */

/** @} */

__END_DECLS

#endif
