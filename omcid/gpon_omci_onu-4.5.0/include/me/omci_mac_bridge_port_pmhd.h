/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_mac_bridge_port_pmhd_h
#define _omci_mac_bridge_port_pmhd_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_MAC_BRIDGE_PORT_PMHD MAC Bridge Port Performance Monitoring History Data Managed Entity

    This Managed Entity collects performance monitoring data associated with a
    MAC bridge port. Instances of this Managed Entity are created and deleted
    by the OLT. An instance of this Managed Entity is associated with an
    instance of a MAC bridge port configuration data Managed Entity.

    @{
*/

/** This structure holds the attributes of the MAC Bridge Port Monitoring
    History Data Managed Entity.
*/
struct omci_me_mac_bridge_port_pmhd {
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

	/** Forwarded Frame Counter

	    This attribute counts frames transmitted successfully on this port.

	    This attribute is read-only by the OLT.
	*/
	uint32_t forwarded_frame_count;

	/** Delay Exceeded Discard Counter
	    This attribute counts frames discarded on this port because the
	    transmission was delayed.

	    This attribute is read-only by the OLT.

	    \remarks This counter is not supported by hardware, the value always
	    set to 0x0000.
	*/
	uint32_t delay_exceeded_discard_count;

	/** MTU Exceeded Discard Counter

	    This attribute counts frames discarded on this port because the MTU
	    (Maximum Transmission Unit) was exceeded. The MTU is defined by the
	    PPTP Ethernet UNI
	    (\ref omci_me_pptp_ethernet_uni::max_frame_size).
	*/
	uint32_t mtu_exceeded_discard_count;

	/** Received Frame Counter

	    This attribute counts frames received on this bridge port.
	*/
	uint32_t received_frame_count;

	/** Received and Discarded Counter

	    This attribute counts frames received on this port that were discarded
	    due to errors.
	*/
	uint32_t received_discard_count;

} __PACKED__;

/** This enumerator holds the attribute numbers of the MAC Bridge Port
   Monitoring History Data Managed Entity.
*/
enum {
	omci_me_mac_bridge_port_pmhd_interval_end_time = 1,
	omci_me_mac_bridge_port_pmhd_thr_data_id = 2,
	omci_me_mac_bridge_port_pmhd_forwarded_frame_count = 3,
	omci_me_mac_bridge_port_pmhd_delay_exceeded_discard_count = 4,
	omci_me_mac_bridge_port_pmhd_mtu_exceeded_discard_count = 5,
	omci_me_mac_bridge_port_pmhd_received_frame_count = 6,
	omci_me_mac_bridge_port_pmhd_received_discarded_count = 7
};

/** @} */

/** @} */

__END_DECLS

#endif
