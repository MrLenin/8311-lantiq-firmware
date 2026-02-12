/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_ethernet_pmhd3_h
#define _omci_ethernet_pmhd3_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME_ETHERNET_PMHD
   @{
*/

/** This structure holds the attributes of the Ethernet Performance Monitoring
    History Data 3 Managed Entity.

    This Managed Entity collects performance monitoring data associated with an
    Ethernet interface. It includes parameters defined in the Ethernet
    statistics group of RFC 2819 that are not already covered by other Ethernet
    monitoring Managed Entities. The received direction is from the CPE toward
    the network (upstream). Instances of this Managed Entity are created and
    deleted by the OLT.
*/
struct omci_me_ethernet_pmhd3 {
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

	/** Drop Event Count

	    The total number of events in which packets were dropped due to lack
	    of resources. This is not necessarily the number of packets dropped;
	    it is the number of times this event was detected.

	    This attribute is read-only by the OLT.
	*/
	uint32_t drop_event_count;

	/** Received Octet (Byte) Count

	    The total number of octets received from the CPE, including those in
	    bad packets, excluding framing bits, but including FCS.

	    This attribute is read-only by the OLT.
	*/
	uint32_t rx_byte_count;

	/** Received Packet Count

	    The total number of packets received, including bad packets,
	    broadcast packets and multicast packets.

	    This attribute is read-only by the OLT.
	    */
	uint32_t rx_packet_count;

	/** Received Broadcast Packet Count

	    The total number of received good packets directed to the broadcast
	    address. This does not include multicast packets.

	    This attribute is read-only by the OLT.
	*/
	uint32_t rx_broadcast_packet_count;

	/** Received Multicast Packet Count

	    The total number of received good packets directed to a multicast
	    address. This does not include broadcast packets.

	    This attribute is read-only by the OLT.
	*/
	uint32_t rx_multicast_packet_count;

	/** Received Undersized Packet Count

	    The total number of packets received that were less than 64 octets
	    long but were otherwise well formed (excluding framing bits, but
	    including FCS octets).

	    This attribute is read-only by the OLT.
	*/
	uint32_t rx_undersized_packet_count;

	/** Received Fragment Count

	    The total number of packets received that were less than 64 octets
	    long, excluding framing bits but including FCS octets, and had
	    either a bad frame check sequence (FCS) with an integral number of
	    octets (FCS error) or a bad FCS with a non-integral number of
	    octets(alignment error).
	    It is entirely normal for this attribute to increment. This is
	    because it counts both runts (which are normal occurrences due to
	    collisions) and noise hits.

	    This attribute is read-only by the OLT.
	*/
	uint32_t rx_fragment_count;

	/** Received Jabber Count

	    The total number of packets received that were longer than 1518
	    octets, excluding framing bits but including FCS octets, and had
	    either a bad frame check sequence (FCS) with an integral number of
	    octets (FCS error) or a bad FCS with a non-integral number of
	    octets (alignment error).
	    The range to detect jabber is between 20 ms and 150 ms.

	    This attribute is read-only by the OLT.
	*/
	uint32_t rx_jabber_count;

	/** Received Frame Size 64 Byte Count

	    The total number of received packets (including bad packets) that
	    were 64 octets long, excluding framing bits but including FCS.

	    This attribute is read-only by the OLT.
	*/
	uint32_t rx_frame64_count;

	/** Received Frame Size 65 to 127 Byte Count

	    The total number of received packets (including bad packets) that
	    were 65..127 octets long, excluding framing bits but including FCS.

	    This attribute is read-only by the OLT.
	*/
	uint32_t rx_frame127_count;

	/** Received Frame Size 128 to 255 Byte Count

	    The total number of received packets (including bad packets) that
	    were 128..255 octets long, excluding framing bits but including FCS.

	    This attribute is read-only by the OLT.
	*/
	uint32_t rx_frame255_count;

	/** Received Frame Size 256 to 511 Byte Count

	    The total number of received packets (including bad packets) that
	    were 256..511 octets long, excluding framing bits but including FCS.

	    This attribute is read-only by the OLT.
	*/
	uint32_t rx_frame511_count;

	/** Received Frame Size 512 to 1023 Byte Count

	    The total number of received packets (including bad packets) that
	    were 512..1023 octets long, excluding framing bits but including
	    FCS.

	    This attribute is read-only by the OLT.
	    */
	uint32_t rx_frame1023_count;

	/** Received Frame Size 1024 to 1518 Byte Count

	    The total number of received packets (including bad packets) that
	    were 1024..1518 octets long, excluding framing bits but including
	    FCS.

	    This attribute is read-only by the OLT.
	    */
	uint32_t rx_frame1518_count;

} __PACKED__;

/** This enumerator holds the attribute numbers of the Ethernet Performance
   Monitoring History Data 3 Managed Entity.
*/
enum {
	omci_me_ethernet_pmhd3_interval_end_time = 1,
	omci_me_ethernet_pmhd3_thr_data_id = 2,
	omci_me_ethernet_pmhd3_drop_event_count = 3,
	omci_me_ethernet_pmhd3_rx_byte_count = 4,
	omci_me_ethernet_pmhd3_rx_packet_count = 5,
	omci_me_ethernet_pmhd3_rx_broadcast_packet_count = 6,
	omci_me_ethernet_pmhd3_rx_multicast_packet_count = 7,
	omci_me_ethernet_pmhd3_rx_undersized_packet_count = 8,
	omci_me_ethernet_pmhd3_rx_fragment_count = 9,
	omci_me_ethernet_pmhd3_rx_jabber_count = 10,
	omci_me_ethernet_pmhd3_rx_frame64_count = 11,
	omci_me_ethernet_pmhd3_rx_frame127_count = 12,
	omci_me_ethernet_pmhd3_rx_frame255_count = 13,
	omci_me_ethernet_pmhd3_rx_frame511_count = 14,
	omci_me_ethernet_pmhd3_rx_frame1023_count = 15,
	omci_me_ethernet_pmhd3_rx_frame1518_count = 16
};

/** @} */

__END_DECLS

#endif
