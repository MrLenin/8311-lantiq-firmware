/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_ethernet_us_pmhd_h
#define _omci_api_me_ethernet_us_pmhd_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_ETHERNET_US_PMHD Ethernet Frame PMHD Upstream

   This Managed Entity collects performance monitoring data associated with
   upstream Ethernet frame delivery. It is based on the Etherstats group of
   RFC 2819 [b-ITU-T G.984.4.6].

   Instances of this Managed Entity are created and deleted by the OLT.
   For a complete discussion of generic PM architecture, refer to clause
   I.1.9/G.984.4.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of a MAC bridge port configuration data. */

/** Retrieve current value of Ethernet Frame PMHD Upstream counters

   \param[in]  ctx                      OMCI API context pointer
   \param[in]  me_id                    Managed Entity identifier
   \param[in]  get_curr                 Get current counters
   \param[in]  reset_cnt                Reset counters
   \param[out] cnt_drop_events          Drop events
   \param[out] cnt_octets               Octets
   \param[out] cnt_packets              Packets
   \param[out] cnt_broadcast_packets    Broadcast packets
   \param[out] cnt_multicast_packets    Multicast packets
   \param[out] cnt_crc_errored_packets  CRC errored packets
   \param[out] cnt_undersized_packets   Undersize packets
   \param[out] cnt_oversized_packets    Oversize packets
   \param[out] cnt64_octets_packets     Packets 64 octets
   \param[out] cnt127_octets_packets    Packets 65 to 127 octets
   \param[out] cnt255_octets_packets    Packets 128 to 255 octets
   \param[out] cnt511_octets_packets    Packets 256 to 511 octets
   \param[out] cnt1023_octets_packets   Packets 512 to 1023 octets
   \param[out] cnt1518_octets_packets   Packets 1024 to 1518 octets
*/
enum omci_api_return
omci_api_ethernet_us_pmhd_cnt_get(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  bool get_curr,
				  bool reset_cnt,
				  uint64_t *cnt_drop_events,
				  uint64_t *cnt_octets,
				  uint64_t *cnt_packets,
				  uint64_t *cnt_broadcast_packets,
				  uint64_t *cnt_multicast_packets,
				  uint64_t *cnt_crc_errored_packets,
				  uint64_t *cnt_undersized_packets,
				  uint64_t *cnt_oversized_packets,
				  uint64_t *cnt64_octets_packets,
				  uint64_t *cnt127_octets_packets,
				  uint64_t *cnt255_octets_packets,
				  uint64_t *cnt511_octets_packets,
				  uint64_t *cnt1023_octets_packets,
				  uint64_t *cnt1518_octets_packets);

/** Set Ethernet Frame PMHD Upstream counters thresholds

   \param[in] ctx                      OMCI API context pointer
   \param[in] me_id                    Managed Entity identifier
   \param[in] cnt_drop_events          Drop events
   \param[in] cnt_crc_errored_packets  CRC errored packets
   \param[in] cnt_undersized_packets   Undersize packets
   \param[in] cnt_oversized_packets    Oversize packets
*/
enum omci_api_return
omci_api_ethernet_us_pmhd_thr_set(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint32_t cnt_drop_events,
				  uint32_t cnt_crc_errored_packets,
				  uint32_t cnt_undersized_packets,
				  uint32_t cnt_oversized_packets);

/** Retrieve cumulative (total) Ethernet Frame US PMHD counters */
enum omci_api_return
omci_api_ethernet_us_pmhd_total_cnt_get(struct omci_api_ctx *ctx,
					uint16_t me_id,
					uint64_t *cnt_drop_events,
					uint64_t *cnt_octets,
					uint64_t *cnt_packets,
					uint64_t *cnt_broadcast_packets,
					uint64_t *cnt_multicast_packets,
					uint64_t *cnt_crc_errored_packets,
					uint64_t *cnt_undersized_packets,
					uint64_t *cnt_oversized_packets,
					uint64_t *cnt64_octets_packets,
					uint64_t *cnt127_octets_packets,
					uint64_t *cnt255_octets_packets,
					uint64_t *cnt511_octets_packets,
					uint64_t *cnt1023_octets_packets,
					uint64_t *cnt1518_octets_packets);

/** @} */

/** @} */

__END_DECLS

#endif
