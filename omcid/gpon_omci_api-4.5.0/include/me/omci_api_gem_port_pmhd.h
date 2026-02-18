/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_gem_port_pmhd
#define _omci_api_me_gem_port_pmhd

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_GEM_PORT_PMHD GEM Port PMHD

   This Managed Entity collects performance monitoring data associated with a
   GEM port network CTP.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of the GEM port network CTP. */

/** Retrieve current value of GEM Port PMHD counters

   \param[in]  ctx                     OMCI API context pointer
   \param[in]  me_id                   Managed Entity identifier
   \param[in]  reset_cnt               Reset counters
   \param[in]  current                 15-min interval (true if current)
   \param[out] tx_gem_frames           Transmitted GEM frames
   \param[out] rx_gem_frames           Received GEM frames (packets)
   \param[out] rx_payload_bytes        Received payload bytes (GEM blocks)
   \param[out] tx_payload_bytes        Transmitted GEM frames (GEM blocks)
   \param[out] lost_packets            Number of dropped RX frames
*/
enum omci_api_return
omci_api_gem_port_pmhd_cnt_get(struct omci_api_ctx *ctx,
			       uint16_t me_id,
			       bool reset_cnt,
			       bool current,
			       uint64_t *tx_gem_frames,
			       uint64_t *rx_gem_frames,
			       uint64_t *rx_payload_bytes,
			       uint64_t *tx_payload_bytes,
			       uint32_t *lost_packets);

/** Set counters thresholds

   \param[in] ctx              OMCI API context pointer
   \param[in] me_id            Managed Entity identifier
   \param[in] tx_gem_frames    Transmitted GEM frames
   \param[in] rx_gem_frames    Received GEM frames (packets)
   \param[in] rx_payload_bytes Received payload bytes (GEM blocks)
   \param[in] tx_payload_bytes Transmitted GEM frames (GEM blocks)
   \param[in] lost_packets     Number of dropped RX frames
*/
enum omci_api_return
omci_api_gem_port_pmhd_thr_set(struct omci_api_ctx *ctx,
			       uint16_t me_id,
			       uint32_t tx_gem_frames,
			       uint32_t rx_gem_frames,
			       uint32_t rx_payload_bytes,
			       uint32_t tx_payload_bytes,
			       uint32_t lost_packets);

/** Reset GEM Port PMHD counters (GTC + GPE GEM) */
enum omci_api_return
omci_api_gem_port_pmhd_cnt_reset(struct omci_api_ctx *ctx,
				 uint16_t me_id);

/** Retrieve cumulative (total) GEM Port PMHD counters */
enum omci_api_return
omci_api_gem_port_pmhd_total_cnt_get(struct omci_api_ctx *ctx,
				     uint16_t me_id,
				     uint64_t *tx_gem_frames,
				     uint64_t *rx_gem_frames,
				     uint64_t *rx_payload_bytes,
				     uint64_t *tx_payload_bytes,
				     uint32_t *lost_packets);

/** @} */

/** @} */

__END_DECLS

#endif
