/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_ethernet_pmhd
#define _omci_api_me_ethernet_pmhd

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_ETHERNET_PMHD Ethernet PMHD

   This Managed Entity collects some of the performance monitoring data for an
   Ethernet interface.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of the physical path termination point Ethernet UNI. */

/** Retrieve current value of Ethernet PMHD counters

   \param[in]  ctx                           OMCI API context pointer
   \param[in]  me_id                         Managed Entity identifier
   \param[in]  get_curr                      Get current value or last interval
   \param[in]  reset_cnt                     Reset counters
   \param[out] cnt_fcs_error                 FCS errors
   \param[out] cnt_excessive_collisions      Excessive collision counter
   \param[out] cnt_late_collisions           Late collision counter
   \param[out] cnt_frames_too_long           Frames too long
   \param[out] cnt_rx_buffer_overflow_events Buffer overflows on receive
   \param[out] cnt_tx_buffer_overflow_events Buffer overflows on transmit
   \param[out] cnt_single_collisions         Single collision frame counter
   \param[out] cnt_multiple_collisions       Multiple collisions frame counter
   \param[out] cnt_sqe_test                  SQE counter
   \param[out] cnt_deferred_transmissions    Deferred transmission counter
   \param[out] cnt_tx_mac_errors             Internal MAC transmit error counter
   \param[out] cnt_carrier_sense_errors      Carrier sense error counter
   \param[out] cnt_alignment_error           Alignment error counter
   \param[out] cnt_rx_mac_errors             Internal MAC receive error counter
*/
enum omci_api_return
omci_api_ethernet_pmhd_cnt_get(struct omci_api_ctx *ctx,
			       uint16_t me_id,
			       bool get_curr,
			       bool reset_cnt,
			       uint64_t *cnt_fcs_error,
			       uint64_t *cnt_excessive_collisions,
			       uint64_t *cnt_late_collisions,
			       uint64_t *cnt_frames_too_long,
			       uint64_t *cnt_rx_buffer_overflow_events,
			       uint64_t *cnt_tx_buffer_overflow_events,
			       uint64_t *cnt_single_collisions,
			       uint64_t *cnt_multiple_collisions,
			       uint64_t *cnt_sqe_test,
			       uint64_t *cnt_deferred_transmissions,
			       uint64_t *cnt_tx_mac_errors,
			       uint64_t *cnt_carrier_sense_errors,
			       uint64_t *cnt_alignment_error,
			       uint64_t *cnt_rx_mac_errors);

/** Set Ethernet PMHD counters thresholds

   \param[in] ctx                           OMCI API context pointer
   \param[in] me_id                         Managed Entity identifier
   \param[in] cnt_fcs_error                 FCS errors
   \param[in] cnt_excessive_collisions      Excessive collision counter
   \param[in] cnt_late_collisions           Late collision counter
   \param[in] cnt_frames_too_long           Frames too long
   \param[in] cnt_rx_buffer_overflow_events Buffer overflows on receive
   \param[in] cnt_tx_buffer_overflow_events Buffer overflows on transmit
   \param[in] cnt_single_collisions         Single collision frame counter
   \param[in] cnt_multiple_collisions       Multiple collisions frame counter
   \param[in] cnt_sqe_test                  SQE counter
   \param[in] cnt_deferred_transmissions    Deferred transmission counter
   \param[in] cnt_tx_mac_errors             Internal MAC transmit error counter
   \param[in] cnt_carrier_sense_errors      Carrier sense error counter
   \param[in] cnt_alignment_error           Alignment error counter
   \param[in] cnt_rx_mac_errors             Internal MAC receive error counter
*/
enum omci_api_return
omci_api_ethernet_pmhd_thr_set(struct omci_api_ctx *ctx,
			       uint16_t me_id,
			       uint32_t cnt_fcs_error,
			       uint32_t cnt_excessive_collisions,
			       uint32_t cnt_late_collisions,
			       uint32_t cnt_frames_too_long,
			       uint32_t cnt_rx_buffer_overflow_events,
			       uint32_t cnt_tx_buffer_overflow_events,
			       uint32_t cnt_single_collisions,
			       uint32_t cnt_multiple_collisions,
			       uint32_t cnt_sqe_test,
			       uint32_t cnt_deferred_transmissions,
			       uint32_t cnt_tx_mac_errors,
			       uint32_t cnt_carrier_sense_errors,
			       uint32_t cnt_alignment_error,
			       uint32_t cnt_rx_mac_errors);

/** Retrieve cumulative (total) Ethernet PMHD counters (curr=true, no reset) */
enum omci_api_return
omci_api_ethernet_pmhd_total_cnt_get(struct omci_api_ctx *ctx,
				     uint16_t me_id,
				     uint64_t *cnt_fcs_error,
				     uint64_t *cnt_excessive_collisions,
				     uint64_t *cnt_late_collisions,
				     uint64_t *cnt_frames_too_long,
				     uint64_t *cnt_rx_buffer_overflow_events,
				     uint64_t *cnt_tx_buffer_overflow_events,
				     uint64_t *cnt_single_collisions,
				     uint64_t *cnt_multiple_collisions,
				     uint64_t *cnt_sqe_test,
				     uint64_t *cnt_deferred_transmissions,
				     uint64_t *cnt_tx_mac_errors,
				     uint64_t *cnt_carrier_sense_errors,
				     uint64_t *cnt_alignment_error,
				     uint64_t *cnt_rx_mac_errors);

/** Reset all Ethernet PMHD counters */
enum omci_api_return
omci_api_ethernet_pmhd_cnt_reset(struct omci_api_ctx *ctx,
				 uint16_t me_id);

/** @} */

/** @} */

__END_DECLS

#endif
