/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_gal_ethernet_pmhd
#define _omci_api_me_gal_ethernet_pmhd

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_GAL_ETHERNET_PMHD GAL Ethernet PMHD

   This Managed Entity collects performance monitoring data associated with a
   GEM interworking termination point when the GEM layer provides Ethernet
   service.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of the GEM interworking TP. */

/** Retrieve current values of GAL Ethernet PMHD ME counters

   \param[in]  ctx                  OMCI API context pointer
   \param[in]  me_id                Managed Entity identifier
   \param[in]  get_curr             Get current value or last interval
   \param[in]  reset_cnt            Reset counters
   \param[out] cnt_discarded_frames Discarded frames
*/
enum omci_api_return
omci_api_gal_ethernet_pmhd_cnt_get(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   bool get_curr,
				   bool reset_cnt,
				   uint64_t *cnt_discarded_frames);

/** Set GAL Ethernet PMHD counters thresholds

   \param[in] ctx                           OMCI API context pointer
   \param[in] me_id                         Managed Entity identifier
   \param[in] cnt_discarded_frames          Discarded frames
*/
enum omci_api_return
omci_api_gal_ethernet_pmhd_thr_set(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint32_t cnt_discarded_frames);

/** @} */

/** @} */

__END_DECLS

#endif
