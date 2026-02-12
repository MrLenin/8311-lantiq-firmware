
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

   This managed entity collects some of the performance monitoring data for an
   Ethernet interface.

   Instances of this managed entity are created and deleted by the OLT.

   @{
*/

/* Through an identical ID, this managed entity is implicitly linked to an
   instance of the physical path termination point Ethernet UNI. */

/** Retrieve current value of Ethernet PMHD counters

   \param[in]  ctx                           OMCI API context pointer
   \param[in]  me_id                         Managed Entity identifier
   \param[in]  get_curr                      Get current value or last interval
   \param[in]  reset_cnt                     Reset counters
   \param[out] cnt_pppoe_filtered_frames     PPPoE filtering counter
*/
enum omci_api_return
omci_api_ethernet_pmhd2_cnt_get(struct omci_api_ctx *ctx,
			        uint16_t me_id,
			        bool get_curr,
			        bool reset_cnt,
			        uint64_t *cnt_pppoe_filtered_frames);

/** Set Ethernet PMHD counters thresholds

   \param[in] ctx                           OMCI API context pointer
   \param[in] me_id                         Managed Entity identifier
   \param[in] cnt_pppoe_filtered_frames     PPPoE filtering counter
*/
enum omci_api_return
omci_api_ethernet_pmhd2_thr_set(struct omci_api_ctx *ctx,
		                uint16_t me_id,
			        uint32_t cnt_pppoe_filtered_frames);

/** @} */

/** @} */

__END_DECLS

#endif
