/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_mac_bridge_pmhd
#define _omci_api_me_mac_bridge_pmhd

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_MAC_BRIDGE_PMHD MAC Bridge PMHD

   This Managed Entity collects performance monitoring data associated with a
   MAC bridge.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of the MAC bridge service profile. */

/** Retrieve current value of MAC Bridge PMHD counters

   \param[in]  ctx                         OMCI API context pointer
   \param[in]  me_id                       Managed Entity identifier
   \param[in]  reset_cnt                   Reset counters
   \param[in]  current                     Current value or last interval
   \param[out] cnt_bridge_learning_discard Bridge learning entry discard count
*/
enum omci_api_return
omci_api_mac_bridge_pmhd_cnt_get(struct omci_api_ctx *ctx,
				 uint16_t me_id,
				 bool reset_cnt,
				 bool current,
				 uint32_t *cnt_bridge_learning_discard);

/** Set thresholds for MAC Bridge PMHD counters

   \param[in] ctx                         OMCI API context pointer
   \param[in] me_id                       Managed Entity identifier
   \param[in] cnt_bridge_learning_discard Bridge learning entry discard count
*/
enum omci_api_return
omci_api_mac_bridge_pmhd_thr_set(struct omci_api_ctx *ctx,
				 uint16_t me_id,
				 uint32_t cnt_bridge_learning_discard);

/** Retrieve cumulative (total) MAC Bridge PMHD counters */
enum omci_api_return
omci_api_mac_bridge_pmhd_total_cnt_get(struct omci_api_ctx *ctx,
				       uint16_t me_id,
				       uint32_t *cnt_bridge_learning_discard);

/** @} */

/** @} */

__END_DECLS

#endif
