/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_mac_bridge_port_pmhd
#define _omci_api_me_mac_bridge_port_pmhd

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_MAC_BRIDGE_PORT_PMHD MAC Bridge Port PMHD

   This Managed Entity collects performance monitoring data associated with a
   MAC bridge. Instances of this Managed Entity are created and deleted by the
   OLT.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of the MAC bridge port configuration data ME. */

/** Retrieve current values of MAC Bridge PMHD ME counters

   \param[in]  ctx                        OMCI API context pointer
   \param[in]  me_id                      Managed Entity identifier
   \param[in]  get_curr                   Get current value or last interval
   \param[in]  reset_cnt                  Reset counters
   \param[out] forwarded_frame            Forwarded frame counter
   \param[out] delay_exceed_discard       Delay exceeded discard counter
   \param[out] mtu_exceed_discard         MTU exceeded discard counter
   \param[out] received_frame             Received frame counter
   \param[out] received_and_discarded     Received and discarded counter
*/
enum omci_api_return
omci_api_mac_bridge_port_pmhd_cnt_get(struct omci_api_ctx *ctx,
				      const uint16_t me_id,
				      const bool get_curr,
				      const bool reset_cnt,
				      uint64_t *forwarded_frame,
				      uint64_t *delay_exceed_discard,
				      uint64_t *mtu_exceed_discard,
				      uint64_t *received_frame,
				      uint64_t *received_and_discarded);

/** @} */

/** @} */

__END_DECLS

#endif
