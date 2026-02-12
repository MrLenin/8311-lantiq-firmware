/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_sip_call_init_pmhd
#define _omci_api_sip_call_init_pmhd

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_SIP_AGENT_PMHD SIP agent PMHD

   This Managed Entity collects performance monitoring data related to a SIP
   session.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an 
   instance of the SIP agent config data or the SIP config portal ME. */

/** Retrieve current value of SIP call initiation PMHD counters

   \param[in]  ctx			OMCI API context pointer
   \param[in]  me_id			Managed Entity identifier
   \param[out] transactions		Transactions
   \param[out] rx_invite_reqs		RX invite requests
   \param[out] rx_invite_retrans	RX invite retransmissions
   \param[out] rx_noninvite_reqs	RX noninvite requests
   \param[out] rx_noninvite_retrans	RX noninvite retransmissions
   \param[out] rx_response		RX Response
   \param[out] rx_response_retrans	RX Response retransmissions
   \param[out] tx_invite_reqs		TX invite requests
   \param[out] tx_invite_retrans	TX invite retransmissions
   \param[out] tx_noninvite_reqs	TX noninvite requests
   \param[out] tx_noninvite_retrans	TX noninvite retransmissions
   \param[out] tx_response		TX Response
   \param[out] tx_response_retrans	TX Response retransmissions

*/
enum omci_api_return
omci_api_sip_agent_pmhd_cnt_get(struct omci_api_ctx *ctx,
				uint16_t me_id,
				uint32_t *transactions,
				uint32_t *rx_invite_reqs,
				uint32_t *rx_invite_retrans,
				uint32_t *rx_noninvite_reqs,
				uint32_t *rx_noninvite_retrans,
				uint32_t *rx_response,
				uint32_t *rx_response_retrans,
				uint32_t *tx_invite_reqs,
				uint32_t *tx_invite_retrans,
				uint32_t *tx_noninvite_reqs,
				uint32_t *tx_noninvite_retrans,
				uint32_t *tx_response,
				uint32_t *tx_response_retrans);

/** @} */

/** @} */

__END_DECLS

#endif
