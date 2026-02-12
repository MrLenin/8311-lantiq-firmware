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

/** \defgroup OMCI_API_ME_SIP_CALL_INIT_PMHD SIP call initiation PMHD

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
   \param[out] failed_to_connect	Failed to connect counter
   \param[out] failed_to_validate	Failed to validate ciounter
   \param[out] timeout			Timeout counter
   \param[out] failure_received		Failure received counter
   \param[out] failed_to_auth		Failed to authenticate counter
*/
enum omci_api_return
omci_api_sip_call_init_pmhd_cnt_get(struct omci_api_ctx *ctx,
				    uint16_t me_id,
				    uint32_t *failed_to_connect,
				    uint32_t *failed_to_validate,
				    uint32_t *timeout,
				    uint32_t *failure_received,
				    uint32_t *failed_to_auth);

/** @} */

/** @} */

__END_DECLS

#endif
