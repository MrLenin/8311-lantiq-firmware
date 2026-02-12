/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_tcont
#define _omci_api_me_tcont

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_TCONT T-CONT

   An instance of the traffic container Managed Entity T-CONT represents a
   logical connection group associated with a PLOAM layer alloc-id. A T-CONT
   can accommodate GEM packets in priority queues or traffic schedulers that
   exist in the GEM layer.

   The ONU autonomously creates instances of this ME. The OLT can discover the
   number of T-CONT instances via the ANI-G ME. When the ONU's MIB is reset or
   created for the first time, all supported T-CONTs are created. The OLT
   provisions allocation-IDs to the ONU via the PLOAM channel. The OLT must
   then set the alloc-id attributes in the T-CONTs that it wants to activate
   for user traffic, to create the appropriate association between the
   allocation ID set in the PLOAM channel and the T-CONT in the OMCI. Once that
   association is created, the mode indicator attribute assumes the mode
   specified in the PLOAM channel. Note that there should be a one-to-one
   relationship between allocation IDs and T-CONT MEs, and the connection of
   multiple T-CONTs to a single allocation ID is undefined.

   @{
*/

/** Update T-CONT ME resources

   \param[in] ctx      OMCI API context pointer
   \param[in] me_id    Managed Entity identifier
   \param[in] policy   Policy
*/
enum omci_api_return omci_api_tcont_create(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint16_t policy);
					   

/** Update T-CONT ME resources

   \param[in] ctx      OMCI API context pointer
   \param[in] me_id    Managed Entity identifier
   \param[in] alloc_id Alloc-id
*/
enum omci_api_return omci_api_tcont_update(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint16_t alloc_id);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

   \param[in] ctx      OMCI API context pointer
   \param[in] me_id    Managed Entity identifier
   \param[in] alloc_id Alloc-id
*/
enum omci_api_return omci_api_tcont_destroy(struct omci_api_ctx *ctx,
					    uint16_t me_id,
					    uint16_t alloc_id);

/** @} */

/** @} */

__END_DECLS

#endif
