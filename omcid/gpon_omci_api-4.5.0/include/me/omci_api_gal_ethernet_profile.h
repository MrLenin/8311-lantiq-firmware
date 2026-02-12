/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_gal_ethernet_profile
#define _omci_api_me_gal_ethernet_profile

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME
   @{
*/

/** \defgroup OMCI_API_ME_GAL_ETHERNET_PROFILE GAL Ethernet Profile

   This Managed Entity organizes data that describes the GTC adaptation layer
   processing functions of the ONU for Ethernet services. It is used with the
   GEM interworking termination point Managed Entity.

   Instances of this Managed Entity are created and deleted on request of the
   OLT.

   @{
*/

/** Update GAL Ethernet Profile resources

   \note Enable Managed Entity identifier mapping to driver index and
   initialize corresponding driver structures when it is called first time
   for the given ME ID

   \param[in] ctx                  OMCI API context pointer
   \param[in] me_id                Managed Entity identifier
   \param[in] gem_payload_size_max Maximum GEM payload size
*/
enum omci_api_return
omci_api_gal_ethernet_profile_update(struct omci_api_ctx *ctx,
				     uint16_t me_id,
				     uint16_t gem_payload_size_max);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_gal_ethernet_profile_destroy(struct omci_api_ctx *ctx,
				      uint16_t me_id);

/** @} */

/** @} */

__END_DECLS

#endif
