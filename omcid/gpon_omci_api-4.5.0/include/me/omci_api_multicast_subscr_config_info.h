/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_multicast_subscr_config_info_h
#define _omci_api_me_multicast_subscr_config_info_h

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_MULTICAST_SUBSCR_CONFIG_INFO Multicast Subscriber Config Info

   This managed entity organizes data associated with multicast management at
   subscriber ports of 802.1 bridges, including 802.1p mappers when the
   provisioning model is mapper-based rather than bridge-based. Instances of
   this managed entity are created and deleted by the OLT. Because of backward
   compatibility considerations, a subscriber port without an associated
   multicast subscriber config info ME would be expected to support unrestricted
   multicast access; this ME may therefore be viewed as restrictive, rather than
   permissive.

   Instances of this managed entity are created and deleted by the OLT.

   @{
*/


/** Update Multicast Subscriber Config Info ME resources

   \note Enable Managed Entity identifier mapping to driver index and
   initialize corresponding driver structures when it is called first time
   for the given ME ID

   \param[in] ctx                        OMCI API context pointer
   \param[in] me_id                      Managed Entity identifier
   \param[in] linked_me_type             Type of linked Managed Entity
   \param[in] pptp_eth_uni_ptr           Pointer to PPTP Ethernet UNI ME
   \param[in] mc_oper_profile_ptr        Multicast operations profile pointer
   \param[in] max_sim_groups             Max simultaneous groups
   \param[in] max_mc_bw                  Max multicast bandwidth
   \param[in] bw_enf                     Bandwidth enforcement

*/
enum omci_api_return
omci_api_multicast_subscr_config_info_update(struct omci_api_ctx *ctx,
					     uint16_t me_id,
					     uint8_t linked_me_type,
					     uint16_t pptp_eth_uni_ptr,
					     uint16_t mc_oper_profile_ptr,
					     uint16_t max_sim_groups,
					     uint32_t max_mc_bw,
					     uint8_t bw_enf);

/** Delete Multicast Operations Profile ME resources

   \param[in] ctx                        OMCI API context pointer
   \param[in] me_id                      Managed Entity identifier
*/
enum omci_api_return
omci_api_multicast_subscr_config_info_destroy(struct omci_api_ctx *ctx,
					      uint16_t me_id);

/** @} */

/** @} */

__END_DECLS

#endif
