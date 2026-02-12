/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_mac_bridge_service_profile
#define _omci_api_me_mac_bridge_service_profile

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_MAC_BRIDGE_SERVICE_PROFILE MAC Bridge Service Profile

   This Managed Entity models a MAC bridge in its entirety; any number of ports
   may then be associated with the bridge through pointers to the MAC bridge
   service profile Managed Entity.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/** Init MAC Bridge Service Profile ME resources.

    Enable Managed Entity identifier mapping to driver index and
    initialize corresponding driver structures when it is called first time
    for the given ME ID

   \param[in] ctx                 OMCI API context pointer
   \param[in] me_id               Managed Entity identifier
*/
enum omci_api_return
omci_api_mac_bridge_service_profile_init(struct omci_api_ctx *ctx,
					 const uint16_t me_id);

/** Update MAC Bridge Service Profile ME resources.

   \param[in] ctx                 OMCI API context pointer
   \param[in] me_id               Managed Entity identifier
   \param[in] learning_ind        Learning ind
   \param[in] port_bridging_ind   Port bridging ind
   \param[in] unknown_mac_discard Unknown MAC address discard
   \param[in] mac_learning_depth  MAC learning depth
   \param[in] mac_aging_time  MAC aging time
*/
enum omci_api_return
omci_api_mac_bridge_service_profile_update(struct omci_api_ctx *ctx,
					   const uint16_t me_id,
					   const uint8_t learning_ind,
					   const uint8_t port_bridging_ind,
					   const uint8_t unknown_mac_discard,
					   const uint8_t mac_learning_depth,
					   const uint32_t mac_aging_time);

/** Disable Managed Entity identifier mapping to driver index
    and clear corresponding driver structures

   \param[in] ctx   OMCI API context pointer
   \param[in] me_id Managed Entity identifier
*/
enum omci_api_return
omci_api_mac_bridge_service_profile_destroy(struct omci_api_ctx *ctx,
					    const uint16_t me_id);

/** Retrieve the number of connectde ports

    \param[in] ctx   OMCI API context pointer
    \param[in] me_id Managed Entity identifier
    \param[out] port_count Bridge port count
*/
enum omci_api_return omci_api_bridge_port_count_get(struct omci_api_ctx *ctx,
						    const uint16_t me_id,
						    uint8_t *port_count);

/** @} */

/** @} */

__END_DECLS

#endif
