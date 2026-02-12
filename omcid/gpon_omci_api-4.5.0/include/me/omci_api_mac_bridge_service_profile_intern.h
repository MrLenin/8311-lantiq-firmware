/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_mac_bridge_service_profile_inter
#define _omci_api_me_mac_bridge_service_profile_inter

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_MAC_BRIDGE_SERVICE_PROFILE_INTERNAL MAC Bridge Service - Profile Internal Interface

   This Managed Entity models a MAC bridge in its entirety; any number of ports
   may then be associated with the bridge through pointers to the MAC bridge
   service profile Managed Entity.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

/** Update MAC Bridge resources.

   \note Validate corresponding driver structures when
         it is called first time for the given Bridge Index.

   \param[in] ctx                 OMCI API context pointer
   \param[in] bridge_index        Bridge index
   \param[in] learning_ind        Learning ind
   \param[in] port_bridging_ind   Port bridging ind
   \param[in] unknown_mac_discard Unknown MAC address discard
   \param[in] mac_learning_depth  MAC learning depth
*/
enum omci_api_return omci_api_mac_bridge_update(struct omci_api_ctx *ctx,
						uint32_t bridge_index,
						uint8_t learning_ind,
						uint8_t port_bridging_ind,
						uint8_t unknown_mac_discard,
						uint8_t mac_learning_depth);

/** Remove MAC Bridge from ONU resources.

   \note Invalidate corresponding driver structures
         for the given Bridge Index.

   \param[in] ctx          OMCI API context pointer
   \param[in] bridge_index Bridge index
*/
enum omci_api_return omci_api_mac_bridge_destroy(struct omci_api_ctx *ctx,
						 uint32_t bridge_index);

/** Set AL internal copy of MAC Bridge resources

   \param[in] ctx                 OMCI API context pointer
   \param[in] bridge_index        Bridge index
   \param[in] learning_ind        Learning ind
   \param[in] port_bridging_ind   Port bridging ind
   \param[in] unknown_mac_discard Unknown MAC address discard
   \param[in] mac_learning_depth  MAC learning depth
*/
enum omci_api_return omci_api_mac_bridge_data_set(struct omci_api_ctx *ctx,
						  uint32_t bridge_index,
						  uint8_t learning_ind,
						  uint8_t port_bridging_ind,
						  uint8_t unknown_mac_discard,
						  uint8_t mac_learning_depth);

/** Retrieve AL internal copy of MAC Bridge resources

   \param[in]  ctx                 OMCI API context pointer
   \param[in]  bridge_index        Bridge index
   \param[out] learning_ind        Learning ind
   \param[out] port_bridging_ind   Port bridging ind
   \param[out] unknown_mac_discard Unknown MAC address discard
   \param[out] mac_learning_depth  MAC learning depth
*/
enum omci_api_return omci_api_mac_bridge_data_get(struct omci_api_ctx *ctx,
						  uint32_t bridge_index,
						  uint8_t *learning_ind,
						  uint8_t *port_bridging_ind,
						  uint8_t *unknown_mac_discard,
						  uint8_t *mac_learning_depth);

/** Clear AL internal copy of MAC Bridge resources

   \param[in] ctx          OMCI API context pointer
   \param[in] bridge_index Bridge Index
*/
enum omci_api_return omci_api_mac_bridge_data_clear(struct omci_api_ctx *ctx,
						    uint32_t bridge_index);

/** Set direction flag of internal MAC bridge data base

   \param[in] ctx                 OMCI API context pointer
   \param[in] bridge_index        Bridge index
   \param[in] direction           Direction
*/
enum omci_api_return omci_api_mac_bridge_direction_set(struct omci_api_ctx *ctx,
						       uint32_t bridge_index,
						       uint8_t direction);

/** Set direction flag of internal MAC bridge data base

   \param[in] ctx                 OMCI API context pointer
   \param[in] bridge_index        Bridge index
   \param[in] direction           Direction
*/
enum omci_api_return omci_api_mac_bridge_direction_get(struct omci_api_ctx *ctx,
						       uint32_t bridge_index,
						       uint8_t *direction);

/** @} */

/** @} */

__END_DECLS

#endif
