/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_mac_bridge_port_config_data_inter
#define _omci_api_me_mac_bridge_port_config_data_inter

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA_INTERNAL MAC Bridge - Port Configuration Data Internal Interface

   This Managed Entity models a port on a MAC bridge.

   Instances of this Managed Entity are created and deleted by the OLT.
   @{
*/

/** Create MAC Bridge Port resources

   \note Validate corresponding driver structures and
         inform Bridge that Port was added

   \param[in] ctx                    OMCI API context pointer
   \param[in] bridge_port_index      MAC Bridge Port index
   \param[in] bridge_index           MAC Bridge index
   \param[in] ani_indication         True if bridge located on the ANI side
   \param[in] pmapper_idx            If the termination point is a p-mapper,
                                     give its index here. If no pmapper, 
									 set to 0xFFFF
   \param[in] outbound_traf_desc_idx Outbound traffic descriptor index.
                                     If no, set to 0xFFFF
   \param[in] inbound_traf_desc_idx  Inbound traffic descriptor index.
                                     If no, set to 0xFFFF
*/
enum omci_api_return
omci_api_mac_bridge_port_create(struct omci_api_ctx *ctx,
				uint32_t bridge_port_index,
				uint32_t bridge_index,
				bool ani_indication,
				uint16_t pmapper_idx,
				uint16_t outbound_traf_desc_idx,
				uint16_t inbound_traf_desc_idx);

/** Update MAC Bridge Port resources

   \param[in] ctx                    OMCI API context pointer
   \param[in] bridge_port_index      MAC Bridge Port index
   \param[in] bridge_index           MAC Bridge index
   \param[in] ani_indication         True if bridge located on the ANI side
   \param[in] pmapper_idx            If the termination point is a p-mapper,
									 give its index here. 
									 If it is not a p-mapper, set to 0xFFFF.
   \param[in] outbound_traf_desc_idx Outbound traffic descriptor index.
                                     If no, set to 0xFFFF
   \param[in] inbound_traf_desc_idx  Inbound traffic descriptor index.
                                     If no, set to 0xFFFF
*/
enum omci_api_return
omci_api_mac_bridge_port_update(struct omci_api_ctx *ctx,
				uint32_t bridge_port_index,
				uint32_t bridge_index,
				bool ani_indication,
				uint16_t pmapper_idx,
				uint16_t outbound_traf_desc_idx,
				uint16_t inbound_traf_desc_idx);

/** Remove MAC Bridge Port from ONU resources

   \note Invalidate corresponding driver structures
         for the given Bridge Port index.

   \param[in] ctx                OMCI API context pointer
   \param[in] bridge_port_index  MAC Bridge Port index
*/
enum omci_api_return
omci_api_mac_bridge_port_destroy(struct omci_api_ctx *ctx,
				 uint32_t bridge_port_index);

/** @} */

/** @} */

__END_DECLS

#endif
