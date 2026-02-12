/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_mac_bridge_port_designation_data
#define _omci_api_me_mac_bridge_port_designation_data

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_MAC_BRIDGE_PORT_DESIGNATION_DATA MAC Bridge Port - Designation Data

   This Managed Entity records data associated with a bridge port.

   The ONU automatically creates or deletes an instance of this Managed Entity
   upon the creation or deletion of a MAC bridge port configuration data ME.

   @{
*/

/* Through an identical ID, this Managed Entity is implicitly linked to an
   instance of the MAC bridge port configuration data. */

/** Retrieve current designated root, designated cost, designated
    bridge and designated port of MAC Bridge Port Designation Data ME

    \param[in]  me_id                  Managed Entity identifier
    \param[out] designated_bridge_ind  Identifier of the designated bridge for
                                       the port segment (8 bytes)
    \param[out] root_bridge_ind        Bridge identifier of the root transmitted
                                       by the designated bridge for the segment
                                       (8 bytes)
    \param[out] designated_port_num    Port number of the designated port on the
                                       designated bridge considered to be part
                                       of this port segment
    \param[out] path_cost_contribution Path cost contribution of the designated
                                       port to this port segment
*/
enum omci_api_return
omci_api_mac_bridge_port_designation_data_designated_bridge_root_cost_port_get(
	uint16_t me_id,
	uint8_t designated_bridge_ind[8],
	uint8_t root_bridge_ind[8],
	uint32_t *designated_port_num,
	uint32_t *path_cost_contribution);

/** Retrieve current Port State

   \param[in]  ctx        OMCI API context pointer
   \param[in]  me_id      Managed Entity identifier
   \param[out] port_state Port state
*/
enum omci_api_return
omci_api_mac_bridge_port_designation_data_port_state_get(struct omci_api_ctx	
							 *ctx,
							 uint16_t me_id,
							 uint8_t *port_state);

/** @} */

/** @} */

__END_DECLS

#endif
