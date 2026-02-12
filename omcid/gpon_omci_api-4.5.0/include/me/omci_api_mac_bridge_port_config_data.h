/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_mac_bridge_port_config_data
#define _omci_api_me_mac_bridge_port_config_data

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA MAC Bridge Port - Configuration Data

   This Managed Entity models a port on a MAC bridge.

   Instances of this Managed Entity are created and deleted by the OLT.

   @{
*/

#define OMCI_API_MAC_BRIDGE_PORT_CONFIG_DATA_MAX	128

/** Update MAC Bridge Port Configuration Data ME resources

    \note Enable Managed Entity identifier mapping to driver index and
    initialize corresponding driver structures, when it is called first time
    for the given Managed Entity ID

    \param[in] ctx                OMCI API context pointer
    \param[in] me_id              Managed Entity identifier
    \param[in] bridge_id_ptr      Bridge id pointer
    \param[in] port_num           Port number
    \param[in] tp_type            TP type
    \param[in] tp_ptr             TP pointer
    \param[in] outbound_td_ptr    Outbound TD pointer
    \param[in] inboud_td_ptr      Inbound TD pointer
    \param[in] mac_learning_depth MAC learning depth
*/
enum omci_api_return
omci_api_mac_bridge_port_config_data_update(struct omci_api_ctx *ctx,
					    uint16_t me_id,
					    uint16_t bridge_id_ptr,
					    uint8_t port_num,
					    uint8_t tp_type,
					    uint16_t tp_ptr,
					    uint16_t outbound_td_ptr,
					    uint16_t inboud_td_ptr,
					    uint8_t mac_learning_depth);

/** Disable Managed Entity identifier mapping to driver index and clear
    corresponding driver structures

    \param[in] ctx   OMCI API context pointer
    \param[in] me_id Managed Entity identifier
    \param[in] tp_type            TP type
    \param[in] tp_ptr             TP pointer
    \param[in] outbound_td_ptr    Outbound TD pointer
    \param[in] inbound_td_ptr     Inbound TD pointer
*/
enum omci_api_return
omci_api_mac_bridge_port_config_data_destroy(struct omci_api_ctx *ctx,
					     uint16_t me_id,
					     uint8_t tp_type,
					     uint16_t tp_ptr,
					     uint16_t outbound_td_ptr,
					     uint16_t inbound_td_ptr);

enum omci_api_return
omci_api_mac_bridge_port_config_data_pmapper(struct omci_api_ctx *ctx,
					     uint16_t bridge_me,
					     uint16_t bridge_port_me_id,
					     uint16_t pmapper_me_id);

enum omci_api_return
omci_api_mac_bridge_port_config_data_uni_fw_policer_rate_set(struct omci_api_ctx *ctx,
							     const uint16_t port_index,
							     const uint32_t rate);

enum omci_api_return
omci_api_mac_bridge_port_config_data_uni(struct omci_api_ctx *ctx,
				         uint16_t bridge_me,
				         uint16_t bridge_port_me_id,
				         uint16_t tp_ptr);

/** @} */

/** @} */

__END_DECLS

#endif
