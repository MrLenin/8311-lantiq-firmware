/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_mac_bridge_port_designation_data.h"

/** \addtogroup OMCI_API_ME_ANI_G

   @{
*/

enum omci_api_return
omci_api_mac_bridge_port_designation_data_designated_bridge_root_cost_port_get(
	uint16_t me_id,
	uint8_t designated_bridge_ind[8],
	uint8_t root_bridge_ind[8],
	uint32_t *designated_port_num,
	uint32_t *path_cost_contribution)
{
	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	/** \todo The related HW value needs to be identified. */

	memset(designated_bridge_ind, 0, sizeof(uint8_t) * 8);
	memset(root_bridge_ind, 0, sizeof(uint8_t) * 8);
	*designated_port_num = 0;
	*path_cost_contribution = 0;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_mac_bridge_port_designation_data_port_state_get(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint8_t *port_state)
{
	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	/**
	\todo HW programming FIO_GPE_TABLE_GET, GPE_bridgePortTable_t,
	      port_state
	*/

	/** \todo The related HW value needs to be identified. */
	*port_state = 0;

	return OMCI_API_SUCCESS;
}

/** @} */
