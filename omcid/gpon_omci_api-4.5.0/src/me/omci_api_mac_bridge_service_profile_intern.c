/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_memory_alloc.h"

#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_mac_bridge_service_profile_intern.h"

/** \addtogroup OMCI_API_ME_MAC_BRIDGE_SERVICE_PROFILE_INTERNAL

   @{
*/

/** MAC Bridge configuration data type definition
*/
struct omci_api_mac_bridge_data {
	/** Learning indication */
	uint8_t learning_ind;
	/** Port bridging indication */
	uint8_t port_bridging_ind;
	/** Unknown MAC address discard indication */
	uint8_t unknown_mac_discard;
	/** MAC learning depth */
	uint8_t mac_learning_depth;
	/** MAC Bridge data validity flag */
	bool valid;
	/** GEM port direction */
	uint8_t direction;
};

/** MAC Bridge configuration data

   \note Store local copy of MAC Bridge
         configuration data for each MAC Bridge
*/
static struct omci_api_mac_bridge_data
			       onu_mac_bridge_data[ONU_GPE_MAX_BRIDGES] = { 0 };

enum omci_api_return omci_api_mac_bridge_data_set(struct omci_api_ctx *ctx,
						  uint32_t bridge_index,
						  uint8_t learning_ind,
						  uint8_t port_bridging_ind,
						  uint8_t unknown_mac_discard,
						  uint8_t mac_learning_depth)
{
	uint8_t bridge_port[OMCI_API_MAX_BRIDGE_PORT], i;

	if (bridge_index >= ONU_GPE_MAX_BRIDGES) {
		DBG(OMCI_API_ERR, ("bridge index %d out of range\n",
								bridge_index));
		return OMCI_API_ERROR;
	}

	onu_mac_bridge_data[bridge_index].learning_ind = learning_ind;
	onu_mac_bridge_data[bridge_index].port_bridging_ind = port_bridging_ind;
	onu_mac_bridge_data[bridge_index].unknown_mac_discard =
							    unknown_mac_discard;
	onu_mac_bridge_data[bridge_index].mac_learning_depth =
							     mac_learning_depth;
	onu_mac_bridge_data[bridge_index].valid = true;

	if (omci_api_bridge_get(ctx, bridge_index, &bridge_port[0])
							  != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("Can't read bridge port info for bridge %d\n",
								bridge_index));
		return OMCI_API_ERROR;
	}

	for (i = 0; i < OMCI_API_MAX_BRIDGE_PORT; i++) {
		if ((bridge_port[i] & 0x80) == 0)
			continue;
		omci_api_bridge_port_learning_limitation_modify(ctx,
							bridge_port[i] & 0x7f,
							learning_ind,
							mac_learning_depth);

		omci_api_bridge_port_local_switching_modify(ctx,
							bridge_port[i] & 0x7f,
							port_bridging_ind);

		omci_api_bridge_port_uuc_mac_flood_modify(ctx,
							  bridge_port[i] & 0x7f,
							  unknown_mac_discard);
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_mac_bridge_data_get(struct omci_api_ctx *ctx,
						  uint32_t bridge_index,
						  uint8_t *learning_ind,
						  uint8_t *port_bridging_ind,
						  uint8_t *unknown_mac_discard,
						  uint8_t *mac_learning_depth)
{
	if (bridge_index >= ONU_GPE_MAX_BRIDGES) {
		DBG(OMCI_API_ERR, ("bridge index %d out of range\n",
								bridge_index));
		return OMCI_API_ERROR;
	}

	if (!onu_mac_bridge_data[bridge_index].valid) {
		DBG(OMCI_API_ERR, ("bridge data %d not valid\n", bridge_index));
		return OMCI_API_ERROR;
	}

	*learning_ind = onu_mac_bridge_data[bridge_index].learning_ind;
	*port_bridging_ind =
			  onu_mac_bridge_data[bridge_index].port_bridging_ind;
	*unknown_mac_discard =
			  onu_mac_bridge_data[bridge_index].unknown_mac_discard;
	*mac_learning_depth =
			  onu_mac_bridge_data[bridge_index].mac_learning_depth;

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_mac_bridge_data_clear(struct omci_api_ctx *ctx,
						    uint32_t bridge_index)
{
	if (bridge_index >= ONU_GPE_MAX_BRIDGES) {
		DBG(OMCI_API_ERR, ("bridge index %d out of range\n",
								bridge_index));
		return OMCI_API_ERROR;
	}

	onu_mac_bridge_data[bridge_index].direction = 0;
	onu_mac_bridge_data[bridge_index].valid = false;

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_mac_bridge_direction_set(struct omci_api_ctx *ctx,
						       uint32_t bridge_index,
						       uint8_t direction)
{
	onu_mac_bridge_data[bridge_index].direction |= direction;

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_mac_bridge_direction_get(struct omci_api_ctx *ctx,
						       uint32_t bridge_index,
						       uint8_t *direction)
{
	*direction = onu_mac_bridge_data[bridge_index].direction;

	return OMCI_API_SUCCESS;
}


/** @} */
