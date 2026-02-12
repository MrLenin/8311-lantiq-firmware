/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_mac_bridge_service_profile.h"
#include "me/omci_api_mac_bridge_service_profile_intern.h"

/** \addtogroup OMCI_API_ME_MAC_BRIDGE_SERVICE_PROFILE

   @{
*/

enum omci_api_return
omci_api_mac_bridge_service_profile_init(struct omci_api_ctx *ctx,
					 const uint16_t me_id)
{
	uint32_t bridge_index = 0;
	enum omci_api_return ret = OMCI_API_SUCCESS;

	ret = id_map(ctx, MAPPER_MACBRIDGE_MEID_TO_IDX, me_id, &bridge_index);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("MAPPER_MACBRIDGE_MEID_TO_IDX: map failed\n"));
		return OMCI_API_ERROR;
	}

	ret = omci_api_bridge_init(ctx, bridge_index);

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_mac_bridge_service_profile_update(struct omci_api_ctx *ctx,
					   const uint16_t me_id,
					   const uint8_t learning_ind,
					   const uint8_t port_bridging_ind,
					   const uint8_t unknown_mac_discard,
					   const uint8_t mac_learning_depth,
					   const uint32_t mac_aging_time)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t bridge_index = 0;
	struct sce_aging_time mat;

	DBG(OMCI_API_MSG, ("bridge service profile:"
		  " me_id=%u" " learning_ind=%u"
		  " port_bridging_ind=%u" " unknown_mac_discard=%u"
		  " mac_learning_depth=%u mac_aging_time=%u\n",
		  me_id, learning_ind, port_bridging_ind,
		  unknown_mac_discard, mac_learning_depth, mac_aging_time));

	ret = index_get(ctx, MAPPER_MACBRIDGE_MEID_TO_IDX,
			me_id, &bridge_index);
	if (ret)
		return OMCI_API_ERROR;

	ret = omci_api_mac_bridge_data_set(ctx, bridge_index,
					   learning_ind, port_bridging_ind,
					   unknown_mac_discard,
					   mac_learning_depth);
	if (ret)
		return ret;

	mat.aging_time = mac_aging_time == 0 ? 300 : mac_aging_time;
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_AGING_TIME_SET,
		      &mat, sizeof(mat));

	return ret;
}

enum omci_api_return
omci_api_mac_bridge_service_profile_destroy(struct omci_api_ctx *ctx,
					    const uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t bridge_index = 0;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	ret = bridge_idx_get(ctx, me_id, &bridge_index);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = omci_api_mac_bridge_data_clear(ctx, bridge_index);
	if (ret != OMCI_API_SUCCESS) {
		(void)error_notify(ctx, 45, me_id,
				   OMCI_API_ACTION_DESTROY, ret);
		return ret;
	}

	ret = id_remove(ctx, MAPPER_MACBRIDGE_MEID_TO_IDX, me_id);
	if (ret != OMCI_API_SUCCESS) {
		(void)error_notify(ctx, 45, me_id,
				   OMCI_API_ACTION_DESTROY, ret);
		return ret;
	}

	return ret;
}

/** @} */
