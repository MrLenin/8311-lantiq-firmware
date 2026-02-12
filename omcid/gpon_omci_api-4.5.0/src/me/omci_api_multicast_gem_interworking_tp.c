/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_multicast_gem_interworking_tp.h"

/** \addtogroup OMCI_API_ME_MULTICAST_GEM_INTERWORKING_TP

   @{
*/

enum omci_api_return
omci_api_multicast_gem_interworking_tp_update(struct omci_api_ctx *ctx,
					      uint16_t me_id,
					      uint16_t ctp_ptr)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t tmp;

	DBG(OMCI_API_MSG, ("multicast itp:"
		  " me_id=%u\n",
		  me_id));

	if (index_get(ctx, MAPPER_MULCTCAST_GEMPORTITP_MEID_TO_CTP_MEID,
		      me_id, &tmp) != OMCI_API_SUCCESS) {
		ret = explicit_map(ctx,
				   MAPPER_MULCTCAST_GEMPORTITP_MEID_TO_CTP_MEID,
				   me_id, ctp_ptr);
	}

	return ret;
}

enum omci_api_return
omci_api_multicast_gem_interworking_tp_destroy(struct omci_api_ctx *ctx,
					       uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t tmp;

	if (index_get(ctx, MAPPER_MULCTCAST_GEMPORTITP_MEID_TO_CTP_MEID,
		      me_id, &tmp)
		!= OMCI_API_SUCCESS) {
		return OMCI_API_SUCCESS;
	}

	ret = id_remove(ctx, MAPPER_MULCTCAST_GEMPORTITP_MEID_TO_CTP_MEID,
			me_id);
	if (ret != OMCI_API_SUCCESS) {
		(void)error_notify(ctx, 262, me_id,
				   OMCI_API_ACTION_DESTROY, ret);
		return ret;
	}

	return ret;
}

enum omci_api_return
omci_api_multicast_gem_interworking_tp_multicast_address_table_entry_add(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint16_t gem_port_id,
	uint16_t secondary_idx,
	uint32_t ip_multicast_address_range_start,
	uint32_t ip_multicast_address_range_stop)
{
	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   gem_port_id=%u\n" "   secondary_idx=%u\n"
		  "   ip_multicast_address_range_start=%u\n"
		  "   ip_multicast_address_range_stop=%u\n",
		  __FUNCTION__,
		  me_id, gem_port_id,
		  secondary_idx, ip_multicast_address_range_start,
		  ip_multicast_address_range_stop));

	/** \todo The related HW value needs to be identified. */

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_multicast_gem_interworking_tp_multicast_address_table_entry_remove(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint16_t gem_port_id,
	uint16_t secondary_idx)
{
	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   gem_port_id=%u\n"
		  "   secondary_idx=%u\n", __FUNCTION__, me_id, gem_port_id,
		  secondary_idx));

	/** \todo The related HW value needs to be identified. */

	return OMCI_API_SUCCESS;
}

/** @} */
