/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include <assert.h>

#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_dot1p_mapper.h"

/** \addtogroup OMCI_API_ME_8021P_MAPPER_SERVICE_PROFILE

   @{
*/

enum omci_api_return
omci_api_8021p_mapper_service_profile_update(struct omci_api_ctx *ctx,
					     const uint16_t me_id,
					     const uint16_t tp_pointer,
					     const uint16_t *gem_port_id,
					     const uint8_t unmarked_frame_opt,
					     const uint8_t *dscp_prio_map,
					     const uint8_t default_priority_marking,
					     const uint8_t tp_pointer_type)
{
	uint32_t pmapper_index;
	uint32_t gpix[8], tmp;
	uint8_t profile_index = 0;
	uint8_t idx = 0;
	unsigned int i;
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s"
		  " me_id=%u"
		  " tp_pointer=%u"
		  " unmarked_frame_opt=%u"
		  " dscp_prio_map=0x%x"
		  " default_priority_marking=%u"
		  " tp_pointer_type=%u\n",
		  __FUNCTION__,
		  me_id,
		  tp_pointer,
		  unmarked_frame_opt, dscp_prio_map,
		  default_priority_marking, tp_pointer_type));

	if (tp_pointer_type != 0) {
		DBG(OMCI_API_ERR,
			("omci_api_8021p_mapper_service_profile_update: "
			 "wrong tp_pointer_type=%u (me_id=%u)\n",
				tp_pointer_type, me_id));
		return OMCI_API_ERROR;
	}

	/* get pmapper index */
	ret = index_get(ctx, MAPPER_DOT1PMAPPER_MEID_TO_IDX,
			me_id, &pmapper_index);
	if (ret == OMCI_API_NOT_FOUND) {
		/* suppose that mapper doesn't exist; create it */
		ret = id_map(ctx, MAPPER_DOT1PMAPPER_MEID_TO_IDX,
			     me_id, &pmapper_index);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	for (i = 0; i < 8; i++) {
		gpix[i] = 0xffff;
		if (gem_port_id[i] == 0xffff)
			continue;
		ret = index_get(ctx, MAPPER_GEMITP_MEID_TO_GPIX,
				gem_port_id[i], &tmp);
		if (ret != OMCI_API_SUCCESS)
			continue;
		gpix[i] = tmp;
	}

	if (unmarked_frame_opt == 0) {
		profile_index = dscp_profile_create(ctx, dscp_prio_map);
		if (profile_index != 255 &&
		    profile_index < ARRAY_SIZE(ctx->pcp)) {
			/* mapping to pcp values */
			omci_api_dscp_profile_add(ctx, profile_index,
						  &ctx->pcp[profile_index][0]);
		} else {
			DBG(OMCI_API_ERR,
				("omci_api_8021p_mapper_service_profile_update:"
				 " no more free dscp entries\n"));
		}
	}

	omci_api_pmapper_add(ctx, pmapper_index, gpix, unmarked_frame_opt,
			     default_priority_marking, profile_index);

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_8021p_mapper_service_profile_destroy(struct omci_api_ctx *ctx,
					      const uint16_t me_id,
					      const uint16_t tp_pointer,
					      const uint8_t tp_pointer_type)
{
	uint32_t pmapper_index;
	enum omci_api_return ret;
	uint8_t unmarked_frame_option;
	uint8_t dscp_profile_index;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	/* get pmapper index */
	ret = index_get(ctx, MAPPER_DOT1PMAPPER_MEID_TO_IDX,
			me_id, &pmapper_index);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	if (omci_api_pmapper_get(ctx, pmapper_index, NULL,
		&unmarked_frame_option, NULL, &dscp_profile_index) == 0) {
		dscp_profile_delete(ctx, dscp_profile_index);
	}

	omci_api_pmapper_remove(ctx, pmapper_index);

	ret = index_remove(ctx, MAPPER_DOT1PMAPPER_MEID_TO_IDX, pmapper_index);

	if (ret != OMCI_API_SUCCESS) {
		(void)error_notify(ctx, 130, me_id,
				   OMCI_API_ACTION_UPDATE, ret);
		return ret;
	}

	return OMCI_API_SUCCESS;
}

/** @} */
