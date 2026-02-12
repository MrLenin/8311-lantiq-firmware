/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_dot1p_rate_limiter.h"

/** \addtogroup OMCI_API_ME_DOT1_RATE_LIMITER

   @{
*/

enum omci_api_return
omci_api_dot1_rate_limiter_update(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint16_t parent_me_ptr,
				  uint8_t tp_type,
				  uint16_t us_unicast_flood_rate_ptr,
				  uint16_t us_broadcast_flood_rate_ptr,
				  uint16_t us_multicast_flood_rate_ptr)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	/** \todo HW policers resource handling has to be fixed.
		  The existing straight forward policers mapping will conflict
	          with policers assignment in the MCC module.
		  Also under the existing A12 chip revision the HW policers
		  are not functional.*/
#ifdef HAS_TO_BE_CLARIFIED
	uint32_t parent_idx = 0, policer_idx = 0, tbl_sz, tbl_id;
	struct gpe_table_entry entry;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   parent_me_ptr=%u\n"
		  "   tp_type=%u\n"
		  "   us_unicast_flood_rate_ptr=%u\n"
		  "   us_broadcast_flood_rate_ptr=%u\n"
		  "   us_multicast_flood_rate_ptr=%u\n",
		  __FUNCTION__,
		  me_id,
		  parent_me_ptr,
		  tp_type,
		  us_unicast_flood_rate_ptr,
		  us_broadcast_flood_rate_ptr, us_multicast_flood_rate_ptr));

	memset(&entry, 0x00, sizeof(entry));

	switch (tp_type) {
	case 1:
		/* get bridge index*/
		ret = bridge_idx_get(ctx, parent_me_ptr, &parent_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		tbl_id = ONU_GPE_BRIDGE_TABLE_ID;
		tbl_sz = TABLE_ENTRY_SIZE(entry.data.bridge);
		break;
	case 2:
		/* get pmapper index */
		ret = index_get(ctx, MAPPER_DOT1PMAPPER_MEID_TO_IDX,
				parent_me_ptr, &parent_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		tbl_id = ONU_GPE_PMAPPER_TABLE_ID;
		tbl_sz = TABLE_ENTRY_SIZE(entry.data.pmapper);
		break;
	default:
		DBG(OMCI_API_ERR, ("omci_api_dot1_rate_limiter_update: "
				   "unknown TP type %u\n", tp_type));
		return OMCI_API_ERROR;
	}

	ret = table_read(ctx, tbl_id, (uint16_t)parent_idx, tbl_sz, &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	if (tp_type == 1) {
		if (us_unicast_flood_rate_ptr != 0x0000 &&
		    us_unicast_flood_rate_ptr != 0xffff) {
			ret = index_get(ctx, MAPPER_TRAFFDESCR_TO_POLICERIDX,
					us_unicast_flood_rate_ptr,
					&policer_idx);
			if (ret != OMCI_API_SUCCESS)
				DBG(OMCI_API_ERR,
					("Can't find UC policer index\n"));
	
			entry.data.bridge.uuc_meter_enable = 1;
			entry.data.bridge.uuc_meter_id = policer_idx;
		} else {
			entry.data.bridge.uuc_meter_enable = 0;
		}
	}

	/** \todo uncomment the pmapper table fields access after the
		  corresponding fields will be available in the FW */

	if (us_broadcast_flood_rate_ptr != 0x0000 &&
	    us_broadcast_flood_rate_ptr != 0xffff) {
		ret = index_get(ctx, MAPPER_TRAFFDESCR_TO_POLICERIDX,
				us_broadcast_flood_rate_ptr, &policer_idx);
		if (ret != OMCI_API_SUCCESS)
			DBG(OMCI_API_ERR, ("Can't find BC policer index\n"));

		if (tp_type == 1) {
			entry.data.bridge.bc_meter_enable = 1;
			entry.data.bridge.bc_meter_id = policer_idx;
		} else {
#if 0
			entry.data.pmapper.bc_meter_enable = 1;
			entry.data.pmapper.bc_meter_id = policer_idx;
#endif
		}
	} else {
		if (tp_type == 1)
			entry.data.bridge.bc_meter_enable = 0;
#if 0
		else
			entry.data.pmapper.bc_meter_enable = 0;
#endif
	}

	if (us_multicast_flood_rate_ptr != 0x0000 &&
	    us_multicast_flood_rate_ptr != 0xffff) {
		ret = index_get(ctx, MAPPER_TRAFFDESCR_TO_POLICERIDX,
				us_multicast_flood_rate_ptr, &policer_idx);
		if (ret != OMCI_API_SUCCESS)
			DBG(OMCI_API_ERR, ("Can't find MC policer index\n"));

		if (tp_type == 1) {
			entry.data.bridge.mc_meter_enable = 1;
			entry.data.bridge.mc_meter_id = policer_idx;
		} else {
#if 0
			entry.data.pmapper.mc_meter_enable = 1;
			entry.data.pmapper.mc_meter_id = policer_idx;
#endif
		}
	} else {
		if (tp_type == 1)
			entry.data.bridge.mc_meter_enable = 0;
#if 0
		else
			entry.data.pmapper.mc_meter_enable = 0;
#endif
	}

	ret = table_write(ctx, tbl_sz, &entry);
	if (ret != OMCI_API_SUCCESS)
		return ret;
#endif /* #ifdef HAS_TO_BE_CLARIFIED*/
	return ret;
}

enum omci_api_return
omci_api_dot1_rate_limiter_destroy(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint16_t parent_me_ptr,
				   uint8_t tp_type)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   parent_me_ptr=%u\n"
		  "   tp_type=%u\n",
		  __FUNCTION__,
		  me_id,
		  parent_me_ptr,
		  tp_type));

	ret = omci_api_dot1_rate_limiter_update(ctx, me_id, parent_me_ptr,
						tp_type,
						0x0000, 0x0000, 0x0000);

	return ret;
}

/** @} */
