/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_multicast_subscr_config_info.h"
#include "me/omci_api_multicast_operations_profile.h"
#include "mcc/omci_api_mcc.h"

/** \addtogroup OMCI_API_ME_MULTICAST_SUBSCR_CONFIG_INFO

   @{
*/

enum omci_api_return
omci_api_multicast_subscr_config_info_update(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint8_t linked_me_type,
	uint16_t pptp_eth_uni_ptr,
	uint16_t mc_oper_profile_ptr,
	uint16_t max_sim_groups,
	uint32_t max_mc_bw,
	uint8_t bw_enf)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	struct omci_api_mcc_subscr_cfg subscr;
	struct omci_api_mcc_profile profile;
	uint8_t ext_vlan_index_egress, ext_vlan_index_ingress,
		ext_vlan_enable_egress, ext_vlan_enable_ingress;
	uint32_t s_idx = 0, p_idx = 0, lan_idx = 0, tmp_idx;
#endif
	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   mc_oper_profile_ptr=%u\n"
		  "   max_sim_groups=%u\n"
		  "   max_mc_bw=%u\n"
		  "   bw_enf=%u\n",
		  __FUNCTION__,
		  me_id, mc_oper_profile_ptr, max_sim_groups, max_mc_bw,
		  bw_enf));

#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	if (linked_me_type != 0)
		/* Link to 802.1p mapper service profile is not supported yet*/
		return OMCI_API_SUCCESS;

	ret = index_get(ctx, MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_IDX, me_id,
			&s_idx);
	if (ret != OMCI_API_SUCCESS) {
		ret = id_map(ctx, MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_IDX,
			     me_id, &s_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	ret = index_get(ctx, MAPPER_MCOPPROFILE_MEID_TO_IDX,
			mc_oper_profile_ptr, &p_idx);
	if (ret == OMCI_API_NOT_FOUND)
		p_idx = MCC_PROFILE_NULL;
		
	ret = index_get(ctx, MAPPER_PPTPETHUNI_MEID_TO_IDX,
			pptp_eth_uni_ptr, &lan_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = index_get(ctx, MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_LAN_IDX, me_id,
			&tmp_idx);
	if (ret != OMCI_API_SUCCESS) {
		ret = explicit_map(ctx, MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_LAN_IDX,
				   me_id, lan_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	memset(&subscr, 0, sizeof(subscr));

	subscr.valid = true;
	subscr.profile_idx = (uint8_t)p_idx;
	subscr.lan_idx = (uint8_t)lan_idx;
	subscr.max_simultaneous_groups = max_sim_groups;
	subscr.max_mc_bw = max_mc_bw;
	subscr.bw_enforcement = bw_enf ? true : false;

	ret = omci_api_mcc_subscr_update(ctx, (uint8_t)s_idx, &subscr);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("MC subscr update failed, me_id=0x%04X, ret=%d\n",
				me_id, ret));
		return ret;
	}

	if (p_idx == MCC_PROFILE_NULL)
		/* Profile is not attached, skip further actions*/
		return OMCI_API_SUCCESS;

	ret = omci_api_mcc_profile_get(ctx, p_idx, &profile);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("MC Profile Get failed, me_id=0x%04X, ret=%d\n",
				me_id, ret));
		return ret;
	}

	if (profile.valid == false)
		/* Not a valid profile, skip further actions*/
		return OMCI_API_SUCCESS;

	ret = omci_api_lan_port_ext_vlan_get(ctx, lan_idx,
					     &ext_vlan_enable_egress,
					     &ext_vlan_index_egress,
					     &ext_vlan_enable_ingress,
					     &ext_vlan_index_ingress,
						 NULL);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("LAN port %u ExtVLAN get failed, me_id=0x%04X, ret=%d\n",
				lan_idx, me_id, ret));
		return ret;
	}

	if ((ext_vlan_enable_egress == 0) && (ext_vlan_enable_ingress == 0))
		/* ExtVLAN entry is not set yet*/
		return OMCI_API_SUCCESS;

	ret = omci_api_multicast_operations_profile_mc_ext_vlan_update(ctx,
						 lan_idx,
						 ext_vlan_index_ingress + 1,
						 ext_vlan_index_egress + 1,
						 profile.us_igmp_tag_ctrl,
						 profile.us_igmp_tci,
						 profile.ds_igmp_mc_tag_ctrl,
						 profile.ds_igmp_mc_tci);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("MC ExtVLAN update failed, me_id=0x%04X, ret=%d\n",
				me_id, ret));
		return ret;
	}

#endif
	return ret;
}

enum omci_api_return
omci_api_multicast_subscr_config_info_destroy(
	struct omci_api_ctx *ctx,
	uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	uint32_t idx = 0;

	ret = index_get(ctx, MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_IDX, me_id, &idx);
	if (ret == OMCI_API_SUCCESS)
		id_remove(ctx, MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_IDX, me_id);

	ret = index_get(ctx, MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_LAN_IDX, me_id, &idx);
	if (ret == OMCI_API_SUCCESS)
		id_remove(ctx, MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_LAN_IDX, me_id);
#endif
	return ret;
}


/** @} */
