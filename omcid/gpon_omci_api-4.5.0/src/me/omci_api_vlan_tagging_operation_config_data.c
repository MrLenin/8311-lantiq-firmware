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
#include "me/omci_api_vlan_tagging_operation_config_data.h"
#include "me/omci_api_multicast_operations_profile.h"

#define GROUP_OFFSET	64
#define RULE_OFFSET	512


/** \addtogroup OMCI_API_ME_VLAN_TAGGING_CONFIG_DATA

   @{
*/

static enum omci_api_return
omci_api_vlan_tagging_operation_us_mode_1(struct omci_api_ctx *ctx,
					  const uint16_t index,
					  const uint16_t tci_value,
					  const uint16_t table_pointer)

{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_ext_vlan extvlan;

	memset(&extvlan, 0x00, sizeof(extvlan));

	extvlan.index = index;
	/*  number of rules  */
	extvlan.num_valid_rules = 1;
	extvlan.max_vlans = OMCI_API_VLAN_RULE_GRP_SIZE;

	/* Ethertype-field (VLAN) */
	extvlan.extended_vlan_tbl.input_tpid = 0x8100;
	/* assigned Ethertype-field */
	extvlan.extended_vlan_tbl.output_tpid = 0x8100;
	extvlan.extended_vlan_tbl.dscp_table_pointer = 0;
	extvlan.extended_vlan_tbl.vlan_rule_table_pointer = table_pointer;
	extvlan.extended_vlan_tbl.valid = 1;

	/* 1st rule: UNTAGGED or SINGLE TAGGED */
	extvlan.vlan_rule_tbl[0].zero_enable = 1;
	extvlan.vlan_rule_tbl[0].one_enable = 1;

	/* this should be the default rule */
	extvlan.vlan_rule_tbl[0].def = 1;

	extvlan.vlan_treatment_tbl[0].tagb_tpid_treatment = 0;
	extvlan.vlan_treatment_tbl[0].tagb_vid_treatment = 0;
	/* no tag */
	extvlan.vlan_treatment_tbl[0].tagb_treatment = 0xF;
	extvlan.vlan_treatment_tbl[0].inner_not_generate = 1;
	extvlan.vlan_treatment_tbl[0].outer_not_generate = 1;
	extvlan.vlan_treatment_tbl[0].discard_enable = 0;

	/* results in 0x8100 for TPID */
	extvlan.vlan_treatment_tbl[0].taga_tpid_treatment = 4;
	extvlan.vlan_treatment_tbl[0].taga_vid_treatment = tci_value & 0xfff;
	extvlan.vlan_treatment_tbl[0].taga_treatment = tci_value >> 13;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
		      &extvlan, sizeof(extvlan));

	return ret;
}

static enum omci_api_return
omci_api_vlan_tagging_operation_us_mode_2(struct omci_api_ctx *ctx,
					  const uint16_t index,
					  const uint16_t tci_value,
					  const uint16_t table_pointer)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_ext_vlan extvlan;

	memset(&extvlan, 0x00, sizeof(extvlan));

	extvlan.index = index;
	/* number of rules  */
	extvlan.num_valid_rules = 2;
	extvlan.max_vlans = OMCI_API_VLAN_RULE_GRP_SIZE;

	/* Ethertype-field (VLAN) */
	extvlan.extended_vlan_tbl.input_tpid = 0x8100;
	/* assigned Ethertype-field */
	extvlan.extended_vlan_tbl.output_tpid = 0x8100;
	extvlan.extended_vlan_tbl.dscp_table_pointer = 0;
	extvlan.extended_vlan_tbl.vlan_rule_table_pointer = table_pointer;
	extvlan.extended_vlan_tbl.valid = 1;

	/* 1st rule: UNTAGGED */
	extvlan.vlan_rule_tbl[0].zero_enable = 1;
	/* this should be the default rule */
	extvlan.vlan_rule_tbl[0].def = 1;

	extvlan.vlan_treatment_tbl[0].tagb_tpid_treatment = 0;
	extvlan.vlan_treatment_tbl[0].tagb_vid_treatment = 0;
	/* no tag */
	extvlan.vlan_treatment_tbl[0].tagb_treatment = 0xF;
	extvlan.vlan_treatment_tbl[0].inner_not_generate = 1;
	extvlan.vlan_treatment_tbl[0].outer_not_generate = 1;
	extvlan.vlan_treatment_tbl[0].discard_enable = 0;

	/* results in 0x8100 for TPID */
	extvlan.vlan_treatment_tbl[0].taga_tpid_treatment = 4;
	extvlan.vlan_treatment_tbl[0].taga_vid_treatment = tci_value & 0xfff;
	extvlan.vlan_treatment_tbl[0].taga_treatment = tci_value >> 13;

	/* 2nd rule: SINGLE TAGGED in -> DOUBLE TAGGED out */
	extvlan.vlan_rule_tbl[1].one_enable = 1;
	/* this should be the default rule */
	extvlan.vlan_rule_tbl[1].def = 1;

	extvlan.vlan_treatment_tbl[1].tagb_tpid_treatment = 0;
	extvlan.vlan_treatment_tbl[1].tagb_vid_treatment = 0;
	/* no tag */
	extvlan.vlan_treatment_tbl[1].tagb_treatment = 0xF;
	extvlan.vlan_treatment_tbl[1].inner_not_generate = 1;
	/* transmit as received…*/
	extvlan.vlan_treatment_tbl[1].outer_not_generate = 0;
	extvlan.vlan_treatment_tbl[1].discard_enable = 0;

	/* results in 0x8100 for TPID */
	extvlan.vlan_treatment_tbl[1].taga_tpid_treatment = 4;
	extvlan.vlan_treatment_tbl[1].taga_vid_treatment = tci_value & 0xfff;
	extvlan.vlan_treatment_tbl[1].taga_treatment =  tci_value >> 13;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
		      &extvlan, sizeof(extvlan));

	return ret;
}

static enum omci_api_return
omci_api_vlan_tagging_operation_ds_mode_1(struct omci_api_ctx *ctx,
					  const uint16_t index,
					  const uint16_t table_pointer)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_ext_vlan extvlan;
	uint8_t i=0;

	memset(&extvlan, 0x00, sizeof(extvlan));

	extvlan.index = index;
	/*  number of rules  */
	extvlan.num_valid_rules = 3;
	extvlan.max_vlans = OMCI_API_VLAN_RULE_GRP_SIZE;

	/* Ethertype-field (VLAN) */
	extvlan.extended_vlan_tbl.input_tpid = 0x8100;
	/* assigned Ethertype-field */
	extvlan.extended_vlan_tbl.output_tpid = 0x8100;
	extvlan.extended_vlan_tbl.dscp_table_pointer = 0;
	extvlan.extended_vlan_tbl.vlan_rule_table_pointer = table_pointer;
	extvlan.extended_vlan_tbl.valid = 1;

	/* 1st rule: UNTAGGED in -> UNTAGGED out */
	extvlan.vlan_rule_tbl[i].zero_enable = 1;
	/* this should be the default rule */
	extvlan.vlan_rule_tbl[i].def = 1;

	/* no tag */
	extvlan.vlan_treatment_tbl[i].tagb_treatment = 0xF;
	/* no tag */
	extvlan.vlan_treatment_tbl[i].taga_treatment = 0xF;
	/* remove outer VLAN */
	extvlan.vlan_treatment_tbl[i].outer_not_generate = 1;
	extvlan.vlan_treatment_tbl[i].inner_not_generate = 1;

	i++;
	/* 2nd rule: SINGLE TAGGED  in -> UNTAGGED out */
	extvlan.vlan_rule_tbl[i].one_enable = 1;
	/* this should be the default rule */
	extvlan.vlan_rule_tbl[i].def = 1;

	/* no tag */
	extvlan.vlan_treatment_tbl[i].tagb_treatment = 0xF;
	/* no tag */
	extvlan.vlan_treatment_tbl[i].taga_treatment = 0xF;
	/* remove outer VLAN */
	extvlan.vlan_treatment_tbl[i].outer_not_generate = 1;
	extvlan.vlan_treatment_tbl[i].inner_not_generate = 1;

	i++;
	/* 3rd rule: DOUBLE TAGGED in -> SINGLE TAGGED out */
	extvlan.vlan_rule_tbl[i].two_enable = 1;
	/* this should be the default rule */
	extvlan.vlan_rule_tbl[i].def = 1;

	/* no tag */
	extvlan.vlan_treatment_tbl[i].tagb_treatment = 0xF;
	/* no tag */
	extvlan.vlan_treatment_tbl[i].taga_treatment = 0xF;
	/* remove outer VLAN */
	extvlan.vlan_treatment_tbl[i].outer_not_generate = 1;
	extvlan.vlan_treatment_tbl[i].inner_not_generate = 0;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
		      &extvlan, sizeof(extvlan));

	return ret;
}

static enum omci_api_return
omci_api_vlan_lan_association_set(struct omci_api_ctx *ctx,
				  const uint16_t index,
				  const uint16_t table_pointer)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	return ret;
}

static enum omci_api_return omci_api_map(struct omci_api_ctx *ctx,
					 const uint16_t me_id,
					 const uint32_t mapper_id,
					 uint32_t *id)
{
	enum omci_api_return ret = index_get(ctx, mapper_id, me_id, id);

	if (ret == OMCI_API_NOT_FOUND)
		ret = id_map(ctx, mapper_id, me_id, id);

	return ret;
}

static enum omci_api_return ext_vlan_init(struct omci_api_ctx *ctx,
					  const uint16_t ext_vlan_idx,
					  const uint32_t rule_ptr)
{
	enum omci_api_return ret;
	union gpe_ext_vlan_get_u ext_vlan;

	memset(&ext_vlan, 0, sizeof(ext_vlan));

	ext_vlan.out.index = ext_vlan_idx;

	/* Ethertype-field (VLAN) */
	ext_vlan.out.extended_vlan_tbl.input_tpid = 0x8100;
	/* assigned Ethertype-field */
	ext_vlan.out.extended_vlan_tbl.output_tpid = 0x8100;
	ext_vlan.out.extended_vlan_tbl.dscp_table_pointer = 0;
	ext_vlan.out.extended_vlan_tbl.vlan_rule_table_pointer = rule_ptr;
	ext_vlan.out.extended_vlan_tbl.valid = 1;
	ext_vlan.out.max_vlans = OMCI_API_VLAN_RULE_GRP_SIZE;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

static enum omci_api_return
omci_api_vlan_tagging_operation_conf_mc_entries_update(struct omci_api_ctx *ctx,
						       const uint16_t me_id,
						       const uint8_t
						          lan_port_idx,
						       const uint16_t
							  ext_vlan_mc_us_idx,
						       const uint16_t
							  ext_vlan_mc_ds_idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	uint32_t mc_subscr_meid, subscr_idx;
	struct omci_api_mcc_subscr_cfg subscr;
	struct omci_api_mcc_profile profile;

	/* Get the related Multicast Subscriber ME Identifier */
	ret = id_get(ctx, MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_LAN_IDX,
		     &mc_subscr_meid, lan_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_SUCCESS;

	/* Get Multicast Subscriber Index*/
	ret = index_get(ctx, MAPPER_MCSUBSCR_CFG_INFO_MEID_TO_IDX,
			mc_subscr_meid, &subscr_idx);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_SUCCESS;

	/* Get Multicast Subscriber Data */
	ret = omci_api_mcc_subscr_get(ctx, subscr_idx, &subscr);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("MC Subscr Get failed, me_id=0x%04X, ret=%d\n",
				me_id, ret));
		return ret;
	}

	if (subscr.valid == false)
		/* No subscriber available */
		return OMCI_API_SUCCESS;

	if (subscr.profile_idx == MCC_PROFILE_NULL)
		/* No profile defined */
		return OMCI_API_SUCCESS;

	ret = omci_api_mcc_profile_get(ctx, subscr.profile_idx, &profile);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("MC Profile Get failed, me_id=0x%04X, ret=%d\n",
				me_id, ret));
		return ret;
	}

	ret = omci_api_multicast_operations_profile_mc_ext_vlan_update(ctx,
						 lan_port_idx,
						 ext_vlan_mc_us_idx,
						 ext_vlan_mc_ds_idx,
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
#endif /* defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)*/
	return ret;
}

enum omci_api_return
omci_api_vlan_tagging_operation_conf_data_update(struct omci_api_ctx *ctx,
						 uint16_t me_id,
						 uint8_t us_vlan_tag_oper_mode,
						 uint16_t us_vlan_tag_tci_value,
						 uint8_t ds_vlan_tag_oper_mode,
						 uint8_t association_type,
						 uint16_t association_ptr)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t vlan_rule_grp_us, vlan_rule_grp_ds;
	uint16_t table_pointer_us, table_pointer_ds;
	uint8_t lan_port;

	DBG(OMCI_API_MSG, ("%s "
		  " me_id=%u"
		  " us_vlan_tag_oper_mode=%u"
		  " us_vlan_tag_tci_value=%u"
		  " ds_vlan_tag_oper_mode=%u"
		  " association_type=%u"
		  " association_ptr=%u\n",
		  __FUNCTION__,
		  me_id, us_vlan_tag_oper_mode, us_vlan_tag_tci_value,
		  ds_vlan_tag_oper_mode, association_type, association_ptr));

	/* create/get mapping  */
	ret = omci_api_map(ctx, me_id, MAPPER_VLANTOCD_MEID_TO_VLANRULEGRP_US,
			   &vlan_rule_grp_us);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = omci_api_map(ctx, me_id, MAPPER_VLANTOCD_MEID_TO_VLANRULEGRP_DS,
			   &vlan_rule_grp_ds);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	/* Reserve N+1 entry for MC VLAN handling */
	vlan_rule_grp_us *= 2;
	vlan_rule_grp_ds *= 2;

	if (vlan_rule_grp_us * OMCI_API_VLAN_RULE_GRP_SIZE > 
		(ONU_GPE_VLAN_RULE_TABLE_SIZE - 2 * OMCI_API_VLAN_RULE_GRP_SIZE)) {
		DBG(OMCI_API_ERR,
			("no more free rules entries for ExtVLAN idx=%u!\n",
			vlan_rule_grp_us));
		return OMCI_API_ERROR;
	}

	table_pointer_us = vlan_rule_grp_us * OMCI_API_VLAN_RULE_GRP_SIZE;
	table_pointer_ds = vlan_rule_grp_ds * OMCI_API_VLAN_RULE_GRP_SIZE;
	vlan_rule_grp_ds += GROUP_OFFSET;
	table_pointer_ds += RULE_OFFSET;

	/* Init N+1 entry for MC VLAN handling */
	(void)ext_vlan_init(ctx, vlan_rule_grp_us + 1,
			    table_pointer_us + OMCI_API_VLAN_RULE_GRP_SIZE);
	(void)ext_vlan_init(ctx, vlan_rule_grp_ds + 1,
			    table_pointer_ds + OMCI_API_VLAN_RULE_GRP_SIZE);

	if (association_type == 0 && association_ptr == 0)
		association_ptr = me_id;

	switch (us_vlan_tag_oper_mode) {
	case 0:
		break;
	case 1:
		ret = omci_api_vlan_tagging_operation_us_mode_1(ctx,
							vlan_rule_grp_us,
							us_vlan_tag_tci_value,
							table_pointer_us);
		break;
	case 2:
		ret = omci_api_vlan_tagging_operation_us_mode_2(ctx,
							vlan_rule_grp_us,
							us_vlan_tag_tci_value,
							table_pointer_us);
		break;
	}

	switch (ds_vlan_tag_oper_mode) {
	case 0:
		break;
	case 1:
		ret = omci_api_vlan_tagging_operation_ds_mode_1(ctx,
							vlan_rule_grp_ds,
							table_pointer_ds);
		break;
	}

	switch (association_type) {
	case 0:
	case 10:
		ret = omci_api_uni2lan(ctx, association_ptr, &lan_port);
		if(ret == OMCI_API_SUCCESS) {
			ret = omci_api_lan_port_ext_vlan_modify(ctx,
					lan_port,
					ds_vlan_tag_oper_mode != 0 ? 1: 0,
					vlan_rule_grp_ds,
					us_vlan_tag_oper_mode != 0 ? 1: 0,
					vlan_rule_grp_us,
					true);
			if (ret != OMCI_API_SUCCESS)
				return ret;

			ret = omci_api_vlan_tagging_operation_conf_mc_entries_update(
					ctx, me_id, lan_port,
					vlan_rule_grp_us + 1, vlan_rule_grp_ds + 1);
		}
		break;
	case 1:
		ret = omci_api_lan_port_ext_vlan_modify(ctx,
				4,
				ds_vlan_tag_oper_mode != 0 ? true: false,
				vlan_rule_grp_ds,
				us_vlan_tag_oper_mode != 0 ? true: false,
				vlan_rule_grp_us,
				true);
		break;
	case 5:
		break;
	case 6:
		break;
	default:
		break;
	}

	return ret;
}

enum omci_api_return
omci_api_vlan_tagging_operation_conf_data_destroy(struct omci_api_ctx *ctx,
						  uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t vlan_rule_grp;
	struct gpe_ext_vlan extvlan;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	ret = index_get(ctx, MAPPER_VLANTOCD_MEID_TO_VLANRULEGRP_US,
		       me_id, &vlan_rule_grp);
	if (ret == OMCI_API_SUCCESS) {
		id_remove(ctx, MAPPER_VLANTOCD_MEID_TO_VLANRULEGRP_US, me_id);
		
		vlan_rule_grp *= 2;

		memset(&extvlan, 0x00, sizeof(struct gpe_ext_vlan));
		extvlan.extended_vlan_tbl.vlan_rule_table_pointer =
				vlan_rule_grp * OMCI_API_VLAN_RULE_GRP_SIZE;
		extvlan.index = vlan_rule_grp;
		extvlan.max_vlans = OMCI_API_VLAN_RULE_GRP_SIZE;
		dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
			&extvlan, sizeof(extvlan));

		/* destroy N+1 entry*/
		memset(&extvlan, 0x00, sizeof(struct gpe_ext_vlan));
		extvlan.extended_vlan_tbl.vlan_rule_table_pointer =
			(vlan_rule_grp + 1) * OMCI_API_VLAN_RULE_GRP_SIZE;
		extvlan.index = vlan_rule_grp + 1;
		extvlan.max_vlans = OMCI_API_VLAN_RULE_GRP_SIZE;
		dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
			&extvlan, sizeof(extvlan));
	}

	ret = index_get(ctx, MAPPER_VLANTOCD_MEID_TO_VLANRULEGRP_DS,
		       me_id, &vlan_rule_grp);
	if (ret == OMCI_API_SUCCESS) {
		id_remove(ctx, MAPPER_VLANTOCD_MEID_TO_VLANRULEGRP_DS, me_id);

		vlan_rule_grp *= 2;

		memset(&extvlan, 0x00, sizeof(struct gpe_ext_vlan));
		extvlan.extended_vlan_tbl.vlan_rule_table_pointer =
				(vlan_rule_grp * OMCI_API_VLAN_RULE_GRP_SIZE) +
							RULE_OFFSET;
		extvlan.index = vlan_rule_grp + GROUP_OFFSET;
		extvlan.max_vlans = OMCI_API_VLAN_RULE_GRP_SIZE;
		dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
			&extvlan, sizeof(extvlan));

		/* destroy N+1 entry*/
		memset(&extvlan, 0x00, sizeof(struct gpe_ext_vlan));
		extvlan.extended_vlan_tbl.vlan_rule_table_pointer =
			(vlan_rule_grp + 1) * OMCI_API_VLAN_RULE_GRP_SIZE +
								RULE_OFFSET;
		extvlan.index = vlan_rule_grp + 1 + GROUP_OFFSET;
		extvlan.max_vlans = OMCI_API_VLAN_RULE_GRP_SIZE;
		dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
			&extvlan, sizeof(extvlan));
	}

	return ret;
}

/** @} */
