/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_extended_vlan_config_data.h"
#include "me/omci_api_multicast_operations_profile.h"
#include "me/omci_api_extended_vlan_table.h"

/** \addtogroup OMCI_API_ME_EXTENDED_VLAN_CONFIG_DATA

@{
*/

static enum omci_api_return ext_vlan_free_idx_get(struct omci_api_ctx *ctx,
						  uint32_t *ext_vlan_idx)
{
	enum omci_api_return ret;
	union gpe_ext_vlan_get_u ext_vlan;
	uint32_t i;

	for (i = 0; i < ONU_GPE_EXTENDED_VLAN_TABLE_SIZE; i++) {
		memset(&ext_vlan, 0, sizeof(ext_vlan));
		ext_vlan.in.index = i;

		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_GET,
			      &ext_vlan, sizeof(ext_vlan));
		if (ret != OMCI_API_SUCCESS)
			return ret;

		if (!ext_vlan.out.extended_vlan_tbl.valid) {
			*ext_vlan_idx = i;
			return OMCI_API_SUCCESS;
		}
	}

	return OMCI_API_NOT_FOUND;
}

static enum omci_api_return ext_vlan_create(struct omci_api_ctx *ctx,
					    uint32_t idx)
{
	enum omci_api_return ret;
	union gpe_ext_vlan_get_u ext_vlan;

	memset(&ext_vlan, 0, sizeof(ext_vlan));
	ext_vlan.in.index = idx;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_GET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	if (ext_vlan.out.extended_vlan_tbl.valid)
		return OMCI_API_ERROR;

	if ((idx * ONU_GPE_MAX_VLANS) >
			(ONU_GPE_VLAN_RULE_TABLE_SIZE - ONU_GPE_MAX_VLANS)) {
		DBG(OMCI_API_ERR,
			("no more free rules entries for ExtVLAN idx=%u!\n",
			idx));
		return OMCI_API_ERROR;
	}

	ext_vlan.out.max_vlans = ONU_GPE_MAX_VLANS;
	ext_vlan.out.extended_vlan_tbl.valid = 1;
	ext_vlan.out.extended_vlan_tbl.vlan_rule_table_pointer =
							idx * ONU_GPE_MAX_VLANS;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

static enum omci_api_return ext_vlan_delete(struct omci_api_ctx *ctx,
					    uint32_t idx)
{
	enum omci_api_return ret;
	union gpe_ext_vlan_get_u ext_vlan;
	uint8_t dscp_profile;
	uint16_t vlan_rule_table_pointer;

	memset(&ext_vlan, 0, sizeof(ext_vlan));
	ext_vlan.in.index = idx;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_GET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	dscp_profile = ext_vlan.out.extended_vlan_tbl.dscp_table_pointer;

	dscp_profile_delete(ctx, dscp_profile);

	vlan_rule_table_pointer =
		ext_vlan.out.extended_vlan_tbl.vlan_rule_table_pointer;

	memset(&ext_vlan, 0, sizeof(ext_vlan));

	ext_vlan.in.index = idx;
	ext_vlan.out.extended_vlan_tbl.vlan_rule_table_pointer =
		vlan_rule_table_pointer;
	ext_vlan.out.max_vlans = ONU_GPE_MAX_VLANS;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

static enum omci_api_return ext_vlan_modify(struct omci_api_ctx *ctx,
					    uint32_t idx,
					    uint16_t input_tpid,
					    uint16_t output_tpid,
					    uint8_t dscp_tp)
{
	enum omci_api_return ret;
	union gpe_ext_vlan_get_u ext_vlan;

	memset(&ext_vlan, 0, sizeof(ext_vlan));
	ext_vlan.in.index = idx;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_GET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ext_vlan.out.extended_vlan_tbl.input_tpid = input_tpid;
	ext_vlan.out.extended_vlan_tbl.output_tpid = output_tpid;

	if (dscp_tp != 0xFF)
		ext_vlan.out.extended_vlan_tbl.dscp_table_pointer = dscp_tp;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

static enum omci_api_return ext_vlan_idx_get(struct omci_api_ctx *ctx,
					     uint16_t me_id,
					     bool ds,
					     bool mc_support,
					     uint32_t *ext_vlan_idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	enum mapper_id_type id_type = ds ?
					MAPPER_EXTVLANCD_MEID_TO_EXTVLANIDX_DS :
					MAPPER_EXTVLANCD_MEID_TO_EXTVLANIDX_US;

	ret = index_get(ctx, id_type, me_id, ext_vlan_idx);
	if (ret != OMCI_API_SUCCESS) {

		ret = ext_vlan_free_idx_get(ctx, ext_vlan_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		ret = explicit_map(ctx, id_type, me_id, *ext_vlan_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		ret = ext_vlan_create(ctx, *ext_vlan_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		/* Create Multicast entry which should always be N + 1*/
		if (mc_support) {
			id_type = ds ?
				MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_DS :
				MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_US;

			ret = explicit_map(ctx, id_type, me_id,
					   *ext_vlan_idx + 1);
			if (ret != OMCI_API_SUCCESS)
				return ret;
	
			ret = ext_vlan_create(ctx, *ext_vlan_idx + 1);
			if (ret != OMCI_API_SUCCESS)
				return ret;
		}
	}

	return ret;
}

/** Retrieve the Bridge location (ANI or UNI side) and the related
    index of the connected Termination Point instance, which can be:
	    - LAN Port index
	    - P-Mapper index
	    - ITP ID (GEM port index, gpix)

   \param[in] ctx	      OMCI API context pointer
   \param[in]  me_id          MAC Bridge Port Configuration data
                              ME identifier
   \param[out] ani_indication ANI side indication
                              (true - ANI side, false - UNI side)
   \param[out] conn_idx       connected Termination Point instance index
*/
/* bridge_port_info_get: use shared omci_api_bridge_port_tp_info_get from
   omci_api_table_access.c (also used by ME 78). */

enum omci_api_return ext_vlan_custom_update(struct omci_api_ctx *ctx,
						   const uint8_t ethertype)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_ext_vlan_custom vlan_custom;
	uint16_t ethertype_val;

	if (ethertype == 0) {
		return OMCI_API_SUCCESS;
	} else if (ethertype == 1) {
		ethertype_val = ONU_ETHERTYPE_IPV4;
	} else if (ethertype == 2) {
		ethertype_val = ONU_ETHERTYPE_PPPOE_DISC;
	} else if (ethertype == 3) {
		ethertype_val = ONU_ETHERTYPE_ARP;
	} else if (ethertype == 4) {
		ethertype_val = ONU_ETHERTYPE_IPV6;
	} else {
		DBG(OMCI_API_ERR, ("wrong ethertype\n"));
		return OMCI_API_ERROR;
	}

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_CUSTOM_GET,
		      &vlan_custom, sizeof(vlan_custom));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("can't read custom vlan\n"));
		return OMCI_API_ERROR;
	}

	/* Check if the given Ethertype value matches one of the configured
	   values. */
	if (vlan_custom.ety1 != ethertype_val &&
	    vlan_custom.ety2 != ethertype_val &&
	    vlan_custom.ety3 != ethertype_val &&
	    vlan_custom.ety4 != ethertype_val &&
	    vlan_custom.ety5 != ethertype_val) {
		/* If not, try to find an unused configuration and define it
		   now. */
		if (vlan_custom.ety1 == 0x0000) {
			vlan_custom.ety1 = ethertype_val;
		} else if (vlan_custom.ety2 == 0x0000) {
			vlan_custom.ety2 = ethertype_val;
		} else if (vlan_custom.ety3 == 0x0000) {
			vlan_custom.ety3 = ethertype_val;
		} else if (vlan_custom.ety4 == 0x0000) {
			vlan_custom.ety4 = ethertype_val;
		} else if (vlan_custom.ety5 == 0x0000) {
			vlan_custom.ety5 = ethertype_val;
		} else {
			DBG(OMCI_API_ERR, ("no free entry found\n"));
			return OMCI_API_ERROR;
		}

		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_CUSTOM_SET,
			      &vlan_custom, sizeof(vlan_custom));
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("can't write custom vlan\n"));
			return OMCI_API_ERROR;
		}
	}

	return OMCI_API_SUCCESS;
}

static enum omci_api_return rule_delete(struct omci_api_ctx *ctx,
					const bool ds,
					uint32_t ext_vlan_idx,
					uint16_t rule_idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	union gpe_ext_vlan_get_u ext_vlan;
	uint16_t i;

	memset(&ext_vlan, 0, sizeof(ext_vlan));
	ext_vlan.in.index = ext_vlan_idx;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_GET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	if (ext_vlan.out.num_valid_rules == 0)
		return OMCI_API_SUCCESS;

	if (rule_idx >= ext_vlan.out.num_valid_rules)
		return OMCI_API_SUCCESS;

	if (ext_vlan.out.num_valid_rules >= ONU_GPE_MAX_VLANS)
		return OMCI_API_ERROR;

	for (i = rule_idx; i < ext_vlan.out.num_valid_rules - 1; i++) {
		ext_vlan.out.vlan_rule_tbl[i] =
			ext_vlan.out.vlan_rule_tbl[i + 1];

		ext_vlan.out.vlan_treatment_tbl[i] =
			ext_vlan.out.vlan_treatment_tbl[i + 1];
	}

	ext_vlan.out.num_valid_rules--;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

static enum omci_api_return rule_clear(struct omci_api_ctx *ctx,
					const bool ds,
					uint32_t ext_vlan_idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	union gpe_ext_vlan_get_u ext_vlan;
	uint16_t i;

	DBG(OMCI_API_MSG, ("clear existing %s rules\n", ds ? "ds" : "us"));

	memset(&ext_vlan, 0, sizeof(ext_vlan));
	ext_vlan.in.index = ext_vlan_idx;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_GET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	if (ext_vlan.out.num_valid_rules == 0)
		return OMCI_API_SUCCESS;

	ext_vlan.out.num_valid_rules = 0;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

static enum omci_api_return rule_add(struct omci_api_ctx *ctx,
				     const bool ds,
				     const uint32_t ext_vlan_idx,
				     const uint16_t rule_idx,
				     const uint16_t omci_idx,
				     const struct vlan_filter *f)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	union gpe_ext_vlan_get_u ext_vlan;
	struct gpe_vlan_rule_table *r;
	struct gpe_vlan_treatment_table *t;
	uint32_t i;
	struct gpe_vlan_rule_table new_rule = { 0 };
	struct gpe_vlan_treatment_table new_treat = { 0 };
	bool overridden = false;

	DBG(OMCI_API_MSG, ("rule_add ext_vlan_idx: %d rule_idx: %d omci_idx: %d\n",
						ext_vlan_idx, rule_idx, omci_idx));

	memset(&ext_vlan, 0, sizeof(ext_vlan));
	ext_vlan.in.index = ext_vlan_idx;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_GET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = ds ? omci_api_rule_ds_map(ctx, omci_idx, f, &new_rule, &new_treat) :
		   omci_api_rule_us_map(ctx, omci_idx, f, &new_rule, &new_treat);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("can't map rule\n"));
		return OMCI_API_ERROR;
	}

	if (new_rule.valid == false || new_treat.valid == false) {
		return OMCI_API_SUCCESS;
	}

	/* if new rule is default, check that we don't have other
	 * default rule for the same tag group (zero, single, double) */
	if (new_rule.def) {
		for (i = 0; i < ext_vlan.out.num_valid_rules; i++) {
			if (ext_vlan.out.vlan_rule_tbl[i].valid == 0)
				continue;

			if (ext_vlan.out.vlan_rule_tbl[i].two_enable !=
			    new_rule.two_enable ||
			    ext_vlan.out.vlan_rule_tbl[i].one_enable !=
			    new_rule.one_enable ||
			    ext_vlan.out.vlan_rule_tbl[i].zero_enable !=
			    new_rule.zero_enable)
				continue;

			if (ext_vlan.out.vlan_rule_tbl[i].def == 1) {
				/* don't rewrite existing default rule */
				overridden = true;

				break;
			}
		}
	}

	if (overridden == false) {
		if (rule_idx < ext_vlan.out.num_valid_rules) {
			if(rule_idx < ONU_GPE_MAX_VLANS) {
				DBG(OMCI_API_MSG, ("replace existing %s rule %d\n", ds ? "ds" : "us", rule_idx));
				r = &(ext_vlan.out.vlan_rule_tbl[rule_idx]);
				t = &(ext_vlan.out.vlan_treatment_tbl[rule_idx]);
				memcpy(r, &new_rule, sizeof(struct gpe_vlan_rule_table));
				memcpy(t, &new_treat, sizeof(struct gpe_vlan_treatment_table));
			}
		} else {
			if(ext_vlan.out.num_valid_rules < ONU_GPE_MAX_VLANS) {
				DBG(OMCI_API_MSG, ("add new %s rule\n", ds ? "ds" : "us"));
				r = &(ext_vlan.out.vlan_rule_tbl[ext_vlan.out.num_valid_rules]);
				t = &(ext_vlan.out.vlan_treatment_tbl[ext_vlan.out.num_valid_rules]);
				memcpy(r, &new_rule, sizeof(struct gpe_vlan_rule_table));
				memcpy(t, &new_treat, sizeof(struct gpe_vlan_treatment_table));
				ext_vlan.out.num_valid_rules++;
			}
		}
	}

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

static enum omci_api_return parser_cfg_update(struct omci_api_ctx *ctx,
					      uint16_t input_tpid)
{
	enum omci_api_return ret;
	struct gpe_parser_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_PARSER_CFG_GET, &cfg, sizeof(cfg));
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	cfg.tpid[3] = input_tpid;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_PARSER_CFG_SET, &cfg, sizeof(cfg));
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_ext_vlan_cfg_data_update(struct omci_api_ctx *ctx,
				  const bool mc_support,
				  uint8_t association_type,
				  uint16_t me_id,
				  uint16_t associated_ptr,
				  uint16_t input_tpid,
				  uint16_t output_tpid,
				  uint8_t *dscp,
				  uint8_t ds_mode)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t ext_vlan_idx[2];
	uint8_t dscp_profile, tp_idx, i, j, ext_vlan_num = ds_mode == 0 ? 2 : 1;
	uint32_t idx, tmp_idx;
	int dispatch = 0;  /* 0=LAN, 1=GEM, 2=pMapper */
	bool enable_egress, enable_ingress = true;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   associated_ptr=%u\n"
		  "   input_tpid=%u\n"
		  "   output_tpid=%u\n"
		  "   ds_mode=%u\n",
		  __FUNCTION__, me_id, associated_ptr, input_tpid, output_tpid,
		  ds_mode));

	/* Set ONU_GPE_EXTENDED_VLAN_TABLE. */
	for (i = 0; i < (mc_support ? 2 : ext_vlan_num); i++) {
		ret = ext_vlan_idx_get(ctx, me_id, (bool)i,
				       mc_support,
				       &ext_vlan_idx[i]);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		dscp_profile = dscp_profile_create(ctx, dscp);
		if (dscp_profile != 255 &&
		    dscp_profile < ARRAY_SIZE(ctx->pcp)) {
			omci_api_dscp_profile_add(ctx, dscp_profile,
						  &ctx->pcp[dscp_profile][0]);
		} else {
			DBG(OMCI_API_ERR, ("omci_api_ext_vlan_cfg_data_update: "
					   "no more free dscp entries\n"));
		}

		for (j = 0; j < (mc_support ? 2 : 1); j++) {
			ret = ext_vlan_modify(ctx, ext_vlan_idx[i] + j,
					      i ? output_tpid : input_tpid,
					      i ? input_tpid : output_tpid,
					      dscp_profile);
			if (ret != OMCI_API_SUCCESS) {
				DBG(OMCI_API_ERR, ("Ext VLAN table modify failed, "
						   "ret=%d, idx=%u!\n",
						   ret, ext_vlan_idx[i] + j));
				return ret;
			}
		}
	}

	/* Update parser configuration*/
	ret = parser_cfg_update(ctx, input_tpid);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Parser config update failed\n"));
		return ret;
	}

	if (mc_support)
		enable_egress = true;
	else
		enable_egress = ds_mode == 0 ? true : false;

	switch (association_type) {
	case 0:
		{
			uint8_t bp_tp_type;

			ret = omci_api_bridge_port_tp_info_get(ctx, associated_ptr,
							       &bp_tp_type, &tp_idx);
			if (ret != OMCI_API_SUCCESS)
				return ret;
			idx = tp_idx;
			/* Map bridge port TP type to dispatch:
			 * 0 (PPTP) -> 0 (LAN)
			 * 2 (p-Mapper) -> 2 (mapper fanout)
			 * 3 (ITP) -> 1 (single GEM port) */
			if (bp_tp_type == 2)
				dispatch = 2;
			else if (bp_tp_type & 0x2)
				dispatch = 1;
		}
		break;
	case 1:
		/* 802.1p Mapper — get mapper hardware index.
		   Ext VLAN will fan out to all GEM ports under this mapper. */
		ret = index_get(ctx, MAPPER_DOT1PMAPPER_MEID_TO_IDX,
				associated_ptr, &idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
		dispatch = 2;  /* pMapper fanout */
		break;
	case 2:
		ret = index_get(ctx, MAPPER_PPTPETHUNI_MEID_TO_IDX,
				associated_ptr, &idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_LAN_IDX,
				me_id, &tmp_idx);
		if (ret != OMCI_API_SUCCESS) {
			ret = explicit_map(ctx, MAPPER_EXTVLANCD_MEID_TO_LAN_IDX,
					   me_id, idx);
			if (ret != OMCI_API_SUCCESS)
				return ret;
		}
		/* dispatch stays 0 = LAN */
		break;
	case 3:
		/* IP host config data — fixed mapping to LAN4 */
		idx = 4;
		/* dispatch stays 0 = LAN */
		break;
	case 4:
		/* IPv6 host config data — v7.5.1 stock uses mapper 0x1f.
		   Same pattern as case 2 (PPTP) and case 10 (VEIP). */
		ret = index_get(ctx, MAPPER_IPV6HOST_MEID_TO_IDX,
				associated_ptr, &idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_LAN_IDX,
				me_id, &tmp_idx);
		if (ret != OMCI_API_SUCCESS) {
			ret = explicit_map(ctx, MAPPER_EXTVLANCD_MEID_TO_LAN_IDX,
					   me_id, idx);
			if (ret != OMCI_API_SUCCESS)
				return ret;
		}
		/* dispatch stays 0 = LAN */
		break;
	case 5:
		ret = index_get(ctx, MAPPER_GEMITP_MEID_TO_GPIX,
				associated_ptr, &idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
		dispatch = 1;  /* single GEM port */
		break;
	case 6:
		ret = index_get(ctx, MAPPER_MULCTCAST_GEMPORTITP_MEID_TO_CTP_MEID,
				associated_ptr, &idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		ret = index_get(ctx, MAPPER_GEMPORTCTP_MEID_TO_IDX, idx, &idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
		idx = idx & 0xFFFF;
		dispatch = 1;  /* single GEM port */
		break;
	case 10:
		/* VEIP — v7.5.1 stock handles this (mapper 0x1e).
		   Same pattern as case 2 but uses VEIP mapper. */
		ret = index_get(ctx, MAPPER_VEIP_MEID_TO_IDX,
				associated_ptr, &idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_LAN_IDX,
				me_id, &tmp_idx);
		if (ret != OMCI_API_SUCCESS) {
			ret = explicit_map(ctx, MAPPER_EXTVLANCD_MEID_TO_LAN_IDX,
					   me_id, idx);
			if (ret != OMCI_API_SUCCESS)
				return ret;
		}
		/* dispatch stays 0 = LAN */
		break;
	default:
		DBG(OMCI_API_ERR, ("Unsupported Association Type %u\n",
					   association_type));
		return OMCI_API_ERROR;
	}

	if (dispatch == 2) {
		/* pMapper: fan out ext VLAN to all GEM ports in the mapper */
		uint32_t gpix[8];
		unsigned int k;

		ret = omci_api_pmapper_get(ctx, (uint16_t)idx, gpix,
					   NULL, NULL, NULL);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("pMapper at index %u get failed, "
					   "ret=%d\n", idx, ret));
			return ret;
		}
		for (k = 0; k < 8; k++) {
			if (gpix[k] == 255 || gpix[k] == 0xffff)
				continue;
			ret = omci_api_gem_port_us_ext_vlan_modify(ctx,
						(uint16_t)gpix[k], true,
						(uint8_t)ext_vlan_idx[0], true);
			if (ret != OMCI_API_SUCCESS)
				return ret;
			ret = omci_api_gem_port_ds_ext_vlan_modify(ctx,
						(uint16_t)gpix[k], true,
						(uint8_t)ext_vlan_idx[1]);
			if (ret != OMCI_API_SUCCESS)
				return ret;
		}
	} else if (dispatch == 1) {
		/* Single GEM port (ANI side) */
		ret = omci_api_gem_port_us_ext_vlan_modify(ctx,
					(uint16_t)idx, true,
					(uint8_t)ext_vlan_idx[0], true);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		ret = omci_api_gem_port_ds_ext_vlan_modify(ctx,
					(uint16_t)idx, true,
					(uint8_t)ext_vlan_idx[1]);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	} else if (dispatch == 0) {
		/* UNI/LAN port */
		ret = omci_api_lan_port_ext_vlan_modify(ctx,
					(uint16_t)idx,
					enable_egress ? 1 : 0,
					(uint8_t)ext_vlan_idx[1],
					enable_ingress ? 1 : 0,
					(uint8_t)ext_vlan_idx[0],
					true);
	} else {
		DBG(OMCI_API_ERR, ("Unsupported Bridge Port TP type %d\n",
				   dispatch));
	}

	return ret;
}

enum omci_api_return
omci_api_ext_vlan_cfg_data_destroy(struct omci_api_ctx *ctx, uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t ext_vlan_idx, idx;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_EXTVLANIDX_US,
			me_id, &ext_vlan_idx);
	if (ret == OMCI_API_SUCCESS) {
		id_remove(ctx, MAPPER_EXTVLANCD_MEID_TO_EXTVLANIDX_US, me_id);
		ret = ext_vlan_delete(ctx, ext_vlan_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_EXTVLANIDX_DS,
			me_id, &ext_vlan_idx);
	if (ret == OMCI_API_SUCCESS) {
		id_remove(ctx, MAPPER_EXTVLANCD_MEID_TO_EXTVLANIDX_DS, me_id);
		ret = ext_vlan_delete(ctx, ext_vlan_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_US,
			me_id, &ext_vlan_idx);
	if (ret == OMCI_API_SUCCESS) {
		id_remove(ctx, MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_US, me_id);
		ret = ext_vlan_delete(ctx, ext_vlan_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_DS,
			me_id, &ext_vlan_idx);
	if (ret == OMCI_API_SUCCESS) {
		id_remove(ctx, MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_DS, me_id);
		ret = ext_vlan_delete(ctx, ext_vlan_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_LAN_IDX,
			me_id, &idx);
	if (ret == OMCI_API_SUCCESS) {
		/* v7.5.1: clear LAN port ext VLAN config before removing mapper.
		   Stock calls lan_port_ext_vlan_modify(ctx, idx, 0,0,0,0,0). */
		ret = omci_api_lan_port_ext_vlan_modify(ctx,
					(uint16_t)idx, 0, 0, 0, 0, 0);
		if (ret == OMCI_API_SUCCESS)
			id_remove(ctx, MAPPER_EXTVLANCD_MEID_TO_LAN_IDX, me_id);
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_extended_vlan_config_data_tag_oper_table_entry_add(struct omci_api_ctx
							    *ctx,
							    uint16_t me_id,
							    uint32_t entry_idx,
							    uint8_t ds_mode,
							    uint8_t
							    filter_outer_priority,
							    uint16_t
							    filter_outer_vid,
							    uint8_t
							    filter_outer_tpid_de,
							    uint8_t
							    filter_inner_priority,
							    uint16_t
							    filter_inner_vid,
							    uint8_t
							    filter_inner_tpid_de,
							    uint8_t
							    filter_ethertype,
							    uint8_t
							    treatment_tags_to_remove,
							    uint8_t
							    treatment_outer_priority,
							    uint16_t
							    treatment_outer_vid,
							    uint8_t
							    treatment_outer_tpid_de,
							    uint8_t
							    treatment_inner_priority,
							    uint16_t
							    treatment_inner_vid,
							    uint8_t
							    treatment_inner_tpid_de)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t ext_vlan_idx;
	uint8_t i, ext_vlan_num = ds_mode == 0 ? 2 : 1;
	int omci_idx;
	struct vlan_filter flt;

	DBG(OMCI_API_MSG, ("%s"
		  " me_id=%u"
		  " entry_idx=%u" " ds_mode=%u"
		  " filter_outer_priority=%u"
		  " filter_outer_vid=%u" " filter_outer_tpid_de=%u"
		  " filter_inner_priority=%u" " filter_inner_vid=%u"
		  " filter_inner_tpid_de=%u" " filter_ethertype=%u"
		  " treatment_tags_to_remove=%u"
		  " treatment_outer_priority=%u"
		  " treatment_outer_vid=%u"
		  " treatment_outer_tpid_de=%u"
		  " treatment_inner_prioprity=%u"
		  " treatment_inner_vid=%u"
		  " treatment_inner_tpid_de=%u\n",
		  __FUNCTION__, me_id, entry_idx, ds_mode,
		  filter_outer_priority,
		  filter_outer_vid,
		  filter_outer_tpid_de, filter_inner_priority, filter_inner_vid,
		  filter_inner_tpid_de, filter_ethertype,
		  treatment_tags_to_remove,
		  treatment_outer_priority, treatment_outer_vid,
		  treatment_outer_tpid_de, treatment_inner_priority,
		  treatment_inner_vid, treatment_inner_tpid_de));

	if (entry_idx >= ONU_GPE_MAX_VLANS) {
		DBG(OMCI_API_ERR, ("%s"
			  " me_id=%u"
			  " entry_idx=%u exceeds max value of %u\n",
			  __FUNCTION__, me_id, entry_idx, ONU_GPE_MAX_VLANS));
		return OMCI_API_ERROR;
	}

	flt.filter_outer_priority = filter_outer_priority;
	flt.filter_outer_vid = filter_outer_vid;
	flt.filter_outer_tpid_de = filter_outer_tpid_de;
	flt.filter_inner_priority = filter_inner_priority;
	flt.filter_inner_vid = filter_inner_vid;
	flt.filter_inner_tpid_de = filter_inner_tpid_de;
	flt.filter_ethertype = filter_ethertype;
	flt.treatment_tags_to_remove = treatment_tags_to_remove;
	flt.treatment_outer_priority = treatment_outer_priority;
	flt.treatment_outer_vid = treatment_outer_vid;
	flt.treatment_outer_tpid_de = treatment_outer_tpid_de;
	flt.treatment_inner_priority = treatment_inner_priority;
	flt.treatment_inner_vid = treatment_inner_vid;
	flt.treatment_inner_tpid_de = treatment_inner_tpid_de;

	omci_idx = omci_api_find_ext_vlan_rule(&flt, false);
	if (omci_idx < 0) {
		DBG(OMCI_API_ERR, ("can't find rule: %s"
			  " me_id=%u"
			  " entry_idx=%u" " ds_mode=%u"
			  " filter_outer_priority=%u"
			  " filter_outer_vid=%u" " filter_outer_tpid_de=%u"
			  " filter_inner_priority=%u" " filter_inner_vid=%u"
			  " filter_inner_tpid_de=%u" " filter_ethertype=%u"
			  " treatment_tags_to_remove=%u"
			  " treatment_outer_priority=%u"
			  " treatment_outer_vid=%u"
			  " treatment_outer_tpid_de=%u"
			  " treatment_inner_prioprity=%u"
			  " treatment_inner_vid=%u"
			  " treatment_inner_tpid_de=%u\n",
			  __FUNCTION__, me_id, entry_idx, ds_mode,
			  filter_outer_priority,
			  filter_outer_vid,
			  filter_outer_tpid_de, filter_inner_priority, filter_inner_vid,
			  filter_inner_tpid_de, filter_ethertype,
			  treatment_tags_to_remove,
			  treatment_outer_priority, treatment_outer_vid,
			  treatment_outer_tpid_de, treatment_inner_priority,
			  treatment_inner_vid, treatment_inner_tpid_de));
		/*omci_api_find_ext_vlan_rule(&flt, true);*/
		return OMCI_API_SUCCESS;
	}

	for (i = 0; i < ext_vlan_num; i++) {
		ret = ext_vlan_idx_get(ctx, me_id, (bool)i, false,
				       &ext_vlan_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		ret = rule_add(ctx, (bool)i, ext_vlan_idx,
			       (uint16_t) entry_idx, omci_idx, &flt);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_extended_vlan_config_data_tag_oper_table_entry_add_dir(
							    struct omci_api_ctx
							    *ctx,
							    uint16_t me_id,
							    uint32_t entry_idx,
							    uint8_t ds_mode,
							    bool ds,
							    uint8_t
							    filter_outer_priority,
							    uint16_t
							    filter_outer_vid,
							    uint8_t
							    filter_outer_tpid_de,
							    uint8_t
							    filter_inner_priority,
							    uint16_t
							    filter_inner_vid,
							    uint8_t
							    filter_inner_tpid_de,
							    uint8_t
							    filter_ethertype,
							    uint8_t
							    treatment_tags_to_remove,
							    uint8_t
							    treatment_outer_priority,
							    uint16_t
							    treatment_outer_vid,
							    uint8_t
							    treatment_outer_tpid_de,
							    uint8_t
							    treatment_inner_priority,
							    uint16_t
							    treatment_inner_vid,
							    uint8_t
							    treatment_inner_tpid_de)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t ext_vlan_idx;
	int omci_idx;
	struct vlan_filter flt;

	DBG(OMCI_API_MSG, ("%s"
		  " me_id=%u"
		  " entry_idx=%u" " ds_mode=%u" " ds=%d"
		  " filter_outer_priority=%u"
		  " filter_outer_vid=%u" " filter_outer_tpid_de=%u"
		  " filter_inner_priority=%u" " filter_inner_vid=%u"
		  " filter_inner_tpid_de=%u" " filter_ethertype=%u"
		  " treatment_tags_to_remove=%u"
		  " treatment_outer_priority=%u"
		  " treatment_outer_vid=%u"
		  " treatment_outer_tpid_de=%u"
		  " treatment_inner_prioprity=%u"
		  " treatment_inner_vid=%u"
		  " treatment_inner_tpid_de=%u\n",
		  __FUNCTION__, me_id, entry_idx, ds_mode, ds,
		  filter_outer_priority,
		  filter_outer_vid,
		  filter_outer_tpid_de, filter_inner_priority, filter_inner_vid,
		  filter_inner_tpid_de, filter_ethertype,
		  treatment_tags_to_remove,
		  treatment_outer_priority, treatment_outer_vid,
		  treatment_outer_tpid_de, treatment_inner_priority,
		  treatment_inner_vid, treatment_inner_tpid_de));

	if (entry_idx >= ONU_GPE_MAX_VLANS) {
		DBG(OMCI_API_ERR, ("%s"
			  " me_id=%u"
			  " entry_idx=%u exceeds max value of %u\n",
			  __FUNCTION__, me_id, entry_idx, ONU_GPE_MAX_VLANS));
		return OMCI_API_ERROR;
	}

	flt.filter_outer_priority = filter_outer_priority;
	flt.filter_outer_vid = filter_outer_vid;
	flt.filter_outer_tpid_de = filter_outer_tpid_de;
	flt.filter_inner_priority = filter_inner_priority;
	flt.filter_inner_vid = filter_inner_vid;
	flt.filter_inner_tpid_de = filter_inner_tpid_de;
	flt.filter_ethertype = filter_ethertype;
	flt.treatment_tags_to_remove = treatment_tags_to_remove;
	flt.treatment_outer_priority = treatment_outer_priority;
	flt.treatment_outer_vid = treatment_outer_vid;
	flt.treatment_outer_tpid_de = treatment_outer_tpid_de;
	flt.treatment_inner_priority = treatment_inner_priority;
	flt.treatment_inner_vid = treatment_inner_vid;
	flt.treatment_inner_tpid_de = treatment_inner_tpid_de;

	omci_idx = omci_api_find_ext_vlan_rule(&flt, false);
	if (omci_idx < 0) {
		DBG(OMCI_API_ERR, ("can't find rule: %s"
			  " me_id=%u"
			  " entry_idx=%u" " ds_mode=%u" " ds=%d\n",
			  __FUNCTION__, me_id, entry_idx, ds_mode, ds));
		return OMCI_API_SUCCESS;
	}

	ret = ext_vlan_idx_get(ctx, me_id, ds, false, &ext_vlan_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = rule_add(ctx, ds, ext_vlan_idx,
		       (uint16_t) entry_idx, omci_idx, &flt);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_extended_vlan_config_data_iop_ds_entry_add(
						    struct omci_api_ctx *ctx,
						    uint16_t me_id,
						    uint32_t entry_idx,
						    uint8_t ds_mode)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t ext_vlan_idx;
	union gpe_ext_vlan_get_u ext_vlan;
	struct gpe_vlan_rule_table *r;
	struct gpe_vlan_treatment_table *t;

	/*
	 * IOP DS passthrough entry (stock DAT_0045d514):
	 * Filter: single-tag, VID=0 (priority-tagged), any priority
	 * Treatment: don't modify either tag (passthrough)
	 *
	 * GPE words: rule 0x00001002 0x80000000
	 *            treatment 0x00007C00 0x03E00000
	 */

	DBG(OMCI_API_MSG, ("%s me_id=%u entry_idx=%u ds_mode=%u\n",
			   __FUNCTION__, me_id, entry_idx, ds_mode));

	if (entry_idx >= ONU_GPE_MAX_VLANS) {
		DBG(OMCI_API_ERR, ("%s entry_idx=%u exceeds max %u\n",
				   __FUNCTION__, entry_idx, ONU_GPE_MAX_VLANS));
		return OMCI_API_ERROR;
	}

	ret = ext_vlan_idx_get(ctx, me_id, true /* DS */, false, &ext_vlan_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	memset(&ext_vlan, 0, sizeof(ext_vlan));
	ext_vlan.in.index = ext_vlan_idx;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_GET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	if (entry_idx < ext_vlan.out.num_valid_rules) {
		if (entry_idx >= ONU_GPE_MAX_VLANS)
			return OMCI_API_ERROR;
		r = &(ext_vlan.out.vlan_rule_tbl[entry_idx]);
		t = &(ext_vlan.out.vlan_treatment_tbl[entry_idx]);
	} else {
		if (ext_vlan.out.num_valid_rules >= ONU_GPE_MAX_VLANS)
			return OMCI_API_ERROR;
		r = &(ext_vlan.out.vlan_rule_tbl[ext_vlan.out.num_valid_rules]);
		t = &(ext_vlan.out.vlan_treatment_tbl[ext_vlan.out.num_valid_rules]);
		ext_vlan.out.num_valid_rules++;
	}

	/* Build IOP DS rule: single-tag VID=0 passthrough */
	memset(r, 0, sizeof(*r));
	r->valid = 1;
	r->one_enable = 1;        /* match single-tagged */
	r->outer_vid_enable = 1;  /* filter on outer VID */
	r->outer_vid_filter = 0;  /* VID = 0 (priority-tagged) */

	/* Build IOP DS treatment: don't modify either tag */
	memset(t, 0, sizeof(*t));
	t->valid = 1;
	t->tagb_treatment = 15;      /* don't modify inner tag */
	t->taga_treatment = 15;      /* don't modify outer tag */
	t->inner_not_generate = 1;   /* don't generate inner tag */
	t->outer_not_generate = 1;   /* don't generate outer tag */

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
		      &ext_vlan, sizeof(ext_vlan));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_extended_vlan_config_data_tag_oper_table_entry_remove(struct
							       omci_api_ctx
							       *ctx,
							       uint16_t me_id,
							       uint32_t entry_idx,
							       uint8_t ds_mode)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t ext_vlan_idx;
	uint8_t i, ext_vlan_num = ds_mode == 0 ? 2 : 1;

	DBG(OMCI_API_MSG, ("%s"
		  " me_id=%u" " entry_idx=%u"
		  " ds_mode=%u\n",
		  __FUNCTION__, me_id, entry_idx, ds_mode));

	if (entry_idx >= ONU_GPE_MAX_VLANS)
		return OMCI_API_ERROR;

	for (i = 0; i < ext_vlan_num; i++) {
		ret = ext_vlan_idx_get(ctx, me_id, (bool)i, false,
				       &ext_vlan_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		ret = rule_delete(ctx, (bool)i, ext_vlan_idx,
				  (uint16_t)entry_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	return ret;
}

enum omci_api_return
omci_api_extended_vlan_config_data_tag_oper_table_clear(struct omci_api_ctx
							*ctx,
							uint16_t me_id,
							uint8_t ds_mode)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t ext_vlan_idx;
	uint8_t i, ext_vlan_num = ds_mode == 0 ? 2 : 1;

	DBG(OMCI_API_MSG, ("%s"
		  " me_id=%u"
		  " ds_mode=%u\n",
		  __FUNCTION__, me_id, ds_mode));

	for (i = 0; i < ext_vlan_num; i++) {
		ret = ext_vlan_idx_get(ctx, me_id, (bool)i, false,
				       &ext_vlan_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
		rule_clear(ctx, (bool)i, ext_vlan_idx);
	}


	return ret;
}

enum omci_api_return
omci_api_extended_vlan_config_data_mc_entries_update(struct omci_api_ctx *ctx,
						     uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	uint32_t ext_vlan_mc_us_idx, ext_vlan_mc_ds_idx,
		 mc_subscr_meid, subscr_idx, lan_port_idx;
	struct omci_api_mcc_subscr_cfg subscr;
	struct omci_api_mcc_profile profile;

	/* Get the related LAN port index */
	ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_LAN_IDX,
			me_id, &lan_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_SUCCESS;

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

	ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_US,
			me_id, &ext_vlan_mc_us_idx);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("MC ExtVLAN US index get failed, me_id=0x%04X, ret=%d\n",
				me_id, ret));
		return ret;
	}

	ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_DS,
			me_id, &ext_vlan_mc_ds_idx);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("MC ExtVLAN DS index get failed, me_id=0x%04X, ret=%d\n",
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
omci_api_extended_vlan_config_data_mc_entries_clear(struct omci_api_ctx *ctx,
						    uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	uint32_t ext_vlan_mc_us_idx, ext_vlan_mc_ds_idx, lan_port_idx;

	/* Get the related LAN port index */
	ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_LAN_IDX,
			me_id, &lan_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_SUCCESS;

	ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_US,
			me_id, &ext_vlan_mc_us_idx);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("MC ExtVLAN US index get failed, me_id=0x%04X, ret=%d\n",
				me_id, ret));
		return ret;
	}

	ret = index_get(ctx, MAPPER_EXTVLANCD_MEID_TO_MC_EXTVLANIDX_DS,
			me_id, &ext_vlan_mc_ds_idx);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("MC ExtVLAN DS index get failed, me_id=0x%04X, ret=%d\n",
				me_id, ret));
		return ret;
	}

	ret = omci_api_multicast_operations_profile_mc_ext_vlan_clear(ctx,
						 lan_port_idx,
						 ext_vlan_mc_us_idx,
						 ext_vlan_mc_ds_idx);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("MC ExtVLAN clear failed, me_id=0x%04X, ret=%d\n",
				me_id, ret));
		return ret;
	}
#endif /* defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)*/
	return ret;
}
/** @} */
