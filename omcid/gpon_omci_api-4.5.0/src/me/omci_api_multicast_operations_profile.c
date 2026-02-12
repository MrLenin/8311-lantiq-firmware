/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_multicast_operations_profile.h"
#include "mcc/omci_api_mcc.h"

/** \addtogroup OMCI_API_ME_MULTICAST_OPERATIONS_PROFILE

   @{
*/

#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)

typedef enum omci_api_return (*mc_vlan_rules_set_t) (struct omci_api_ctx *ctx,
						const uint8_t tag_ctrl,
						const uint16_t tci,
						uint16_t *num_rules,
						struct gpe_vlan_rule_table *r,
						struct gpe_vlan_treatment_table *t);

struct mc_treatment {
	uint8_t taga_treatment;
	uint16_t taga_vid_treatment;
	uint8_t taga_tpid_treatment;
	uint8_t discard_enable;
	uint8_t outer_not_generate;
	uint8_t inner_not_generate;
};

#define MC_TREATMENTS_PER_EXT_VLAN	3
#define MC_TREATMENTS_US_NUM		3
#define MC_TREATMENTS_DS_NUM		7
#define PCPx				0xFF
#define VIDx				0xFFFF

struct mc_treatment us_mc_treatment[MC_TREATMENTS_US_NUM]
				   [MC_TREATMENTS_PER_EXT_VLAN]= {
	/* Tag Control Option 1*/
	{
		{PCPx, VIDx, 6, 0, 1, 1}, /* Untagged*/
		{PCPx, VIDx, 6, 0, 0, 1}, /* Single-tagged*/
		{PCPx, VIDx, 6, 0, 0, 0}  /* Double-tagged*/
	},
	/* Tag Control Option 2*/
	{
		{PCPx, VIDx, 6, 0, 1, 1}, /* Untagged*/
		{PCPx, VIDx, 6, 0, 1, 1}, /* Single-tagged*/
		{PCPx, VIDx, 6, 0, 1, 0}  /* Double-tagged*/
	},
	/* Tag Control Option 3*/
	{
		{PCPx, VIDx, 6, 0, 1, 1}, /* Untagged*/
		{9,    VIDx, 3, 0, 1, 1}, /* Single-tagged*/
		{9,    VIDx, 3, 0, 1, 0} /* Double-tagged*/
	}
};

struct mc_treatment ds_mc_treatment[MC_TREATMENTS_DS_NUM]
				   [MC_TREATMENTS_PER_EXT_VLAN]= {
	/* Tag Control Option 1*/
	{
		{0xF,  0,    0, 0, 1, 1}, /* Untagged*/
		{0xF,  0,    0, 0, 1, 1}, /* Single-tagged*/
		{0xF,  0,    0, 0, 1, 0}  /* Double-tagged*/
	},
	/* Tag Control Option 2*/
	{
		{PCPx, VIDx, 6, 0, 1, 1}, /* Untagged*/
		{PCPx, VIDx, 6, 0, 1, 1}, /* Single-tagged*/
		{PCPx, VIDx, 6, 0, 0, 0}  /* Double-tagged*/
	},
	/* Tag Control Option 3*/
	{
		{PCPx, VIDx, 6, 0, 1, 1}, /* Untagged*/
		{PCPx, VIDx, 6, 0, 1, 1}, /* Single-tagged*/
		{PCPx, VIDx, 6, 0, 1, 0}  /* Double-tagged*/
	},
	/* Tag Control Option 4*/
	{
		{PCPx, VIDx, 6, 0, 1, 1}, /* Untagged*/
		{9,    VIDx, 3, 0, 1, 1}, /* Single-tagged*/
		{9,    VIDx, 3, 0, 1, 0}  /* Double-tagged*/
	},
	/* Tag Control Option 5*/
	{
		{PCPx, VIDx, 6, 0, 1, 1}, /* Untagged*/
		{PCPx, VIDx, 6, 0, 1, 1}, /* Single-tagged*/
		{PCPx, VIDx, 6, 0, 0, 0}  /* Double-tagged*/
	},
	/* Tag Control Option 6*/
	{
		{PCPx, VIDx, 6, 0, 1, 1}, /* Untagged*/
		{PCPx, VIDx, 6, 0, 1, 1}, /* Single-tagged*/
		{PCPx, VIDx, 6, 0, 1, 0}, /* Double-tagged*/
	},
	/* Tag Control Option 7*/
	{
		{PCPx, VIDx, 6, 0, 1, 1}, /* Untagged*/
		{9,    VIDx, 3, 0, 1, 1}, /* Single-tagged*/
		{9,    VIDx, 3, 0, 1, 0}  /* Double-tagged*/
	}
};

static void mc_vlan_rules_set(struct gpe_vlan_rule_table *r)
{
	/* Setup MC rules */
	memset(r, 0, sizeof(*r)*MC_TREATMENTS_PER_EXT_VLAN);
	r[0].def = 1;
	r[0].valid = 1;
	r[0].zero_enable = 1;

	r[1].def = 1;
	r[1].valid = 1;
	r[1].one_enable = 1;

	r[2].def = 1;
	r[2].valid = 1;
	r[2].two_enable = 1;
}

static void mc_vlan_treatments_set(const uint16_t tci,
				   struct mc_treatment *ref_tbl,
				   struct gpe_vlan_treatment_table *t)
{
	uint8_t i, pcp;
	uint16_t vid;

	pcp = tci & 0x7;
	vid = (tci >> 4) & 0xFFF;

	for (i = 0; i < MC_TREATMENTS_PER_EXT_VLAN; i++) {
		memset(&t[i], 0, sizeof(*t));
		t[i].tagb_treatment = 0xF;

		t[i].taga_treatment =
				ref_tbl[i].taga_treatment == PCPx ?
					pcp :
					ref_tbl[i].taga_treatment;

		t[i].taga_vid_treatment =
				ref_tbl[i].taga_vid_treatment == VIDx ?
					vid :
					ref_tbl[i].taga_vid_treatment;

		t[i].taga_tpid_treatment =
				ref_tbl[i].taga_tpid_treatment;
		t[i].discard_enable	=
				ref_tbl[i].discard_enable;
		t[i].outer_not_generate =
				ref_tbl[i].outer_not_generate;
		t[i].inner_not_generate = 
				ref_tbl[i].inner_not_generate;
		t[i].valid = 1;
	}
}

static enum omci_api_return mc_us_vlan_rules_set(struct omci_api_ctx *ctx,
					    const uint8_t us_igmp_tag_ctrl,
					    const uint16_t us_igmp_tci,
					    uint16_t *num_rules,
					    struct gpe_vlan_rule_table *r,
					    struct gpe_vlan_treatment_table *t)
{
	uint8_t opt_idx;

	switch (us_igmp_tag_ctrl) {
	case 0:
		/* No rules/treatments are needed */
		*num_rules = 0;
		return OMCI_API_SUCCESS;
	case 1:
	case 2:
	case 3:
		opt_idx = us_igmp_tag_ctrl - 1;
		break;
	default:
		DBG(OMCI_API_ERR, ("%s: unsupported US Tag Ctrl 0x%02X\n",
			  __FUNCTION__, us_igmp_tag_ctrl));
		return OMCI_API_ERROR;
	}

	mc_vlan_rules_set(r);

	mc_vlan_treatments_set(us_igmp_tci, &us_mc_treatment[opt_idx][0], t);

	*num_rules = MC_TREATMENTS_PER_EXT_VLAN;

	return OMCI_API_SUCCESS;
}

static enum omci_api_return mc_ds_vlan_rules_set(struct omci_api_ctx *ctx,
					    const uint8_t ds_igmp_tag_ctrl,
					    const uint16_t ds_igmp_tci,
					    uint16_t *num_rules,
					    struct gpe_vlan_rule_table *r,
					    struct gpe_vlan_treatment_table *t)
{
	uint8_t opt_idx;

	switch (ds_igmp_tag_ctrl) {
	case 0:
		/* No rules/treatments are needed */
		*num_rules = 0;
		return OMCI_API_SUCCESS;
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
		opt_idx = ds_igmp_tag_ctrl - 1;
		break;
	default:
		DBG(OMCI_API_ERR, ("%s: unsupported DS Tag Ctrl 0x%02X\n",
			  __FUNCTION__, ds_igmp_tag_ctrl));
		return OMCI_API_ERROR;
	}

	mc_vlan_rules_set(r);

	mc_vlan_treatments_set(ds_igmp_tci, &ds_mc_treatment[opt_idx][0], t);

	*num_rules = MC_TREATMENTS_PER_EXT_VLAN;

	return OMCI_API_SUCCESS;
}
#endif /* defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)*/

enum omci_api_return
omci_api_multicast_operations_profile_mc_ext_vlan_update(struct omci_api_ctx
							 *ctx,
							 const uint16_t lan_idx,
							 const uint16_t
							 ext_vlan_mc_us_idx,
							 const uint16_t
							 ext_vlan_mc_ds_idx,
							 const uint8_t
							 us_igmp_tag_ctrl,
							 const uint16_t
							 us_igmp_tci,
							 const uint8_t
							 ds_igmp_mc_tag_ctrl,
							 const uint16_t
							 ds_igmp_mc_tci)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	uint8_t enable_mc[] = {0, 0}, i;
	union gpe_ext_vlan_get_u ext_vlan;
	uint8_t tag_ctrl[] = {us_igmp_tag_ctrl, ds_igmp_mc_tag_ctrl};
	uint16_t tci[] = {us_igmp_tci, ds_igmp_mc_tci};
	uint16_t ext_vlan_idx[] = {ext_vlan_mc_us_idx, ext_vlan_mc_ds_idx};
	
	mc_vlan_rules_set_t f[] = {mc_us_vlan_rules_set, mc_ds_vlan_rules_set};

	for (i = 0; i < ARRAY_SIZE(ext_vlan_idx); i++) {
		if (tag_ctrl[i] == 0)
			continue;

		memset(&ext_vlan, 0, sizeof(ext_vlan));
		ext_vlan.in.index = ext_vlan_idx[i];
		/* Get ExtVLAN entry */
		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_GET,
			      &ext_vlan, sizeof(ext_vlan));
		if (ret != OMCI_API_SUCCESS)
			return ret;

		ret = f[i](ctx, tag_ctrl[i], tci[i],
			   &ext_vlan.out.num_valid_rules,
			   ext_vlan.out.vlan_rule_tbl,
			   ext_vlan.out.vlan_treatment_tbl);

		if (ret != OMCI_API_SUCCESS)
			return ret;
	
		/* Set ExtVLAN entry */
		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
			      &ext_vlan, sizeof(ext_vlan));
		if (ret != OMCI_API_SUCCESS)
			return ret;
	
		enable_mc[i] = 1;
	}

	ret = omci_api_lan_port_mc_ext_vlan_modify(ctx, lan_idx,
						   enable_mc[1],
						   enable_mc[0]);
	if (ret != OMCI_API_SUCCESS)
		return ret;
#endif /* defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)*/
	return ret;
}

enum omci_api_return
omci_api_multicast_operations_profile_mc_ext_vlan_clear(struct omci_api_ctx
							 *ctx,
							 const uint16_t lan_idx,
							 const uint16_t
							 ext_vlan_mc_us_idx,
							 const uint16_t
							 ext_vlan_mc_ds_idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	union gpe_ext_vlan_get_u ext_vlan;
	uint16_t idx[] = {ext_vlan_mc_us_idx, ext_vlan_mc_ds_idx}, i;

	for (i = 0; i < ARRAY_SIZE(idx); i++) {
		memset(&ext_vlan, 0, sizeof(ext_vlan));
		ext_vlan.in.index = idx[i];
		/* Get ExtVLAN entry */
		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_GET,
			      &ext_vlan, sizeof(ext_vlan));
		if (ret != OMCI_API_SUCCESS)
			return ret;
	
		memset(ext_vlan.out.vlan_rule_tbl, 0,
		       sizeof(ext_vlan.out.vlan_rule_tbl));
		memset(ext_vlan.out.vlan_treatment_tbl, 0,
		       sizeof(ext_vlan.out.vlan_treatment_tbl));
	
		/* Set ExtVLAN entry */
		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_EXT_VLAN_SET,
			      &ext_vlan, sizeof(ext_vlan));
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	ret = omci_api_lan_port_mc_ext_vlan_modify(ctx, lan_idx, 0, 0);
	if (ret != OMCI_API_SUCCESS)
		return ret;
#endif /* defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)*/
	return ret;
}

enum omci_api_return
omci_api_multicast_operations_profile_update(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint8_t igmp_version,
	uint8_t igmp_function,
	uint8_t immediate_leave,
	uint16_t us_igmp_tci,
	uint8_t us_igmp_tag_control,
	uint32_t us_igmp_rate,
	uint8_t robustness,
	uint32_t querier_ip_address,
	uint32_t query_interval,
	uint32_t query_max_response_time,
	uint32_t last_member_query_interval,
	uint16_t ds_igmp_mc_tci,
	uint8_t ds_igmp_mc_tag_control)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	struct omci_api_mcc_profile profile;
	uint32_t idx = 0;
#endif

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   igmp_version=%u\n"
		  "   igmp_function=%u\n" "   immediate_leave=%u\n"
		  "   us_igmp_tci=%u\n" "   us_igmp_tag_control=%u\n"
		  "   us_igmp_rate=%u\n" "   robustness=%u\n"
		  "   querier_ip_address=%u\n" "   query_interval=%u\n"
		  "   query_max_response_time=%u\n"
		  "   last_member_query_interval=%u\n",
		  __FUNCTION__,
		  me_id, igmp_version, igmp_function, immediate_leave,
		  us_igmp_tci, us_igmp_tag_control,
		  us_igmp_rate, robustness,
		  querier_ip_address, query_interval,
		  query_max_response_time, last_member_query_interval));

#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	ret = index_get(ctx, MAPPER_MCOPPROFILE_MEID_TO_IDX, me_id, &idx);
	if (ret != OMCI_API_SUCCESS) {
		ret = id_map(ctx, MAPPER_MCOPPROFILE_MEID_TO_IDX, me_id, &idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	memset(&profile, 0, sizeof(profile));

	profile.valid = true;
	profile.igmp_ver = igmp_version;
	profile.igmp_func = igmp_function;
	profile.imm_leave = immediate_leave ? true : false;
	profile.us_igmp_tci = us_igmp_tci;
	profile.us_igmp_tag_ctrl = us_igmp_tag_control;
	profile.us_igmp_rate = us_igmp_rate;
	profile.ds_igmp_mc_tag_ctrl = ds_igmp_mc_tag_control;
	profile.ds_igmp_mc_tci = ds_igmp_mc_tci;

	ret = omci_api_mcc_profile_update(ctx, (uint8_t)idx, &profile);
#endif

	return ret;
}

enum omci_api_return
omci_api_multicast_operations_profile_dynamic_acl_table_update(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	const struct omci_api_multicast_operations_profile_acl *acl)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	uint32_t idx = 0;
#endif

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n", __FUNCTION__, me_id));

#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	ret = index_get(ctx, MAPPER_MCOPPROFILE_MEID_TO_IDX, me_id, &idx);
	if (ret != OMCI_API_SUCCESS) {
		ret = id_map(ctx, MAPPER_MCOPPROFILE_MEID_TO_IDX, me_id, &idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	ret = omci_api_mcc_profile_dacl_update(ctx, idx, acl);
#endif

	return ret;
}

enum omci_api_return
omci_api_multicast_operations_profile_destroy(
	struct omci_api_ctx *ctx,
	uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	uint32_t idx = 0;

	ret = index_get(ctx, MAPPER_MCOPPROFILE_MEID_TO_IDX, me_id, &idx);
	if (ret == OMCI_API_SUCCESS)
		id_remove(ctx, MAPPER_MCOPPROFILE_MEID_TO_IDX, me_id);
#endif
	return ret;
}

enum omci_api_return
omci_api_multicast_operations_profile_static_acl_table_entry_add(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint16_t table_idx,
	uint16_t gem_port_id,
	uint16_t vlan_id,
	const uint8_t src_ip_addr[4],
	const uint8_t dest_ip_addr_mc_range_start[4],
	const uint8_t dest_ip_addr_mc_range_end[4],
	uint32_t imputed_group_bandwidth)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   table_idx=%u\n"
		  "   gem_port_id=%u\n" "   vlan_id=%u\n"
		  "   src_ip_addr=%u.%u.%u.%u\n"
		  "   dest_ip_addr_mc_range_start=%u.%u.%u.%u\n"
		  "   dest_ip_addr_mc_range_end=%u.%u.%u.%u\n"
		  "   imputed_group_bandwidth=%u\n",
		  __FUNCTION__,
		  me_id, table_idx, gem_port_id,
		  vlan_id, src_ip_addr[0], src_ip_addr[1], src_ip_addr[2],
		  src_ip_addr[3], dest_ip_addr_mc_range_start[0],
		  dest_ip_addr_mc_range_start[1],
		  dest_ip_addr_mc_range_start[2],
		  dest_ip_addr_mc_range_start[3], dest_ip_addr_mc_range_end[0],
		  dest_ip_addr_mc_range_end[1], dest_ip_addr_mc_range_end[2],
		  dest_ip_addr_mc_range_end[3], imputed_group_bandwidth));

	/** \todo add implementation */

	return ret;
}

enum omci_api_return
omci_api_multicast_operations_profile_static_acl_table_entry_remove(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint16_t table_idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   table_idx=%u\n",
		  __FUNCTION__, me_id, table_idx));

	/** \todo add implementation */

	return ret;
}

enum omci_api_return
omci_api_multicast_operations_profile_lost_group_list_table_get(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	unsigned int *entry_num,
	struct omci_api_multicast_operations_profile_lost_group_list_table_entry
	**entries)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	struct omci_api_multicast_operations_profile_lost_group_list_table_entry *table;
	struct omci_api_mcc_lost_groups_list list;
	uint32_t idx = 0;
#endif

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	ret = index_get(ctx, MAPPER_MCOPPROFILE_MEID_TO_IDX, me_id, &idx);
	if (ret != OMCI_API_SUCCESS) {
		ret = id_map(ctx, MAPPER_MCOPPROFILE_MEID_TO_IDX, me_id, &idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	ret = omci_api_mcc_lost_groups_list_get(ctx, (uint8_t)idx, &list);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	if (list.count == 0) {
		*entry_num = 0;
		*entries = 0;
		return ret;
	}

	table = IFXOS_MemAlloc(list.count * sizeof(*table));
	if (table == NULL)
		return OMCI_API_NO_MEMORY;

	memset(table, 0, list.count * sizeof(*table));
	for (idx = 0; idx < list.count; idx++) {
		table[idx].vlan_id = list.entry[idx].vlan_id;
		*((uint32_t*)(table[idx].mc_dest_ip_addr)) =
							list.entry[idx].addr;

	}
	*entry_num = list.count;
	*entries = table;
#else
	*entry_num = 0;
	*entries = NULL;
#endif

	return ret;
}

/** @} */
