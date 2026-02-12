/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_vlan_tagging_filter_data.h"

/** \addtogroup OMCI_API_ME_VLAN_TAGGING_FILTER_DATA

   @{
*/

struct vops
{
	uint32_t index:8;
	uint32_t tci_mask:16;
	uint32_t untagged_drop:1;
	uint32_t tagged_pass:1;
	uint32_t tagged_drop:1;
	uint32_t pass_on_match:1;
	uint32_t bi_directional:1;
	uint32_t untagged_bridging:1;
};

struct vops vops[] = {
	{0x00,0x0000,0,1,0,1,0,1},
	{0x01,0x0000,0,0,1,0,0,1},
	{0x02,0x0000,0,1,0,1,0,0},
	{0x03,0x0fff,0,0,0,1,1,1},
	{0x04,0x0fff,1,0,0,1,1,0},
	{0x05,0x0fff,0,0,0,0,0,1},
	{0x06,0x0fff,1,0,0,0,0,0},
	{0x07,0xe000,0,0,0,1,1,1},
	{0x08,0xe000,1,0,0,1,1,0},
	{0x09,0xe000,0,0,0,0,0,1},
	{0x0a,0xe000,1,0,0,0,0,0},
	{0x0b,0xefff,0,0,0,1,1,1},
	{0x0c,0xefff,1,0,0,1,1,0},
	{0x0d,0xefff,0,0,0,0,0,1},
	{0x0e,0xefff,1,0,0,0,0,0},
	{0x0f,0x0fff,0,0,0,1,1,1},
	{0x10,0x0fff,1,0,0,1,1,0},
	{0x11,0xe000,0,0,0,1,1,1},
	{0x12,0xe000,1,0,0,1,1,0},
	{0x13,0xefff,0,0,0,1,1,1},
	{0x14,0xefff,1,0,0,1,1,0},
	{0x15,0x0000,0,1,0,1,0,0},
	{0x16,0x0fff,0,0,0,1,0,1},
	{0x17,0x0fff,1,0,0,1,0,0},
	{0x18,0xe000,0,0,0,1,0,1},
	{0x19,0xe000,1,0,0,1,0,0},
	{0x1a,0xefff,0,0,0,1,0,1},
	{0x1b,0xefff,1,0,0,1,0,0},
	{0x1c,0x0fff,0,0,0,1,1,1},
	{0x1d,0x0fff,1,0,0,1,1,0},
	{0x1e,0xe000,0,0,0,1,1,1},
	{0x1f,0xe000,1,0,0,1,1,0},
	{0x20,0xefff,0,0,0,1,1,1},
	{0x21,0xefff,1,0,0,1,1,0}
};

enum omci_api_return
omci_api_vlan_tagging_filter_data_update(struct omci_api_ctx *ctx,
					 uint16_t me_id,
					 const uint16_t filter_list[OMCI_API_VLAN_TAGGINGFILTERDATA_FILTERLIST_SIZE],
					 uint8_t num,
					 uint8_t fwrd_op)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t vlan_grp;
	uint32_t bridge_port_idx;
	uint8_t i;
	struct gpe_tagging tagging;
	struct gpe_table_entry entry;
	struct gpe_bridge_port_table *bridge_port = &entry.data.bridge_port;
	struct gpe_sce_constants constants;

	DBG(OMCI_API_MSG, ("%s"
		  " me_id=%u"
		  " num=%u"
		  " fwrd_op=%u\n",
		  __FUNCTION__,
		  me_id, num, fwrd_op));
	if (num > OMCI_API_VLAN_TAGGINGFILTERDATA_FILTERLIST_SIZE)
		return -1;

	/* create/get mapping  */
	ret = bridge_port_idx_get(ctx, -1, me_id, &bridge_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return -2;

	ret = index_get(ctx, MAPPER_VLANTFD_MEID_TO_VLANGRP, me_id, &vlan_grp);
	if (ret == OMCI_API_NOT_FOUND) {
		ret = id_map(ctx, MAPPER_VLANTFD_MEID_TO_VLANGRP,
			     me_id, &vlan_grp);
		if (ret != OMCI_API_SUCCESS)
			return -3;
	} else if (ret != OMCI_API_SUCCESS) {
		return -4;
	}

	memset(&tagging, 0x00, sizeof(tagging));
	tagging.num_valid_vlans = num;
	tagging.index = vlan_grp;

	if (fwrd_op >= sizeof(vops)/sizeof(vops[0]))
		fwrd_op = 0;

	for (i = 0; i < tagging.num_valid_vlans; i++)
		tagging.vlan_tbl[i].tci =
					filter_list[i] & vops[fwrd_op].tci_mask;

	if (vops[fwrd_op].untagged_bridging) {
		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_GPE_SCE_CONSTANTS_GET,
			      &constants, sizeof(constants));
		if (ret != OMCI_API_SUCCESS)
			return ret;

		tagging.vlan_tbl[tagging.num_valid_vlans++].tci =
		       constants.default_outer_vid & vops[fwrd_op].tci_mask;
	}

	tagging.tagging_filter_tbl.valid =
				tagging.num_valid_vlans ? true : false;
	tagging.tagging_filter_tbl.pass_on_match_enable =
				vops[fwrd_op].pass_on_match;
	tagging.tagging_filter_tbl.untagged_drop_enable =
				vops[fwrd_op].untagged_drop;
	tagging.tagging_filter_tbl.tagged_drop_enable =
				vops[fwrd_op].tagged_drop;
	tagging.tagging_filter_tbl.tagged_pass_enable =
				vops[fwrd_op].tagged_pass;
	tagging.tagging_filter_tbl.tci_mask =
				vops[fwrd_op].tci_mask;
	tagging.tagging_filter_tbl.vlan_table_index =
				vlan_grp * OMCI_API_VLAN_GRP_SIZE;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TAGGING_FILTER_SET,
		      &tagging, sizeof(tagging));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, bridge_port_idx,
			 sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != OMCI_API_SUCCESS)
		return -6;

	bridge_port->tagging_filter_ingress = vlan_grp;
	bridge_port->tagging_filter_ingress_enable = true;
	if (vops[fwrd_op].bi_directional) {
		bridge_port->tagging_filter_egress = vlan_grp;
		bridge_port->tagging_filter_egress_enable = true;
	} else {
		bridge_port->tagging_filter_egress_enable = false;
	}
	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != OMCI_API_SUCCESS)
		return -7;

	return ret;
}

enum omci_api_return
omci_api_vlan_tagging_filter_data_destroy(struct omci_api_ctx *ctx,
					  uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t vlan_grp;
	uint32_t bridge_port_idx;
	struct gpe_table_entry entry;
	struct gpe_bridge_port_table *bridge_port = &entry.data.bridge_port;
	struct gpe_tagging tagging;

	DBG(OMCI_API_MSG, ("%s me_id=%u\n", __FUNCTION__, me_id));

	ret = bridge_port_idx_get(ctx, -1, me_id, &bridge_port_idx);
	if (ret == OMCI_API_SUCCESS) {
		/* remove ONU_GPE_BRIDGE_PORT_TABLE_ID */
		ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID,
				 bridge_port_idx,
				 sizeof(struct gpe_bridge_port_table), &entry);
		if (ret != OMCI_API_SUCCESS)
			return -3;

		bridge_port->tagging_filter_ingress_enable = false;
		bridge_port->tagging_filter_egress_enable = false;
		ret = table_write(ctx, sizeof(struct gpe_bridge_port_table),
				  &entry);
		if (ret != OMCI_API_SUCCESS)
			return -4;
	}

	ret = index_get(ctx, MAPPER_VLANTFD_MEID_TO_VLANGRP, me_id, &vlan_grp);
	if (ret == OMCI_API_SUCCESS) {
		memset(&tagging, 0x00, sizeof(tagging));
		tagging.index = vlan_grp;
		tagging.num_valid_vlans = 0;
		tagging.tagging_filter_tbl.vlan_table_index =
					      vlan_grp * OMCI_API_VLAN_GRP_SIZE;
		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_GPE_TAGGING_FILTER_SET,
			      &tagging, sizeof(tagging));
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	/* remove mapping */
	ret = id_remove(ctx, MAPPER_VLANTFD_MEID_TO_VLANGRP, me_id);
	if (ret != OMCI_API_SUCCESS) {
		(void)error_notify(ctx, 84, me_id,
				   OMCI_API_ACTION_DESTROY, ret);
		return -7;
	}

	return ret;
}

/** @} */
