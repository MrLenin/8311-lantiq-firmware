/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_traffic_descriptor.h"

/** \addtogroup OMCI_API_TABLE_ACCESS

   @{
*/

const uint8_t mc_ip_tbl[][4] = {
	{224, 0, 0, 22},
	{224, 0, 0, 2},
	{224, 0, 0, 1}
};

enum omci_api_return table_read(struct omci_api_ctx *ctx,
				const uint32_t id,
				const uint16_t idx,
				const uint32_t size,
				struct gpe_table_entry *entry)
{
	enum omci_api_return ret;

	memset(entry, 0x00, size);
	entry->id = id;
	if (GPE_IS_PE_TABLE(id))
		entry->instance = 0x1;
	else
		entry->instance = 0;
	entry->index = idx;
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TABLE_ENTRY_GET, entry,
		      offsetof(struct gpe_table_entry, data) + size);
	if (ret != OMCI_API_SUCCESS)
		DBG(OMCI_API_ERR,
			("table_read: failed id %d, idx %d, size %d\n",
							id, idx, size));
	return ret;
}

enum omci_api_return table_write(struct omci_api_ctx *ctx,
				 const uint32_t size,
				 struct gpe_table_entry *entry)
{
	enum omci_api_return ret;

	if (GPE_IS_PE_TABLE(entry->id))
		entry->instance = 0x3F;
	else
		entry->instance = 0;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TABLE_ENTRY_SET, entry,
		      offsetof(struct gpe_table_entry, data) + size);
	if (ret != OMCI_API_SUCCESS)
		DBG(OMCI_API_MSG,
			("table_write: failed id %d, idx %d, size %d\n",
				entry->id, entry->index, size));
	return ret;
}

/** Modify multicast forwarding table entries (add or delete).
    This function is used to add or remove a multicast forwarding entry to/from
    the multicast forwarding table.

    Adding/removing ports to/from existing multicast groups is done on-the-fly.

	\param mcc MCC context.
	\param add Controls, if the entry shall be added or deleted.
	\param bridge_idx This selects the bridge (one of 8 bridges)
	\param port_map This bit map defines, to which bridge ports a multicast
	                packet shall be replicated.
	\param ip IPv4 multicast address, index 0 holds the first byte "AA" of a
	           IP address AA.BB.CC.DD

	\return Return value as follows:
	- OMCI_API_SUCCESS The function has successfully returned.
	- Others in case of errors.
*/
static enum omci_api_return mcc_short_fwd_entry_delete(struct omci_api_ctx *ctx,
						     const uint8_t bridge_idx,
						     const uint8_t ip[4])
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	memset(&entry, 0x00, sizeof(entry));

	entry.data.short_fwd_table_ipv4_mc.ip_address = 
				ip[0] << 24 | ip[1] << 16 | ip[2] << 8  | ip[3];

	entry.data.short_fwd_table_ipv4_mc.bridge_index = bridge_idx;
	entry.data.short_fwd_table_ipv4_mc.port_map = 0;
	/** \todo it will be better to have gpe tables related definitions
	  (gnerated automatically) for the key_code possible values.
	  Here we use:
	  4: IPv4 (only used for ONU_GPE_SHORT_FWD_TABLE_IPV4) */
	entry.data.short_fwd_table_ipv4_mc.key_code = 4;
	entry.data.short_fwd_table_ipv4_mc.fid = ONU_GPE_CONSTANT_VAL_DEFAULT_FID;
	entry.data.short_fwd_table_ipv4_mc.include_enable = 1;
	entry.data.short_fwd_table_ipv4_mc.msf_enable = 0;
	entry.data.short_fwd_table_ipv4_mc.zero_dynamic_enable = 0;
	entry.data.short_fwd_table_ipv4_mc.zero_limitation = 0;
	entry.data.short_fwd_table_ipv4_mc.one_port_map_indicator = 1;
	entry.data.short_fwd_table_ipv4_mc.igmp = 1; /* set IGMP flag*/

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_SHORT_FWD_DELETE,
		      &entry,
		      TABLE_ENTRY_SIZE(entry.data.short_fwd_table_ipv4_mc));
	if (ret == OMCI_API_SUCCESS) {
		DBG(OMCI_API_MSG, ("MCC IPv4 MC entry %s: %u.%u.%u.%u\n",
				   "removed", ip[0], ip[1], ip[2], ip[3]));
	}

	return ret;
}

static enum omci_api_return
mcc_short_fwd_entry_modify(struct omci_api_ctx *ctx,
			   const uint8_t bridge_idx,
			   const uint8_t port_map_index,
			   const uint8_t ip[4])
{
	enum omci_api_return ret;
	struct gpe_ipv4_mc_port_modify mc_port;

	mc_port.bridge_index = bridge_idx;
	mc_port.port_map_index = port_map_index;
	mc_port.fid = ONU_GPE_CONSTANT_VAL_DEFAULT_FID;
	mc_port.igmp = 1;
	memcpy(&mc_port.ip[0], ip, 4);

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_SHORT_FWD_IPV4_MC_PORT_MODIFY,
		      &mc_port, sizeof(mc_port));
	if (ret == OMCI_API_SUCCESS) {
		DBG(OMCI_API_MSG, ("MCC IPv4 MC port map index %u %s: "
				"%u.%u.%u.%u\n",
				   port_map_index,
				   "modified",
				   ip[0], ip[1], ip[2], ip[3]));
	}

	return ret;
}


enum omci_api_return
omci_api_bridge_flooding_modify(struct omci_api_ctx *ctx,
				const bool is_uni,
				const uint8_t lan_port,
				const uint16_t bridge_index,
				const uint16_t bridge_port_index)
{
	int i, empty = -1, idx_s, idx_e;
	enum omci_api_return ret;
	struct gpe_table_entry entry;
	uint32_t flooding_index[OMCI_API_MAX_BRIDGE_PORT];

	if (is_uni && lan_port >= ONU_GPE_MAX_UNI) {
		DBG(OMCI_API_ERR,
			("omci_api_bridge_flooding_modify: wrong"
			 " LAN port index 0x%02X\n", lan_port));
		return OMCI_API_ERROR;
	}

	ret = table_read(ctx, ONU_GPE_BRIDGE_TABLE_ID, bridge_index,
			 sizeof(struct gpe_bridge_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;
	
	/* first 4 entries are hard mapped to UNI0..3 */
	flooding_index[0] = entry.data.bridge.egress_bridge_port_index0;
	flooding_index[1] = entry.data.bridge.egress_bridge_port_index1;
	flooding_index[2] = entry.data.bridge.egress_bridge_port_index2;
	flooding_index[3] = entry.data.bridge.egress_bridge_port_index3;
	flooding_index[4] = entry.data.bridge.egress_bridge_port_index4;
	flooding_index[5] = entry.data.bridge.egress_bridge_port_index5;
	flooding_index[6] = entry.data.bridge.egress_bridge_port_index6;
	flooding_index[7] = entry.data.bridge.egress_bridge_port_index7;
	flooding_index[8] = entry.data.bridge.egress_bridge_port_index8;
	flooding_index[9] = entry.data.bridge.egress_bridge_port_index9;
	flooding_index[10] = entry.data.bridge.egress_bridge_port_index10;
	flooding_index[11] = entry.data.bridge.egress_bridge_port_index11;
	flooding_index[12] = entry.data.bridge.egress_bridge_port_index12;
	flooding_index[13] = entry.data.bridge.egress_bridge_port_index13;
	flooding_index[14] = entry.data.bridge.egress_bridge_port_index14;
	flooding_index[15] = entry.data.bridge.egress_bridge_port_index15;

	if (is_uni) {
		idx_s = lan_port;
		idx_e = lan_port;
	} else {
		idx_s = ONU_GPE_MAX_UNI;
		idx_e = OMCI_API_MAX_BRIDGE_PORT - 1;
	}

	for (i = idx_s; i <= idx_e; i++) {
		if (entry.data.bridge.flooding_bridge_port_enable & (1 << i)
		    && flooding_index[i] == bridge_port_index) {
			return OMCI_API_SUCCESS;
		} else if (!(entry.data.bridge.flooding_bridge_port_enable & (1 << i))
			   && empty == -1) {
			empty = i;
			break;
		}
	}

	if (empty == -1) {
		DBG(OMCI_API_ERR,
			("omci_api_bridge_flooding_modify: failed to find "
			 "free slot,  bridge=%u, bridge_port=%u, is_uni=%u\n",
			bridge_index, bridge_port_index, is_uni));
		return OMCI_API_ERROR;
	}

	switch (empty) {
	case 0:
		entry.data.bridge.egress_bridge_port_index0 = bridge_port_index;
		break;
	case 1:
		entry.data.bridge.egress_bridge_port_index1 = bridge_port_index;
		break;
	case 2:
		entry.data.bridge.egress_bridge_port_index2 = bridge_port_index;
		break;
	case 3:
		entry.data.bridge.egress_bridge_port_index3 = bridge_port_index;
		break;
	case 4:
		entry.data.bridge.egress_bridge_port_index4 = bridge_port_index;
		break;
	case 5:
		entry.data.bridge.egress_bridge_port_index5 = bridge_port_index;
		break;
	case 6:
		entry.data.bridge.egress_bridge_port_index6 = bridge_port_index;
		break;
	case 7:
		entry.data.bridge.egress_bridge_port_index7 = bridge_port_index;
		break;
	case 8:
		entry.data.bridge.egress_bridge_port_index8 = bridge_port_index;
		break;
	case 9:
		entry.data.bridge.egress_bridge_port_index9 = bridge_port_index;
		break;
	case 10:
		entry.data.bridge.egress_bridge_port_index10 = bridge_port_index;
		break;
	case 11:
		entry.data.bridge.egress_bridge_port_index11 = bridge_port_index;
		break;
	case 12:
		entry.data.bridge.egress_bridge_port_index12 = bridge_port_index;
		break;
	case 13:
		entry.data.bridge.egress_bridge_port_index13 = bridge_port_index;
		break;
	case 14:
		entry.data.bridge.egress_bridge_port_index14 = bridge_port_index;
		break;
	case 15:
		entry.data.bridge.egress_bridge_port_index15 = bridge_port_index;
		break;
	}

	entry.data.bridge.flooding_bridge_port_enable |= (1 << empty);

	DBG(OMCI_API_MSG, ("BRIDGE_TABLE[%d]: set bridge port flooding %d\n",
		bridge_index, bridge_port_index));

	ret = table_write(ctx, sizeof(struct gpe_bridge_table), &entry);

	/** add / modify well known MC IPv4 entries */
	for (i = 0; i < sizeof(mc_ip_tbl)/sizeof(mc_ip_tbl[0]); i++) {
		mcc_short_fwd_entry_modify(ctx, bridge_index, empty, &mc_ip_tbl[i][0]);
	}

	return ret;
}

enum omci_api_return omci_api_bridge_init(struct omci_api_ctx *ctx,
					  const uint16_t bridge_index)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;
	int i;

	ret = table_read(ctx, ONU_GPE_BRIDGE_TABLE_ID, bridge_index,
			 sizeof(struct gpe_bridge_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.data.bridge.flooding_bridge_port_enable = 0;
	entry.data.bridge.egress_bridge_port_index0 = 127;
	entry.data.bridge.egress_bridge_port_index1 = 127;
	entry.data.bridge.egress_bridge_port_index2 = 127;
	entry.data.bridge.egress_bridge_port_index3 = 127;
	entry.data.bridge.egress_bridge_port_index4 = 127;
	entry.data.bridge.egress_bridge_port_index5 = 127;
	entry.data.bridge.egress_bridge_port_index6 = 127;
	entry.data.bridge.egress_bridge_port_index7 = 127;
	entry.data.bridge.egress_bridge_port_index8 = 127;
	entry.data.bridge.egress_bridge_port_index9 = 127;
	entry.data.bridge.egress_bridge_port_index10 = 127;
	entry.data.bridge.egress_bridge_port_index11 = 127;
	entry.data.bridge.egress_bridge_port_index12 = 127;
	entry.data.bridge.egress_bridge_port_index13 = 127;
	entry.data.bridge.egress_bridge_port_index14 = 127;
	entry.data.bridge.egress_bridge_port_index15 = 127;

	ret = table_write(ctx, sizeof(struct gpe_bridge_table), &entry);

	/** remove well known MC IPv4 entries */
	for (i = 0; i < sizeof(mc_ip_tbl)/sizeof(mc_ip_tbl[0]); i++) {
		mcc_short_fwd_entry_delete(ctx, bridge_index, &mc_ip_tbl[i][0]);
	}

	return ret;
}

enum omci_api_return
omci_api_bridge_get(struct omci_api_ctx *ctx,
		    const uint16_t bridge_index,
		    uint8_t bridge_port[OMCI_API_MAX_BRIDGE_PORT])
{
	unsigned int i;
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_BRIDGE_TABLE_ID, bridge_index,
			 sizeof(struct gpe_bridge_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	bridge_port[0] = entry.data.bridge.egress_bridge_port_index0;
	bridge_port[1] = entry.data.bridge.egress_bridge_port_index1;
	bridge_port[2] = entry.data.bridge.egress_bridge_port_index2;
	bridge_port[3] = entry.data.bridge.egress_bridge_port_index3;
	bridge_port[4] = entry.data.bridge.egress_bridge_port_index4;
	bridge_port[5] = entry.data.bridge.egress_bridge_port_index5;
	bridge_port[6] = entry.data.bridge.egress_bridge_port_index6;
	bridge_port[7] = entry.data.bridge.egress_bridge_port_index7;
	bridge_port[8] = entry.data.bridge.egress_bridge_port_index8;
	bridge_port[9] = entry.data.bridge.egress_bridge_port_index9;
	bridge_port[10] = entry.data.bridge.egress_bridge_port_index10;
	bridge_port[11] = entry.data.bridge.egress_bridge_port_index11;
	bridge_port[12] = entry.data.bridge.egress_bridge_port_index12;
	bridge_port[13] = entry.data.bridge.egress_bridge_port_index13;
	bridge_port[14] = entry.data.bridge.egress_bridge_port_index14;
	bridge_port[15] = entry.data.bridge.egress_bridge_port_index15;

	for (i = 0; i < OMCI_API_MAX_BRIDGE_PORT; i++)
		if (entry.data.bridge.flooding_bridge_port_enable & (1 << i))
			bridge_port[i] |= 0x80;

	return ret;
}

enum omci_api_return
omci_api_bridge_port_ingress_color_marking_modify(struct omci_api_ctx *ctx,
						  const uint16_t index,
						  const uint8_t color_marking)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, index,
			 sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	DBG(OMCI_API_MSG,
		("BRIDGE_PORT_TABLE[%d]: set ingress color marking %d\n",
			index, color_marking));

	entry.data.bridge_port.ingress_color_marking = color_marking;

	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_bridge_port_egress_color_marking_modify(struct omci_api_ctx *ctx,
						  const uint16_t index,
						  const uint8_t color_marking)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, index,
			 sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	DBG(OMCI_API_ERR,
		("BRIDGE_PORT_TABLE[%d]: set egress color marking %d\n",
			index, color_marking));

	entry.data.bridge_port.egress_color_marking = color_marking;

	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_bridge_port_bridge_get(struct omci_api_ctx *ctx,
				const uint16_t bridge_port_index,
				uint8_t *bridge_index)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, bridge_port_index,
			 sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	*bridge_index = entry.data.bridge_port.bridge_index;

	return ret;
}

enum omci_api_return
omci_api_bridge_port_learning_limitation_modify(struct omci_api_ctx *ctx,
						const uint16_t bridge_port_index,
						const uint8_t learning_ind,
						const uint8_t mac_learning_depth)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_LEARNING_LIMITATION_TABLE_ID,
			 bridge_port_index,
			 sizeof(struct gpe_learning_limitation_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	if (learning_ind)
		entry.data.learning_limitation.learning_limit =
			(mac_learning_depth == 0) ? 0x3ff : mac_learning_depth;
	else
		entry.data.learning_limitation.learning_limit = 0x3ff;

	DBG(OMCI_API_MSG,
		("LEARNING_LIMITATION_TABLE[%d]: set learning limit %d\n",
			bridge_port_index,
			entry.data.learning_limitation.learning_limit));

	ret = table_write(ctx, sizeof(struct gpe_learning_limitation_table),
			  &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, bridge_port_index,
			 sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	DBG(OMCI_API_MSG, ("BRIDGE_PORT_TABLE[%d]: set learning enable %d\n",
		bridge_port_index, learning_ind));

	entry.data.bridge_port.learning_enable = learning_ind;

	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_bridge_port_local_switching_modify(struct omci_api_ctx *ctx,
					    const uint16_t bridge_port_index,
					    const uint8_t port_bridging_ind)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, bridge_port_index,
			 sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	DBG(OMCI_API_MSG,
		("BRIDGE_PORT_TABLE[%d]: set local switching enable %d\n",
			bridge_port_index, port_bridging_ind));

	entry.data.bridge_port.local_switching_enable = port_bridging_ind;

	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_bridge_port_uuc_mac_flood_modify(struct omci_api_ctx *ctx,
					  const uint16_t bridge_port_index,
					  const uint8_t unknown_mac_discard)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, bridge_port_index,
			sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	/**\todo Check correct usage of uuc_flood_disable */
	if (unknown_mac_discard)
		entry.data.bridge_port.uuc_flood_disable  = 1;
	else
		entry.data.bridge_port.uuc_flood_disable = 0;

	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_bridge_port_umc_mac_flood_modify(struct omci_api_ctx *ctx,
					  const uint16_t bridge_port_index,
					  const uint8_t flag1,
					  const uint8_t flag2)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;
	uint8_t *raw;

	ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, bridge_port_index,
			sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	/* v7.5.1: Two MC flood control bits in bridge port table raw data.
	   flag1 -> data byte 15, bit 4
	   flag2 -> data byte 14, bit 2 */
	raw = (uint8_t *)&entry.data.bridge_port;
	raw[15] = (raw[15] & 0xef) | ((flag1 ? 1 : 0) << 4);
	raw[14] = (raw[14] & 0xfb) | ((flag2 ? 1 : 0) << 2);

	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_bridge_port_tp_modify(struct omci_api_ctx *ctx,
			       const uint16_t bridge_port_index,
			       const uint16_t tp_type,
			       const uint16_t tp_pointer)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, bridge_port_index,
			sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.data.bridge_port.tp_type = tp_type;
	entry.data.bridge_port.tp_pointer = tp_pointer;

	DBG(OMCI_API_MSG,
		("BRIDGE_PORT_TABLE[%d]: set tp_pointer %d, tp_type %d\n",
			bridge_port_index,
			entry.data.bridge_port.tp_pointer,
			entry.data.bridge_port.tp_type));

	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_bridge_port_eth_uni_index_get(struct omci_api_ctx *ctx,
				       uint16_t bp_me_id,
				       uint8_t *port_index)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_table_entry entry;
	uint32_t bridge_port_index = 0;

	ret = bridge_port_idx_get(ctx, -1, bp_me_id, &bridge_port_index);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	entry.id = ONU_GPE_BRIDGE_PORT_TABLE_ID;
	entry.instance = 1;
	entry.index = (uint8_t)bridge_port_index;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TABLE_ENTRY_GET, &entry,
		      TABLE_ENTRY_SIZE(entry.data.bridge_port));
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	if (entry.data.bridge_port.tp_type == 0) {
		*port_index = entry.data.bridge_port.tp_pointer;
	} else {
		*port_index = 0;
		return OMCI_API_NOT_FOUND;
	}

	return ret;
}

enum omci_api_return
omci_api_bridge_port_ingress_meter_set(struct omci_api_ctx *ctx,
				       const uint16_t bridge_port_index,
				       const uint8_t idx,
				       const bool enable)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, bridge_port_index,
			 sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	DBG(OMCI_API_MSG, ("BRIDGE_PORT_TABLE[%d]: meter_id_ingress %d\n",
		bridge_port_index, idx));

	entry.data.bridge_port.meter_id_ingress = idx;
	entry.data.bridge_port.meter_id_ingress = enable;

	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_bridge_port_egress_meter_set(struct omci_api_ctx *ctx,
				      const uint16_t bridge_port_index,
				      const uint8_t idx,
				      const bool enable)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, bridge_port_index,
			 sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	DBG(OMCI_API_MSG, ("BRIDGE_PORT_TABLE[%d]: meter_id_egress %d\n",
		bridge_port_index, idx));

	entry.data.bridge_port.meter_id_egress = idx;
	entry.data.bridge_port.meter_id_egress = enable;

	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);

	return ret;
}

enum omci_api_return omci_api_gem_port_loop_modify(struct omci_api_ctx *ctx,
						   const uint16_t gpix,
						   const uint16_t loop)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;
	struct gpe_table_entry entry_us;

	ret = table_read(ctx, ONU_GPE_DS_GEM_PORT_TABLE_ID, gpix,
			sizeof(struct gpe_ds_gem_port_table), &entry);
	if (ret != 0) return OMCI_API_ERROR;

	if (loop) {
		ret = table_read(ctx, ONU_GPE_US_GEM_PORT_TABLE_ID, gpix,
				 sizeof(struct gpe_us_gem_port_table),
				 &entry_us);
		if (ret != 0)
			return OMCI_API_ERROR;

		DBG(OMCI_API_MSG, ("DS_GEM_PORT_TABLE[%d]: enable loop\n",
			gpix));
		/* comes from ctp */
		entry.data.ds_gem_port.bridge_port_index0 =
				entry_us.data.us_gem_port.egress_queue_index;
		entry.data.ds_gem_port.gem_loopback_enable = 1;
		entry.data.ds_gem_port.valid = 1;
	} else {
		DBG(OMCI_API_MSG, ("DS_GEM_PORT_TABLE[%d]: disable loop\n",
			gpix));
		entry.data.ds_gem_port.gem_loopback_enable = 0;
		entry.data.ds_gem_port.valid = 0;
	}

	ret = table_write(ctx, sizeof(struct gpe_ds_gem_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_gem_port_interworking_modify(struct omci_api_ctx *ctx,
				      const uint16_t gpix,
				      const uint16_t interworking_option,
				      const uint8_t gem_port_type,
				      const uint8_t port_index)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;
	uint32_t i;
	uint8_t add = 1;
	uint8_t tmp[8];

	if (!(interworking_option == 1 || interworking_option == 5 ||
	      interworking_option == 6)) {
		DBG(OMCI_API_ERR,
			("DS_GEM_PORT_TABLE[%d]: wrong interworking %d value"
			 " for port %d\n",
				gpix, interworking_option, port_index));
		return OMCI_API_ERROR;
	}

	ret = table_read(ctx, ONU_GPE_DS_GEM_PORT_TABLE_ID, gpix,
			 sizeof(struct gpe_ds_gem_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	/* 1,5,6 */
	DBG(OMCI_API_MSG, ("DS_GEM_PORT_TABLE[%d]: interworking %d port %d\n",
		gpix, interworking_option, port_index));

	entry.data.ds_gem_port.interworking_option = interworking_option;
	entry.data.ds_gem_port.gem_port_type = gem_port_type;

	switch (interworking_option) {
	case 1:
		entry.data.ds_gem_port.bridge_port_index0 = port_index;
		entry.data.ds_gem_port.max_bridge_index = 0;
		break;
	case 5:
		entry.data.ds_gem_port.lan_port_index = port_index;
		break;
	case 6:
		tmp[0] = entry.data.ds_gem_port.bridge_port_index0;
		tmp[1] = entry.data.ds_gem_port.bridge_port_index1;
		tmp[2] = entry.data.ds_gem_port.bridge_port_index2;
		tmp[3] = entry.data.ds_gem_port.bridge_port_index3;
		tmp[4] = entry.data.ds_gem_port.bridge_port_index4;
		tmp[5] = entry.data.ds_gem_port.bridge_port_index5;
		tmp[6] = entry.data.ds_gem_port.bridge_port_index6;
		tmp[7] = entry.data.ds_gem_port.bridge_port_index7;
		if (entry.data.ds_gem_port.valid == 0) {
			entry.data.ds_gem_port.max_bridge_index = 0;
		} else {
			for (i=0;i<entry.data.ds_gem_port.max_bridge_index+1;
									  i++) {
				if (port_index == tmp[i]) {
					add = 0;
					break;
				}
			}
			if (add)
				entry.data.ds_gem_port.max_bridge_index++;
		}
		if (add) {
			if (entry.data.ds_gem_port.max_bridge_index == 0)
				entry.data.ds_gem_port.bridge_port_index0 =
								     port_index;
			else if (entry.data.ds_gem_port.max_bridge_index == 1)
				entry.data.ds_gem_port.bridge_port_index1 =
								     port_index;
			else if (entry.data.ds_gem_port.max_bridge_index == 2)
				entry.data.ds_gem_port.bridge_port_index2 =
								     port_index;
			else if (entry.data.ds_gem_port.max_bridge_index == 3)
				entry.data.ds_gem_port.bridge_port_index3 =
								     port_index;
			else if (entry.data.ds_gem_port.max_bridge_index == 4)
				entry.data.ds_gem_port.bridge_port_index4 =
								     port_index;
			else if (entry.data.ds_gem_port.max_bridge_index == 5)
				entry.data.ds_gem_port.bridge_port_index5 =
								     port_index;
			else if (entry.data.ds_gem_port.max_bridge_index == 6)
				entry.data.ds_gem_port.bridge_port_index6 =
								     port_index;
			else if (entry.data.ds_gem_port.max_bridge_index == 7)
				entry.data.ds_gem_port.bridge_port_index7 =
								     port_index;
		}
		break;
	}
	entry.data.ds_gem_port.valid = 1;
	ret = table_write(ctx, sizeof(struct gpe_ds_gem_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

/** Retrieve the number of connected ports

    \param[in] ctx   OMCI API context pointer
    \param[in] me_id Managed Entity identifier
    \param[inout] port_count Bridge port count
*/
enum omci_api_return omci_api_bridge_port_count_get(struct omci_api_ctx *ctx,
						    const uint16_t me_id,
						    uint8_t *port_count)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;
	uint32_t bridge_idx = 0, i, k=0;

	ret = bridge_idx_get(ctx, me_id, &bridge_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	for (i = 0; i < 128; i++) {
		ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, i,
				 sizeof(struct gpe_bridge_port_table), &entry);
		if (ret != 0)
			continue;

		if (entry.data.bridge_port.valid == 0)
			continue;

		if (entry.data.bridge_port.bridge_index == bridge_idx)
			k++;
	}

	*port_count = k;

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_bridge_port_add(struct omci_api_ctx *ctx,
					      const uint16_t bridge_port_index,
					      const uint16_t bridge_index)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	DBG(OMCI_API_MSG, ("BRIDGE_PORT_TABLE[%d] enable\n",
							bridge_port_index));

	memset(&entry.data, 0x00, sizeof(struct gpe_bridge_port_table));
	entry.id = ONU_GPE_BRIDGE_PORT_TABLE_ID;
	entry.instance = 0x3f;
	entry.index = bridge_port_index;
	entry.data.bridge_port.valid = 1;
	entry.data.bridge_port.bridge_index = bridge_index;
	entry.data.bridge_port.forwarding_method = 0;

	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_bridge_port_delete(struct omci_api_ctx *ctx,
						 const uint16_t
						 bridge_port_index)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	DBG(OMCI_API_MSG, ("BRIDGE_PORT_TABLE[%d] disable\n",
							bridge_port_index));
	memset(&entry.data, 0x00, sizeof(struct gpe_bridge_port_table));
	entry.id = ONU_GPE_BRIDGE_PORT_TABLE_ID;
	entry.instance = 0x3f;
	entry.index = bridge_port_index;

	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

/** Retrieve the Bridge location (ANI or UNI side)

   \param[in]  me_id          MAC Bridge Port Configuration data
                              ME identifier
   \param[out] ani_indication ANI side indication
                              (true - ANI side, false - UNI side)
*/
enum omci_api_return omci_api_mac_bridge_port_is_ani(struct omci_api_ctx *ctx,
						     uint16_t me_id,
						     bool *ani_indication)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_table_entry entry;
	uint32_t bridge_port_index = 0;

	ret = bridge_port_idx_get(ctx, -1, me_id, &bridge_port_index);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	entry.id = ONU_GPE_BRIDGE_PORT_TABLE_ID;
	entry.instance = 1;
	entry.index = (uint8_t)bridge_port_index;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TABLE_ENTRY_GET, &entry,
		      TABLE_ENTRY_SIZE(entry.data.bridge_port));
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	/* TP Type, indicates the type of instance connected to the egress
	    bridge port. Values 0 to 3 are valid. The MSB of this field serves
	    as the ANI indication (1 = ANI side, 0 = UNI side).
	    - 0: PPTP Ethernet UNI
	    - 1: reserved (do not use)
	    - 2: p-Mapper
	    - 3: ITP
	*/
	*ani_indication = entry.data.bridge_port.tp_type & 0x2 ? true : false;

	return ret;
}

enum omci_api_return
omci_api_bridge_port_tp_info_get(struct omci_api_ctx *ctx,
				 uint16_t me_id,
				 uint8_t *tp_type,
				 uint8_t *conn_idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_table_entry entry;
	uint32_t bridge_port_index = 0;

	ret = bridge_port_idx_get(ctx, -1, me_id, &bridge_port_index);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	entry.id = ONU_GPE_BRIDGE_PORT_TABLE_ID;
	entry.instance = 1;
	entry.index = (uint8_t)bridge_port_index;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TABLE_ENTRY_GET, &entry,
		      TABLE_ENTRY_SIZE(entry.data.bridge_port));
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	*tp_type = (uint8_t)entry.data.bridge_port.tp_type;
	*conn_idx = (uint8_t)entry.data.bridge_port.tp_pointer;

	return ret;
}

enum omci_api_return omci_api_gem_port_us_add(struct omci_api_ctx *ctx,
						const uint16_t gpix,
						const uint16_t egress_queue_index)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	DBG(OMCI_API_MSG, ("US_GEM_PORT_TABLE[%d] enable (eqidx %d)\n",
						gpix, egress_queue_index));

	memset(&entry.data, 0x00, sizeof(struct gpe_us_gem_port_table));
	entry.id = ONU_GPE_US_GEM_PORT_TABLE_ID;
	entry.index = gpix;
	entry.data.us_gem_port.valid = 1;
	entry.data.us_gem_port.egress_queue_index = egress_queue_index;
	entry.data.us_gem_port.queue_marking_mode = 1;
/*	entry.data.us_gem_port.unused2 = 0;
	entry.data.us_gem_port.dscp_table_pointer = 0;
	
	entry.data.us_gem_port.unused1 = 0;
	entry.data.us_gem_port.pppoe_enable = 0;
	entry.data.us_gem_port.napt_enable = 0;
	entry.data.us_gem_port.egress_color_marking = 0;
	entry.data.us_gem_port.ext_vlan_enable = 0;
	entry.data.us_gem_port.ext_vlan_index = 0;*/
	ret = table_write(ctx, sizeof(struct gpe_us_gem_port_table), &entry);

	return ret;
}

enum omci_api_return omci_api_gem_port_us_delete(struct omci_api_ctx *ctx,
						 const uint16_t gpix)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	DBG(OMCI_API_MSG, ("US_GEM_PORT_TABLE[%d] delete\n", gpix));

	memset(&entry.data, 0x00, sizeof(struct gpe_us_gem_port_table));
	entry.id = ONU_GPE_US_GEM_PORT_TABLE_ID;
	entry.index = gpix;
	ret = table_write(ctx, sizeof(struct gpe_us_gem_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_gem_port_us_ext_vlan_modify(struct omci_api_ctx *ctx,
				     const uint16_t gpix,
				     const bool ext_vlan_enable,
				     const uint8_t ext_vlan_index,
				     const uint8_t ext_vlan_incremental_enable)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_US_GEM_PORT_TABLE_ID, gpix,
			sizeof(struct gpe_us_gem_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.id = ONU_GPE_US_GEM_PORT_TABLE_ID;
	entry.index = gpix;
	entry.data.us_gem_port.ext_vlan_enable = ext_vlan_enable == true;
	entry.data.us_gem_port.ext_vlan_index = ext_vlan_index;
	entry.data.us_gem_port.ext_vlan_incremental_enable = ext_vlan_incremental_enable;

	ret = table_write(ctx, sizeof(struct gpe_us_gem_port_table), &entry);

	return ret;
}


enum omci_api_return omci_api_gem_port_us_info_get(struct omci_api_ctx *ctx,
						   const uint16_t gpix,
						   bool *valid)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_US_GEM_PORT_TABLE_ID, gpix,
			sizeof(struct gpe_us_gem_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	*valid = (bool)entry.data.us_gem_port.valid;

	return ret;
}

enum omci_api_return omci_api_gem_port_ds_delete(struct omci_api_ctx *ctx,
						 const uint16_t gpix)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	DBG(OMCI_API_MSG, ("DS_GEM_PORT_TABLE[%d] delete\n", gpix));

	memset(&entry.data, 0x00, sizeof(struct gpe_ds_gem_port_table));
	entry.id = ONU_GPE_DS_GEM_PORT_TABLE_ID;
	entry.index = gpix;
	entry.data.ds_gem_port.fid_mask_pcpi = ONU_GPE_FID_INNER_PCP_MASK;
	entry.data.ds_gem_port.fid_mask_pcpo = ONU_GPE_FID_OUTER_PCP_MASK;
	entry.data.ds_gem_port.fid_mask_vidi = ONU_GPE_FID_INNER_VID_MASK;
	entry.data.ds_gem_port.fid_mask_vido = ONU_GPE_FID_OUTER_VID_MASK;
	ret = table_write(ctx, sizeof(struct gpe_ds_gem_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_gem_port_ds_ext_vlan_modify(struct omci_api_ctx *ctx,
				     const uint16_t gpix,
				     const bool ext_vlan_enable,
				     const uint8_t ext_vlan_index)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_DS_GEM_PORT_TABLE_ID, gpix,
			 sizeof(struct gpe_ds_gem_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.id = ONU_GPE_DS_GEM_PORT_TABLE_ID;
	entry.index = gpix;
	entry.data.ds_gem_port.ext_vlan_enable = ext_vlan_enable == true;
	entry.data.ds_gem_port.ext_vlan_index = ext_vlan_index;

	ret = table_write(ctx, sizeof(struct gpe_ds_gem_port_table), &entry);

	return ret;
}

enum omci_api_return omci_api_gem_port_ds_type_modify(struct omci_api_ctx *ctx,
						      const uint16_t gpix,
						      const bool mc)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_DS_GEM_PORT_TABLE_ID, gpix,
			 sizeof(struct gpe_ds_gem_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.id = ONU_GPE_DS_GEM_PORT_TABLE_ID;
	entry.index = gpix;
	entry.data.ds_gem_port.gem_port_type = mc == true;

	ret = table_write(ctx, sizeof(struct gpe_ds_gem_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_gem_port_ds_ingress_color_marking_modify(struct omci_api_ctx *ctx,
						  const uint16_t gpix,
						  const uint8_t marking)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_DS_GEM_PORT_TABLE_ID, gpix,
			 sizeof(struct gpe_ds_gem_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.id = ONU_GPE_DS_GEM_PORT_TABLE_ID;
	entry.index = gpix;
	entry.data.ds_gem_port.ingress_color_marking = marking;

	ret = table_write(ctx, sizeof(struct gpe_ds_gem_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_gem_port_ds_prio_selection_modify(struct omci_api_ctx *ctx,
						  const uint16_t gpix,
						  const bool enable,
						  const uint16_t prio)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_DS_GEM_PORT_TABLE_ID, gpix,
			 sizeof(struct gpe_ds_gem_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.id = ONU_GPE_DS_GEM_PORT_TABLE_ID;
	entry.index = gpix;
	entry.data.ds_gem_port.queue_selection_mode = enable;
	entry.data.ds_gem_port.egress_queue_offset = prio;

	ret = table_write(ctx, sizeof(struct gpe_ds_gem_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_gem_port_us_queue_marking_mode_modify(struct omci_api_ctx *ctx,
						  const uint16_t gpix,
						  const uint8_t marking)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_US_GEM_PORT_TABLE_ID, gpix,
			 sizeof(struct gpe_us_gem_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.id = ONU_GPE_US_GEM_PORT_TABLE_ID;
	entry.index = gpix;
	entry.data.us_gem_port.queue_marking_mode = marking;

	ret = table_write(ctx, sizeof(struct gpe_us_gem_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_meter_create(struct omci_api_ctx *ctx, uint32_t *meter_idx)
{
	enum omci_api_return ret;
	struct gpe_meter meter;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_METER_CREATE,
		      &meter, sizeof(meter));
	if (ret != OMCI_API_SUCCESS)
		DBG(OMCI_API_ERR, ("meter create failed, ret=%d\n", ret));

	*meter_idx = meter.index;

	return ret;
}

enum omci_api_return omci_api_meter_delete(struct omci_api_ctx *ctx,
					   const uint8_t meter_idx)
{
	enum omci_api_return ret;
	struct gpe_meter meter;

	meter.index = meter_idx;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_METER_DELETE,
		      &meter, sizeof(meter));

	if (ret != OMCI_API_SUCCESS)
		DBG(OMCI_API_ERR, ("meter %u delete failed, ret=%d\n",
							meter_idx, ret));

	return ret;
}

enum omci_api_return
omci_api_meter_set(struct omci_api_ctx *ctx,
		   const uint16_t meter_index,
		   const struct omci_api_traffic_descriptor *td)
{
	enum omci_api_return ret;
	struct gpe_meter_cfg meter;

	memset(&meter, 0, sizeof(meter));
	meter.index = meter_index;
	meter.cir = td->cir;
	meter.pir = td->pir;
	meter.cbs = td->cbs;
	meter.pbs = td->pbs;
	meter.mode = td->meter_type;
	meter.color_aware = td->color_mode;

/*
	uint8_t ingress_color_marking,
	uint8_t egress_color_marking,
*/

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_METER_CFG_SET,
		      &meter, sizeof(meter));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("meter %u failed on cfg set, ret=%d\n",
					meter.index, ret));
		return ret;
	}

	return ret;
}

enum omci_api_return omci_api_gem_port_shaper_add(struct omci_api_ctx *ctx,
						const uint16_t gpix,
						const uint16_t queue_ptr,
						const uint16_t td_ptr)
{
	enum omci_api_return ret;
	uint32_t td_idx;
	uint32_t shaper_idx = 0;

	ret = index_get(ctx, MAPPER_PQUEUE_MEID_TO_TBS_IDX, queue_ptr, &shaper_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = index_get(ctx, MAPPER_TRAFFDESCR_TO_IDX, td_ptr, &td_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = omci_api_traffic_descriptor_shaper_attach(ctx, td_idx, shaper_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = omci_api_shaper_update(ctx, shaper_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return ret;
}

enum omci_api_return omci_api_gemport_meter_add(struct omci_api_ctx *ctx,
						  const uint16_t gpix,
						  const uint16_t me_id,
						  const uint16_t td_ptr)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;
	struct omci_api_traffic_descriptor td;
	uint32_t td_idx, meter_idx;

	ret = index_get(ctx, MAPPER_TRAFFDESCR_TO_IDX, td_ptr, &td_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = omci_api_traffic_descriptor_get(ctx, td_idx, &td);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = index_get(ctx, MAPPER_GEMPORTCTP_MEID_TO_METER_IDX, me_id, &meter_idx);
	if (ret == OMCI_API_NOT_FOUND) {
		/* create meter */
		ret = omci_api_meter_create(ctx, &meter_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
		ret = explicit_map(ctx, MAPPER_GEMPORTCTP_MEID_TO_METER_IDX, me_id, meter_idx);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR,
				("MAPPER_GEMPORTCTP_MEID_TO_METER_IDX: can't map %d id\n",
									me_id));
			return OMCI_API_ERROR;
		}
		/* attach meter */
		ret = omci_api_traffic_descriptor_meter_attach(ctx, td_idx,
							       meter_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	} else if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("MAPPER_GEMPORTCTP_MEID_TO_METER_IDX: failed\n"));
		return OMCI_API_ERROR;
	}

	ret = omci_api_meter_set(ctx, meter_idx, &td);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = table_read(ctx, ONU_GPE_DS_GEM_PORT_TABLE_ID, gpix,
			 sizeof(struct gpe_ds_gem_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.data.ds_gem_port.ds_gem_meter_id = meter_idx;
	entry.data.ds_gem_port.ds_gem_meter_enable = 1;

	ret = table_write(ctx, sizeof(struct gpe_ds_gem_port_table), &entry);

	return ret;
}

enum omci_api_return omci_api_gemport_meter_delete(struct omci_api_ctx *ctx,
						   const uint16_t gpix,
						   const uint16_t me_id,
						   const uint16_t td_ptr)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;
	uint32_t td_idx, meter_idx;

	ret = index_get(ctx, MAPPER_TRAFFDESCR_TO_IDX, td_ptr, &td_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = table_read(ctx, ONU_GPE_DS_GEM_PORT_TABLE_ID, gpix,
			 sizeof(struct gpe_ds_gem_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.data.ds_gem_port.ds_gem_meter_id = 0;
	entry.data.ds_gem_port.ds_gem_meter_enable = 0;

	ret = table_write(ctx, sizeof(struct gpe_ds_gem_port_table), &entry);

	ret = index_get(ctx, MAPPER_GEMPORTCTP_MEID_TO_METER_IDX, me_id, &meter_idx);
	if (ret == OMCI_API_SUCCESS) {
		omci_api_traffic_descriptor_meter_detach(ctx, td_idx, meter_idx);
		omci_api_meter_delete(ctx, meter_idx);
		id_remove(ctx, MAPPER_GEMPORTCTP_MEID_TO_METER_IDX, me_id);
	}

	return ret;
}

enum omci_api_return omci_api_gemport_shaper_delete(struct omci_api_ctx *ctx,
						   const uint16_t gpix,
						   const uint16_t td_ptr)
{
	enum omci_api_return ret;
	uint32_t td_idx;

	ret = index_get(ctx, MAPPER_TRAFFDESCR_TO_IDX, td_ptr, &td_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = omci_api_shaper_clean(ctx, td_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = omci_api_traffic_descriptor_shaper_detach(ctx, td_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return ret;
}

enum omci_api_return omci_api_bridge_port_meter_add(struct omci_api_ctx *ctx,
						const uint16_t bridge_port_idx,
						const uint16_t me_id,
						const uint16_t tp_ptr,
						const uint16_t tp_type,
						const uint16_t td_ptr,
						const uint8_t inbound)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;
	struct omci_api_traffic_descriptor td;
	uint32_t td_idx, meter_idx, id;
	uint8_t lan_port;

	ret = omci_api_uni2lan(ctx, tp_ptr, &lan_port);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = index_get(ctx, MAPPER_TRAFFDESCR_TO_IDX, td_ptr, &td_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = omci_api_traffic_descriptor_get(ctx, td_idx, &td);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	if (ctx->capability.hw_version <= 0xA12) {
		if (inbound && tp_type == 1) {
			ret = omci_api_mac_bridge_port_config_data_uni_fw_policer_rate_set(
					ctx, lan_port, td.pir);
		}
		return ret;
	}

	if (inbound)
		id = MAPPER_MACBRIDGEPORT_MEID_TO_INGRESS_METER_IDX;
	else
		id = MAPPER_MACBRIDGEPORT_MEID_TO_EGRESS_METER_IDX;

	ret = index_get(ctx, id, me_id, &meter_idx);
	if (ret == OMCI_API_NOT_FOUND) {
		/* create meter */
		ret = omci_api_meter_create(ctx, &meter_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
		ret = explicit_map(ctx, id, me_id, meter_idx);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR,
				("MAPPER_MACBRIDGEPORT_MEID_TO_xxx_METER_IDX: can't map %d id\n",
									me_id));
			return OMCI_API_ERROR;
		}
		/* attach meter */
		ret = omci_api_traffic_descriptor_meter_attach(ctx, td_idx,
							       meter_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	} else if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("MAPPER_MACBRIDGEPORT_MEID_TO_xxx_METER_IDX: failed\n"));
		return OMCI_API_ERROR;
	}

	ret = omci_api_meter_set(ctx, meter_idx, &td);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	if (inbound) {
		ret = omci_api_bridge_port_ingress_meter_set(ctx,
							     bridge_port_idx,
							     meter_idx, true);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	} else {
		ret = omci_api_bridge_port_egress_meter_set(ctx,
							    bridge_port_idx,
							    meter_idx, true);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	return ret;
}

enum omci_api_return
omci_api_bridge_port_meter_delete(struct omci_api_ctx *ctx,
				  const uint16_t bridge_port_idx,
				  const uint16_t me_id,
				  const uint16_t tp_ptr,
				  const uint16_t tp_type,
				  const uint16_t td_ptr,
				  const uint8_t inbound)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_table_entry entry;
	uint32_t td_idx, id;
	uint32_t meter_idx;
	uint8_t lan_port;

	ret = omci_api_uni2lan(ctx, tp_ptr, &lan_port);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	if (ctx->capability.hw_version <= 0xA12) {
		if (tp_type == 1) {
			ret = omci_api_mac_bridge_port_config_data_uni_fw_policer_rate_set(
					ctx, lan_port, 0);
		}
		return ret;
	}

	ret = index_get(ctx, MAPPER_TRAFFDESCR_TO_IDX, td_ptr, &td_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	if (inbound) {
		id = MAPPER_MACBRIDGEPORT_MEID_TO_INGRESS_METER_IDX;
	} else {
		id = MAPPER_MACBRIDGEPORT_MEID_TO_EGRESS_METER_IDX;
	}
	ret = index_get(ctx, id, me_id, &meter_idx);
	if (ret == OMCI_API_SUCCESS) {
		if (inbound) {
			omci_api_bridge_port_ingress_meter_set(ctx,
									 bridge_port_idx,
									 meter_idx, false);
		} else {
			omci_api_bridge_port_egress_meter_set(ctx,
									bridge_port_idx,
									meter_idx, false);
		}
		omci_api_traffic_descriptor_meter_detach(ctx, td_idx, meter_idx);
		omci_api_meter_delete(ctx, meter_idx);
		id_remove(ctx, id, me_id);
	}

	return ret;
}

enum omci_api_return
omci_api_lan_port_queue_marking_mode_modify(struct omci_api_ctx *ctx,
					    const uint16_t port_index,
					    const uint8_t queue_marking_mode)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_LAN_PORT_TABLE_ID, port_index,
			 sizeof(struct gpe_lan_port_table), &entry);
	if (ret != 0) return OMCI_API_ERROR;

	DBG(OMCI_API_MSG, ("LAN_PORT_TABLE[%d]: modify lan port"
			   " queue marking mode to %d\n", port_index,
						   queue_marking_mode));

	entry.data.lan_port.queue_marking_mode = queue_marking_mode;

	ret = table_write(ctx, sizeof(struct gpe_lan_port_table), &entry);

	return ret;
}

enum omci_api_return omci_api_lan_port_ppoe_modify(struct omci_api_ctx *ctx,
				const uint16_t port_index,
				const uint8_t pppoe_filter_enable)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_LAN_PORT_TABLE_ID, port_index,
			 sizeof(struct gpe_lan_port_table), &entry);
	if (ret != 0) return OMCI_API_ERROR;

	DBG(OMCI_API_MSG, ("LAN_PORT_TABLE[%d]: modify lan port"
			   " ppoe filter to %d\n", port_index,
						   pppoe_filter_enable));

	entry.data.lan_port.pppoe_filter_enable = pppoe_filter_enable;

	ret = table_write(ctx, sizeof(struct gpe_lan_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_lan_port_interworking_modify(struct omci_api_ctx *ctx,
				      const uint16_t port_index,
				      const uint8_t queue_index,
				      const uint8_t interworking_option,
				      const uint8_t interworking_index)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_LAN_PORT_TABLE_ID, port_index,
			 sizeof(struct gpe_lan_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	DBG(OMCI_API_MSG, ("LAN_PORT_TABLE[%d]: interworking_option to %d"
			   " queue_index %d, interworking_index %d\n",
				port_index, interworking_option,
				queue_index, interworking_index));

	entry.data.lan_port.interworking_option = interworking_option;
	entry.data.lan_port.interworking_index = interworking_index;
	entry.data.lan_port.base_queue_index = queue_index;

	ret = table_write(ctx, sizeof(struct gpe_lan_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_lan_port_base_queue_get(struct omci_api_ctx *ctx,
				 const uint16_t port_index,
				 uint8_t *queue_index)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_LAN_PORT_TABLE_ID, port_index,
			 sizeof(struct gpe_lan_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	*queue_index = entry.data.lan_port.base_queue_index;

	return ret;
}

enum omci_api_return
omci_api_lan_port_ext_vlan_get(struct omci_api_ctx *ctx,
			       uint16_t port_index,
			       uint8_t *ext_vlan_enable_egress,
			       uint8_t *ext_vlan_index_egress,
			       uint8_t *ext_vlan_enable_ingress,
			       uint8_t *ext_vlan_index_ingress,
			       uint8_t *ext_vlan_incremental_enable)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_LAN_PORT_TABLE_ID, port_index,
			 sizeof(struct gpe_lan_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	if(ext_vlan_enable_egress)
		*ext_vlan_enable_egress = entry.data.lan_port.ext_vlan_enable_egress;
	if(ext_vlan_index_egress)
		*ext_vlan_index_egress = entry.data.lan_port.ext_vlan_index_egress;
	if(ext_vlan_enable_ingress)
		*ext_vlan_enable_ingress = entry.data.lan_port.ext_vlan_enable_ingress;
	if(ext_vlan_index_ingress)
		*ext_vlan_index_ingress = entry.data.lan_port.ext_vlan_index_ingress;
	if(ext_vlan_incremental_enable)
		*ext_vlan_incremental_enable = entry.data.lan_port.ext_vlan_incremental_enable;

	return ret;
}

enum omci_api_return
omci_api_lan_port_ext_vlan_modify(struct omci_api_ctx *ctx,
				  const uint16_t port_index,
				  const uint8_t ext_vlan_enable_egress,
				  const uint8_t ext_vlan_index_egress,
				  const uint8_t ext_vlan_enable_ingress,
				  const uint8_t ext_vlan_index_ingress,
				  const uint8_t ext_vlan_incremental_enable)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_LAN_PORT_TABLE_ID, port_index,
			 sizeof(struct gpe_lan_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.data.lan_port.ext_vlan_enable_egress = ext_vlan_enable_egress;
	entry.data.lan_port.ext_vlan_index_egress = ext_vlan_index_egress;
	entry.data.lan_port.ext_vlan_enable_ingress = ext_vlan_enable_ingress;
	entry.data.lan_port.ext_vlan_index_ingress = ext_vlan_index_ingress;
	entry.data.lan_port.ext_vlan_incremental_enable = ext_vlan_incremental_enable;

	ret = table_write(ctx, sizeof(struct gpe_lan_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_lan_port_mc_ext_vlan_modify(struct omci_api_ctx *ctx,
				     const uint16_t port_index,
				     const uint8_t ext_vlan_mc_enable_egress,
				     const uint8_t ext_vlan_mc_enable_ingress)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_LAN_PORT_TABLE_ID, port_index,
			 sizeof(struct gpe_lan_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.data.lan_port.ext_vlan_mc_enable_egress =
						ext_vlan_mc_enable_egress;
	entry.data.lan_port.ext_vlan_mc_enable_ingress =
						ext_vlan_mc_enable_ingress;

	ret = table_write(ctx, sizeof(struct gpe_lan_port_table), &entry);

	return ret;
}

enum omci_api_return omci_api_lan_port_enable(struct omci_api_ctx *ctx,
					      const uint16_t port_index,
					      const uint8_t enable)
{
	struct lan_port_index idx;
	enum omci_api_return ret;

	if (ctx->remote)
		return OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("LAN port %d: %s\n", port_index,
			   enable ? "enable" : "disable"));

	idx.index = port_index;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      enable ? FIO_LAN_PORT_ENABLE : FIO_LAN_PORT_DISABLE,
		      &idx, sizeof(idx));

	{
		FILE *_f = fopen("/tmp/8311_carrier.log", "a");
		if (_f) {
			fprintf(_f, "lan_port_enable: port=%u en=%u "
				"ioctl=0x%x ret=%d\n",
				port_index, enable,
				enable ? FIO_LAN_PORT_ENABLE
				       : FIO_LAN_PORT_DISABLE,
				ret);
			fclose(_f);
		}
	}

	return ret;
}

enum omci_api_return omci_api_op_state_get(struct omci_api_ctx *ctx,
					   const uint16_t gpix,
					   const uint8_t direction,
					   uint8_t *op_state)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry1;
	struct gpe_table_entry entry2;

	if (direction & 2) {
		ret = table_read(ctx, ONU_GPE_DS_GEM_PORT_TABLE_ID,
			gpix, sizeof(struct gpe_ds_gem_port_table), &entry1);
		if (ret != 0) {
			*op_state = 1;
			return OMCI_API_ERROR;
		}
	} else {
		entry1.data.ds_gem_port.valid = 1;
	}

	if (direction & 1) {
		ret = table_read(ctx, ONU_GPE_US_GEM_PORT_TABLE_ID,
				 gpix, sizeof(struct gpe_us_gem_port_table),
				 &entry2);
		if (ret != 0) {
			*op_state = 1;
			return OMCI_API_ERROR;
		}
	} else {
		entry2.data.us_gem_port.valid = 1;
	}
	*op_state = (entry1.data.ds_gem_port.valid == 1 &&
				    entry2.data.us_gem_port.valid == 1) ? 0 : 1;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_pmapper_add(struct omci_api_ctx *ctx,
		     const uint16_t pmapper_index,
		     const uint32_t *gpix,
		     const uint16_t unmarked_frame_option,
		     const uint16_t default_priority_marking,
		     const uint16_t dscp_profile_index)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_PMAPPER_TABLE_ID, pmapper_index,
			 sizeof(struct gpe_pmapper_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.data.pmapper.valid = 1;
	entry.data.pmapper.itp_id0 = gpix[0];
	entry.data.pmapper.itp_id1 = gpix[1];
	entry.data.pmapper.itp_id2 = gpix[2];
	entry.data.pmapper.itp_id3 = gpix[3];
	entry.data.pmapper.itp_id4 = gpix[4];
	entry.data.pmapper.itp_id5 = gpix[5];
	entry.data.pmapper.itp_id6 = gpix[6];
	entry.data.pmapper.itp_id7 = gpix[7];
	entry.data.pmapper.unmarked_frame_option = unmarked_frame_option;
	entry.data.pmapper.default_pcp = default_priority_marking;
	entry.data.pmapper.dscp_table_pointer = dscp_profile_index;

	DBG(OMCI_API_MSG,
		("PMAPPER_TABLE[%d]: set gpix %d %d %d %d %d %d %d %d\n",
			pmapper_index,
			gpix[0], gpix[1], gpix[2], gpix[3],
			gpix[4], gpix[5], gpix[6], gpix[7]));

	ret = table_write(ctx, sizeof(struct gpe_pmapper_table), &entry);

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_pmapper_get(struct omci_api_ctx *ctx,
		     const uint16_t pmapper_index,
		     uint32_t *gpix,
		     uint8_t *unmarked_frame_option,
		     uint8_t *default_priority_marking,
		     uint8_t *dscp_profile_index)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_PMAPPER_TABLE_ID, pmapper_index,
			 sizeof(struct gpe_pmapper_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	if (entry.data.pmapper.valid == 0)
		return OMCI_API_ERROR;

	if (gpix) {
		gpix[0] = entry.data.pmapper.itp_id0;
		gpix[1] = entry.data.pmapper.itp_id1;
		gpix[2] = entry.data.pmapper.itp_id2;
		gpix[3] = entry.data.pmapper.itp_id3;
		gpix[4] = entry.data.pmapper.itp_id4;
		gpix[5] = entry.data.pmapper.itp_id5;
		gpix[6] = entry.data.pmapper.itp_id6;
		gpix[7] = entry.data.pmapper.itp_id7;
	}

	if (unmarked_frame_option)
		*unmarked_frame_option =
				entry.data.pmapper.unmarked_frame_option;

	if (default_priority_marking)
		*default_priority_marking = entry.data.pmapper.default_pcp;

	if (dscp_profile_index)
		*dscp_profile_index = entry.data.pmapper.dscp_table_pointer;

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_pmapper_remove(struct omci_api_ctx *ctx,
					     const uint16_t pmapper_index)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_PMAPPER_TABLE_ID, pmapper_index,
			 sizeof(struct gpe_pmapper_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	memset(&entry.data, 0x00, sizeof(struct gpe_pmapper_table));

	ret = table_write(ctx, sizeof(struct gpe_pmapper_table), &entry);

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_dscp_profile_add(struct omci_api_ctx *ctx,
			  const uint16_t dscp_profile_index,
			  const uint8_t *pcp)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;
	uint8_t i;

	DBG(OMCI_API_MSG, ("PMAPPER_TABLE[%d]: write dscp profile\n",
		dscp_profile_index));

	for (i = 0; i < 64; i++) {
		ret = table_read(ctx, ONU_GPE_DSCP_DECODING_TABLE_ID,
				 (dscp_profile_index << 6) | i,
				 sizeof(struct gpe_dscp_decoding_table),
				 &entry);
		if (ret != 0)
			return OMCI_API_ERROR;

		entry.data.dscp_decoding.pcp = pcp[i];
		entry.data.dscp_decoding.color = 0;
		entry.data.dscp_decoding.de = 0;

		ret = table_write(ctx, sizeof(struct gpe_dscp_decoding_table),
				  &entry);
	}

	return OMCI_API_SUCCESS;
}


/** @} */
