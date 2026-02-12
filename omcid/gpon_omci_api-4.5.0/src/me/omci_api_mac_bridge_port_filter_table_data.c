/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_mac_bridge_port_filter_table_data.h"

/** \addtogroup OMCI_API_ME_MAC_BRIDGE_PORT_FILTER_TABLE_DATA

   @{
*/


/** Source MAC filter table entries per Bridge Port group
*/
#define OMCI_API_MAC_FILTER_ENTRIES_PER_GROUP	16
/** Source and Destimnation groups
*/
#define OMCI_API_MAC_FILTER_ENTRIES_GROUP_NUM	2

/** Total MAC filter table entries per Bridge Port
*/
#define OMCI_API_MAC_FILTER_ENTRIES_PER_BRIDGE_PORT_TOTAL \
		(OMCI_API_MAC_FILTER_ENTRIES_PER_GROUP * \
		 OMCI_API_MAC_FILTER_ENTRIES_GROUP_NUM)

#define OMCI_API_MAC_FILTER_BRIDGE_PORT_TOTAL \
		(ONU_GPE_MAC_FILTER_TABLE_SIZE / \
			OMCI_API_MAC_FILTER_ENTRIES_PER_BRIDGE_PORT_TOTAL) \

struct mac_flt_idx {
	uint8_t sa;
	uint8_t da;
};

struct bp_mac_flt_entry {
	bool valid;
	uint32_t bp_idx;
	struct mac_flt_idx mac_flt_idx;
};

static struct bp_mac_flt_entry
	bp_mac_flt_tbl[OMCI_API_MAC_FILTER_BRIDGE_PORT_TOTAL] = {0};

static struct bp_mac_flt_entry
*bp_mac_flt_tbl_entry_get(const uint8_t bp_idx)
{
	uint8_t i;

	for (i = 0; i < OMCI_API_MAC_FILTER_BRIDGE_PORT_TOTAL; i++) {
		if (bp_mac_flt_tbl[i].valid)
			if (bp_mac_flt_tbl[i].bp_idx == bp_idx)
				return &bp_mac_flt_tbl[i];
	}

	return NULL;
}

static struct bp_mac_flt_entry
*bp_mac_flt_tbl_entry_create(const uint8_t bp_idx)
{
	uint8_t i;

	for (i = 0; i < OMCI_API_MAC_FILTER_BRIDGE_PORT_TOTAL; i++) {
		if (!bp_mac_flt_tbl[i].valid) {
			bp_mac_flt_tbl[i].mac_flt_idx.sa =
				i * OMCI_API_MAC_FILTER_ENTRIES_PER_BRIDGE_PORT_TOTAL;
			bp_mac_flt_tbl[i].mac_flt_idx.da =
				bp_mac_flt_tbl[i].mac_flt_idx.sa +
				OMCI_API_MAC_FILTER_ENTRIES_PER_GROUP;
			bp_mac_flt_tbl[i].bp_idx = bp_idx;
			bp_mac_flt_tbl[i].valid = true;

			return &bp_mac_flt_tbl[i];
		}
	}

	return NULL;
}

static enum omci_api_return
bp_mac_flt_tbl_entry_delete(const uint8_t bp_idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint8_t i;

	for (i = 0; i < OMCI_API_MAC_FILTER_BRIDGE_PORT_TOTAL; i++) {
		if (bp_mac_flt_tbl[i].valid) {
			ret = OMCI_API_ERROR;
			if (bp_mac_flt_tbl[i].bp_idx == bp_idx) {
				bp_mac_flt_tbl[i].valid = false;

				return 0;
			}
		}
	}

	return ret;
}

enum omci_api_return mac_flt_tbl_entry_add_remove(struct omci_api_ctx *ctx,
						  const struct mac_flt_idx *group_idx,
						  const uint8_t entry_idx,
						  const bool add,
						  const bool is_source,
						  const uint8_t mac_address[6])
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	/* remove opposite entry first */
	memset(&entry.data, 0x00, sizeof(struct gpe_mac_filter_table));
	entry.id = ONU_GPE_MAC_FILTER_TABLE_ID;
	entry.instance = 1;
	entry.index = (is_source ? group_idx->da : group_idx->sa)  + entry_idx;
	entry.data.mac_filter.valid = 0;
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_TABLE_ENTRY_WRITE, &entry,
		      TABLE_ENTRY_SIZE(entry.data.mac_filter));
	if (ret != 0)
		return OMCI_API_ERROR;

	/* handle main add/remove */
	entry.index = (is_source ? group_idx->sa : group_idx->da)  + entry_idx;
	entry.data.mac_filter.valid = add ? 1 : 0;
	if (add) {
		entry.data.mac_filter.key_code = is_source ? 0 : 1;

		entry.data.mac_filter.mac_address_high =
			mac_address[0] << 8 | mac_address[1];
		entry.data.mac_filter.mac_address_low =
			mac_address[2] << 24 | mac_address[3] << 16 |
			mac_address[4] << 8 | mac_address[5];
	}

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_TABLE_ENTRY_WRITE, &entry,
		      TABLE_ENTRY_SIZE(entry.data.mac_filter));
	if (ret != 0)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

static enum omci_api_return mac_flt_tbl_group_init(struct omci_api_ctx *ctx,
						   const uint8_t group_idx)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;
	uint8_t i;

	for (i = 0; i < OMCI_API_MAC_FILTER_ENTRIES_PER_GROUP; i++) {
		memset(&entry.data, 0x00, sizeof(struct gpe_mac_filter_table));
		entry.id = ONU_GPE_MAC_FILTER_TABLE_ID;
		entry.instance = 1;
		entry.index = group_idx + i;
		entry.data.mac_filter.end =
			i == OMCI_API_MAC_FILTER_ENTRIES_PER_GROUP - 1 ? 1 : 0;

		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_GPE_TABLE_ENTRY_WRITE, &entry,
			      TABLE_ENTRY_SIZE(entry.data.mac_filter));
		if (ret != 0) {
			DBG(OMCI_API_ERR,
				("MAC Filter Table idx=%u write failed\n",
								entry.index));
			return OMCI_API_ERROR;
		}
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_mac_bridge_port_filter_table_data_create(struct omci_api_ctx *ctx,
						  uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	memset(bp_mac_flt_tbl, 0, sizeof(bp_mac_flt_tbl));

	return ret;
}

enum omci_api_return
omci_api_mac_bridge_port_filter_table_data_destroy(struct omci_api_ctx *ctx,
						   uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_table_entry entry;
	uint32_t bridge_port_idx;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	ret = bridge_port_idx_get(ctx, -1, me_id, &bridge_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = bp_mac_flt_tbl_entry_delete((uint8_t)bridge_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, bridge_port_idx,
			 sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	entry.data.bridge_port.sa_filter_mode = 0;
	entry.data.bridge_port.da_filter_mode = 0;

	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	return ret;
}

static enum omci_api_return
filter_entry_add_remove(struct omci_api_ctx *ctx,
			uint16_t me_id,
			uint16_t bridge_me_id,
			const uint8_t idx,
			const uint8_t filter_byte,
			const uint8_t mac_address[6],
			const bool add)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;
	struct bp_mac_flt_entry *bp_mac_flt_entry;
	uint32_t bridge_idx, bridge_port_idx;
	bool is_source;

	ret = bridge_idx_get(ctx, bridge_me_id, &bridge_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = bridge_port_idx_get(ctx, bridge_idx, me_id, &bridge_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	bp_mac_flt_entry = bp_mac_flt_tbl_entry_get((uint8_t)bridge_port_idx);
	if (!bp_mac_flt_entry) {
		bp_mac_flt_entry = bp_mac_flt_tbl_entry_create(
						(uint8_t)bridge_port_idx);
		if (!bp_mac_flt_entry) {
			DBG(OMCI_API_ERR,
			      ("Bridge Port MAC filter entry create failed\n"));
			return OMCI_API_ERROR;
		} else {
			/* Init Source MAC filter group */
			ret = mac_flt_tbl_group_init(ctx,
					      bp_mac_flt_entry->mac_flt_idx.sa);
			if (ret != OMCI_API_SUCCESS) {
				DBG(OMCI_API_ERR,
					("Source MAC filter table group init failed\n"));
				return ret;
			}
			/* Init Destination MAC filter group */
			ret = mac_flt_tbl_group_init(ctx,
					      bp_mac_flt_entry->mac_flt_idx.da);
			if (ret != OMCI_API_SUCCESS) {
				DBG(OMCI_API_ERR,
					("Destination MAC filter table group"
					 " init failed\n"));
				return ret;
			}
		}
	}

	/* Read Bridge port table*/
	ret = table_read(ctx, ONU_GPE_BRIDGE_PORT_TABLE_ID, bridge_port_idx,
			 sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	entry.data.bridge_port.sa_filter_pointer =
					bp_mac_flt_entry->mac_flt_idx.sa;
	entry.data.bridge_port.da_filter_pointer =
					bp_mac_flt_entry->mac_flt_idx.da;

	is_source = (filter_byte & (1 << 1)) ? true : false;

	if (add) {
		if (is_source) {
			entry.data.bridge_port.sa_filter_mode =
				(filter_byte & (1 << 0)) ? 0x2 : 0x3;
		} else {
			entry.data.bridge_port.da_filter_mode =
				(filter_byte & (1 << 0)) ? 0x2 : 0x3;
		}
	}

	/* Handle MAC Filter Table entry */
	ret = mac_flt_tbl_entry_add_remove(ctx, &bp_mac_flt_entry->mac_flt_idx,
					   idx, add, is_source, mac_address);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	/* Write Bridge port table*/
	ret = table_write(ctx, sizeof(struct gpe_bridge_port_table), &entry);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_mac_bridge_port_filter_table_data_mac_filter_table_entry_add(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint16_t bridge_me_id,
	const uint8_t idx,
	const uint8_t filter_forward,
	const uint8_t mac_address[6])
{
	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   bridge_me_id=%u\n"
		  "   idx=%u\n"
		  "   filter_forward=%u\n"
		  "   mac_address=%x-%x-%x-%x-%x-%x\n",
		  __FUNCTION__,
		  me_id, bridge_me_id, idx, filter_forward,
		  mac_address[0], mac_address[1], mac_address[2],
		  mac_address[3], mac_address[4], mac_address[5]));

	if (idx >= OMCI_API_MAC_FILTER_ENTRIES_PER_GROUP)
		return OMCI_API_NOT_AVAIL;

	return filter_entry_add_remove(ctx, me_id, bridge_me_id,
				       idx, filter_forward, mac_address, true);
}

enum omci_api_return
omci_api_mac_bridge_port_filter_table_data_mac_filter_table_entry_remove(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint16_t bridge_me_id,
	const uint8_t idx)
{
	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   bridge_me_id=%u\n"
		  "   idx=%u\n",
		  __FUNCTION__, me_id, bridge_me_id, idx));

	if (idx >= OMCI_API_MAC_FILTER_ENTRIES_PER_GROUP)
		return OMCI_API_NOT_AVAIL;

	return filter_entry_add_remove(ctx, me_id, bridge_me_id,
				       idx, 0, NULL, false);

	return OMCI_API_SUCCESS;
}

/** @} */
