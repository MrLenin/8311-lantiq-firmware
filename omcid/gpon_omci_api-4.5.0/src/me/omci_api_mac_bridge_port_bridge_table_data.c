/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_memory_alloc.h"

#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_mac_bridge_port_bridge_table_data.h"

/** \addtogroup OMCI_API_ME_MAC_BRIDGE_PORT_BRIDGE_TABLE_DATA

   @{
*/

#define AGE_MAX		4095

enum omci_api_return
omci_api_mac_bridge_port_bridge_table_data_create(struct omci_api_ctx *ctx,
						  uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	/** \todo add implementation */

	return ret;
}

enum omci_api_return
omci_api_mac_bridge_port_bridge_table_data_destroy(struct omci_api_ctx *ctx,
						   uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	/** \todo add implementation */

	return ret;
}

enum omci_api_return
omci_api_mac_bridge_port_bridge_table_data_bridge_table_get(struct omci_api_ctx *ctx,
							    uint16_t me_id,
							    uint16_t bridge_me_id,
							    unsigned int *entry_num,
							    struct omci_api_mac_bridge_port_bridge_table_data_bridge_table_entry **entries)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	union {
		struct gpe_table_entry entry;
		struct sce_mac_entry_age age;
	} tbl;
	uint32_t bridge_idx, bridge_port_idx, i;

	DBG(OMCI_API_MSG, ("%s\n"
			   "   bridge_me_id=%u\n", __FUNCTION__, bridge_me_id));

	if (*entries != NULL || entry_num == NULL)
		return OMCI_API_ERROR;

	*entry_num = 0;

	ret = bridge_idx_get(ctx, bridge_me_id, &bridge_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = bridge_port_idx_get(ctx, bridge_idx, me_id, &bridge_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	*entries = (struct omci_api_mac_bridge_port_bridge_table_data_bridge_table_entry*)
			IFXOS_MemAlloc(
			  sizeof(struct omci_api_mac_bridge_port_bridge_table_data_bridge_table_entry) *
			  ONU_GPE_SHORT_FWD_TABLE_MAC_SIZE);

	if (*entries == NULL)
		return OMCI_API_ERROR;

	for (i = 0; i < ONU_GPE_SHORT_FWD_TABLE_MAC_SIZE; i++) {

		tbl.entry.id = ONU_GPE_SHORT_FWD_TABLE_MAC_ID;
		tbl.entry.instance = 1;
		tbl.entry.index = i;

		/** \todo Crosscheck why GET is not working!
		*/
		/*ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TABLE_ENTRY_GET, &tbl,*/
		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_GPE_TABLE_ENTRY_READ, &tbl,
			      TABLE_ENTRY_SIZE(tbl.entry.data.short_fwd_table_mac));
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("short fwd mac table get failed,"
					   " index=%u\n", i));
			break;
		}

		if ((uint32_t)tbl.entry.data.short_fwd_table_mac.bridge_index != bridge_idx ||
		    (uint32_t)tbl.entry.data.short_fwd_table_mac.bridge_port_index != bridge_port_idx ||
		    !tbl.entry.data.short_fwd_table_mac.valid)
			continue;

		(*entries)[*entry_num].p_mac_adress[0] =
			(tbl.entry.data.short_fwd_table_mac.mac_address_high >> 8) & 0xFF;
		(*entries)[*entry_num].p_mac_adress[1] =
			tbl.entry.data.short_fwd_table_mac.mac_address_high & 0xFF;
		(*entries)[*entry_num].p_mac_adress[2] =
			(tbl.entry.data.short_fwd_table_mac.mac_address_low >> 24) & 0xFF;
		(*entries)[*entry_num].p_mac_adress[3] =
			(tbl.entry.data.short_fwd_table_mac.mac_address_low >> 16) & 0xFF;
		(*entries)[*entry_num].p_mac_adress[4] =
			(tbl.entry.data.short_fwd_table_mac.mac_address_low >> 8) & 0xFF;
		(*entries)[*entry_num].p_mac_adress[5] =
			tbl.entry.data.short_fwd_table_mac.mac_address_low & 0xFF;


		/* not supported, set to 0 (forward) */
		(*entries)[*entry_num].information.info_fields.mode = 0;
		(*entries)[*entry_num].information.info_fields.type =
			tbl.entry.data.short_fwd_table_mac.dynamic_enable;


		tbl.entry.id = ONU_GPE_SHORT_FWD_TABLE_MAC_ID;
		tbl.entry.instance = 1;
		tbl.entry.index = i;

		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_GPE_AGE_GET, &tbl, sizeof(tbl));
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("short fwd table unicast age get "
					   "failed, index=%u\n", i));
			break;
		}

		(*entries)[*entry_num].information.info_fields.age =
			tbl.age.age > AGE_MAX ? AGE_MAX : tbl.age.age;

		*entry_num += 1;
	}

	if (ret != OMCI_API_SUCCESS) {
		IFXOS_MemFree(*entries);
		*entries = NULL;
		*entry_num = 0;
	}

	return ret;
}

void
omci_api_mac_bridge_port_bridge_table_data_bridge_table_free(struct omci_api_ctx *ctx,
							     uint16_t me_id,
							     uint16_t bridge_me_id,
							     unsigned int *entry_num,
							     struct omci_api_mac_bridge_port_bridge_table_data_bridge_table_entry **entries)
{
	*entry_num = 0;
	IFXOS_MemFree(*entries);
	*entries = NULL;
}

/** @} */
