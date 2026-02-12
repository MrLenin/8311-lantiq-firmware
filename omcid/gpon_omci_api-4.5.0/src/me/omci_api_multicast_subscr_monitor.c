/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_multicast_subscr_monitor.h"
#include "mcc/omci_api_mcc.h"

/** \addtogroup OMCI_API_ME_MULTICAST_OPERATIONS_PROFILE

   @{
*/


enum omci_api_return omci_api_multicast_subscriber_monitor_data_get(
	struct omci_api_ctx *ctx,
	const uint16_t me_id,
	struct omci_api_multicast_subscriber_monitor_data *monitor)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	uint32_t idx = 0;
	struct omci_api_mcc_subscr_status status;
#endif

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	ret = index_get(ctx, MAPPER_MCSUBSCR_MONITOR_MEID_TO_IDX, me_id, &idx);
	if (ret != OMCI_API_SUCCESS) {
		ret = id_map(ctx, MAPPER_MCSUBSCR_MONITOR_MEID_TO_IDX,
			     me_id, &idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	ret = omci_api_mcc_subscr_status_get(ctx, idx, &status);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	monitor->curr_mc_bw = status.curr_mc_bw;
	monitor->join_msg_cnt = status.join_msg_cnt;
	monitor->bw_exc_cnt = status.bw_exc_cnt;
#else
	memset(monitor, 0, sizeof(*monitor));
#endif
	return ret;
}

enum omci_api_return omci_api_multicast_subscriber_monitor_agl_table_get(
	struct omci_api_ctx *ctx,
	uint16_t me_id,
	uint8_t linked_me_type,
	unsigned int *entry_num,
	struct omci_api_multicast_subscriber_monitor_agl_table_entry **entries)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	struct omci_api_multicast_subscriber_monitor_agl_table_entry *table;
	struct omci_api_mcc_active_groups_list list;
	uint32_t idx = 0;
#endif

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	if (linked_me_type != 0)
		/* Link to 802.1p mapper service profile is not supported yet*/
		return OMCI_API_SUCCESS;

	ret = index_get(ctx, MAPPER_MCSUBSCR_MONITOR_MEID_TO_IDX, me_id, &idx);
	if (ret != OMCI_API_SUCCESS) {
		ret = id_map(ctx, MAPPER_MCSUBSCR_MONITOR_MEID_TO_IDX,
			     me_id, &idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	ret = omci_api_mcc_active_groups_list_get(ctx, (uint8_t)idx, &list);
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
	for (idx = 0; idx < list.count; idx++)
		memcpy(&table[idx], &list.entry[idx], sizeof(list.entry[idx]));

	*entry_num = list.count;
	*entries = table;
#else
	*entry_num = 0;
	*entries = NULL;
#endif

	return ret;
}

enum omci_api_return omci_api_multicast_subscriber_monitor_destroy(
	struct omci_api_ctx *ctx,
	uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
#if defined(LINUX) && defined(INCLUDE_OMCI_API_MCC)
	uint32_t idx = 0;

	ret = index_get(ctx, MAPPER_MCSUBSCR_MONITOR_MEID_TO_IDX, me_id, &idx);
	if (ret == OMCI_API_NOT_FOUND) {
		return OMCI_API_SUCCESS;
	} else if (ret == OMCI_API_SUCCESS) {
		(void)omci_api_mcc_subscr_status_reset(ctx, idx);

		id_remove(ctx, MAPPER_MCSUBSCR_MONITOR_MEID_TO_IDX, me_id);
	}
#endif
	return ret;
}

/** @} */
