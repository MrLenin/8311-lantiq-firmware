/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_mac_bridge_port_pmhd.h"

/** \addtogroup OMCI_API_ME_MAC_BRIDGE_PORT_PMHD

   @{
*/

enum omci_api_return
omci_api_mac_bridge_port_pmhd_cnt_get(struct omci_api_ctx *ctx,
				      const uint16_t me_id,
				      const bool get_curr,
				      const bool reset_cnt,
				      uint64_t *cnt_forwarded_frame,
				      uint64_t *cnt_delay_exceed_discard,
				      uint64_t *cnt_mtu_exceed_discard,
				      uint64_t *cnt_received_frame,
				      uint64_t *cnt_received_and_discarded)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	union gpe_bridge_port_counter_get_u param;
	uint32_t bridge_port_idx;

	DBG(OMCI_API_MSG, ("%s"
		  "   me_id=%u"
		  "   get_curr=%u"
		  "   reset_cnt=%u\n", __FUNCTION__,
		  me_id, get_curr, reset_cnt));

	ret = index_get(ctx, MAPPER_MACBRIDGEPORT_MEID_TO_IDX,
			me_id, &bridge_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	memset(&param, 0, sizeof(param));

	param.in.index = bridge_port_idx;
	param.in.curr = get_curr;
	param.in.reset_mask = reset_cnt ? 0xFF : 0;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
	      FIO_GPE_BRIDGE_PORT_COUNTER_GET, &param, sizeof(param));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	*cnt_received_frame = param.out.val.ibp_good;
	*cnt_received_and_discarded = param.out.val.ibp_discard;
	*cnt_forwarded_frame = param.out.val.ebp_good;
	*cnt_mtu_exceed_discard = param.out.val.ebp_discard;

	/*  \remark This counter is not supported by hardware, the value always
	   set to 0x0000. */
	*cnt_delay_exceed_discard = 0;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_mac_bridge_port_pmhd_total_cnt_get(
				struct omci_api_ctx *ctx,
				const uint16_t me_id,
				uint64_t *forwarded_frame,
				uint64_t *delay_exceed_discard,
				uint64_t *mtu_exceed_discard,
				uint64_t *received_frame,
				uint64_t *received_and_discarded)
{
	return omci_api_mac_bridge_port_pmhd_cnt_get(ctx, me_id, true, false,
						     forwarded_frame,
						     delay_exceed_discard,
						     mtu_exceed_discard,
						     received_frame,
						     received_and_discarded);
}

enum omci_api_return
omci_api_mac_bridge_port_pmhd_mtu_exceeded_discard_cnt_get(
				struct omci_api_ctx *ctx,
				const uint16_t me_id,
				const bool get_curr,
				uint64_t *mtu_exceed_discard)
{
	uint64_t unused_fwd, unused_delay, unused_rx, unused_discard;

	return omci_api_mac_bridge_port_pmhd_cnt_get(ctx, me_id,
						     get_curr, false,
						     &unused_fwd,
						     &unused_delay,
						     mtu_exceed_discard,
						     &unused_rx,
						     &unused_discard);
}

enum omci_api_return
omci_api_mac_bridge_port_pmhd_mtu_exceeded_discard_total_cnt_get(
				struct omci_api_ctx *ctx,
				const uint16_t me_id,
				uint64_t *mtu_exceed_discard)
{
	return omci_api_mac_bridge_port_pmhd_mtu_exceeded_discard_cnt_get(
					ctx, me_id, true, mtu_exceed_discard);
}

/** @} */
