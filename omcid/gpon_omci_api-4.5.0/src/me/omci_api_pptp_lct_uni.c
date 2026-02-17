/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_api_pptp_lct_uni.c
   v7.5.1 LCT UNI API — implements meter + exception setup for the LCT port.

   Reverse-engineered from stock omcid v7.5.1:
     FUN_0043fb20 = omci_api_pptp_lct_uni_create
     FUN_0043fcb8 = omci_api_pptp_lct_uni_update
     FUN_0043fd84 = omci_api_pptp_lct_uni_destroy

   Stock uses mapper tables 0x1c (me_id→lan_port) and 0x1d (me_id→meter_idx)
   for tracking LCT resources. Our mapper enum equivalents:
     MAPPER_LCT_MEID_TO_LAN_IDX   (= stock 0x1c)
     MAPPER_LCT_MEID_TO_METER_IDX (= stock 0x1d)
*/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "omci_api_mapper.h"
#include "me/omci_api_pptp_lct_uni.h"
#include "me/omci_api_table_access.h"

/**
   v7.5.1 LCT exception extraction mask (DAT_0043fd7c = 0x10488000):
     Bit 28 = LOCAL_MAC
     Bit 22 = ICMP
     Bit 19 = BPDU
     Bit 15 = IPX
*/
#define LCT_EXCEPTION_MASK 0x10488000

enum omci_api_return
omci_api_pptp_lct_uni_create(struct omci_api_ctx *ctx,
			     uint16_t me_id)
{
	enum omci_api_return ret;
	uint8_t lan_port;
	uint32_t meter_idx = 0;
	struct gpe_meter_cfg meter_cfg;

	DBG(OMCI_API_MSG, ("%s me_id=%u\n", __FUNCTION__, me_id));

	/* Resolve me_id → lan_port (stock calls omci_api_uni2lan first) */
	ret = omci_api_uni2lan(ctx, me_id, &lan_port);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* Register me_id→lan_port in mapper (stock mapper 0x1c) */
	ret = explicit_map(ctx, MAPPER_LCT_MEID_TO_LAN_IDX,
			   me_id, lan_port);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* Idempotency: if meter already mapped, we're done (stock behavior) */
	ret = index_get(ctx, MAPPER_LCT_MEID_TO_METER_IDX,
			me_id, &meter_idx);
	if (ret == OMCI_API_SUCCESS)
		return OMCI_API_SUCCESS;

	/* Create a GPE meter for LCT traffic rate limiting */
	ret = omci_api_meter_create(ctx, &meter_idx);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("%s lan_lct_meter_create_failed, ret=%d\n",
			 __FUNCTION__, ret));
		return ret;
	}

	/* Map me_id→meter_idx in mapper (stock mapper 0x1d) */
	ret = explicit_map(ctx, MAPPER_LCT_MEID_TO_METER_IDX,
			   me_id, meter_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* Configure the meter — stock uses CIR=8Mbps, CBS=240K
	   (confirmed matching: trace entry 407) */
	memset(&meter_cfg, 0, sizeof(meter_cfg));
	meter_cfg.index = meter_idx;
	meter_cfg.cir = ONU_GPE_QOSL * 1000;
	meter_cfg.pir = ONU_GPE_QOSL * 1000;
	meter_cfg.cbs = ONU_GPE_QOSL * 30;
	meter_cfg.pbs = ONU_GPE_QOSL * 30;
	meter_cfg.mode = GPE_METER_RFC2698;
	meter_cfg.color_aware = 0;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_METER_CFG_SET,
		      &meter_cfg, sizeof(meter_cfg));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("%s lan_lct_meter_config_failed, ret=%d\n",
			 __FUNCTION__, ret));
		return ret;
	}

	/* Associate meter with the LCT LAN port */
	ret = lan_exception_meter_setup(ctx, lan_port,
					meter_idx, 1);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("%s lan_lct_meter_setup_failed, ret=%d\n",
			 __FUNCTION__, ret));
		return ret;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_pptp_lct_uni_update(struct omci_api_ctx *ctx,
			     uint16_t me_id,
			     uint8_t admin_state)
{
	enum omci_api_return ret;
	uint8_t lan_port;
	uint32_t set_mask, clr_mask;

	DBG(OMCI_API_MSG, ("%s me_id=%u admin_state=%u\n",
		__FUNCTION__, me_id, admin_state));

	/* Resolve me_id → lan_port (stock calls omci_api_uni2lan first) */
	ret = omci_api_uni2lan(ctx, me_id, &lan_port);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* Stock (FUN_0043fcb8):
	   admin_state == 0 (unlocked): set LCT_EXCEPTION_MASK
	   admin_state != 0 (locked):   clear LCT_EXCEPTION_MASK */
	if (admin_state == 0) {
		set_mask = LCT_EXCEPTION_MASK;
		clr_mask = 0;
	} else {
		set_mask = 0;
		clr_mask = LCT_EXCEPTION_MASK;
	}

	ret = lan_exception_setup(ctx, lan_port, 1,
				  set_mask, clr_mask,
				  0, 0);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("%s lan_lct_exception_setup_failed, ret=%d\n",
			 __FUNCTION__, ret));
	}

	return ret;
}

enum omci_api_return
omci_api_pptp_lct_uni_destroy(struct omci_api_ctx *ctx,
			      uint16_t me_id)
{
	enum omci_api_return ret;
	uint32_t lan_port_buf;
	uint8_t lan_port;
	uint32_t meter_idx;

	DBG(OMCI_API_MSG, ("%s me_id=%u\n", __FUNCTION__, me_id));

	/* Get lan_port from mapper (stock mapper 0x1c) */
	ret = index_get(ctx, MAPPER_LCT_MEID_TO_LAN_IDX,
			me_id, &lan_port_buf);
	if (ret != OMCI_API_SUCCESS)
		return ret;
	lan_port = (uint8_t)lan_port_buf;

	/* Get meter from mapper (stock mapper 0x1d) — may not exist */
	ret = index_get(ctx, MAPPER_LCT_MEID_TO_METER_IDX,
			me_id, &meter_idx);
	if (ret == OMCI_API_SUCCESS) {
		/* Clear meter association */
		ret = lan_exception_meter_setup(ctx, lan_port,
						meter_idx, 0);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR,
				("%s lan_lct_meter_setup_failed, ret=%d\n",
				 __FUNCTION__, ret));
			return ret;
		}

		/* Delete the meter */
		ret = omci_api_meter_delete(ctx, (uint8_t)meter_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret;

		/* Unmap meter */
		ret = id_remove(ctx, MAPPER_LCT_MEID_TO_METER_IDX, me_id);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	/* Force locked state via _update */
	ret = omci_api_pptp_lct_uni_update(ctx, me_id, 1);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* Unmap lan_port */
	ret = id_remove(ctx, MAPPER_LCT_MEID_TO_LAN_IDX, me_id);

	return ret;
}
