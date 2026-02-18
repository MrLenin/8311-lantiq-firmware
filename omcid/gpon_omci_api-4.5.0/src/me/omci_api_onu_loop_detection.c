/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_api_onu_loop_detection.c
   Loop detection API — ioctl wrappers for vendor-specific ME ~65528.

   Reverse-engineered from stock omcid v7.5.1:
     0x00443610 = omci_api_onu_loop_detection_create     (130B)
     0x004436ac = omci_api_onu_loop_detection_update     (232B)
     0x004437b4 = omci_api_onu_loop_detection_destroy    (62B)
     0x00443808 = omci_api_onu_loop_detection_packet_send (196B)

   Stock helper function mappings:
     FUN_00434de0 = index_get(ctx, mapper_id, me_id, &result)
     FUN_00432244 = dev_ctl(remote, fd, ioctl, data, size)
     FUN_004331bc = lan_exception_setup (shared helper, see lan_exception_setup.c)
     FUN_00446850 = loop detection exception ethertype setup (3 params)

   Stock uses mapper 0x1b for PPTP ETH UNI → LAN port index lookup.
*/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "omci_api_mapper.h"
#include "me/omci_api_onu_loop_detection.h"

/** \addtogroup OMCI_API_ME_ONU_LOOP_DETECTION
   @{
*/

/**
   Set up GPE exception handling for loop detection ethertype 0xFFFA.

   Stock FUN_00446850(ctx, 1, 0xfffa) — only called from _create.
   Exact implementation needs decompilation of FUN_00446850 @ 0x00446850.

   The function likely configures the GPE ethertype filter or exception table
   to redirect frames with ethertype 0xFFFA to CPU for loop detection processing.

   \param[in] ctx        OMCI API context pointer
   \param[in] instance   GPE table instance (stock passes 1)
   \param[in] ethertype  Ethertype to register (stock passes 0xFFFA)
*/
static enum omci_api_return
loop_detection_exception_ethertype_setup(struct omci_api_ctx *ctx,
					 uint32_t instance,
					 uint16_t ethertype)
{
	/* TODO: Decompile FUN_00446850 @ 0x00446850 for exact implementation.
	   Stock _create is 130 bytes total, mostly logging — the real work
	   is this single call. Until decompiled, return success so the ME
	   handler can proceed with _update (which does the actual ioctl). */
	DBG(OMCI_API_MSG, ("%s instance=%u ethertype=0x%04x\n",
			   __FUNCTION__, instance, ethertype));

	(void)ctx;
	(void)instance;
	(void)ethertype;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_onu_loop_detection_create(struct omci_api_ctx *ctx,
				   uint16_t me_id)
{
	enum omci_api_return ret;

	DBG(OMCI_API_MSG, ("%s me_id=%u\n", __FUNCTION__, me_id));

	ret = loop_detection_exception_ethertype_setup(ctx, 1, 0xfffa);
	if (ret != OMCI_API_SUCCESS)
		DBG(OMCI_API_ERR, ("Loop Detection exception ethertype "
				   "setup failed, ret=%d\n", ret));

	return ret;
}

enum omci_api_return
omci_api_onu_loop_detection_update(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint16_t uni_me_id,
				   uint16_t enable,
				   uint16_t port_shutdown)
{
	enum omci_api_return ret;
	uint32_t port_idx = 0;
	struct lan_port_loop_detection_cfg cfg;

	DBG(OMCI_API_MSG, ("%s me_id=%u uni_me_id=%u enable=%u "
			   "port_shutdown=%u\n",
			   __FUNCTION__, me_id, uni_me_id,
			   enable, port_shutdown));

	/* Stock: FUN_00434de0(ctx, 0x1b, uni_me_id, &port_idx)
	   Mapper 0x1b = MAPPER_PPTPETHUNI_MEID_TO_IDX */
	ret = index_get(ctx, MAPPER_PPTPETHUNI_MEID_TO_IDX,
			uni_me_id, &port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* Stock: FUN_004331bc(ctx, port_idx & 0xff, 0, DAT_004437a8, 0, 0, 0)
	   lan_exception_setup — configures exception handling for the port.
	   The DAT_004437a8 constant is an exception mask for loop detection.
	   TODO: Implement lan_exception_setup as shared helper (Phase C). */

	/* Stock: dev_ctl(remote, fd, FIO_LAN_PORT_LOOP_DETECTION_CFG_SET, &cfg, 12)
	   Boolean normalization: stock uses (-val >> 31) to convert non-zero to 1 */
	cfg.index = port_idx;
	cfg.enable = enable ? 1 : 0;
	cfg.port_shutdown = port_shutdown ? 1 : 0;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_LAN_PORT_LOOP_DETECTION_CFG_SET,
		      &cfg, sizeof(cfg));
	if (ret != OMCI_API_SUCCESS)
		DBG(OMCI_API_ERR, ("Loop Detection cfg set failed, "
				   "ret=%d\n", ret));

	return ret;
}

enum omci_api_return
omci_api_onu_loop_detection_destroy(struct omci_api_ctx *ctx,
				    uint16_t me_id)
{
	/* Stock: logging only, returns 0. No hardware cleanup. */
	DBG(OMCI_API_MSG, ("%s me_id=%u\n", __FUNCTION__, me_id));

	(void)ctx;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_onu_loop_detection_packet_send(struct omci_api_ctx *ctx,
					uint16_t me_id,
					uint16_t svlan,
					uint16_t cvlan,
					uint16_t uni_me_id)
{
	enum omci_api_return ret;
	uint32_t port_idx = 0;
	struct lan_port_loop_detection_packet_send pkt;

	DBG(OMCI_API_MSG, ("%s me_id=%u svlan=%u cvlan=%u uni_me_id=%u\n",
			   __FUNCTION__, me_id, svlan, cvlan, uni_me_id));

	/* Stock: FUN_00434de0(ctx, 0x1b, uni_me_id, &port_idx) */
	ret = index_get(ctx, MAPPER_PPTPETHUNI_MEID_TO_IDX,
			uni_me_id, &port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* Stock: builds {port_idx, svlan(16)|cvlan(16)} then
	   dev_ctl(remote, fd, FIO_LAN_PORT_LOOP_DETECTION_PACKET_SEND, &pkt, 8) */
	pkt.index = port_idx;
	pkt.svlan = svlan;
	pkt.cvlan = cvlan;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_LAN_PORT_LOOP_DETECTION_PACKET_SEND,
		      &pkt, sizeof(pkt));
	if (ret != OMCI_API_SUCCESS)
		DBG(OMCI_API_ERR, ("Loop Detection packet send failed, "
				   "ret=%d\n", ret));

	return ret;
}

/** @} */
