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
#include "me/omci_api_pptp_ethernet_uni.h"

/** \addtogroup OMCI_API_ME_ANI_G

   @{
*/

/** Expected type default value definition */
#define OMCI_API_PPTPETHUNI_EXPECTEDTYPE_DEFAULT  0
/** Pause time default value definition */
#define OMCI_API_PPTPETHUNI_PAUSETIME_DEFAULT     0xffff
/** Bridge or IP indication default value definition */
#define OMCI_API_PPTPETHUNI_BRIDGEIND_DEFAULT     0x0

static enum omci_api_return omci_api_pptp_ethernet_uni_config(
	struct omci_api_ctx *ctx,
	uint8_t port_idx,
	bool create,
	uint8_t expected_type,
	uint8_t auto_detect_cfg,
	uint8_t ethernet_loopback,
	uint16_t max_frame_size,
	uint8_t dte_dce_ind,
	uint16_t pause_time,
	uint8_t bridge_or_router_cfg,
	uint8_t pppoe_filter,
	uint8_t power_control,
	uint8_t admin_state)
{
	enum omci_api_return ret = OMCI_API_SUCCESS, err;
	struct lan_port_cfg lan_cfg;
	union lan_port_cfg_get_u lan_cfg_old;
	struct lan_loop_cfg loop_cfg;
	union lan_loop_cfg_get_u loop_cfg_old;
	struct gpe_cfg gpe_cfg, gpe_cfg_old;
	struct lan_port_capability_cfg lan_cap_cfg;
	union lan_port_capability_cfg_get_u lan_cap_cfg_old;

	if (ctx->remote)
		return ret;

	lan_cap_cfg_old.in.index = port_idx;
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_PORT_CAPABILITY_CFG_GET,
		      &lan_cap_cfg_old, sizeof(lan_cap_cfg_old));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("%s lan port capability cfg get error\n",
			__FUNCTION__));
		return ret;
	}

	memcpy(&lan_cap_cfg, &lan_cap_cfg_old.out, sizeof(lan_cap_cfg));

	lan_cfg_old.in.index = port_idx;
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_PORT_CFG_GET,
		      &lan_cfg_old, sizeof(union lan_port_cfg_get_u));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("%s lan port cfg get error\n",
			__FUNCTION__));
		return ret;
	}

	memcpy(&lan_cfg, &lan_cfg_old.out, sizeof(struct lan_port_cfg));

	if (lan_cfg.mode == LAN_MODE_OFF) {
		DBG(OMCI_API_ERR, ("lan port %d isn't configured yet, "
				   "skip configuration\n", port_idx ));
		return OMCI_API_SUCCESS;
	}

	loop_cfg_old.in.index = port_idx;
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_LOOP_CFG_GET,
		      &loop_cfg_old, sizeof(union lan_loop_cfg_get_u));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("%s lan port loop cfg get error\n",
			__FUNCTION__));
		return ret;
	}

	memcpy(&loop_cfg, &loop_cfg_old.out, sizeof(struct lan_loop_cfg));

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_CFG_GET, &gpe_cfg_old, sizeof(gpe_cfg_old));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("%s GPE cfg get failed, %d\n",
			__FUNCTION__, ret));
		return ret;
	}

	memcpy(&gpe_cfg, &gpe_cfg_old, sizeof(gpe_cfg));

	switch (ethernet_loopback) {
	case OMCI_API_PPPTPETHUNI_LOOPBACK_DISABLED:
		loop_cfg.phy_ingress_loop_en = false;
		break;

	case OMCI_API_PPPTPETHUNI_LOOPBACK_ENABLED:
		loop_cfg.phy_ingress_loop_en = true;
		break;

	default:
		DBG(OMCI_API_ERR, ("%s: loopback error\n", __FUNCTION__));
		return OMCI_API_ERROR;
	}

	switch (expected_type) {
	case OMCI_API_PPTPETHUNI_EXPECTED_TYPE_NOLIM:
		lan_cfg.speed_mode = LAN_MODE_SPEED_AUTO;
		lan_cfg.duplex_mode = LAN_PHY_MODE_DUPLEX_AUTO;
		break;

	case OMCI_API_PPTPETHUNI_EXPECTED_TYPE_10BASET:
		lan_cfg.speed_mode = LAN_MODE_SPEED_10;
		lan_cfg.duplex_mode = LAN_PHY_MODE_DUPLEX_FULL;
		break;

	case OMCI_API_PPTPETHUNI_EXPECTED_TYPE_10_100BASET:
	case OMCI_API_PPTPETHUNI_EXPECTED_TYPE_100BASET:
		lan_cfg.speed_mode = LAN_MODE_SPEED_100;
		lan_cfg.duplex_mode = LAN_PHY_MODE_DUPLEX_FULL;
		break;

	case OMCI_API_PPTPETHUNI_EXPECTED_TYPE_10_100_1000BASET:
		lan_cfg.speed_mode = LAN_MODE_SPEED_1000;
		lan_cfg.duplex_mode = LAN_PHY_MODE_DUPLEX_FULL;
		break;

	default:
		DBG(OMCI_API_ERR, ("%s: unsupported expected type (%d)\n",
				   __FUNCTION__, expected_type));
		return OMCI_API_ERROR;
	}

	/** \note DTE/DCE is defined by initialization
		  and can't be changed by OLT */
	/** \todo Add check if dte_dce_ind value is valid */
	switch (auto_detect_cfg) {
	case OMCI_API_PPPTPETHUNI_DETECT_10_FULL:
		lan_cap_cfg.full_duplex = true;
		lan_cap_cfg.half_duplex = false;
		lan_cap_cfg.mbit_10 = true;
		lan_cap_cfg.mbit_100 = false;
		lan_cap_cfg.mbit_1000 = false;
		break;

	case OMCI_API_PPPTPETHUNI_DETECT_100_FULL:
		lan_cap_cfg.full_duplex = true;
		lan_cap_cfg.half_duplex = false;
		lan_cap_cfg.mbit_10 = false;
		lan_cap_cfg.mbit_100 = true;
		lan_cap_cfg.mbit_1000 = false;
		break;

	case OMCI_API_PPPTPETHUNI_DETECT_1000_FULL:
		lan_cap_cfg.full_duplex = true;
		lan_cap_cfg.half_duplex = false;
		lan_cap_cfg.mbit_10 = false;
		lan_cap_cfg.mbit_100 = false;
		lan_cap_cfg.mbit_1000 = true;
		break;

	case OMCI_API_PPPTPETHUNI_DETECT_AUTO:
		lan_cap_cfg.full_duplex = true;
		lan_cap_cfg.half_duplex = true;
		lan_cap_cfg.mbit_10 = true;
		lan_cap_cfg.mbit_100 = true;
		lan_cap_cfg.mbit_1000 = true;
		break;

	case OMCI_API_PPPTPETHUNI_DETECT_AUTO_FULL:
		lan_cap_cfg.full_duplex = true;
		lan_cap_cfg.half_duplex = false;
		lan_cap_cfg.mbit_10 = true;
		lan_cap_cfg.mbit_100 = true;
		lan_cap_cfg.mbit_1000 = true;
		break;

	case OMCI_API_PPPTPETHUNI_DETECT_10_AUTO:
		lan_cap_cfg.full_duplex = true;
		lan_cap_cfg.half_duplex = true;
		lan_cap_cfg.mbit_10 = true;
		lan_cap_cfg.mbit_100 = false;
		lan_cap_cfg.mbit_1000 = false;
		break;

	case OMCI_API_PPPTPETHUNI_DETECT_10_HALF:
		lan_cap_cfg.full_duplex = false;
		lan_cap_cfg.half_duplex = true;
		lan_cap_cfg.mbit_10 = true;
		lan_cap_cfg.mbit_100 = false;
		lan_cap_cfg.mbit_1000 = false;
		break;

	case OMCI_API_PPPTPETHUNI_DETECT_100_HALF:
		lan_cap_cfg.full_duplex = false;
		lan_cap_cfg.half_duplex = true;
		lan_cap_cfg.mbit_10 = false;
		lan_cap_cfg.mbit_100 = true;
		lan_cap_cfg.mbit_1000 = false;
		break;

	case OMCI_API_PPPTPETHUNI_DETECT_1000_HALF:
		lan_cap_cfg.full_duplex = false;
		lan_cap_cfg.half_duplex = true;
		lan_cap_cfg.mbit_10 = false;
		lan_cap_cfg.mbit_100 = false;
		lan_cap_cfg.mbit_1000 = true;
		break;

	case OMCI_API_PPPTPETHUNI_DETECT_AUTO_HALF:
		lan_cap_cfg.full_duplex = false;
		lan_cap_cfg.half_duplex = true;
		lan_cap_cfg.mbit_10 = true;
		lan_cap_cfg.mbit_100 = true;
		lan_cap_cfg.mbit_1000 = true;
		break;

	case OMCI_API_PPPTPETHUNI_DETECT_1000_AUTO:
		lan_cap_cfg.full_duplex = true;
		lan_cap_cfg.half_duplex = true;
		lan_cap_cfg.mbit_10 = false;
		lan_cap_cfg.mbit_100 = false;
		lan_cap_cfg.mbit_1000 = true;
		break;

	case OMCI_API_PPPTPETHUNI_DETECT_100_AUTO:
		lan_cap_cfg.full_duplex = true;
		lan_cap_cfg.half_duplex = true;
		lan_cap_cfg.mbit_10 = false;
		lan_cap_cfg.mbit_100 = true;
		lan_cap_cfg.mbit_1000 = false;
		break;

	default:
		DBG(OMCI_API_ERR, ("%s: auto_detect_cfg error\n",
			__FUNCTION__));
		return OMCI_API_ERROR;
	}

	omci_api_lan_port_ppoe_modify(ctx, port_idx, pppoe_filter);
	loop_cfg.index = port_idx;
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_LOOP_CFG_SET,
		      &loop_cfg, sizeof(struct lan_loop_cfg));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("%s: lan port loop cfg set error %d, enable %d\n",
						__FUNCTION__, ret,
						loop_cfg.phy_ingress_loop_en));
		goto lan_loop_restore;
	}

	lan_cfg.uni_port_en = admin_state == 0;
	lan_cfg.max_frame_size = max_frame_size;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_PORT_CFG_SET,
		      &lan_cfg, sizeof(struct lan_port_cfg));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("%s: lan port cfg set error %d\n",
					__FUNCTION__, ret));
		DBG(OMCI_API_ERR,
			("%s: restore lan port settings, speed %d, duplex %d\n",
						__FUNCTION__,
						lan_cfg_old.out.speed_mode,
						lan_cfg_old.out.duplex_mode));
		goto lan_port_restore;
	}

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_PORT_CAPABILITY_CFG_SET,
		      &lan_cap_cfg, sizeof(lan_cap_cfg));
	if (ret != OMCI_API_SUCCESS && ret != LAN_STATUS_NO_SUPPORT) {
		lan_cap_cfg.full_duplex = true;
		lan_cap_cfg.half_duplex = true;
		lan_cap_cfg.mbit_10 = false;
		lan_cap_cfg.mbit_100 = true;
		lan_cap_cfg.mbit_1000 = false;
		DBG(OMCI_API_ERR,
			("%s: lan port capability cfg set error %d, "
			 "full_duplex %d, half_duplex %d, mbit_10 %d, "
			 "mbit_100 %d, mbit_1000 %d\n",
			 __FUNCTION__, ret,
			 lan_cap_cfg.full_duplex, lan_cap_cfg.half_duplex,
			 lan_cap_cfg.mbit_10, lan_cap_cfg.mbit_100,
			 lan_cap_cfg.mbit_1000));
		DBG(OMCI_API_ERR,
			("%s: restore lan port capability cfg, "
			 "full_duplex %d, half_duplex %d, mbit_10 %d, "
			 "mbit_100 %d, mbit_1000 %d\n",
			 __FUNCTION__, ret,
			 lan_cap_cfg_old.out.full_duplex,
			 lan_cap_cfg_old.out.half_duplex,
			 lan_cap_cfg_old.out.mbit_10, lan_cap_cfg_old.out.mbit_100,
			 lan_cap_cfg_old.out.mbit_1000));
		goto lan_port_restore;
	}

	/* Set GPE Eth PDU max size*/
	gpe_cfg.pdu_size_max_eth = max_frame_size;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_CFG_SET, &gpe_cfg, sizeof(gpe_cfg));
	if (ret != OMCI_API_SUCCESS)
		goto restore;

	omci_api_lan_port_enable(ctx, port_idx, admin_state == 0);

	return ret;
restore:
	/* Restore GPE config */
	err = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_CFG_SET, &gpe_cfg_old, sizeof(gpe_cfg_old));
	if (err != OMCI_API_SUCCESS)
		DBG(OMCI_API_ERR, ("%s: GPE config restore failed\n",
			__FUNCTION__));

lan_port_capability_restore:
	/* Restore LAN port capability config */
	err = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_PORT_CAPABILITY_CFG_SET,
		      &lan_cap_cfg_old, sizeof(lan_cap_cfg_old));
	if (err != OMCI_API_SUCCESS)
		DBG(OMCI_API_ERR, ("%s: LAN port capability config restore "
				   "failed\n", __FUNCTION__));

lan_port_restore:
	/* Restore LAN port config */
	err = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_PORT_CFG_SET,
		      &lan_cfg_old, sizeof(struct lan_port_cfg));
	if (err != OMCI_API_SUCCESS)
		DBG(OMCI_API_ERR, ("%s: LAN port config restore failed\n",
			__FUNCTION__));

lan_loop_restore:
	/* Restore LAN Loop config */
	err = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_LOOP_CFG_SET,
		      &loop_cfg_old, sizeof(struct lan_loop_cfg));
	if (err != OMCI_API_SUCCESS)
		DBG(OMCI_API_ERR, ("%s: restore loop settings failed\n",
			__FUNCTION__));

	return ret;
}

enum omci_api_return
omci_api_pptp_ethernet_uni_create(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint8_t admin_state,
				  uint8_t expected_type,
				  uint8_t auto_detect_cfg,
				  uint8_t ethernet_loopback,
				  uint16_t max_frame_size,
				  uint8_t dte_dce_ind,
				  uint16_t pause_time,
				  uint8_t bridge_or_router_cfg,
				  uint8_t pppoe_filter,
				  uint8_t power_control)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint8_t lan_port;

	ret = omci_api_uni2lan(ctx, me_id, &lan_port);
	if(ret != OMCI_API_SUCCESS)
		return ret;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   expected_type=%u\n"
		  "   auto_detect_cfg=%u\n" "   ethernet_loopback=%u\n"
		  "   max_frame_size=%u\n" "   dte_dce_ind=%u\n"
		  "   pause_time=%u\n" "   bridge_or_router_cfg=%u\n"
		  "   pppoe_filter=%u\n" "   power_control=%u\n",
		  __FUNCTION__,
		  me_id, expected_type,
		  auto_detect_cfg, ethernet_loopback, max_frame_size,
		  dte_dce_ind, pause_time, bridge_or_router_cfg, pppoe_filter,
		  power_control));

	ret = explicit_map(ctx, MAPPER_PPTPETHUNI_MEID_TO_IDX,
				   me_id, lan_port);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = omci_api_pptp_ethernet_uni_config(ctx,
						lan_port,
						true,
						expected_type,
						auto_detect_cfg,
						ethernet_loopback,
						max_frame_size,
						dte_dce_ind,
						pause_time,
						bridge_or_router_cfg,
						pppoe_filter,
						power_control,
						admin_state);

	if (ret != OMCI_API_SUCCESS) {
		(void)error_notify(ctx, 11, me_id, OMCI_API_ACTION_CREATE, ret);
		return ret;
	}

	return ret;
}

enum omci_api_return
omci_api_pptp_ethernet_uni_destroy(struct omci_api_ctx *ctx,
				   uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t uni_port_idx = 0;
	struct lan_port_cfg cfg;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	ret = index_get(ctx, MAPPER_PPTPETHUNI_MEID_TO_IDX,
			me_id, &uni_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	omci_api_lan_port_enable(ctx, uni_port_idx, 0);

	cfg.index = (uint8_t)uni_port_idx;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_PORT_CFG_GET,
		      &cfg, sizeof(struct lan_port_cfg));

	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("%s: lan port cfg get error\n",
			__FUNCTION__));
		return ret;
	}

	if (cfg.mode == LAN_MODE_OFF) {
		DBG(OMCI_API_ERR, ("lan port %d isn't configured yet, "
				   "skip configuration\n", uni_port_idx ));
	} else {
		cfg.index = (uint8_t)uni_port_idx;
		cfg.uni_port_en = false;

		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_PORT_CFG_SET,
			      &cfg, sizeof(struct lan_port_cfg));
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("%s: lan port cfg get error\n",
				__FUNCTION__));
			return ret;
		}
	}

	ret = id_remove(ctx, MAPPER_PPTPETHUNI_MEID_TO_IDX, me_id);

	return ret;
}

enum omci_api_return
omci_api_pptp_ethernet_uni_update(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint8_t admin_state,
				  uint8_t expected_type,
				  uint8_t auto_detect_cfg,
				  uint8_t ethernet_loopback,
				  uint16_t max_frame_size,
				  uint8_t dte_dce_ind,
				  uint16_t pause_time,
				  uint8_t bridge_or_router_cfg,
				  uint8_t pppoe_filter,
				  uint8_t power_control)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t uni_port_idx = 0;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   expected_type=%u\n"
		  "   auto_detect_cfg=%u\n" "   ethernet_loopback=%u\n"
		  "   max_frame_size=%u\n" "   dte_dce_ind=%u\n"
		  "   pause_time=%u\n" "   bridge_or_router_cfg=%u\n"
		  "   pppoe_filter=%u\n" "   power_control=%u\n",
		  __FUNCTION__,
		  me_id, expected_type,
		  auto_detect_cfg, ethernet_loopback, max_frame_size,
		  dte_dce_ind, pause_time, bridge_or_router_cfg, pppoe_filter,
		  power_control));

	ret = index_get(ctx, MAPPER_PPTPETHUNI_MEID_TO_IDX,
			me_id, &uni_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = omci_api_pptp_ethernet_uni_config(ctx,
						uni_port_idx,
						false,
						expected_type,
						auto_detect_cfg,
						ethernet_loopback,
						max_frame_size,
						dte_dce_ind,
						pause_time,
						bridge_or_router_cfg,
						pppoe_filter,
						power_control,
						admin_state);

	if (ret != OMCI_API_SUCCESS) {
		(void)error_notify(ctx, 11, me_id, OMCI_API_ACTION_UPDATE, ret);
		return ret;
	}

	return ret;
}

enum omci_api_return
omci_api_pptp_ethernet_uni_configuration_ind_get(struct omci_api_ctx *ctx,
						 uint16_t me_id,
						 uint8_t *cfg_ind)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t uni_port_idx = 0;
	union lan_port_status_get_u status;

	DBG(OMCI_API_MSG, ("%s\n   me_id = %u", __FUNCTION__, me_id));

	*cfg_ind = 0;

	ret = index_get(ctx, MAPPER_PPTPETHUNI_MEID_TO_IDX,
			me_id, &uni_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	status.in.index = (uint8_t)uni_port_idx;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_LAN_PORT_STATUS_GET,
		      &status, sizeof(status));

	if (ret != OMCI_API_SUCCESS)
		return ret;

	if (status.out.phy_duplex == LAN_PHY_MODE_DUPLEX_FULL) {
		switch (status.out.link_status) {
		case LAN_PHY_STATUS_OFF:
		case LAN_PHY_STATUS_DOWN:
		case LAN_PHY_STATUS_NONE:
		case LAN_PHY_STATUS_UNKNOWN:
			*cfg_ind = 0;
			break;

		case LAN_PHY_STATUS_10_UP:
			*cfg_ind = OMCI_API_PPPTPETHUNI_DETECT_10_FULL;
			break;

		case LAN_PHY_STATUS_100_UP:
			*cfg_ind = OMCI_API_PPPTPETHUNI_DETECT_100_FULL;
			break;

		case LAN_PHY_STATUS_1000_UP:
			*cfg_ind = OMCI_API_PPPTPETHUNI_DETECT_1000_FULL;
			break;

		default:
			return OMCI_API_ERROR;
		}
	} else if (status.out.phy_duplex == LAN_PHY_MODE_DUPLEX_HALF) {
		switch (status.out.link_status) {
		case LAN_PHY_STATUS_OFF:
		case LAN_PHY_STATUS_DOWN:
		case LAN_PHY_STATUS_NONE:
		case LAN_PHY_STATUS_UNKNOWN:
			*cfg_ind = 0;
			break;

		case LAN_PHY_STATUS_10_UP:
			*cfg_ind = OMCI_API_PPPTPETHUNI_DETECT_10_HALF;
			break;

		case LAN_PHY_STATUS_100_UP:
			*cfg_ind = OMCI_API_PPPTPETHUNI_DETECT_100_HALF;
			break;

		case LAN_PHY_STATUS_1000_UP:
			*cfg_ind = OMCI_API_PPPTPETHUNI_DETECT_1000_HALF;
			break;

		default:
			return OMCI_API_ERROR;
		}
	} else {
		/** The auto negotiation is in progress,
		    the configuration is undefined */
		*cfg_ind = 0;
	}

	return ret;
}

/** @} */
