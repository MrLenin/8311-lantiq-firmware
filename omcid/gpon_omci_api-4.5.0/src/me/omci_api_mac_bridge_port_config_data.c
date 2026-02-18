/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_priority_queue.h"
#include "me/omci_api_mac_bridge_port_config_data.h"
#include "me/omci_api_mac_bridge_port_config_data_intern.h"
#include "me/omci_api_mac_bridge_service_profile_intern.h"
#include "me/omci_api_pptp_ethernet_uni.h"

/** \addtogroup OMCI_API_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA

   @{
*/

enum omci_api_return
omci_api_mac_bridge_port_config_data_pmapper(struct omci_api_ctx *ctx,
					    uint16_t bridge_me,
					    uint16_t bridge_port_me_id,
					    uint16_t pmapper_me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t eth_uni_meid;
	uint32_t bridge_idx = 0;
	uint32_t bridge_port_idx = 0;
	uint32_t pmapper_index = 0;
	uint32_t gpix[8], i;
	uint8_t color_marking_us, color_marking_ds, lan_port;

	DBG(OMCI_API_MSG, ("bridge port:"
		  " bridge_port_me_id=%u"
		  " pmapper_me_id=%u\n",
		  bridge_port_me_id, pmapper_me_id));

	ret = index_get(ctx, MAPPER_MACBRIDGEPORT_MEID_TO_IDX,
			bridge_port_me_id, &bridge_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = index_get(ctx, MAPPER_DOT1PMAPPER_MEID_TO_IDX,
			pmapper_me_id, &pmapper_index);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("bridge port:"
			  " bridge_port_me_id=%u"
			  " pmapper_me_id=%u is not valid (yet),"
			  " please fix the OLT software\n",
				bridge_port_me_id, pmapper_me_id));
		return ret;
	}

	ret = bridge_idx_get(ctx, bridge_me, &bridge_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	/* find the first valid Eth UNI */
	for (i = 0; i < OMCI_API_PPPTP_ETHERNET_UNI_MAX; i++) {
		ret = id_get(ctx, MAPPER_PPTPETHUNI_MEID_TO_IDX,
			     &eth_uni_meid, i);
		lan_port = i;
		if (ret == OMCI_API_SUCCESS)
			break;
	}

	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = omci_api_priority_queue_drop_precedence_color_marking_get(
					OMCI_API_QUEUE_DIRECTION_UPSTREAM,
					lan_port,
					&color_marking_us);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("US Color Marking get failed, "
				"idx=0x%02X, ret=%d\n", bridge_port_idx,
							ret));
		return OMCI_API_ERROR;
	}

	ret = omci_api_priority_queue_drop_precedence_color_marking_get(
					OMCI_API_QUEUE_DIRECTION_DOWNSTREAM,
					lan_port,
					&color_marking_ds);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("DS Color Marking get failed, "
				"idx=0x%02X, ret=%d\n", bridge_port_idx,
							ret));
		return OMCI_API_ERROR;
	}

	omci_api_bridge_port_tp_modify(ctx, bridge_port_idx, 2, pmapper_index);
	omci_api_bridge_flooding_modify(ctx, false, 0xFF,
					bridge_idx, bridge_port_idx);

	if (omci_api_pmapper_get(ctx, pmapper_index, gpix,
				 NULL, NULL, NULL) == 0) {

		for (i=0;i<8;i++) {
			if (gpix[i] == 255)
				continue;
			omci_api_gem_port_interworking_modify(ctx, gpix[i], 6,
							      0,
							      bridge_port_idx);
			omci_api_gem_port_ds_ingress_color_marking_modify(ctx,
						          gpix[i],
						          1);
			omci_api_gem_port_us_queue_marking_mode_modify(ctx,
						          gpix[i],
						          color_marking_us);
		}

	}

	omci_api_bridge_port_ingress_color_marking_modify(ctx,
						bridge_port_idx,
						color_marking_ds);

	return ret;
}

enum omci_api_return
omci_api_mac_bridge_port_config_data_uni_fw_policer_rate_set(struct omci_api_ctx *ctx,
							     const uint16_t port_index,
							     const uint32_t rate)
{
	enum omci_api_return ret;
	struct gpe_table_entry entry;

	ret = table_read(ctx, ONU_GPE_LAN_PORT_TABLE_ID, port_index,
			 sizeof(struct gpe_lan_port_table), &entry);
	if (ret != 0)
		return OMCI_API_ERROR;

	entry.data.lan_port.policer_threshold = rate / 286;

	ret = table_write(ctx, sizeof(struct gpe_lan_port_table), &entry);

	return ret;
}

enum omci_api_return
omci_api_mac_bridge_port_config_data_uni(struct omci_api_ctx *ctx,
					    uint16_t bridge_me,
					    uint16_t bridge_port_me_id,
					    uint16_t tp_ptr)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t bridge_idx = 0;
	uint32_t bridge_port_idx = 0;
	uint8_t dir;
	uint8_t lan_port;
	uint8_t color_marking_us, color_marking_ds;

	ret = omci_api_uni2lan(ctx, tp_ptr, &lan_port);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = bridge_idx_get(ctx, bridge_me, &bridge_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = index_get(ctx, MAPPER_MACBRIDGEPORT_MEID_TO_IDX,
			bridge_port_me_id, &bridge_port_idx);
	if (ret == OMCI_API_NOT_FOUND) {
		ret = id_map(ctx, MAPPER_MACBRIDGEPORT_MEID_TO_IDX,
			     bridge_port_me_id, &bridge_port_idx);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("MAPPER_MACBRIDGEPORT_MEID_TO_IDX:"
					   " can't map %d id\n",
							bridge_port_me_id));
			return OMCI_API_ERROR;
		}
	} else if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
				("MAPPER_MACBRIDGEPORT_MEID_TO_IDX: failed\n"));
		return OMCI_API_ERROR;
	}

	dir = 0;
	omci_api_mac_bridge_direction_get(ctx, bridge_idx, &dir);
	if (dir == 3) {
		/* add for upstream traffic */
		/* link: lan port -> bridge port */
		/* add for downstream traffic */
		/* link: lan port -> queue index
			see mib.ini - downstream prio queue index
		*/
		omci_api_lan_port_interworking_modify(ctx,
		lan_port, 0x80 + 8*lan_port, 0, bridge_port_idx);
	}
	/* link: bridge port -> lan port */
	omci_api_bridge_port_tp_modify(ctx, bridge_port_idx,
					   0, lan_port);
	omci_api_bridge_flooding_modify(ctx, true, lan_port,
					bridge_idx, bridge_port_idx);

	ret = omci_api_priority_queue_drop_precedence_color_marking_get(
					OMCI_API_QUEUE_DIRECTION_UPSTREAM,
					lan_port,
					&color_marking_us);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("US Color Marking get failed, "
				"idx=0x%02X, ret=%d\n", lan_port,
							ret));
		return OMCI_API_ERROR;
	}

	ret = omci_api_priority_queue_drop_precedence_color_marking_get(
					OMCI_API_QUEUE_DIRECTION_DOWNSTREAM,
					lan_port,
					&color_marking_ds);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("DS Color Marking get failed, "
				"idx=0x%02X, ret=%d\n", lan_port,
							ret));
		return OMCI_API_ERROR;
	}

	omci_api_lan_port_queue_marking_mode_modify(ctx,
						lan_port,
						color_marking_ds);

	omci_api_bridge_port_ingress_color_marking_modify(ctx,
						bridge_port_idx,
						color_marking_us);

	return ret;
}

enum omci_api_return
omci_api_mac_bridge_port_config_data_update(struct omci_api_ctx *ctx,
					    uint16_t me_id,
					    uint16_t bridge_id_ptr,
					    uint8_t port_num,
					    uint8_t tp_type,
					    uint16_t tp_ptr,
					    uint16_t outbound_td_ptr,
					    uint16_t inbound_td_ptr,
					    uint8_t mac_learning_depth,
					    uint8_t mc_umc_flag1,
					    uint8_t mc_umc_flag2)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t bridge_idx = 0;
	uint32_t bridge_port_idx = 0;
	bool pmapper_indication = false;
	bool ani_indication = false;
	bool no_learning = false, gp_valid = true;
	uint32_t gpix = 0xffffffff;
	uint32_t ctp;
	uint8_t learning_ind;
	uint8_t port_bridging_ind;
	uint8_t unknown_uc_mac_discard;
	uint8_t umc_flag1 = 0, umc_flag2 = 0;
	uint8_t mac_learning_depth_from_bridge;
	uint8_t dir;
	struct gpe_gem_port gem_port;

	DBG(OMCI_API_MSG, ("bridge port:"
		  " me_id=%u"
		  " bridge_id_ptr=%u"
		  " port_num=%u"
		  " tp_type=%u"
		  " tp_ptr=%u"
		  " outbound_td_ptr=%u"
		  " inbound_td_ptr=%u\n",
		  me_id,
		  bridge_id_ptr, port_num, tp_type,
		  tp_ptr, outbound_td_ptr, inbound_td_ptr));

	ret = bridge_idx_get(ctx, bridge_id_ptr, &bridge_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = index_get(ctx, MAPPER_MACBRIDGEPORT_MEID_TO_IDX,
			me_id, &bridge_port_idx);
	if (ret == OMCI_API_NOT_FOUND) {
		ret = id_map(ctx, MAPPER_MACBRIDGEPORT_MEID_TO_IDX,
			     me_id, &bridge_port_idx);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("MAPPER_MACBRIDGEPORT_MEID_TO_IDX:"
					   " can't map %d id\n", me_id));
			return OMCI_API_ERROR;
		}
	} else if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
				("MAPPER_MACBRIDGEPORT_MEID_TO_IDX: failed\n"));
		return OMCI_API_ERROR;
	}

	/* link: bridge port -> bridge */
	omci_api_bridge_port_add(ctx, bridge_port_idx, bridge_idx);
	omci_api_bridge_port_meter_add(ctx, bridge_port_idx, me_id,
				       tp_ptr, tp_type, inbound_td_ptr, 1);
	omci_api_bridge_port_meter_add(ctx, bridge_port_idx, me_id,
				       tp_ptr, tp_type, outbound_td_ptr, 0);

	switch (tp_type) {
		case 1: /* Physical path termination point Ethernet UNI */
		omci_api_mac_bridge_port_config_data_uni(ctx, bridge_id_ptr,
							 me_id, tp_ptr);
		break;

		case 3: /* 802.1p mapper service profile */
		omci_api_mac_bridge_port_config_data_pmapper(ctx, bridge_id_ptr,
							     me_id, tp_ptr);
		omci_api_mac_bridge_direction_set(ctx, bridge_idx, 3);
		break;

		case 4: /* IP host config data */
		/* link: bridge port -> lan port */
		omci_api_bridge_port_tp_modify(ctx, bridge_port_idx, 0, 4);
		omci_api_bridge_flooding_modify(ctx, false, 0xFF,
						bridge_idx, bridge_port_idx);
		/* add for upstream traffic */
		/* link: lan port -> bridge port */
		/* add for downstream traffic */
		/* link: lan port -> queue index
			see mib.ini - downstream prio queue index
		*/
		dir = 0;
		omci_api_mac_bridge_direction_get(ctx, bridge_idx, &dir);
		if (dir == 3) {
			omci_api_lan_port_interworking_modify(ctx, 4, 0xa0, 0,
							      bridge_port_idx);
			omci_api_lan_port_enable(ctx, 4, 1);
		}
		break;

		case 5: /* GEM interworking termination point */
		ret = index_get(ctx, MAPPER_GEMITP_MEID_TO_GPIX, tp_ptr, &gpix);
		if (ret == OMCI_API_SUCCESS) {
			gpix = gpix & 0xFFFF;
			/* link: gem port -> bridge port */
			omci_api_gem_port_interworking_modify(ctx, gpix, 6, 0,
							      bridge_port_idx);
				/* v7.5.1: removed port_num==0x88 special case.
			   link: bridge port -> gem port */
			omci_api_bridge_port_tp_modify(ctx,
						       bridge_port_idx,
						       3, gpix);

			omci_api_gem_port_us_info_get(ctx, gpix,
						      &gp_valid);
			if (!gp_valid)
				no_learning = true;
			omci_api_bridge_flooding_modify(ctx, false, 0xFF,
							bridge_idx,
							bridge_port_idx);
		} else {
			DBG(OMCI_API_ERR,
				("omci_api_mac_bridge_port_config_data_update:"
				 " CTP missing\n"));
		}
		break;

		case 6: /* Multicast GEM interworking termination point */
		ret = index_get(ctx, MAPPER_MULCTCAST_GEMPORTITP_MEID_TO_CTP_MEID,
							tp_ptr, &ctp);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR,
				("omci_api_mac_bridge_port_config_data_update:"
				 " CTP missing\n"));
			break;
		}

		ret = index_get(ctx, MAPPER_GEMPORTCTP_MEID_TO_IDX, ctp, &gpix);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR,
				("omci_api_mac_bridge_port_config_data_update:"
				 " GPIX missing\n"));
			break;
		}

		gem_port.gem_port_id = (uint16_t)(gpix >> 16);
		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_GEM_PORT_GET,
			                    &gem_port, sizeof(gem_port));
		if (ret != 0) {
			DBG(OMCI_API_ERR,
				("omci_api_mac_bridge_port_config_data_update:"
				 " GEM port %d missing (error %d, 0x%x)\n", gem_port.gem_port_id, ret, gpix));
			break;
		}
		gem_port.gem_port_is_mc = true;
		if (dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_GEM_PORT_SET,
				                &gem_port, sizeof(gem_port)) != 0)
			DBG(OMCI_API_ERR, ("FIO_GPE_GEM_PORT_SET %d failed\n",
									ctp));
		/* link: gem port -> bridge port */
		omci_api_gem_port_interworking_modify(ctx, gpix & 0xFFFF, 6, 1,
							    bridge_port_idx);
		/* v7.5.1: bridge_port_tp_modify for MC GEM (stock has this) */
		omci_api_bridge_port_tp_modify(ctx, bridge_port_idx,
					       3, gpix & 0xFFFF);
		no_learning = true;
		/* v7.5.1: MC flood flags from caller (MCC sets these) */
		umc_flag1 = mc_umc_flag1 ? 1 : 0;
		umc_flag2 = mc_umc_flag2 ? 1 : 0;
		break;

		case 11: /* VEIP */
		omci_api_bridge_flooding_modify(ctx, false, 0xFF,
						bridge_idx, bridge_port_idx);
		break;

		case 0xFF: /* Internal bridge port */
		omci_api_mac_bridge_direction_set(ctx, bridge_idx, 3);
		omci_api_bridge_flooding_modify(ctx, true, 2,
						bridge_idx, bridge_port_idx);
		omci_api_bridge_port_tp_modify(ctx, bridge_port_idx, 1, 0);
		omci_api_lan_port_interworking_modify(ctx, 3, 0x90, 0,
						      bridge_port_idx);
		break;
	}

	if (omci_api_mac_bridge_data_get(ctx, bridge_idx,
			&learning_ind,
			&port_bridging_ind,
			&unknown_uc_mac_discard,
			&mac_learning_depth_from_bridge) != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("omci_api_mac_bridge_data_get: failed\n"));
		return OMCI_API_ERROR;
	}

	learning_ind = no_learning ? 0 : learning_ind;

	omci_api_bridge_port_learning_limitation_modify(ctx, bridge_port_idx,
							learning_ind,
							mac_learning_depth);

	/* v7.5.1: no port_num==0x88 special case */
	omci_api_bridge_port_local_switching_modify(ctx, bridge_port_idx,
						    port_bridging_ind);

	omci_api_bridge_port_uuc_mac_flood_modify(ctx, bridge_port_idx,
						  unknown_uc_mac_discard);

	omci_api_bridge_port_umc_mac_flood_modify(ctx, bridge_port_idx,
						  umc_flag1, umc_flag2);

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_mac_bridge_port_config_data_destroy(struct omci_api_ctx *ctx,
					     uint16_t me_id,
					     uint8_t tp_type,
					     uint16_t tp_ptr,
					     uint16_t outbound_td_ptr,
					     uint16_t inbound_td_ptr)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t bridge_port_idx = 0;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	ret = index_get(ctx, MAPPER_MACBRIDGEPORT_MEID_TO_IDX,
		       me_id, &bridge_port_idx);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	omci_api_bridge_port_meter_delete(ctx, bridge_port_idx, me_id, tp_ptr, tp_type,
					  inbound_td_ptr, 1);
	omci_api_bridge_port_meter_delete(ctx, bridge_port_idx, me_id, tp_ptr, tp_type,
					  outbound_td_ptr, 0);

	omci_api_bridge_port_delete(ctx, bridge_port_idx);

	ret = index_remove(ctx, MAPPER_MACBRIDGEPORT_MEID_TO_IDX,
			  bridge_port_idx);
	if (ret != OMCI_API_SUCCESS) {
		(void)error_notify(ctx, 47, me_id,
				   OMCI_API_ACTION_DESTROY, ret);
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}

/** @} */
