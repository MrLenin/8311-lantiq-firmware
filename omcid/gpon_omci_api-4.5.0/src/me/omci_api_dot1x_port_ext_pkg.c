/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_api_dot1x_port_ext_pkg.c

   802.1X port extension package — enforcement via kernel driver ioctl.

   Issues FIO_LAN_PORT_802_1X_AUTH_CFG_SET (defined in drv_onu_lan_interface.h)
   when the OLT updates ME 290 attributes.
*/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_dot1x_port_ext_pkg.h"

enum omci_api_return
omci_api_dot1x_port_ext_pkg_update(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint8_t dot1x_enable,
				   uint8_t action_register)
{
	enum omci_api_return ret;
	uint32_t port_idx = 0;
	struct lan_port_802_1x_auth_cfg auth_cfg;

	DBG(OMCI_API_MSG, ("%s: me_id=%u dot1x_enable=%u "
			   "action_register=%u\n",
			   __FUNCTION__, me_id, dot1x_enable,
			   action_register));

	if (ctx->remote)
		return OMCI_API_SUCCESS;

	/* ME 290 instance_id matches the associated PPTP Ethernet UNI ME ID.
	   Use the same mapper to resolve the LAN port index. */
	ret = index_get(ctx, MAPPER_PPTPETHUNI_MEID_TO_IDX,
			me_id, &port_idx);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("%s: can't map ME %u to LAN port index\n",
				   __FUNCTION__, me_id));
		return ret;
	}

	auth_cfg.port_id = port_idx;

	/*
	 * Standard OMCI decision tree (G.988 Section 9.3.13):
	 *
	 * - dot1x_enable=0: 802.1X not imposed -> OPEN
	 * - action_register=3 (force authenticated): unconditionally -> OPEN
	 * - action_register=1 (force re-auth): -> BLOCK (until re-auth passes)
	 * - action_register=2 (force unauthenticated): -> BLOCK
	 */
	if (!dot1x_enable || action_register == 3)
		auth_cfg.auth_result = LAN_PORT_802_1X_AUTH_OPEN;
	else
		auth_cfg.auth_result = LAN_PORT_802_1X_AUTH_BLOCK;

	DBG(OMCI_API_MSG, ("%s: port %u -> %s\n", __FUNCTION__,
			   port_idx,
			   auth_cfg.auth_result == LAN_PORT_802_1X_AUTH_OPEN ?
			   "OPEN" : "BLOCK"));

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_LAN_PORT_802_1X_AUTH_CFG_SET,
		      &auth_cfg, sizeof(auth_cfg));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("%s: 802.1x auth cfg set error %d "
				   "(port %u)\n",
				   __FUNCTION__, ret, port_idx));
		return ret;
	}

	return OMCI_API_SUCCESS;
}
