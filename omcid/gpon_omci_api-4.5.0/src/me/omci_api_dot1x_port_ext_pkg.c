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

   8311 mod: When UCI 8311.config.omcid_8021x=1, enforcement is disabled —
   all ports are forced OPEN regardless of what the OLT requests. This
   replaces the former runtime binary patch at offset 0x43589.
*/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_dot1x_port_ext_pkg.h"
#include <stdio.h>

/** Cached 802.1x disable flag: -1=unchecked, 0=enforce, 1=disable */
static int dot1x_disable_cached = -1;

static int dot1x_enforcement_disabled(void)
{
	FILE *fp;
	char val[8];
	size_t len;

	if (dot1x_disable_cached >= 0)
		return dot1x_disable_cached;

	dot1x_disable_cached = 0;
	fp = popen("uci -q get 8311.config.omcid_8021x", "r");
	if (!fp)
		return 0;

	len = fread(val, 1, sizeof(val) - 1, fp);
	(void)pclose(fp);

	if (len > 0) {
		val[len] = '\0';
		if (val[0] == '1')
			dot1x_disable_cached = 1;
	}

	return dot1x_disable_cached;
}

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

	/* 8311 mod: when enforcement is disabled via UCI, force OPEN always */
	if (dot1x_enforcement_disabled()) {
		auth_cfg.auth_result = LAN_PORT_802_1X_AUTH_OPEN;
		DBG(OMCI_API_MSG, ("%s: 802.1x disabled via UCI, "
				   "forcing OPEN\n", __FUNCTION__));
	}
	/*
	 * Standard OMCI decision tree (G.988 Section 9.3.13):
	 *
	 * - dot1x_enable=0: 802.1X not imposed -> OPEN
	 * - action_register=3 (force authenticated): unconditionally -> OPEN
	 * - action_register=1 (force re-auth): -> BLOCK (until re-auth passes)
	 * - action_register=2 (force unauthenticated): -> BLOCK
	 */
	else if (!dot1x_enable || action_register == 3)
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
