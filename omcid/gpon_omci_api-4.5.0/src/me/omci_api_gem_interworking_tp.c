/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_gem_interworking_tp.h"
#include "me/omci_api_mac_bridge_port_config_data_intern.h"
#include "me/omci_api_mac_bridge_service_profile_intern.h"

/** \addtogroup OMCI_API_ME_GEM_INTERWORKING_TP

   @{
*/

enum omci_api_return
omci_api_gem_interworking_tp_update(struct omci_api_ctx *ctx,
				    uint16_t me_id,
				    uint16_t gem_port_id,
				    uint8_t interworking_option,
				    uint16_t service_profile_pointer,
				    uint16_t interworking_tp_pointer,
				    uint8_t gal_loopback_configuration,
				    struct bridge_data *bridge)
{
	enum omci_api_return ret;
	struct gpe_gem_port gem_port;
	uint32_t gpix = 0xffffffff;
	uint32_t bridge_idx = 0, i;
	uint32_t bridge_port_idx = 0;
	uint8_t lan_port;
	uint32_t tmp;

	DBG(OMCI_API_MSG, ("gem port itp:"
		  " me_id=%u"
		  " gem_port_id=%u"
		  " interworking_option=%u"
		  " service_profile_pointer=%u"
		  " interworking_tp_pointer=%u"
		  " gal_loopback_configuration=%u\n",
		  me_id, gem_port_id, interworking_option,
		  service_profile_pointer, interworking_tp_pointer,
		  gal_loopback_configuration));

	memset(&gem_port, 0x00, sizeof(gem_port));
	gem_port.gem_port_id = gem_port_id;
	if (dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_GEM_PORT_GET,
		    &gem_port, sizeof(gem_port)) != 0) {
		DBG(OMCI_API_ERR, ("FIO_GPE_GEM_PORT_GET: can't find %d id\n",
								gem_port_id));
		return OMCI_API_ERROR;
	}
	gpix = gem_port.gem_port_index;

	if (index_get(ctx, MAPPER_GEMITP_MEID_TO_GPIX,
		      me_id, &tmp) != OMCI_API_SUCCESS) {
		ret = explicit_map(ctx, MAPPER_GEMITP_MEID_TO_GPIX,
				   me_id, gpix);
		if (ret != OMCI_API_SUCCESS)
			return ret;
	}

	/* v7.5.1: skip loopback modify for broadcast GEM (interworking 6) */
	if (interworking_option != 6)
		omci_api_gem_port_loop_modify(ctx, gpix,
					      gal_loopback_configuration);

	if (gem_port.data_direction == 3) {
		for (i=0;i<bridge->count;i++) {
			if ((bridge->port[i].tp_type != 1) &&
			    (bridge->port[i].tp_type != 4) &&
			    (bridge->port[i].tp_type != 7))
				continue;
			ret = index_get(ctx, MAPPER_MACBRIDGEPORT_MEID_TO_IDX,
					bridge->port[i].me_id,
					&bridge_port_idx);
			if (ret != OMCI_API_SUCCESS)
				continue;
			if (bridge->port[i].tp_type == 1) {
				ret = omci_api_uni2lan(ctx, bridge->port[i].tp_ptr, &lan_port);
				if(ret == OMCI_API_SUCCESS) {
					omci_api_lan_port_interworking_modify(ctx,
						lan_port, 0x80 + 8*lan_port, 0,
						bridge_port_idx);
				}
			}
			/* v7.5.1: tp_type 7 = IPv6 host config data */
			if (bridge->port[i].tp_type == 7) {
				uint32_t port_idx;
				ret = index_get(ctx,
						MAPPER_IPV6HOST_MEID_TO_IDX,
						bridge->port[i].tp_ptr,
						&port_idx);
				if (ret == OMCI_API_SUCCESS) {
					omci_api_lan_port_interworking_modify(
						ctx, port_idx & 0xffff,
						((port_idx + 0x40) * 2) & 0xff,
						0, bridge_port_idx);
				}
			}
			if (bridge->port[i].tp_type == 4) {
				struct lan_port_802_1x_auth_cfg auth;
				omci_api_lan_port_interworking_modify(ctx,
					4, 0xa0, 0, bridge_port_idx);
				omci_api_lan_port_enable(ctx, 4, 1);
				/* v7.5.1: disable 802.1x auth for VEIP */
				auth.port_id = 4;
				auth.auth_result =
					LAN_PORT_802_1X_AUTH_OPEN;
				dev_ctl(ctx->remote, ctx->onu_fd,
					FIO_LAN_PORT_802_1X_AUTH_CFG_SET,
					&auth, sizeof(auth));
			}
		}
	}

	switch (interworking_option) {
		case 1: /* bridge */
		ret = index_get(ctx, MAPPER_MACBRIDGE_MEID_TO_IDX,
				service_profile_pointer, &bridge_idx);
		if (ret == OMCI_API_SUCCESS) {
			/* set direction derived from gem port ctp */
			omci_api_mac_bridge_direction_set(ctx, bridge_idx,
							  gem_port.
								data_direction);
		}
		break;

		case 5: /* pmapper */
		break;

		case 6: /* gem broadcast - bridge */
		break;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_gem_interworking_tp_destroy(struct omci_api_ctx *ctx,
				     uint16_t me_id,
				     uint16_t gem_port_id,
				     uint8_t interworking_option,
				     uint16_t service_profile_pointer)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t tmp;

	if (index_get(ctx, MAPPER_GEMITP_MEID_TO_GPIX, me_id, &tmp)
		!= OMCI_API_SUCCESS) {
		return OMCI_API_SUCCESS;
	}

	ret = id_remove(ctx, MAPPER_GEMITP_MEID_TO_GPIX, me_id);
	if (ret != OMCI_API_SUCCESS) {
		(void)error_notify(ctx, 266, me_id,
				   OMCI_API_ACTION_DESTROY, ret);
		return ret;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_gem_interworking_tp_op_state_get(struct omci_api_ctx *ctx,
					  const uint16_t me_id,
					  const uint16_t gem_port_id,
					  uint8_t *op_state)
{
	enum omci_api_return ret;
	struct gpe_gem_port gem_port;

	memset(&gem_port, 0x00, sizeof(gem_port));
	gem_port.gem_port_id = gem_port_id;
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_GEM_PORT_GET,
		      &gem_port, sizeof(gem_port));
	if (ret != 0)
		*op_state = 1;
	else
		omci_api_op_state_get(ctx, gem_port.gem_port_index,
				    gem_port.data_direction, op_state);

	return OMCI_API_SUCCESS;
}


/** @} */
