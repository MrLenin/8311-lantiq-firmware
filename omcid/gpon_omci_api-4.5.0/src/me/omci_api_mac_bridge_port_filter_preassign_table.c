/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_mac_bridge_port_filter_preassign_table.h"

/** \addtogroup OMCI_API_ME_MAC_BRIDGE_PORT_FILTER_PREASSIGN_TABLE

   @{
*/

#define OPERATION_FORWARD	0
#define OPERATION_FILTER	1

/** Change snooping value in the redirection table

   \param index Redirection table entry index
   \param snooping Whether enable (true) or disable (false) snooping
*/
static enum omci_api_return snooping_set(struct omci_api_ctx *ctx,
					 uint32_t index, bool snooping)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_table_entry entry;

	entry.id = ONU_GPE_REDIRECTION_TABLE_ID;
	entry.instance = 1;
	entry.index = index;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TABLE_ENTRY_GET,
		      &entry, TABLE_ENTRY_SIZE(entry.data.redirection));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	entry.data.redirection.snooping_enable = snooping;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TABLE_ENTRY_SET,
		      &entry, TABLE_ENTRY_SIZE(entry.data.redirection));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

/** Update exception configuration table entry resources

   \param[in] exception_table_entry_idx		Exception table entry index
   \param[in] ani_indication			ANI side indication
   \param[in] ipv4_multicast_filtering		IPv4 multicast filtering
   \param[in] ipv6_multicast_filtering		IPv6 multicast filtering
   \param[in] ipv4_broadcast_filtering		IPv4 broadcast filtering
   \param[in] rarp_filtering			RARP filtering
   \param[in] ipx_filtering			IPX filtering
   \param[in] net_beui_filtering		NetBEUI filtering
   \param[in] apple_talk_filtering		AppleTalk filtering
   \param[in] bridge_managment_inf_filtering	Bridge management information
						filtering
   \param[in] arp_filtering			ARP filtering
   \param[in] pppoe_filtering			PPPoE filtering
*/
static enum omci_api_return
omci_api_exception_config_table_entry_update(struct omci_api_ctx *ctx,
					     uint32_t exception_table_entry_idx,
					     bool ani_indication,
					     bool ingress_enable,
					     bool egress_enable,
					     uint8_t ipv4_multicast_filtering,
					     uint8_t ipv6_multicast_filtering,
					     uint8_t ipv4_broadcast_filtering,
					     uint8_t rarp_filtering,
					     uint8_t ipx_filtering,
					     uint8_t net_beui_filtering,
					     uint8_t apple_talk_filtering,
					     uint8_t bridge_managment_inf_filtering,
					     uint8_t arp_filtering,
					     uint8_t pppoe_filtering)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_table_entry entry;

	uint8_t filtering_table[] = {
		ipv4_multicast_filtering,
		ipv6_multicast_filtering,
		ipv4_broadcast_filtering,
		rarp_filtering,
		ipx_filtering,
		net_beui_filtering,
		apple_talk_filtering,
		bridge_managment_inf_filtering,
		arp_filtering,
		pppoe_filtering
	};

	uint32_t filtering_mask[] = {
		1 << ONU_GPE_EXCEPTION_OFFSET_IPV4_MC,
		1 << ONU_GPE_EXCEPTION_OFFSET_IPV6_MC,
		1 << ONU_GPE_EXCEPTION_OFFSET_IPV4_BC,
		1 << ONU_GPE_EXCEPTION_OFFSET_RARP,
		1 << ONU_GPE_EXCEPTION_OFFSET_IPX,
		1 << ONU_GPE_EXCEPTION_OFFSET_NETBEUI,
		1 << ONU_GPE_EXCEPTION_OFFSET_APPLETALK,
		1 << ONU_GPE_EXCEPTION_OFFSET_BPDU,
		1 << ONU_GPE_EXCEPTION_OFFSET_ARP,
		1 << ONU_GPE_EXCEPTION_OFFSET_PPPOE_8863
	};

	uint8_t i;
	uint32_t exception_flag_mask;

	entry.id 	= ONU_GPE_EXCEPTION_TABLE_ID;
	entry.instance 	= 1;
	entry.index 	= exception_table_entry_idx;
#if 0
	/** \todo review implementation - was just a quick fix for new FW
	    interface */

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TABLE_ENTRY_GET,
		      &entry, TABLE_ENTRY_SIZE(entry.data.exception));
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;
#endif
	/** \todo correct exception mask */
	exception_flag_mask =
		entry.data.exception.egress_exception_flag_mask;

	for (i = 0; i < sizeof(filtering_table); i++) {
		/* for ARP we need to change snooping value, because
		   disabling ARP exception breaks br-lct */
		if (filtering_mask[i] == (1 << ONU_GPE_EXCEPTION_OFFSET_ARP) &&
		    exception_flag_mask & (1 << ONU_GPE_EXCEPTION_OFFSET_ARP)) {

			if (filtering_table[i] == OPERATION_FORWARD)
				ret = snooping_set(ctx, i, false);
			else
				ret = snooping_set(ctx, i, true);

			if (ret != OMCI_API_SUCCESS)
				return ret;

			continue;
		}

		switch (filtering_table[i]) {
		case OPERATION_FORWARD:
			exception_flag_mask &= ~filtering_mask[i];
			break;

		case OPERATION_FILTER:
			exception_flag_mask |= filtering_mask[i];
			break;

		default:
			return OMCI_API_ERROR;
		}
	}
#if 0
	if (ani_indication) {
		entry.data.ani_exception.exception_flag_mask =
			exception_flag_mask;
		entry.data.ani_exception.ingress_enable =
			ingress_enable ? 1 : 0;
		entry.data.ani_exception.egress_enable = egress_enable ? 1 : 0;
	} else {
		entry.data.lan_exception.exception_flag_mask =
			exception_flag_mask;
		/* don't switch off ingress exceptions if they are already
		   enabled */
		entry.data.lan_exception.ingress_enable |= ingress_enable;
		entry.data.lan_exception.egress_enable = egress_enable ? 1 : 0;
	}

	/** \todo review implementation - was just a quick fix for new FW
	    interface */
	if (ingress_enable)
		entry.data.exception.ingress_exception_flag_mask =
			exception_flag_mask;
	else
		entry.data.exception.egress_exception_flag_mask =
			exception_flag_mask;

	entry.id 	= ONU_GPE_EXCEPTION_TABLE_ID;
	entry.instance 	= 1;
	entry.index 	= exception_table_entry_idx;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TABLE_ENTRY_SET, &entry,
			TABLE_ENTRY_SIZE(entry.data.exception));
#endif
	return ret;
}

enum omci_api_return
omci_api_mac_bridge_port_filter_preassign_table_create(struct omci_api_ctx *ctx,
						       uint16_t me_id,
						       uint8_t ipv4_multicast_filtering,
						       uint8_t ipv6_multicast_filtering,
						       uint8_t ipv4_broadcast_filtering,
						       uint8_t rarp_filtering,
						       uint8_t ipx_filtering,
						       uint8_t net_beui_filtering,
						       uint8_t apple_talk_filtering,
						       uint8_t bridge_managment_inf_filtering,
						       uint8_t arp_filtering,
						       uint8_t pppoe_filtering)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t exception_idx = 0;
	bool ani_indication = false;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   ipv4_multicast_filtering=%u\n"
		  "   ipv6_multicast_filtering=%u\n"
		  "   ipv4_broadcast_filtering=%u\n" "   rarp_filtering=%u\n"
		  "   ipx_filtering=%u\n" "   net_beui_filtering=%u\n"
		  "   apple_talk_filtering=%u\n"
		  "   bridge_managment_inf_filtering=%u\n"
		  "   arp_filtering=%u\n"
		  "   pppoe_filtering=%u\n", __FUNCTION__, me_id,
		  ipv4_multicast_filtering, ipv6_multicast_filtering,
		  ipv4_broadcast_filtering, rarp_filtering, ipx_filtering,
		  net_beui_filtering, apple_talk_filtering,
		  bridge_managment_inf_filtering, arp_filtering,
		  pppoe_filtering));

	ret = omci_api_mac_bridge_port_is_ani(ctx, me_id, &ani_indication);

	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = id_map(ctx,
		     ani_indication ?
			MAPPER_MACBRIDGEPORTFPTD_MEID_TO_USEXCEPTIDX :
			MAPPER_MACBRIDGEPORTFPTD_MEID_TO_DSEXCEPTIDX,
		     me_id,
		     &exception_idx);

	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;


	ret = omci_api_exception_config_table_entry_update(ctx,
						exception_idx,
						ani_indication,
						false, true,
						ipv4_multicast_filtering,
						ipv6_multicast_filtering,
						ipv4_broadcast_filtering,
						rarp_filtering,
						ipx_filtering,
						net_beui_filtering,
						apple_talk_filtering,
						bridge_managment_inf_filtering,
						arp_filtering,
						pppoe_filtering);
	if (ret != OMCI_API_SUCCESS) {

		ret = id_remove(ctx,
				ani_indication ?
				 MAPPER_MACBRIDGEPORTFPTD_MEID_TO_USEXCEPTIDX :
				 MAPPER_MACBRIDGEPORTFPTD_MEID_TO_DSEXCEPTIDX,
				me_id);

		if (ret != OMCI_API_SUCCESS)
			(void)error_notify(ctx, 79, me_id,
					   OMCI_API_ACTION_CREATE, ret);
	}

	return ret;
}

enum omci_api_return
omci_api_mac_bridge_port_filter_preassign_table_destroy(struct omci_api_ctx *ctx,
							uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t exception_idx = 0;
	bool ani_indication = false;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n", __FUNCTION__, me_id));

	ret = omci_api_mac_bridge_port_is_ani(ctx, me_id, &ani_indication);

	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = index_get(ctx, ani_indication ?
			MAPPER_MACBRIDGEPORTFPTD_MEID_TO_USEXCEPTIDX :
			MAPPER_MACBRIDGEPORTFPTD_MEID_TO_DSEXCEPTIDX,
		        me_id, &exception_idx);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;


	ret = omci_api_exception_config_table_entry_update(ctx, exception_idx,
						ani_indication, false, false,
						0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = id_remove(ctx,
			ani_indication ?
			 MAPPER_MACBRIDGEPORTFPTD_MEID_TO_USEXCEPTIDX :
			 MAPPER_MACBRIDGEPORTFPTD_MEID_TO_DSEXCEPTIDX, me_id);

	if (ret != OMCI_API_SUCCESS)
		(void)error_notify(ctx, 79, me_id,
				   OMCI_API_ACTION_DESTROY, ret);

	return ret;
}

enum omci_api_return
omci_api_mac_bridge_port_filter_preassign_table_update(struct omci_api_ctx *ctx,
						       uint16_t me_id,
						       uint8_t ipv4_multicast_filtering,
						       uint8_t ipv6_multicast_filtering,
						       uint8_t ipv4_broadcast_filtering,
						       uint8_t rarp_filtering,
						       uint8_t ipx_filtering,
						       uint8_t net_beui_filtering,
						       uint8_t apple_talk_filtering,
						       uint8_t bridge_managment_inf_filtering,
						       uint8_t arp_filtering,
						       uint8_t pppoe_filtering)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t exception_idx = 0;
	bool ani_indication = false;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   ipv4_multicast_filtering=%u\n"
		  "   ipv6_multicast_filtering=%u\n"
		  "   ipv4_broadcast_filtering=%u\n" "   rarp_filtering=%u\n"
		  "   ipx_filtering=%u\n" "   net_beui_filtering=%u\n"
		  "   apple_talk_filtering=%u\n"
		  "   bridge_managment_inf_filtering=%u\n"
		  "   arp_filtering=%u\n"
		  "   pppoe_filtering=%u\n", __FUNCTION__, me_id,
		  ipv4_multicast_filtering, ipv6_multicast_filtering,
		  ipv4_broadcast_filtering, rarp_filtering, ipx_filtering,
		  net_beui_filtering, apple_talk_filtering,
		  bridge_managment_inf_filtering, arp_filtering,
		  pppoe_filtering));

	ret = omci_api_mac_bridge_port_is_ani(ctx, me_id, &ani_indication);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = index_get(ctx, ani_indication ?
				MAPPER_MACBRIDGEPORTFPTD_MEID_TO_USEXCEPTIDX :
				MAPPER_MACBRIDGEPORTFPTD_MEID_TO_DSEXCEPTIDX,
			me_id, &exception_idx);

	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_ERROR;

	ret = omci_api_exception_config_table_entry_update(ctx,
						exception_idx,
						ani_indication,
						false, true,
						ipv4_multicast_filtering,
						ipv6_multicast_filtering,
						ipv4_broadcast_filtering,
						rarp_filtering,
						ipx_filtering,
						net_beui_filtering,
						apple_talk_filtering,
						bridge_managment_inf_filtering,
						arp_filtering,
						pppoe_filtering);

	return ret;
}

/** @} */
