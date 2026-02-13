/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_mac_bridge_port_filter_preassign_table.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_mac_bridge_port_filter_preassign_table.h"
#include "me/omci_api_mac_bridge_port_filter_preassign_table.h"

/** \addtogroup OMCI_ME_MAC_BRIDGE_PORT_FILTER_PREASSIGN_TABLE
   @{
*/

#define ME_API_UPDATE  omci_api_mac_bridge_port_filter_preassign_table_update
#define ME_API_CREATE  omci_api_mac_bridge_port_filter_preassign_table_create
#define ME_API_DESTROY omci_api_mac_bridge_port_filter_preassign_table_destroy

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	struct omci_me_mac_bridge_port_filter_preassign_table *upd_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_mac_bridge_port_filter_preassign_table *)
		data;

	if (me->is_initialized)
		ret = ME_API_UPDATE(context->api,
				    me->instance_id,
				    upd_data->ipv4_mc_filter_enable,
				    upd_data->ipv6_mc_filter_enable,
				    upd_data->ipv4_bc_filter_enable,
				    upd_data->rarp_filter_enable,
				    upd_data->ipx_filter_enable,
				    upd_data->netbeui_filter_enable,
				    upd_data->appletalk_filtering_enable,
				    upd_data->bridge_management_filter_enable,
				    upd_data->arp_filter_enable,
				    upd_data->pppoe_filter_enable);
	else
		ret = ME_API_CREATE(context->api,
				    me->instance_id,
				    upd_data->ipv4_mc_filter_enable,
				    upd_data->ipv6_mc_filter_enable,
				    upd_data->ipv4_bc_filter_enable,
				    upd_data->rarp_filter_enable,
				    upd_data->ipx_filter_enable,
				    upd_data->netbeui_filter_enable,
				    upd_data->appletalk_filtering_enable,
				    upd_data->bridge_management_filter_enable,
				    upd_data->arp_filter_enable,
				    upd_data->pppoe_filter_enable);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't update Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	ret = ME_API_DESTROY(context->api, me->instance_id);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_mac_bridge_port_filter_preassign_table_class = {
	/* Class ID */
	OMCI_ME_MAC_BRIDGE_PORT_FILTER_PREASSIGN_TABLE,
	/* Attributes */
	{
		/* 1. IPv4 Multicast Filtering */
		ATTR_BOOL("IPv4 multicast filtering",
			  ATTR_SUPPORTED,
			  offsetof(struct
				   omci_me_mac_bridge_port_filter_preassign_table,
				   ipv4_mc_filter_enable),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 2. IPv6 Multicast Filtering */
		ATTR_BOOL("IPv6 multicast filtering",
			  ATTR_SUPPORTED,
			  offsetof(struct
				   omci_me_mac_bridge_port_filter_preassign_table,
				   ipv6_mc_filter_enable),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 3. IPv4 Broadcast Filtering */
		ATTR_BOOL("IPv4 broadcast filtering",
			  ATTR_SUPPORTED,
			  offsetof(struct
				   omci_me_mac_bridge_port_filter_preassign_table,
				   ipv4_bc_filter_enable),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 4. RARP Filtering */
		ATTR_BOOL("RARP filtering",
			  ATTR_SUPPORTED,
			  offsetof(struct
				   omci_me_mac_bridge_port_filter_preassign_table,
				   rarp_filter_enable),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 5. IPX Filtering */
		ATTR_BOOL("IPX filtering",
			  ATTR_SUPPORTED,
			  offsetof(struct
				   omci_me_mac_bridge_port_filter_preassign_table,
				   ipx_filter_enable),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 6. NetBEUI Filtering */
		ATTR_BOOL("NetBEUI filtering",
			  ATTR_SUPPORTED,
			  offsetof(struct
				   omci_me_mac_bridge_port_filter_preassign_table,
				   netbeui_filter_enable),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 7. AppleTalk Filtering */
		ATTR_BOOL("AppleTalk filtering",
			  ATTR_SUPPORTED,
			  offsetof(struct
				   omci_me_mac_bridge_port_filter_preassign_table,
				   appletalk_filtering_enable),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 8. Bridge Management Information Filtering */
		ATTR_BOOL("Bridge MI filtering",
			  ATTR_SUPPORTED,
			  offsetof(struct
				   omci_me_mac_bridge_port_filter_preassign_table,
				   bridge_management_filter_enable),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 9. ARP Filtering */
		ATTR_BOOL("ARP filtering",
			  ATTR_SUPPORTED,
			  offsetof(struct
				   omci_me_mac_bridge_port_filter_preassign_table,
				   arp_filter_enable),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 10. PPPoE Broadcast Filtering */
		ATTR_BOOL("PPPoE filtering",
			  ATTR_SUPPORTED,
			  offsetof(struct
				   omci_me_mac_bridge_port_filter_preassign_table,
				   pppoe_filter_enable),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 11-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
	},
	/* Actions */
	{
		NULL, NULL, NULL, NULL,
		/* Create */
		NULL,
		NULL,
		/* Delete */
		NULL,
		NULL,
		/* Set */
		set_action_handle,
		/* Get */
		get_action_handle,
		NULL,
		/* Get all alarms */
		NULL,
		/* Get all alarms next */
		NULL,
		/* MIB upload */
		NULL,
		/* MIB upload next */
		NULL,
		/* MIB reset */
		NULL,
		/* Alarm */
		NULL,
		/* Attribute value change */
		NULL,
		/* Test */
		NULL,
		/* Start SW download */
		NULL,
		/* Download section */
		NULL,
		/* End SW download */
		NULL,
		/* Activate software */
		NULL,
		/* Commit software */
		NULL,
		/* Synchronize Time */
		NULL,
		/* Reboot */
		NULL,
		/* Get next */
		NULL,
		/* Test result */
		NULL,
		/* Get current data */
		NULL
	},
	/* Init Handler */
	default_me_init,
	/* Shutdown Handler */
	me_shutdown,
	/* Validate Handler */
	default_me_validate,
	/* Update Handler */
	me_update,
	/* Table Attribute Copy Handler */
	NULL,
	/* Table Attribute Operations Handler */
	NULL,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	NULL,
	/* Thresholds set Handler */
	NULL,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_me_mac_bridge_port_filter_preassign_table),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Bridge port filter pre",
		/* Access */
		ME_CREATED_BY_ONT,
		/* Supported alarms */
		NULL,
		/* Supported alarms count */
		0,
		/* Support */
		ME_SUPPORTED
	},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */
