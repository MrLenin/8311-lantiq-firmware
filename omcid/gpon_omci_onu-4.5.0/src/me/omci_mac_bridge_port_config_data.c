/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_mac_bridge_port_config_data.c

   \todo Check if we can specify 0x0000 for TP pointer
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_mac_bridge_port_config_data.h"
#include "me/omci_api_mac_bridge_port_config_data.h"
#include "me/omci_gem_port_network_ctp.h"
#include "me/omci_traffic_descriptor.h"

enum omci_error find_bridge_ports(struct omci_context *context,
				 struct me *me,
				 void *shared_data);

/** \addtogroup OMCI_ME_MAC_BRIDGE_PORT_CONFIG_DATA
    @{
*/

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask,
				   const void *data)
{
	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me_class,
	       (void *)exec_mask, (void *)data);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error bridge_port_walker(struct omci_context *context, const uint32_t me_id)
{
	uint16_t i;
	enum omci_error error;
	struct bridge_data bridge;

	bridge.me_id = me_id;
	bridge.count = 0;
	error = mib_walk_by_class(context,
				  OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
				  find_bridge_ports, &bridge);
	RETURN_IF_ERROR(error);
	for (i=0;i<bridge.count;i++) {
		switch (bridge.port[i].tp_type) {
		case 1:
			omci_api_mac_bridge_port_config_data_uni(context->api,
						bridge.me_id,
						bridge.port[i].me_id,
						bridge.port[i].tp_ptr);
			break;
		}
	}

	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_error error;
	enum omci_api_return ret;
	struct omci_me_mac_bridge_port_config_data *upd_data;
	struct omci_me_mac_bridge_port_config_data *me_data;
	struct me *td;
	uint32_t pir = 0;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_mac_bridge_port_config_data *)data;
	me_data = (struct omci_me_mac_bridge_port_config_data *)me->data;

	ret = omci_api_mac_bridge_port_config_data_update(context->api,
							  me->instance_id,
							  upd_data->
								bridge_id_ptr,
							  upd_data->port_number,
							  upd_data->tp_type,
							  upd_data->tp_ptr,
							  upd_data->
							  outbound_td_ptr,
							  upd_data->
							  inbound_td_ptr,
							  upd_data->
							  mac_learning_depth);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "can't update Managed Entitiy");

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	if(upd_data->tp_type == 3) {
		bridge_port_walker(context, upd_data->bridge_id_ptr);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	struct me *port_filter_preassigned_table;
	struct me *port_designation_me;
	struct me *port_filter_table_data;
	struct me *port_bridge_table_me;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	if (!init_data) {
		dbg_out_ret(__func__, OMCI_ERROR);
		return OMCI_ERROR;
	}

	error = me_update(context, me, init_data, me->class->data_size);

	/** \todo fill child managed entities data */

	/* create instance of MAC bridge port filter preassign table ME */
	error = mib_me_create(context,
			      true,
			      OMCI_ME_MAC_BRIDGE_PORT_FILTER_PREASSIGN_TABLE,
			      me->instance_id,
			      &port_filter_preassigned_table, NULL,
			      0x0000);

	RETURN_IF_ERROR(error);

	/* create instance of MAC bridge port designation data Managed Entity */
	error = mib_me_create(context,
			      true,
			      OMCI_ME_MAC_BRIDGE_PORT_DESIGNATION_DATA,
			      me->instance_id,
			      &port_designation_me, NULL,
			      0x0000);

	if (error != OMCI_SUCCESS) {
		(void)mib_me_delete(context, port_filter_preassigned_table);

		RETURN_IF_ERROR(error);
	}

	/* create instance of MAC bridge port filter table data */
	error = mib_me_create(context,
			      true,
			      OMCI_ME_MAC_BRIDGE_PORT_FILTER_TABLE_DATA,
			      me->instance_id,
			      &port_filter_table_data, NULL,
			      0x0000);

	if (error != OMCI_SUCCESS) {
		(void)mib_me_delete(context, port_designation_me);
		(void)mib_me_delete(context, port_filter_preassigned_table);

		RETURN_IF_ERROR(error);
	}

	/* create instance of MAC bridge port bridge table data */
	error = mib_me_create(context,
			      true,
			      OMCI_ME_MAC_BRIDGE_PORT_BRIDGE_TABLE_DATA,
			      me->instance_id,
			      &port_bridge_table_me, NULL,
			      0x0000);

	if (error != OMCI_SUCCESS) {
		(void)mib_me_delete(context, port_filter_table_data);
		(void)mib_me_delete(context, port_designation_me);
		(void)mib_me_delete(context, port_filter_preassigned_table);

		RETURN_IF_ERROR(error);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	struct me *child_me;
	enum omci_api_return ret;
	struct omci_me_mac_bridge_port_config_data *me_data;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	me_data = (struct omci_me_mac_bridge_port_config_data *)me->data;

	/* delete related instance of MAC bridge port filter preassigned table
	   Managed Entity */
	(void)mib_me_find(context,
			  OMCI_ME_MAC_BRIDGE_PORT_FILTER_PREASSIGN_TABLE,
			  me->instance_id, &child_me);

	if (child_me != NULL)
		(void)mib_me_delete(context, child_me);

	/* delete related instance of MAC bridge port designation data Managed
	   Entity */
	(void)mib_me_find(context,
			  OMCI_ME_MAC_BRIDGE_PORT_DESIGNATION_DATA,
			  me->instance_id, &child_me);

	if (child_me != NULL)
		(void)mib_me_delete(context, child_me);

	/* delete related instance of MAC bridge port filter table data Managed
	   Entity */
	(void)mib_me_find(context,
			  OMCI_ME_MAC_BRIDGE_PORT_FILTER_TABLE_DATA,
			  me->instance_id, &child_me);

	if (child_me != NULL)
		(void)mib_me_delete(context, child_me);

	/* delete related instance of MAC bridge port bridge table data Managed
	   Entity */
	(void)mib_me_find(context,
			  OMCI_ME_MAC_BRIDGE_PORT_BRIDGE_TABLE_DATA,
			  me->instance_id, &child_me);

	if (child_me != NULL)
		(void)mib_me_delete(context, child_me);

	ret = omci_api_mac_bridge_port_config_data_destroy(context->api,
						me->instance_id,
						me_data->tp_type,
						me_data->tp_ptr,
						me_data->outbound_td_ptr,
						me_data->inbound_td_ptr);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static uint16_t tp_type_cp[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

/** Managed Entity class */
struct me_class me_mac_bridge_port_config_data_class = {
	/* Class ID */
	OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
	/* Attributes */
	{
		/* 1. Bridge ID Pointer */
		ATTR_PTR("Bridge id ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct
				  omci_me_mac_bridge_port_config_data,
				  bridge_id_ptr),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 2. Port Number */
		ATTR_UINT("Port num",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct
				   omci_me_mac_bridge_port_config_data,
				   port_number),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 3. Termination Point Type */
		ATTR_ENUM("TP type",
			  ATTR_SUPPORTED,
			  tp_type_cp,
			  offsetof(struct
				   omci_me_mac_bridge_port_config_data,
				   tp_type),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_PARTLY,
			  NULL),
		/* 4. Termination Point Pointer */
		ATTR_PTR("TP ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct
				  omci_me_mac_bridge_port_config_data,
				  tp_ptr),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 5. Port Priority */
		ATTR_UINT("Port priority",
			  ATTR_SUPPORTED,
			  0,
			  255,
			  offsetof(struct
				   omci_me_mac_bridge_port_config_data,
				   port_prio),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 6. Port Path Cost */
		ATTR_UINT("Port path cost",
			  ATTR_SUPPORTED,
			  1,
			  65535,
			  offsetof(struct
				   omci_me_mac_bridge_port_config_data,
				   port_path_cost),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 7. Port Spanning Tree Indication */
		ATTR_BOOL("Port spanning tree ind",
			  ATTR_SUPPORTED,
			  offsetof(struct
				   omci_me_mac_bridge_port_config_data,
				   port_spanning_tree_ind),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 8. Encapsulation Method */
		ATTR_UINT("Encapsulation method",
			  ATTR_SUPPORTED,
			  1,
			  1,
			  offsetof(struct
				   omci_me_mac_bridge_port_config_data,
				   encap_method),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 9. LAN FCS Indication */
		ATTR_BOOL("LAN FCS ind",
			  ATTR_SUPPORTED,
			  offsetof(struct
				   omci_me_mac_bridge_port_config_data,
				   lan_fcs_ind),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 10. Port MAC Address */
		ATTR_STR("Port MAC address",
			 ATTR_SUPPORTED,
			 offsetof(struct
				  omci_me_mac_bridge_port_config_data,
				  port_mac_address),
			 6,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL |
			 OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 11. Outbound Traffic Descriptor Pointer */
		ATTR_PTR("Outbound TD ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct
				  omci_me_mac_bridge_port_config_data,
				  outbound_td_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 12. Inbound Traffic Descriptor Pointer */
		ATTR_PTR("Inbound TD ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct
				  omci_me_mac_bridge_port_config_data,
				  inbound_td_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 13. MAC Learning Depth */
		ATTR_UINT("MAC learning depth",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct
				   omci_me_mac_bridge_port_config_data,
				   mac_learning_depth),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 14-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
	},
	/* Actions */
	{
		NULL, NULL, NULL, NULL,
		/* Create */
		create_action_handle,
		NULL,
		/* Delete */
		delete_action_handle,
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
	me_init,
	/* Shutdown Handler */
	me_shutdown,
	/* Validate Handler */
	me_validate,
	/* Update Handler */
	me_update,
	/* Table Attribute Copy Handler */
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
	sizeof(struct omci_me_mac_bridge_port_config_data),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Bridge port config data",
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
