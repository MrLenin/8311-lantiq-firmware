/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_multicast_subscriber_config.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_mac_bridge_port_config_data.h"
#include "me/omci_api_multicast_subscr_config_info.h"
#include "me/omci_multicast_subscriber_config.h"

/** \addtogroup OMCI_ME_MULTICAST_SUBSCRIBER_CONFIG
   @{
*/

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask,
				   const void *data)
{
	struct omci_me_multicast_subscriber_config *upd_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me_class,
	       (void *)exec_mask, (void *)data);

	upd_data = (struct omci_me_multicast_subscriber_config *) data;

	error = default_me_validate(context, me_class, exec_mask, data);
	RETURN_IF_ERROR(error);

	error = mib_me_find(context,
			    OMCI_ME_MULTICAST_OPERATIONS_PROFILE,
			    upd_data->mc_ops_profile_ptr,
			    NULL);
	if (error) {
		*exec_mask |=
			omci_attr2mask
			(omci_me_multicast_subscriber_config_me_type);
		*exec_mask |=
			omci_attr2mask
			(omci_me_multicast_subscriber_config_mc_ops_profile_ptr);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_error error;
	enum omci_api_return ret;
	struct omci_me_multicast_subscriber_config *upd_data;
	struct omci_me_multicast_subscriber_config *me_data;
	struct me *mac_bridge_port;
	struct omci_me_mac_bridge_port_config_data mac_bridge_port_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_multicast_subscriber_config *) data;
	me_data = (struct omci_me_multicast_subscriber_config *) me->data;

	error = mib_me_find(context, 
			    OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
			    me->instance_id,
			    &mac_bridge_port);
	RETURN_IF_ERROR(error);

	me_lock(context, mac_bridge_port);
	error = me_data_read(context, mac_bridge_port,
			     &mac_bridge_port_data,
			     sizeof(mac_bridge_port_data),
			     OMCI_PM_INTERVAL_CURR);
	me_unlock(context, mac_bridge_port);
	RETURN_IF_ERROR(error);

	if (mac_bridge_port_data.tp_type != 1) {
		me_dbg_err(me, "DRV ERR Can't update "
			   "Managed Entity, invalid connection");

		dbg_out_ret(__func__, OMCI_ERROR_INVALID_VAL);
		return OMCI_ERROR_INVALID_VAL;
	}

	ret = omci_api_multicast_subscr_config_info_update(
				context->api,
				me->instance_id,
				upd_data->me_type,
				mac_bridge_port_data.tp_ptr,
				upd_data->mc_ops_profile_ptr,
				upd_data->max_simultaneous_groups,
				upd_data->max_mc_bw,
				upd_data->bw_enforcement);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't update "
			   "Managed Entity", ret);

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

	ret = omci_api_multicast_subscr_config_info_destroy(context->api,
							    me->instance_id);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't shutdown "
			   "Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;
	struct omci_me_multicast_subscriber_config *upd_data = init_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	switch (upd_data->me_type) {
	case 0x00:
		error = mib_me_find(context,
				    OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
				    me->instance_id,
				    NULL);
		break;
#if 0
	/* Not supported yet */
	case 0x01:
		error = mib_me_find(context,
				    OMCI_ME_DOT1P_MAPPER_SERVICE_PROFILE,
				    me->instance_id,
				    NULL);
		break;
#endif
	default:
		error = OMCI_ERROR;
		break;
	}

	RETURN_IF_ERROR(error);

	error = me_data_write(context, me, init_data, me->class->data_size,
			      me->class->sbc_attr_mask, suppress_avc);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}
static uint16_t me_type_cp[] = {
	0,
	1
};

/** Managed Entity class */
struct me_class me_multicast_subscriber_config_class = {
	/* Class ID */
	OMCI_ME_MULTICAST_SUBSCRIBER_CONFIG_INFO,
	/* Attributes */
	{
		/* 1. ME type */
		ATTR_ENUM("ME type",
			  ATTR_SUPPORTED,
			  me_type_cp,
			  offsetof(struct omci_me_multicast_subscriber_config,
				   me_type),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR
			  | OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_PARTLY,
			  NULL),
		/* 2. Multicast operations profile pointer */
		ATTR_PTR("Multicast oper prof ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_multicast_subscriber_config,
				  mc_ops_profile_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 3. Max simultaneous groups */
		ATTR_UINT("Max simultaneous groups",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_multicast_subscriber_config,
				  max_simultaneous_groups),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 4. Max multicast bandwidth */
		ATTR_UINT("Max multicast bandwidth",
			 ATTR_SUPPORTED,
			 0x00000000,
			 0xffffffff,
			 offsetof(struct omci_me_multicast_subscriber_config,
				  max_mc_bw),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL |
			 OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 5. Bandwidth enforcement */
		ATTR_BOOL("Bandwidth enforcement",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_multicast_subscriber_config,
				   bw_enforcement),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 6-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
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
	sizeof(struct omci_me_multicast_subscriber_config),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Multicast subscriber conf",
		/* Access */
		ME_CREATED_BY_OLT,
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
