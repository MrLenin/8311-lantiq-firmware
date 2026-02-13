/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_vlan_tagging_operation_config_data.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_vlan_tagging_operation_config_data.h"
#include "me/omci_api_vlan_tagging_operation_config_data.h"

/** \addtogroup OMCI_ME_VLAN_TAGGING_OPERATION_CONFIG_DATA
   @{
*/

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask,
				   const void *data)
{
	struct omci_me_vlan_tagging_operation_config_data *upd_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me_class,
	       (void *)exec_mask, (void *)data);

	upd_data = (struct omci_me_vlan_tagging_operation_config_data *) data;

	error = default_me_validate(context, me_class, exec_mask, data);
	RETURN_IF_ERROR(error);

	switch (upd_data->association_type) {
	case 0:
		error = OMCI_SUCCESS;
		break;

	case 1:
		error = mib_me_find(context, OMCI_ME_IP_HOST_CONFIG_DATA,
				    upd_data->associated_me_ptr, NULL);
		break;

	case 2:
		error = mib_me_find(context,
				    OMCI_ME_DOT1P_MAPPER_SERVICE_PROFILE,
				    upd_data->associated_me_ptr, NULL);
		break;

	case 3:
		error = mib_me_find(context,
				    OMCI_ME_MAC_BRIDGE_PORT_CONFIGURATION_DATA,
				    upd_data->associated_me_ptr, NULL);
		break;

	case 4:
		error = mib_me_find(context, OMCI_ME_PPTP_XDSL_UNI_1,
				    upd_data->associated_me_ptr, NULL);
		break;

	case 5:
		error = mib_me_find(context, OMCI_ME_GEM_INTERWORKING_TP,
				    upd_data->associated_me_ptr, NULL);
		break;

	case 6:
		error = mib_me_find(context,
				    OMCI_ME_MULTICAST_GEM_INTERWORKING_TP,
				    upd_data->associated_me_ptr, NULL);
		break;

	case 7:
		error = mib_me_find(context, OMCI_ME_PPTP_MOCA_UNI,
				    upd_data->associated_me_ptr, NULL);
		break;

	case 8:
		error = mib_me_find(context, OMCI_ME_PPTP_80211_UNI,
				    upd_data->associated_me_ptr, NULL);
		break;

	case 9:
		error = mib_me_find(context, OMCI_ME_ETHERNET_FLOW_TP,
				    upd_data->associated_me_ptr, NULL);
		break;

	case 10:
		error = mib_me_find(context, OMCI_ME_PPTP_ETHERNET_UNI,
				    upd_data->associated_me_ptr, NULL);
		break;

	default:
		error = OMCI_SUCCESS;
		break;
	}

	if (error) {
		dbg_err("vlan_tagging_operation_config_data " 
			"validation error: type 0x%x, ptr 0x%x",
			upd_data->association_type,
			upd_data->associated_me_ptr);
		*exec_mask |=
			omci_attr2mask(omci_me_vlan_tagging_operation_config_data_associated_me_ptr);
		*exec_mask |=
			omci_attr2mask(omci_me_vlan_tagging_operation_config_data_association_type);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	struct omci_me_vlan_tagging_operation_config_data *upd_data;
	struct omci_me_vlan_tagging_operation_config_data *me_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_vlan_tagging_operation_config_data *) data;
	me_data = (struct omci_me_vlan_tagging_operation_config_data *) me->data;

	ret = omci_api_vlan_tagging_operation_conf_data_update(context->api,
							       me->instance_id,
							       upd_data->
							       us_tagging_mode,
							       upd_data->
							       us_tci_value,
							       upd_data->
							       ds_tagging_mode,
							       upd_data->
							       association_type,
							       upd_data->
							       associated_me_ptr);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't update Managed Entity", ret);

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

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	if (!init_data) {
		dbg_out_ret(__func__, OMCI_ERROR);
		return OMCI_ERROR;
	}

	error = me_update(context, me, init_data, me->class->data_size);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	ret = omci_api_vlan_tagging_operation_conf_data_destroy(context->api,
								me->instance_id);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static uint16_t us_tagging_mode_cp[] = { 0, 1, 2 };
static uint16_t ds_tagging_mode_cp[] = { 0, 1 };
static uint16_t association_type_cp[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

/** Managed Entity class */
struct me_class me_vlan_tagging_operation_config_data_class = {
	/* Class ID */
	OMCI_ME_VLAN_TAGGING_OPERATION_CONFIG_DATA,
	/* Attributes */
	{
		/* 1. Upstream VLAN Tagging Operation Mode */
		ATTR_ENUM("US VLAN tagging op mode",
			  ATTR_SUPPORTED,
			  us_tagging_mode_cp,
			  offsetof
			  (struct omci_me_vlan_tagging_operation_config_data,
			   us_tagging_mode),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 2. Upstream VLAN Tag TCI Value */
		ATTR_UINT("US VLAN tag TCI value",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof
			  (struct omci_me_vlan_tagging_operation_config_data,
			   us_tci_value),
			  2,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 3. Downstream VLAN Tagging Operation Mode */
		ATTR_ENUM("DS VLAN tagging op mode",
			  ATTR_SUPPORTED,
			  ds_tagging_mode_cp,
			  offsetof
			  (struct omci_me_vlan_tagging_operation_config_data,
			   ds_tagging_mode),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 4. Association Type */
		ATTR_ENUM("Association type",
			  ATTR_SUPPORTED,
			  association_type_cp,
			  offsetof
			  (struct omci_me_vlan_tagging_operation_config_data,
			   association_type),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 5. Associated Managed Entity Pointer */
		ATTR_PTR("Associated ME ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_vlan_tagging_operation_config_data,
				  associated_me_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
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
	sizeof(struct omci_me_vlan_tagging_operation_config_data),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"VLAN tagging op config",
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
