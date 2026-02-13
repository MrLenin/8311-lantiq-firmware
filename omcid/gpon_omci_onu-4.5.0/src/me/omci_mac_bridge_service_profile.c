/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_mac_bridge_service_profile.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_mac_bridge_service_profile.h"
#include "me/omci_api_mac_bridge_service_profile.h"

/** \addtogroup OMCI_ME_MAC_BRIDGE_SERVICE_PROFILE
    @{
*/

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask,
				   const void *data)
{
	struct omci_me_mac_bridge_service_profile *upd_data;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me_class,
	       (void *)exec_mask, (void *)data);

	upd_data = (struct omci_me_mac_bridge_service_profile *)data;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	struct omci_me_mac_bridge_service_profile *upd_data;
	struct omci_me_mac_bridge_service_profile *me_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_mac_bridge_service_profile *)data;
	me_data = (struct omci_me_mac_bridge_service_profile *)me->data;

	ret = omci_api_mac_bridge_service_profile_update(context->api,
							 me->instance_id,
							 upd_data->learning_ind,
							 upd_data->
							 port_bridging_ind,
							 upd_data->
							 unknown_mac_discard,
							 upd_data->
							 mac_learning_depth,
							 upd_data->
							 mac_aging_time);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "can't update");
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
	enum omci_api_return ret;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	if (!init_data) {
		dbg_out_ret(__func__, OMCI_ERROR);
		return OMCI_ERROR;
	}

	ret = omci_api_mac_bridge_service_profile_init(context->api,
						       me->instance_id);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't init Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	error = me_update(context, me, init_data, me->class->data_size);
	RETURN_IF_ERROR(error);

	/** \todo fill child managed entities data */

	/* create instance of MAC Bridge Configuration Data Managed Entity */
	error = mib_me_create(context, true, OMCI_ME_MAC_BRIDGE_CONFIGURATION_DATA,
			      me->instance_id, NULL, NULL, 0x0000);

	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	struct me *child_me;
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	ret = omci_api_mac_bridge_service_profile_destroy(context->api,
							  me->instance_id);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	/* delete related instance of MAC
	   Bridge Configuration Data Managed Entity */
	(void)mib_me_find(context, OMCI_ME_MAC_BRIDGE_CONFIGURATION_DATA,
			  me->instance_id, &child_me);

	if (child_me != NULL)
		(void)mib_me_delete(context, child_me);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_mac_bridge_service_profile_class = {
	/* Class ID */
	OMCI_ME_MAC_BRIDGE_SERVICE_PROFILE,
	/* Attributes */
	{
		/* 1. Spanning Tree Indication */
		ATTR_BOOL("Spanning tree ind",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_mac_bridge_service_profile,
				   spanning_tree_ind),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 2. Learning Indication */
		ATTR_BOOL("Learning ind",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_mac_bridge_service_profile,
				   learning_ind),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 3. Port Bridging Indication */
		ATTR_BOOL("Port bridging ind",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_mac_bridge_service_profile,
				   port_bridging_ind),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 4. Priority */
		ATTR_UINT("Priority",
			  ATTR_SUPPORTED,
			  0,
			  65535,
			  offsetof(struct omci_me_mac_bridge_service_profile,
				   prio),
			  2,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 5. Maximum Age */
		ATTR_UINT("Max age",
			  ATTR_SUPPORTED,
			  0x0600,
			  0x2800,
			  offsetof(struct omci_me_mac_bridge_service_profile,
				   max_age),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 6. Hello Time */
		ATTR_UINT("Hello time",
			  ATTR_SUPPORTED,
			  0x0100,
			  0x0a00,
			  offsetof(struct omci_me_mac_bridge_service_profile,
				   hello_time),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 7. Forward Delay */
		ATTR_UINT("Forward delay",
			  ATTR_SUPPORTED,
			  0x0400,
			  0x1e00,
			  offsetof(struct omci_me_mac_bridge_service_profile,
				   forward_delay),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 8. Unknown MAC Address Discarding */
		ATTR_BOOL("Unknown MAC addr discard",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_mac_bridge_service_profile,
				   unknown_mac_discard),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 9. MAC Learning Depth */
		ATTR_UINT("MAC learning depth",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_mac_bridge_service_profile,
				   mac_learning_depth),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 10. MAC Aging Time */
		ATTR_UINT("MAC aging time",
			  ATTR_SUPPORTED,
			  10,
			  1000000,
			  offsetof(struct omci_me_mac_bridge_service_profile,
				   mac_aging_time),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
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
	sizeof(struct omci_me_mac_bridge_service_profile),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Bridge service profile",
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
