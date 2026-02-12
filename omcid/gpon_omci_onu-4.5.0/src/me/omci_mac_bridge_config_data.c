/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_mac_bridge_config_data.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_mac_bridge_config_data.h"
#include "me/omci_api_mac_bridge_service_profile.h"

/** \addtogroup OMCI_ME_MAC_BRIDGE_CONFIG_DATA
   @{
*/

/** Get Bridge Priority

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error bridge_prio_get(struct omci_context *context,
				       struct me *me,
				       void *data,
				       size_t data_size)
{
	struct me *parent_me;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 2);

	error = mib_me_find(context, OMCI_ME_MAC_BRIDGE_SERVICE_PROFILE,
			    me->instance_id, &parent_me);

	if (error != OMCI_SUCCESS) {
		dbg_out_ret(__func__, OMCI_ERROR_INVALID_VAL);
		return OMCI_ERROR_INVALID_VAL;
	}

	me_lock(context, parent_me);
	error = me_attr_read(context, parent_me, 4, data, data_size);
	me_unlock(context, parent_me);
	if (error != OMCI_SUCCESS) {
		dbg_out_ret(__func__, OMCI_ERROR_INVALID_VAL);
		return OMCI_ERROR_INVALID_VAL;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get Bridge Port Count

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error bridge_port_count_get(struct omci_context *context,
					     struct me *me,
					     void *data,
					     size_t data_size)
{
	enum omci_api_return ret;

	assert(data_size == 1);
	ret = omci_api_bridge_port_count_get(context->api,
					     me->instance_id,data);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;
	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	struct omci_me_mac_bridge_config_data *upd_data;
	struct omci_me_mac_bridge_config_data *me_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_mac_bridge_config_data *)data;
	me_data = (struct omci_me_mac_bridge_config_data *)me->data;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_mac_bridge_config_data_class = {
	/* Class ID */
	OMCI_ME_MAC_BRIDGE_CONFIGURATION_DATA,
	/* Attributes */
	{
		/* 1. Bridge MAC Address */
		ATTR_STR("Bridge MAC address",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_mac_bridge_config_data,
				  bridge_mac_address),
			 6,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 2. Bridge Priority */
		ATTR_UINT("Bridge priority",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_mac_bridge_config_data,
				   bridge_prio),
			  2,
			  OMCI_ATTR_PROP_RD,
			  bridge_prio_get),
		/* 3. Designated Root */
		ATTR_STR("Designated root",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_mac_bridge_config_data,
				  designated_root),
			 8,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 4. Root Path Cost */
		ATTR_UINT("Root path cost",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_mac_bridge_config_data,
				   root_path_cost),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 5. Bridge Port Count */
		ATTR_UINT("Bridge port count",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_mac_bridge_config_data,
				   bridge_port_count),
			  1,
			  OMCI_ATTR_PROP_RD,
			  bridge_port_count_get),
		/* 6. Root Port Number */
		ATTR_UINT("Root port num",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_mac_bridge_config_data,
				   root_port_number),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 7. Hello Time */
		ATTR_UINT("Hello time",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_mac_bridge_config_data,
				   hello_time),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 8. Forward Delay */
		ATTR_UINT("Forward delay",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_mac_bridge_config_data,
				   forward_delay),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 9-16. Doesn't exist */
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
	me_init,
	/* Shutdown Handler */
	NULL,
	/* Validate Handler */
	NULL,
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
	sizeof(struct omci_me_mac_bridge_config_data),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Bridge config data",
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
