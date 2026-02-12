/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_mac_bridge_port_designation_data.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_mac_bridge_port_designation_data.h"
#if 0
#include "me/omci_api_mac_bridge_port_designation_data.h"
#endif

/** \addtogroup OMCI_ME_MAC_BRIDGE_PORT_DESIGNATION_DATA
   @{
*/

/** Get Port State

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error port_state_get(struct omci_context *context,
				      struct me *me,
				      void *data,
				      size_t data_size)
{
#if 0
	enum omci_api_return ret;
#endif

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 1);

#if 0
	ret = omci_api_mac_bridge_port_designation_data_port_state_get(
		context->api,
		me->instance_id,
		(uint8_t *)data);

	if (ret != OMCI_API_SUCCESS) {
		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}
#endif

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

static uint16_t port_state_cp[] = { 0, 1, 2, 3, 4, 5, 6, 7 };

/** Managed Entity class */
struct me_class me_mac_bridge_port_designation_data_class = {
	/* Class ID */
	OMCI_ME_MAC_BRIDGE_PORT_DESIGNATION_DATA,
	/* Attributes */
	{
		/* 1. Designated Bridge Root Cost Port */
		ATTR_STR("Bridge root cost port",
			 ATTR_SUPPORTED,
			 offsetof(struct
				  omci_me_mac_bridge_port_designation_data,
				  root_cost_port),
			 24,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 2. Port State */
		ATTR_ENUM("Port state",
			  ATTR_SUPPORTED,
			  port_state_cp,
			  offsetof(struct
				   omci_me_mac_bridge_port_designation_data,
				   port_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  port_state_get),
		/* 3-16. Doesn't exist */
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
		NULL,
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
	default_me_update,
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
	sizeof(struct omci_me_mac_bridge_port_designation_data),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Bridge port design data",
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
