/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_voip_config_data.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_voip_config_data.h"

#ifdef INCLUDE_OMCI_ONU_VOIP

/** \addtogroup OMCI_ME_VOIP_CONFIG_DATA
   @{
*/

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	struct omci_me_voip_config_data *upd_data;
	struct omci_me_voip_config_data *me_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	upd_data = (struct omci_me_voip_config_data *) data;
	me_data = (struct omci_me_voip_config_data *) me->data;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_voip_config_data_class = {
	/* Class ID */
	OMCI_ME_VOIP_CONFIG_DATA,
	/* Attributes */
	{
		ATTR_UINT("Avail. protocols",
			  ATTR_SUPPORTED,
			  1,
			  3,
			  offsetof(struct omci_me_voip_config_data,
				   available_signalling_protocols),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		ATTR_UINT("Protocol used",
			  ATTR_SUPPORTED,
			  0,
			  0xff,
			  offsetof(struct omci_me_voip_config_data,
				   signalling_protocol_used),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		ATTR_UINT("Avail. config methods",
			  ATTR_SUPPORTED,
			  0,
			  0xffffffff,
			  offsetof(struct omci_me_voip_config_data,
				   available_voip_config_methods),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		ATTR_UINT("Config. method used",
			  ATTR_SUPPORTED,
			  0,
			  0xff,
			  offsetof(struct omci_me_voip_config_data,
				   voip_configuration_method_used),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		ATTR_UINT("Config. address pointer",
			  ATTR_SUPPORTED,
			  0,
			  0xffff,
			  offsetof(struct omci_me_voip_config_data,
				   voip_config_address_ptr),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		ATTR_UINT("Config state",
			  ATTR_SUPPORTED,
			  0,
			  3,
			  offsetof(struct omci_me_voip_config_data,
				   voip_configuration_state),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		ATTR_UINT("Retrieve profile",
			  ATTR_SUPPORTED,
			  0,
			  0xFF,
			  offsetof(struct omci_me_voip_config_data,
				   retrieve_profile),
			  1,
			  OMCI_ATTR_PROP_WR,
			  NULL),
		/* profile version */
		ATTR_STR("Provile version",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_voip_config_data,
				  profile_version),
			 25,
			 OMCI_ATTR_PROP_WR,
			 NULL),
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
	default_me_init,
	/* Shutdown Handler */
	default_me_shutdown,
	/* Validate Handler */
	default_me_validate,
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
	sizeof(struct omci_me_voip_config_data),
	/* Properties */
	OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"VOIP config data",
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

#endif
