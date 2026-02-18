/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_sip_user_data.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_sip_user_data.h"


/** \addtogroup OMCI_SIP_USER_DATA
   @{
*/

/** Managed Entity class */
struct me_class me_sip_user_data_class = {
	/* Class ID */
	OMCI_ME_SIP_USER_DATA,
	/* Attributes */
	{
		ATTR_PTR("SIP agent pointer",
			 ATTR_SUPPORTED,
			 0,
			 0xffff,
			 offsetof(struct omci_sip_user_data, sip_agent_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_PTR("User part AOR",
			 ATTR_SUPPORTED,
			 0,
			 0xffff,
			 offsetof(struct omci_sip_user_data, user_part_aor),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_STR("SIP display name",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_sip_user_data, sip_display_name),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		ATTR_PTR("Username/passwd",
			 ATTR_SUPPORTED,
			 0,
			 0xffff,
			 offsetof(struct omci_sip_user_data, username_password),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_PTR("Voicemail SIP URI",
			 ATTR_SUPPORTED,
			 0,
			 0xffff,
			 offsetof(struct omci_sip_user_data,
				  voicemail_server_sip_uri),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_UINT("Voicemail subscription",
			  ATTR_SUPPORTED,
			  0,
			  0xffffffff,
			  offsetof(struct omci_sip_user_data,
				   voicemail_subscription_expiration_time),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_PTR("Network dial plan",
			 ATTR_SUPPORTED,
			 0,
			 0xffff,
			 offsetof(struct omci_sip_user_data,
				  network_dial_plan_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_PTR("Application service",
			 ATTR_SUPPORTED,
			 0,
			 0xffff,
			 offsetof(struct omci_sip_user_data,
				  application_services_profile_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_PTR("Feature code",
			 ATTR_SUPPORTED,
			 0,
			 0xffff,
			 offsetof(struct omci_sip_user_data,
				  feature_code_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_PTR("PPTP",
			 ATTR_SUPPORTED,
			 0,
			 0xffff,
			 offsetof(struct omci_sip_user_data, pptp_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_UINT("Release timer",
			  ATTR_SUPPORTED,
			  0,
			  0xff,
			  offsetof(struct omci_sip_user_data, release_timer),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("ROH timer",
			  ATTR_SUPPORTED,
			  0,
			  0xff,
			  offsetof(struct omci_sip_user_data, roh_timer),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
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
	default_me_update,
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
	sizeof(struct omci_sip_user_data),
	/* Properties */
	OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"SIP user data",
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
