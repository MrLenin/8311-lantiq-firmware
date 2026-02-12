/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_dot1x_port_ext_pkg.c
*/

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_dot1x_port_ext_pkg.h"

/** \addtogroup OMCI_ME_DOT1X_PORT_EXTENSION_PACKAGE
   @{
*/

static uint16_t action_register_cp[] = {1, 2, 3};
static uint16_t auth_pae_state_cp[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
static uint16_t backend_auth_state_cp[] = {0, 1, 2, 3, 4, 5, 6, 7};
static uint16_t auth_controlled_port_status_cp[] = {1, 2};
static uint16_t admin_controlled_dirs_cp[] = {0, 1};
static uint16_t op_controlled_dirs_cp[] = {0, 1};

/** Managed Entity class */
struct me_class me_dot1x_port_ext_pkg_class = {
	/* Class ID */
	OMCI_ME_DOT1X_PORT_EXTENSION_PACKAGE,
	/* Attributes */
	{
		/* 1. Dot1x enable */
		ATTR_BOOL("Dot1x enable",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_dot1x_port_ext_pkg,
				   dot1x_enable),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 2. Action register*/
		ATTR_ENUM("Action register",
			  ATTR_SUPPORTED,
			  action_register_cp,
			  offsetof(struct omci_me_dot1x_port_ext_pkg,
				   action_register),
			  1,
			  OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 3. Authenticator PAE state*/
		ATTR_ENUM("Auth PAE state",
			  ATTR_SUPPORTED,
			  auth_pae_state_cp,
			  offsetof(struct omci_me_dot1x_port_ext_pkg,
				   auth_pae_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 4. Backend authentication state*/
		ATTR_ENUM("Backend auth state",
			  ATTR_SUPPORTED,
			  backend_auth_state_cp,
			  offsetof(struct omci_me_dot1x_port_ext_pkg,
				   backend_auth_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 5. Admin controlled directions*/
		ATTR_ENUM("Admin ctrld dirs",
			  ATTR_SUPPORTED,
			  admin_controlled_dirs_cp,
			  offsetof(struct omci_me_dot1x_port_ext_pkg,
				   admin_controlled_dirs),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),

		/* 6. Operational controlled directions*/
		ATTR_ENUM("Oper controlled dirs",
			  ATTR_SUPPORTED,
			  op_controlled_dirs_cp,
			  offsetof(struct omci_me_dot1x_port_ext_pkg,
				   op_controlled_dirs),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 7. Authenticator controlled port status*/
		ATTR_ENUM("Auth ctrl port status",
			  ATTR_SUPPORTED,
			  auth_controlled_port_status_cp,
			  offsetof(struct omci_me_dot1x_port_ext_pkg,
				   auth_controlled_port_status),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 8. Quiet period*/
		ATTR_UINT("Quiet period",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_dot1x_port_ext_pkg,
				   quiet_period),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 9. Server timeout period*/
		ATTR_UINT("Server to period",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_dot1x_port_ext_pkg,
				   server_timeout_period),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 10. Re-authentication period*/
		ATTR_UINT("Re-auth period",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_dot1x_port_ext_pkg,
				   re_auth_period),
			  2,
			  OMCI_ATTR_PROP_RD |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 11. Re-authentication enabled*/
		ATTR_BOOL("Re-auth enabled",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_dot1x_port_ext_pkg,
				   re_auth_enabled),
			  1,
			  OMCI_ATTR_PROP_RD |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 12. Key transmission enabled*/
		ATTR_BOOL("Key tx enabled",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_dot1x_port_ext_pkg,
				   key_tx_enabled),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
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
	NULL,
	/* Validate Handler */
	default_me_validate,
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
	sizeof(struct omci_me_dot1x_port_ext_pkg),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Dot1X port ext pkg",
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
