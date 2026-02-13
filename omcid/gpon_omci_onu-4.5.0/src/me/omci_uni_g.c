/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_uni_g.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_uni_g.h"
#include "me/omci_pptp_ethernet_uni.h"
#include "me/omci_pptp_pots_uni.h"

/** \addtogroup OMCI_ME_UNI_G
   @{
*/

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_error error;
	struct omci_me_uni_g *upd_data;
	struct omci_me_uni_g *me_data;
	struct me *related_me;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
		(void *)me, (void *)data, attr_mask);

	upd_data = (struct omci_me_uni_g *) data;
	me_data = (struct omci_me_uni_g *) me->data;

	/** \todo crosscheck if it is required to change AND to OR handling
		  for admin state.
	*/
	if (omci_attr2mask(omci_me_uni_g_admin_state) & attr_mask) {
		error = mib_me_find(context, OMCI_ME_PPTP_ETHERNET_UNI,
				    me->instance_id, &related_me);
		if (error == OMCI_SUCCESS) {
			me_lock(context, related_me);
			error = me_attr_write(context, related_me,
					      omci_me_pptp_ethernet_uni_admin_state,
					      &upd_data->admin_state,
					      sizeof(upd_data->admin_state),
					      true);
			me_unlock(context, related_me);
			RETURN_IF_ERROR(error);	
		}
	
		error = mib_me_find(context, OMCI_ME_PPTP_POTS_UNI,
				    me->instance_id, &related_me);
		if (error == OMCI_SUCCESS) {
			me_lock(context, related_me);
			error = me_attr_write(context, related_me,
					      omci_me_pptp_pots_uni_admin_state,
					      &upd_data->admin_state,
					      sizeof(upd_data->admin_state),
					      true);
			me_unlock(context, related_me);
			RETURN_IF_ERROR(error);	
		}
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);

	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_uni_g_class = {
	/* Class ID */
	OMCI_ME_UNI_G,
	/* Attributes */
	{
		/* 1. Configuration option status */
		ATTR_BF("Config option status",
			ATTR_SUPPORTED,
			0x7000,
			offsetof(struct omci_me_uni_g,
				 config_option_status),
			2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			OMCI_ATTR_PROP_TEMPLATE,
			NULL),
		/* 2. Administrative state */
		ATTR_BOOL("Administrative state",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_uni_g,
				   admin_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
#ifdef INCLUDE_G984_4_AMENDMENT_2
		/* 3. Management capability */
		ATTR_UINT("Management capability",
			  ATTR_SUPPORTED,
			  0,
			  2,
			  offsetof(struct omci_me_uni_g,
				   mgmt_capability),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 4. Non-OMCI management identifier */
		ATTR_UINT("Non-OMCI management id",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_uni_g,
				   non_omci_mgmg_id),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 5-16. Doesn't exist */
#else
		/* 3-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
#endif
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
	sizeof(struct omci_me_uni_g),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"UNI-G",
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
