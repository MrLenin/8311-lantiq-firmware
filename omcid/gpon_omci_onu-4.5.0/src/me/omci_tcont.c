/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_tcont.c
*/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_tcont.h"
#include "me/omci_api_tcont.h"

/** \addtogroup OMCI_ME_TCONT
   @{
*/

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct omci_me_tcont *upd_data;
	(void)context;
	(void)attr_mask;

	upd_data = (struct omci_me_tcont *) data;

	if (!me->is_initialized)
		ret = omci_api_tcont_create(context->api,
					    me->instance_id,
					    upd_data->policy);
	else
		ret = omci_api_tcont_update(context->api,
					    me->instance_id,
					    upd_data->alloc_id);

	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;

	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;
	struct omci_me_tcont *me_data;
	(void)context;

	me_data = (struct omci_me_tcont *) me->data;
	ret = omci_api_tcont_destroy(context->api,
				     me->instance_id,
				     me_data->alloc_id);

	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;

	return OMCI_SUCCESS;
}

static uint16_t mode_indicator_cp[] = { 1 };
static uint16_t policy_cp[] = { 0, 1, 2};

/** Managed Entity class */
struct me_class me_tcont_class = {
	/* Class ID */
	OMCI_ME_TCONT,
	/* Attributes */
	{
		/* 1. Alloc-ID */
		ATTR_UINT("Alloc-id",
			  ATTR_SUPPORTED,
			  0x0000,
			  0x0fff,
			  offsetof(struct omci_me_tcont,
				   alloc_id),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 2. Mode indicator */
		ATTR_ENUM("Mode indicator",
			  ATTR_SUPPORTED,
			  mode_indicator_cp,
			  offsetof(struct omci_me_tcont,
				   mode_indicator),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 3. Policy */
		ATTR_ENUM("Policy",
			  ATTR_SUPPORTED,
			  policy_cp,
			  offsetof(struct omci_me_tcont,
				   policy),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 4-16. Doesn't exist */
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
	me_shutdown,
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
	sizeof(struct omci_me_tcont),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"T-CONT",
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
