/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_voip_line_status.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_voip_line_status.h"


#ifdef INCLUDE_OMCI_ONU_VOIP

/** \addtogroup OMCI_ME_VOIP_LINE_STATUS
   @{
*/

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask,
				   const void *data)
{
	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me_class,
	       (void *)exec_mask, (void *)data);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_error error;
	struct omci_me_voip_line_status *upd_data;
	struct omci_me_voip_line_status *me_data;
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	upd_data = (struct omci_me_voip_line_status *) data;
	me_data = (struct omci_me_voip_line_status *) me->data;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_voip_line_status_class = {
	/* Class ID */
	OMCI_ME_VOIP_LINE_STATUS,
	/* Attributes */
	{
		ATTR_PTR("VoIP codec used",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_voip_line_status,
				  voip_codec_used),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_PTR("Server status",
			 ATTR_SUPPORTED,
			 0x00,
			 0xff,
			 offsetof(struct omci_me_voip_line_status, server_status),
			 1,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_PTR("Session type",
			 ATTR_SUPPORTED,
			 0x00,
			 0xff,
			 offsetof(struct omci_me_voip_line_status, session_type),
			 1,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_PTR("Call 1 packet period",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_voip_line_status,
				  call_1_packet_period),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_PTR("Call 2 packet period",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_voip_line_status,
				  call_2_packet_period),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_STR("Call 1 dest addr",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_voip_line_status,
				  call_1_dest_addr),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_STR("Call 2 dest addr",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_voip_line_status,
				  call_2_dest_addr),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
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
	NULL,
	/* Validate Handler */
	me_validate,
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
	sizeof(struct omci_me_voip_line_status),
	/* Properties */
	OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"VoIP Line Status",
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
