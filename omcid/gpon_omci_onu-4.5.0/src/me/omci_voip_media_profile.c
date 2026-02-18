/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_voip_media_profile.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_voip_media_profile.h"


/** \addtogroup OMCI_ME_VOIP_MEDIA_PROFILE
   @{
*/

static enum omci_error test_action_handle(struct omci_context *context,
					  struct me *me,
					  const union omci_msg *msg,
					  union omci_msg *rsp)
{
	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me,
	       (void *)msg, (void *)rsp);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_voip_media_profile_class = {
	/* Class ID */
	OMCI_ME_VOIP_MEDIA_PROFILE,
	/* Attributes */
	{
		ATTR_UINT("Fax mode",
			  ATTR_SUPPORTED,
			  0,
			  1,
			  offsetof(struct omci_me_voip_media_profile, fax_mode),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_PTR("Voice service profile ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_voip_media_profile,
				  voice_service_profile_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_UINT("Code selection 1",
			  ATTR_SUPPORTED,
			  0,
			  18,
			  offsetof(struct omci_me_voip_media_profile,
				   code_selection_1),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("Packet period selection",
			  ATTR_SUPPORTED,
			  10,
			  30,
			  offsetof(struct omci_me_voip_media_profile,
				   packet_period_selection_1),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_BOOL("Signaling code",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_voip_media_profile,
				   silence_suppression_1),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("Code selection 2",
			  ATTR_SUPPORTED,
			  0,
			  18,
			  offsetof(struct omci_me_voip_media_profile,
				   code_selection_2),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("Packet period selection 2",
			  ATTR_SUPPORTED,
			  10,
			  30,
			  offsetof(struct omci_me_voip_media_profile,
				   packet_period_selection_2),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_BOOL("Signaling code 2",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_voip_media_profile,
				   silence_suppression_2),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("Code selection 3",
			  ATTR_SUPPORTED,
			  0,
			  18,
			  offsetof(struct omci_me_voip_media_profile,
				   code_selection_3),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("Packet period selection 3",
			  ATTR_SUPPORTED,
			  10,
			  30,
			  offsetof(struct omci_me_voip_media_profile,
				   packet_period_selection_3),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_BOOL("Signaling code 3",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_voip_media_profile,
				   silence_suppression_3),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("Code selection 4",
			  ATTR_SUPPORTED,
			  0,
			  18,
			  offsetof(struct omci_me_voip_media_profile,
				   code_selection_4),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("Packet period selection 4",
			  ATTR_SUPPORTED,
			  10,
			  30,
			  offsetof(struct omci_me_voip_media_profile,
				   packet_period_selection_4),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_BOOL("Signaling code 4",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_voip_media_profile,
				   silence_suppression_4),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_BOOL("OOB DTMF",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_voip_media_profile, oob_dtmf),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_PTR("RTP profile pointer",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_voip_media_profile,
				  rtp_profile_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
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
		test_action_handle,
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
	sizeof(struct omci_me_voip_media_profile),
	/* Properties */
	OMCI_ME_PROP_HAS_ARC,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"VoIP media profile",
		/* Access */
		ME_CREATED_BY_OLT,
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
