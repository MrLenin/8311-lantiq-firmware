/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_rtp_profile_data.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_rtp_profile_data.h"


/** \addtogroup OMCI_ME_RTP_PROFILE_DATA
   @{
*/

/** Managed Entity class */
struct me_class me_rtp_profile_data_class = {
	/* Class ID */
	OMCI_ME_RTP_PROFILE_DATA,
	/* Attributes */
	{
		/* 1. Local port min */
		ATTR_UINT("Local port min",
			  ATTR_SUPPORTED,
			  0,
			  0xFFFF,
			  offsetof(struct omci_me_rtp_profile_data,
				   local_port_min),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 2. Local port max */
		ATTR_UINT("Local port max",
			  ATTR_SUPPORTED,
			  0,
			  0xFFFF,
			  offsetof(struct omci_me_rtp_profile_data,
				   local_port_max),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 3. DSCP mark */
		ATTR_UINT("DSCP mark",
			  ATTR_SUPPORTED,
			  0,
			  0xFF,
			  offsetof(struct omci_me_rtp_profile_data,
				   dscp_mark),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 4. Piggyback events */
		ATTR_BOOL("Piggyback events",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_rtp_profile_data,
				   piggyback_events),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 5. Tone events */
		ATTR_BOOL("Tone events",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_rtp_profile_data,
				   tone_events),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 6. DTMF events */
		ATTR_BOOL("DTMF events",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_rtp_profile_data,
				   dtmf_events),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 7. CAS events */
		ATTR_BOOL("CAS events",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_rtp_profile_data,
				   cas_events),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 8-16. Doesn't exist */
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
	sizeof(struct omci_me_rtp_profile_data),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"RTP profile data",
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
