/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_voip_voice_ctp.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_voip_voice_ctp.h"
#include "me/omci_voip_media_profile.h"
#include "me/omci_voice_service_profile.h"
#include "me/omci_rtp_profile_data.h"
#include "me/omci_api_voip_voice_ctp.h"

#ifdef INCLUDE_OMCI_ONU_VOIP

/** \addtogroup OMCI_ME_VOIP_VOICE_CTP
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
	struct me *voip_media_prof;
	struct me *voice_service_prof;
	struct me *rtp_profile;
	struct omci_me_voip_voice_ctp *upd_data;
	struct omci_me_voip_voice_ctp *me_data;
	struct omci_me_voip_media_profile voip_media;
	struct omci_me_voice_service_profile voice_service;
	struct omci_me_rtp_profile_data rtp_data;
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	upd_data = (struct omci_me_voip_voice_ctp *) data;
	me_data = (struct omci_me_voip_voice_ctp *) me->data;

	error = mib_me_find(context,
			    OMCI_ME_VOIP_MEDIA_PROFILE,
			    upd_data->voip_media_ptr,
			    &voip_media_prof);
	RETURN_IF_ERROR(error);

	me_lock(context, voip_media_prof);
	error = me_data_read(context, voip_media_prof,
			     &voip_media, sizeof(voip_media),
			     OMCI_PM_INTERVAL_CURR);
	me_unlock(context, voip_media_prof);
	RETURN_IF_ERROR(error);

	ret = omci_api_voip_voice_ctp_media_update(context->api,
						   me->instance_id,
						   upd_data->user_protocol_ptr,
						   voip_media.code_selection_1,
						   voip_media.code_selection_2,
						   voip_media.code_selection_3,
						   voip_media.code_selection_4);

	if (ret != OMCI_API_SUCCESS) {
		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	error = mib_me_find(context,
			    OMCI_ME_VOICE_SERVICE_PROFILE_AAL,
			    voip_media.voice_service_profile_ptr,
			    &voice_service_prof);
	if (error == OMCI_SUCCESS) {
		me_lock(context, voice_service_prof);
		error = me_data_read(context, voice_service_prof,
				     &voice_service, sizeof(voice_service),
				     OMCI_PM_INTERVAL_CURR);
		me_unlock(context, voice_service_prof);
		RETURN_IF_ERROR(error);

		ret = omci_api_voip_voice_ctp_service_update(context->api,
					me->instance_id,
					upd_data->pptp_ptr,
					voice_service.announcement_type,
					voice_service.jitter_target,
					voice_service.jitter_buffer_max,
					voice_service.echo_cancel_ind,
					voice_service.pstn_protocol_variant,
					voice_service.dtmf_digit_levels,
					voice_service.dtmf_digit_duration,
					voice_service.hook_flash_minimum_time,
					voice_service.hook_flash_maximum_time);
	
		if (ret != OMCI_API_SUCCESS) {
			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}
	}

	error = mib_me_find(context,
			    OMCI_ME_RTP_PROFILE_DATA,
			    voip_media.rtp_profile_ptr,
			    &rtp_profile);
	if (error == OMCI_SUCCESS) {
		me_lock(context, rtp_profile);
		error = me_data_read(context, rtp_profile,
				     &rtp_data, sizeof(rtp_data),
				     OMCI_PM_INTERVAL_CURR);
		me_unlock(context, rtp_profile);
		RETURN_IF_ERROR(error);

		ret = omci_api_voip_voice_ctp_rtp_update(context->api,
					me->instance_id,
					rtp_data.local_port_min,
					rtp_data.local_port_max,
					rtp_data.dscp_mark,
					rtp_data.piggyback_events,
					rtp_data.tone_events,
					rtp_data.dtmf_events,
					rtp_data.cas_events);
	
		if (ret != OMCI_API_SUCCESS) {
			dbg_out_ret(__func__, OMCI_ERROR_DRV);
			return OMCI_ERROR_DRV;
		}
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

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
struct me_class me_voip_voice_ctp_class = {
	/* Class ID */
	OMCI_ME_VOIP_VOICE_CTP,
	/* Attributes */
	{
		ATTR_PTR("User protocol pointer",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_voip_voice_ctp,
				  user_protocol_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_PTR("PPTP TP pointer",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_voip_voice_ctp, pptp_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_PTR("VOIP media pointer",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_voip_voice_ctp,
				  voip_media_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
			 NULL),
		ATTR_PTR("Signalling code",
			 ATTR_SUPPORTED,
			 1,
			 6,
			 offsetof(struct omci_me_voip_voice_ctp,
				  signalling_code),
			 1,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC,
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
	me_validate,
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
	sizeof(struct omci_me_voip_voice_ctp),
	/* Properties */
	OMCI_ME_PROP_HAS_ARC,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"VoIP Voice CTP",
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

#endif
