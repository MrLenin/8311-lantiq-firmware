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
#include "me/omci_authentication_security_method.h"
#include "me/omci_large_string.h"
#include "me/omci_sip_agent_config_data.h"
#include "me/omci_tcp_udp_config_data.h"
#include "me/omci_ip_host_config_data.h"
#include "me/omci_api_sip_user_data.h"

#ifdef INCLUDE_OMCI_ONU_VOIP


/** \addtogroup OMCI_SIP_USER_DATA
   @{
*/

static uint32_t sip_user_ip_addr_get(struct omci_context *context,
				     struct me *me,
				     uint16_t sip_agent_ptr)
{
	struct me *sip_agent_me, *tcp_udp_me, *ip_host_me;
	uint16_t tcp_udp_ptr, ip_host_ptr;
	enum omci_error error;
	uint32_t ip_addr;

	error = mib_me_find(context,
			    OMCI_ME_SIP_AGENT_CONFIG_DATA,
			    sip_agent_ptr,
			    &sip_agent_me);
	if (error != OMCI_SUCCESS)
		return 0;

	me_lock(context, sip_agent_me);
	error = me_attr_read(context, sip_agent_me,
			     omci_sip_agent_config_data_tcp_udp_ptr,
			     &tcp_udp_ptr, sizeof(tcp_udp_ptr));
	me_unlock(context, sip_agent_me);
	if (error != OMCI_SUCCESS)
		return 0;

	error = mib_me_find(context,
			    OMCI_ME_TCP_UDP_CONFIG_DATA,
			    tcp_udp_ptr,
			    &tcp_udp_me);
	if (error != OMCI_SUCCESS)
		return 0;

	me_lock(context, tcp_udp_me);
	error = me_attr_read(context, tcp_udp_me,
			     omci_me_tcp_udp_config_data_ip_host_ptr,
			     &ip_host_ptr, sizeof(ip_host_ptr));
	me_unlock(context, tcp_udp_me);
	if (error != OMCI_SUCCESS)
		return 0;

	error = mib_me_find(context,
			    OMCI_ME_IP_HOST_CONFIG_DATA,
			    ip_host_ptr,
			    &ip_host_me);
	if (error != OMCI_SUCCESS)
		return 0;

	me_lock(context, tcp_udp_me);
	error = me_attr_read(context, ip_host_me,
			     omci_me_ip_host_config_data_ip_address,
			     &ip_addr, sizeof(ip_addr));
	me_unlock(context, tcp_udp_me);

	if (error != OMCI_SUCCESS)
		return 0;

	return ip_addr;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_error error;
	enum omci_api_return ret;
	struct omci_sip_user_data *upd_data;
	struct omci_sip_user_data *me_data;
	struct me *auth_me, *user_part_aor_me;
	char username[50] = { 0 };
	char password[25] = { 0 };
	char realm[25] = { 0 };
	char user_part_aor[OMCI_ME_LARGE_STRING_SIZE] = { 0 };
	uint32_t ip_addr;
	uint8_t validation_scheme = 0;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	upd_data = (struct omci_sip_user_data *) data;
	me_data = (struct omci_sip_user_data *) me->data;

	error = mib_me_find(context,
			    OMCI_ME_AUTHENTICATION_SECURITY_METHOD,
			    upd_data->username_password,
			    &auth_me);

	if (auth_me) {
		me_lock(context, auth_me);

		error = me_attr_read(context, auth_me,
				     omci_me_authentication_username_1,
				     &username[0],
				     sizeof(username) / 2);
		if (error) {
			me_unlock(context, auth_me);
			RETURN_IF_ERROR(error);
		}

		error = me_attr_read(context, auth_me,
				     omci_me_authentication_username_2,
				     &username[sizeof(username) / 2],
				     sizeof(username) / 2);
		if (error) {
			me_unlock(context, auth_me);
			RETURN_IF_ERROR(error);
		}

		error = me_attr_read(context, auth_me,
				     omci_me_authentication_password,
				     &password[0],
				     sizeof(password));
		if (error) {
			me_unlock(context, auth_me);
			RETURN_IF_ERROR(error);
		}

		error = me_attr_read(context, auth_me,
				     omci_me_authentication_realm,
				     &realm[0],
				     sizeof(realm));
		if (error) {
			me_unlock(context, auth_me);
			RETURN_IF_ERROR(error);
		}

		error = me_attr_read(context, auth_me,
				     omci_me_authentication_validation_scheme,
				     &validation_scheme,
				     sizeof(validation_scheme));
		if (error) {
			me_unlock(context, auth_me);
			RETURN_IF_ERROR(error);
		}

		me_unlock(context, auth_me);
	} else {
		username[0] = '\0';
		password[0] = '\0';
		realm[0] = '\0';
	}

	if (!omci_is_ptr_null(upd_data->user_part_aor)) {
		error = mib_me_find(context,
				    OMCI_ME_LARGE_STRING,
				    upd_data->user_part_aor,
				    &user_part_aor_me);
		RETURN_IF_ERROR(error);

		me_lock(context, user_part_aor_me);
		large_string_get(context, user_part_aor_me, user_part_aor);
		me_unlock(context, user_part_aor_me);
	}

	if (!omci_is_ptr_null(upd_data->sip_agent_ptr))
		ip_addr = sip_user_ip_addr_get(context, me,
					       upd_data->sip_agent_ptr);
	else
		ip_addr = 0;

	ret = omci_api_sip_user_data_update(context->api,
					    me->instance_id,
					    upd_data->sip_agent_ptr,
					    user_part_aor,
					    username,
					    password,
					    realm,
					    validation_scheme,
					    upd_data->pptp_ptr,
					    ip_addr);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;
	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	ret = omci_api_sip_user_data_destroy(context->api, me->instance_id);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

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
	me_shutdown,
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

#endif
