/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_dot1p_rate_limiter.c
*/

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_dot1p_rate_limiter.h"
#include "me/omci_api_dot1p_rate_limiter.h"

/** \addtogroup OMCI_ME_DOT1P_RATE_LIMITER
   @{
*/

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask,
				   const void *data)
{
	struct omci_me_dot1p_rate_limiter *upd_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %p", (void *)context, (void *)me_class,
	       (void *)exec_mask, (void *)data);

	upd_data = (struct omci_me_dot1p_rate_limiter *)data;

	error = default_me_validate(context, me_class, exec_mask, data);
	RETURN_IF_ERROR(error);

	switch (upd_data->tp_type) {
	case 0x01:
		error = mib_me_find(context,
				    OMCI_ME_MAC_BRIDGE_CONFIGURATION_DATA,
				    upd_data->parent_me_ptr, NULL);

		break;

	case 0x02:
		error = mib_me_find(context,
				    OMCI_ME_DOT1P_MAPPER_SERVICE_PROFILE,
				    upd_data->parent_me_ptr, NULL);

		break;

	default:
		error = OMCI_ERROR;
		break;
	}

	if (error) {
		*exec_mask |=
			omci_attr2mask(omci_me_dot1p_rate_limiter_parent_me_ptr);
		*exec_mask |=
			omci_attr2mask(omci_me_dot1p_rate_limiter_tp_type);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	struct omci_me_dot1p_rate_limiter *upd_data;
	struct omci_me_dot1p_rate_limiter *me_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_dot1p_rate_limiter *)data;
	me_data = (struct omci_me_dot1p_rate_limiter *)me->data;

	ret = omci_api_dot1_rate_limiter_update(context->api,
						me->instance_id,
						upd_data->parent_me_ptr,
						upd_data->tp_type,
						upd_data->
						us_unicast_flood_rate_ptr,
						upd_data->us_broadcast_rate_ptr,
						upd_data->
						us_multicast_payload_rate_ptr);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't update Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;
	struct omci_me_dot1p_rate_limiter *me_data;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	me_data = (struct omci_me_dot1p_rate_limiter *)me->data;

	ret = omci_api_dot1_rate_limiter_destroy(context->api, me->instance_id,
						 me_data->parent_me_ptr,
						 me_data->tp_type);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static uint16_t tp_ptr_type_cp[] = { 1, 2 };

/** Managed Entity class */
struct me_class me_dot1p_rate_limiter_class = {
	/* Class ID */
	OMCI_ME_DOT1P_RATE_LIMITER,
	/* Attributes */
	{
		/* 1. Parent Managed Entity Pointer  */
		ATTR_PTR("Parent ME ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_dot1p_rate_limiter,
				  parent_me_ptr),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 2. Termination Point Type */
		ATTR_ENUM("TP type",
			  ATTR_SUPPORTED,
			  tp_ptr_type_cp,
			  offsetof(struct omci_me_dot1p_rate_limiter,
				   tp_type),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 3. Upstream Unicast Flood Rate Pointer Type */
		ATTR_PTR("US unicast flood ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_dot1p_rate_limiter,
				  us_unicast_flood_rate_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 4. Upstream Broadcast Rate Pointer */
		ATTR_PTR("US broadcast rate ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_dot1p_rate_limiter,
				  us_broadcast_rate_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL |
			 OMCI_ATTR_PROP_PARTLY,
			 NULL),
		/* 5. Upstream Multicast Payload Rate Pointer */
		ATTR_PTR("US multicast payload ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_dot1p_rate_limiter,
				  us_multicast_payload_rate_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_OPTIONAL |
			 OMCI_ATTR_PROP_PARTLY,
			 NULL),
		/* 6-16. Doesn't exist */
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
	me_init,
	/* Shutdown Handler */
	me_shutdown,
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
	sizeof(struct omci_me_dot1p_rate_limiter),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Dot1 rate limiter",
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
