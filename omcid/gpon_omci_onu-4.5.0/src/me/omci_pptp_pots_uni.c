/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_pptp_pots_uni.c
*/
#define OMCI_DBG_MODULE OMCI_DBG_MODULE_CORE

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_pptp_pots_uni.h"
#include "me/omci_api_pptp_pots_uni.h"

/*#ifdef INCLUDE_OMCI_ONU_VOIP*/


/** \addtogroup OMCI_ME_PPTP_POTS_UNI
   @{
*/

static enum omci_error hook_state_get(struct omci_context *context,
				      struct me *me,
				      void *data,
				      size_t data_size)
{
#ifdef INCLUDE_OMCI_ONU_VOIP
	enum omci_api_return ret;
#endif

	assert(data_size == 1);

#ifdef INCLUDE_OMCI_ONU_VOIP
	ret = omci_api_pptp_pots_uni_hook_state_get(context->api,
						    me->instance_id,
						    (uint8_t *)data);

	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;
#endif

	return OMCI_SUCCESS;
}

static enum omci_error me_validate(struct omci_context *context,
				   const struct me_class *me_class,
				   uint16_t *exec_mask,
				   const void *data)
{
	struct omci_me_pptp_pots_uni *upd_data;
#if 0
	enum omci_error error;
#endif

	upd_data = (struct omci_me_pptp_pots_uni *) data;

#if 0
	error = default_me_validate(context, me_class, exec_mask, data);
	RETURN_IF_ERROR(error);

	error = mib_me_find(context,
			    OMCI_ME_GEM_INTERWORKING_TP,
			    upd_data->interworking_tp_ptr, NULL);

	if (error) {
		*exec_mask |=
		    omci_attr2mask(omci_me_pptp_pots_uni_interworking_tp_ptr);
	}
#endif

	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
#ifdef INCLUDE_OMCI_ONU_VOIP
	enum omci_api_return ret;
#endif
	struct omci_me_pptp_pots_uni *upd_data;
	struct omci_me_pptp_pots_uni *me_data;
	enum omci_error error;

	upd_data = (struct omci_me_pptp_pots_uni *) data;
	me_data = (struct omci_me_pptp_pots_uni *) me->data;

	if (attr_mask & omci_attr2mask(omci_me_pptp_pots_uni_arc)
	    || attr_mask & omci_attr2mask(omci_me_pptp_pots_uni_arc_interval)) {
		me_data->arc = upd_data->arc;

		error = arc_interval_set(context, me,
					 &upd_data->arc_interval,
					 sizeof(upd_data->arc_interval));
		RETURN_IF_ERROR(error);
	}

#ifdef INCLUDE_OMCI_ONU_VOIP
	ret = omci_api_pptp_pots_uni_update(context->api,
					    me->instance_id,
					    upd_data->admin_state,
					    upd_data->impedance,
					    upd_data->rx_gain,
					    upd_data->tx_gain);

	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;
#endif

	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;
#ifdef INCLUDE_OMCI_ONU_VOIP
	enum omci_api_return ret;
#endif

	/* setup ARC support */
	me->arc_context->arc_attr = 3;
	me->arc_context->arc_interval_attr = 4;
#ifdef INCLUDE_OMCI_ONU_VOIP
	ret = omci_api_pptp_pots_uni_create(context->api,
					    me->instance_id);

	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;
#endif
	error = me_data_write(context, me, init_data, me->class->data_size,
			      ~me->class->inv_attr_mask, suppress_avc);
	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
#ifdef INCLUDE_OMCI_ONU_VOIP
	enum omci_api_return ret;

	ret = omci_api_pptp_pots_uni_destroy(context->api,
					     me->instance_id);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);
		return OMCI_ERROR_DRV;
	}
#else
	(void)context;
#endif
	return OMCI_SUCCESS;
}

static enum omci_error test_action_handle(struct omci_context *context,
					  struct me *me,
					  const union omci_msg *msg,
					  union omci_msg *rsp)
{
	return OMCI_SUCCESS;
}

static uint16_t impedance_cp[] = {
	0,
	1,
	2,
	3,
	4,
	0xff			/* for NSN OLT */
};

/** Managed Entity class */
struct me_class me_pptp_pots_uni_class = {
	/* Class ID */
	OMCI_ME_PPTP_POTS_UNI,
	/* Attributes */
	{
		/* 1. Administrative state */
		ATTR_BOOL("Administrative state",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_pptp_pots_uni,
				   admin_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 2. Interworking TP pointer */
		ATTR_PTR("Interworking TP pointer",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_pptp_pots_uni,
				  interworking_tp_ptr),
			 2,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 3. ARC */
		ATTR_BOOL("ARC",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_pptp_pots_uni,
				   arc),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_AVC | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 4. ARC interval */
		ATTR_UINT("ARC interval",
			  ATTR_SUPPORTED,
			  0,
			  255,
			  offsetof(struct omci_me_pptp_pots_uni,
				   arc_interval),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 5. Impedance */
		ATTR_ENUM("Impedance",
			  ATTR_SUPPORTED,
			  impedance_cp,
			  offsetof(struct omci_me_pptp_pots_uni,
				   impedance),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 6. Transmission path */
		ATTR_UINT("Transmission path",
			  ATTR_SUPPORTED,
			  0,
			  1,
			  offsetof(struct omci_me_pptp_pots_uni,
				   transmission_path),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 7. Rx gain */
		ATTR_INT("Rx gain",
			 ATTR_SUPPORTED,
			 0x00,
			 0xff,
			 offsetof(struct omci_me_pptp_pots_uni,
				  rx_gain),
			 1,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 8. Tx gain */
		ATTR_INT("Tx gain",
			 ATTR_SUPPORTED,
			 0x00,
			 0xff,
			 offsetof(struct omci_me_pptp_pots_uni,
				  tx_gain),
			 1,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 9. Operational state */
		ATTR_BOOL("Operational state",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_pptp_pots_uni,
				   oper_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC,
			  NULL),
		/* 10. Hook state */
		ATTR_UINT("Hook state",
			  ATTR_SUPPORTED,
			  0,
			  1,
			  offsetof(struct omci_me_pptp_pots_uni,
				   hook_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  hook_state_get),
		/* 11. POTS holdover time */
		ATTR_UINT("POTS holdover time",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_pptp_pots_uni,
				   pots_holdover_time),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),

		/* 12-16. Doesn't exist */
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
	me_init,
	/* Shutdown Handler */
	me_shutdown,
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
	sizeof(struct omci_me_pptp_pots_uni),
	/* Properties */
	OMCI_ME_PROP_HAS_ARC | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"PPTP POTS UNI",
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

/*#endif*/
