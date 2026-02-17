/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_pptp_lct_uni.c

   v7.5.1 ME 83 (PPTP LCT UNI) handler.
   Matches stock function pointer table at 0x0046e028:
     FUN_00422270 = me_init
     FUN_00422208 = me_shutdown
     FUN_0042a980 = me_validate (= default_me_validate)
     FUN_004220d8 = me_update

   Key difference from v4.5.0: stock calls _create BEFORE me_data_write
   in me_init. me_data_write triggers me_update → _update, so the meter
   must exist before _update configures exception profiles.
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"

#define DLOG(fmt, ...) do { \
	FILE *_f = fopen("/tmp/8311_me83.log", "a"); \
	if (_f) { fprintf(_f, fmt "\n", ##__VA_ARGS__); fclose(_f); } \
} while (0)
#include "me/omci_pptp_lct_uni.h"
#include "me/omci_api_pptp_lct_uni.h"

/** \addtogroup OMCI_ME_PPTP_LCT_UNI
   @{
*/

/**
   Stock me_update (FUN_004220d8):
   Only acts on admin_state changes (attr 1 = bit 15 of attr_mask).
   Calls _update(ctx->api, me_id, admin_state) — no lan_port param,
   _update resolves it internally via uni2lan.
*/
static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_api_return ret;
	struct omci_me_pptp_lct_uni *me_data =
		(struct omci_me_pptp_lct_uni *)data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	/* Stock: only act on admin_state (attr 1 = bit 15) */
	if (!(attr_mask & omci_attr2mask(omci_me_pptp_lct_uni_admin_state))) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	ret = omci_api_pptp_lct_uni_update(context->api,
					   me->instance_id,
					   me_data->admin_state);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't update Managed Entity", ret);
		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/**
   Stock me_init (FUN_00422270):
   1. mib_me_find(PPTP_ETH_UNI, me->instance_id) — validate UNI exists
   2. _create(ctx->api, me->instance_id) — BEFORE me_data_write
   3. me_data_write — triggers me_update → _update (meter already exists)
*/
static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;
	enum omci_api_return ret;
	struct omci_me_pptp_lct_uni me_data_buf;
	struct me *uni_me;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)init_data, suppress_avc);

	DLOG("ME83 init: inst=%u init_data=%p", me->instance_id, init_data);

	/* Stock: validate that the associated PPTP ETH UNI exists.
	   FUN_0040bd58(ctx, 0x0b, me->instance_id, &uni_me) */
	error = mib_me_find(context, OMCI_ME_PPTP_ETHERNET_UNI,
			    me->instance_id, &uni_me);
	if (error != OMCI_SUCCESS) {
		DLOG("ME83 init: PPTP ETH UNI %u not found (err=%d)",
		     me->instance_id, error);
		dbg_out_ret(__func__, error);
		return error;
	}

	/* Stock: handle NULL init_data (mib_lct_create passes NULL).
	   Default admin_state = 0 (unlocked). */
	if (init_data != NULL)
		memcpy(&me_data_buf, init_data, sizeof(me_data_buf));
	else
		memset(&me_data_buf, 0, sizeof(me_data_buf));

	/* Stock: _create BEFORE me_data_write.
	   This ensures the meter exists before me_data_write triggers
	   me_update → _update which configures exception profiles. */
	ret = omci_api_pptp_lct_uni_create(context->api, me->instance_id);
	DLOG("ME83 init: create ret=%d", ret);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "API ERR(%d) LCT UNI create failed", ret);
		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	/* me_data_write triggers me_update → _update */
	error = me_data_write(context, me, &me_data_buf,
			      me->class->data_size,
			      ~me->class->inv_attr_mask, suppress_avc);
	DLOG("ME83 init: me_data_write ret=%d", error);
	if (error != OMCI_SUCCESS) {
		dbg_out_ret(__func__, error);
		return error;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/**
   Stock me_shutdown (FUN_00422208):
   1. _destroy(ctx->api, me->instance_id) — no lan_port, no mac_filter
   2. Conditional port unlink (skipped for single-UNI)
*/
static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	ret = omci_api_pptp_lct_uni_destroy(context->api, me->instance_id);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't delete Managed Entity", ret);
		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_pptp_lct_uni_class = {
	/* Class ID */
	OMCI_ME_PPTP_LCT_UNI,
	/* Attributes */
	{
		/* 1. Administrative state */
		ATTR_BOOL("Administrative state",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_pptp_lct_uni,
				   admin_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 2-16. Doesn't exist */
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
	me_init,
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
	sizeof(struct omci_me_pptp_lct_uni),
	/* Properties */
	OMCI_ME_PROP_NO_UPLOAD | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"PPTP LCT UNI",
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
