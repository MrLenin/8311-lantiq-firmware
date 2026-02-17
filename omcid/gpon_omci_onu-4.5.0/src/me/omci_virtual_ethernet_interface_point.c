/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_virtual_ethernet_interface_point.c
   v7.5.1 Virtual Ethernet Interface Point — mapper-only UNI port.

   Reverse-engineered from stock omcid v7.5.1 (patched function table
   at 0x00479ec0):
     me_init     = 0x00426d48  (me_data_write + omci_api_veip_create)
     me_update   = 0x00426c48  (admin_state lock/unlock, circuit_pack gate)
     me_shutdown = 0x00426bb4  (omci_api_veip_destroy)
     me_validate = no-op

   VEIP is a virtual UNI — no FIO_LAN_PORT_CFG_SET, only mapper
   registration (explicit_map with mapper 0x1e) and port enable/disable.

   8311 mod: admin_state lock requests are ignored (force-unlocked) to
   prevent the OLT from locking the shared LAN port and stranding the
   user.  The ME data still stores the OLT-requested value for Get
   queries.
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_virtual_ethernet_interface_point.h"
#include "me/omci_api_veip.h"

/** \addtogroup OMCI_ME_VIRTUAL_ETHERNET_INTERFACE_POINT
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
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	/* v7.5.1: only act on admin_state changes (attr 1 = bit 15) */
	if (!(attr_mask & omci_attr2mask(omci_me_veip_admin_state))) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	/* v7.5.1 behavior: if LOCKED, call lock_port; if UNLOCKED,
	   check circuit_pack type VEIP admin_state, then unlock_port.

	   8311 mod: always force-unlock to prevent the OLT from locking
	   the shared LAN port and stranding the user. */
	ret = omci_api_veip_unlock(context->api, me->instance_id);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't unlock VEIP", ret);
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
	enum omci_error error;
	enum omci_api_return ret;
	struct omci_me_virtual_ethernet_interface_point data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)init_data, suppress_avc);

	/* v7.5.1: copy init_data or zero-fill */
	if (init_data)
		memcpy(&data, init_data, sizeof(data));
	else
		memset(&data, 0x00, sizeof(data));

	error = me_data_write(context, me, &data, sizeof(data),
			      ~me->class->inv_attr_mask, suppress_avc);
	RETURN_IF_ERROR(error);

	/* v7.5.1: register in mapper during init */
	ret = omci_api_veip_create(context->api, me->instance_id);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) VEIP create failed", ret);
		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	ret = omci_api_veip_destroy(context->api, me->instance_id);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) VEIP destroy failed", ret);
		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
static uint8_t alarm_table[] = { 0 };
#endif

/** Managed Entity class */
struct me_class me_virtual_ethernet_interface_point_class = {
	/* Class ID */
	OMCI_ME_VIRTUAL_ETHERNET_INTERFACE_POINT,
	/* Attributes */
	{
		/* 1. Administrative state */
		ATTR_BOOL("Administrative state",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_virtual_ethernet_interface_point,
				   admin_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 2. Operational state */
		ATTR_BOOL("Operational state",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_virtual_ethernet_interface_point,
				   oper_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 3. Interdomain name*/
		ATTR_STR("Interdomain name",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_virtual_ethernet_interface_point,
				  interdomain_name),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 4. TCP/UDP pointer*/
		ATTR_PTR("TCP/UDP pointer",
		  ATTR_SUPPORTED,
		  0x0000,
		  0xffff,
		  offsetof(struct omci_me_virtual_ethernet_interface_point,
			   tcp_udp_pointer),
		  2,
		  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL |
		  OMCI_ATTR_PROP_TEMPLATE,
		  NULL),
		/* 5. IANA assigned port*/
		ATTR_PTR("IANA assigned port",
		  ATTR_SUPPORTED,
		  0x0000,
		  0xffff,
		  offsetof(struct omci_me_virtual_ethernet_interface_point,
			   iana_assigned_port),
		  2,
		  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
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
	sizeof(struct omci_me_virtual_ethernet_interface_point),
	/* Properties */
	OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Virtual Eth i/f point",
		/* Access */
		ME_CREATED_BY_ONT,
		/* Supported alarms */
		alarm_table,
		/* Supported alarms count */
		sizeof(alarm_table) / sizeof(alarm_table[0]),
		/* Support */
		ME_SUPPORTED
	},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */
