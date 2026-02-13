/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_cardholder.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_cardholder.h"

/** \addtogroup OMCI_ME_CARDHOLDER
   @{
*/

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	struct omci_me_cardholder *upd_data;
	struct omci_me_cardholder *me_data;

#ifdef WE_REALLY_SUPPORT_ARC_FOR_CARDHOLDER
	enum omci_error error;
#endif

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_cardholder *)data;
	me_data = (struct omci_me_cardholder *)me->data;

#ifdef WE_REALLY_SUPPORT_ARC_FOR_CARDHOLDER
	if (attr_mask & omci_attr2mask(OMCI_XXX_Arc)
	    || attr_mask & omci_attr2mask(OMCI_XXX_ArcInterval)) {
		me_data->arc = upd_data->arc;

		error = arc_interval_set(context, me,
					 &upd_data->arc_interval,
					 sizeof(upd_data->arc_interval));
		RETURN_IF_ERROR(error);
	}
#endif

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static uint16_t actual_plugin_unit_type_cp[] = {
	OMCI_CIRCUIT_PACK_TYPE_NO_LIM,
	OMCI_CIRCUIT_PACK_TYPE_10BASET,
	OMCI_CIRCUIT_PACK_TYPE_100BASET,
	OMCI_CIRCUIT_PACK_TYPE_10100BASET,
	OMCI_CIRCUIT_PACK_TYPE_101001000BASET,
	OMCI_CIRCUIT_PACK_TYPE_GPON1244155,
	OMCI_CIRCUIT_PACK_TYPE_GPON1244622,
	OMCI_CIRCUIT_PACK_TYPE_GPON12441244,
	OMCI_CIRCUIT_PACK_TYPE_GPON2488155,
	OMCI_CIRCUIT_PACK_TYPE_GPON2488622,
	OMCI_CIRCUIT_PACK_TYPE_GPON24881244,
	OMCI_CIRCUIT_PACK_TYPE_GPON24882488,
	OMCI_CIRCUIT_PACK_POTS
};

static uint16_t invoke_protection_switch_cp[] = {
	0, 1, 2, 3
};

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
static uint8_t alarm_table[] = { 0, 1, 2, 3, 4 };
#endif

/** Managed Entity class */
struct me_class me_cardholder_class = {
	/* Class ID */
	OMCI_ME_CARDHOLDER,
	/* Attributes */
	{
		/* 1. Actual plug-in unit type */
		ATTR_ENUM("Actual plug-in unit type",
			  ATTR_SUPPORTED,
			  actual_plugin_unit_type_cp,
			  offsetof(struct omci_me_cardholder,
				   actual_plugin_type),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC,
			  NULL),
		/* 2. Expected plug-in unit type */
		ATTR_ENUM("Expected plug-in unit typ",
			  ATTR_SUPPORTED,
			  actual_plugin_unit_type_cp,
			  offsetof(struct omci_me_cardholder,
				   expected_plugin_type),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 3. Expected port count */
		ATTR_UINT("Expected port count",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_cardholder,
				   expected_port_count),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 4. Expected equipment id */
		ATTR_STR("Expected equipment id",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_cardholder,
				  expected_equipment_id),
			 20,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 5. Actual equipment id */
		ATTR_STR("Actual equipment id",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_cardholder,
				  actual_equipment_id),
			 20,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			 OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 6. Protection profile pointer */
		ATTR_PTR("Protection profile ptr",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_cardholder,
				  protection_profile_ptr),
			 1,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE |
			 OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 7. Invoke protection switch - optional */
		ATTR_ENUM("Invoke protection switch",
			  ATTR_SUPPORTED,
			  invoke_protection_switch_cp,
			  offsetof(struct omci_me_cardholder,
				   invoke_protection_switch),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_TEMPLATE | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 8. Alarm Reporting Control */
		ATTR_BOOL("ARC",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_cardholder, arc),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_AVC | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 9. Alarm Reporting Interval */
		ATTR_UINT("ARC interval",
			  ATTR_SUPPORTED,
			  0,
			  255,
			  offsetof(struct omci_me_cardholder, arc_interval),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 10-16. Doesn't exist */
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
	default_me_shutdown,
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
	sizeof(struct omci_me_cardholder),
	/* Properties */
	OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Cardholder",
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
