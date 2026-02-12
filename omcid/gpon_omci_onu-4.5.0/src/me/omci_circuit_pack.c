/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_circuit_pack.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_circuit_pack.h"
#include "me/omci_api_onu_g.h"

/** \addtogroup OMCI_ME_CIRCUIT_PACK
   @{
*/

static enum omci_error serial_number_get(struct omci_context *context,
					  struct me *me,
					  void *data,
					  size_t data_size)
{
	enum omci_api_return ret;

	assert(data_size == 8);

	ret = omci_api_onu_g_serial_number_get(context->api,
					       me->instance_id,
					       (uint8_t *)data);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_ERROR_DRV;

	return OMCI_SUCCESS;
}

static uint16_t type_cp[] = {
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

static uint16_t bridged_or_ip_cp[] = { 0, 1, 2 };

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
static uint8_t alarm_table[] = { 0, 1, 2, 3, 4, 5 };
#endif

/** Managed Entity class */
struct me_class me_circuit_pack_class = {
	/* Class ID */
	OMCI_ME_CIRCUIT_PACK,
	/* Attributes */
	{
		/* 1. Type */
		ATTR_ENUM("Type",
			  ATTR_SUPPORTED,
			  type_cp,
			  offsetof(struct omci_me_circuit_pack, type),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 2. Number of ports */
		ATTR_UINT("Number of ports",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_circuit_pack,
				   number_of_ports),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 3. Serial number */
		ATTR_STR("Serial number",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_circuit_pack, serial_num),
			 8,
			 OMCI_ATTR_PROP_RD,
			 serial_number_get),
		/* 4. Version */
		ATTR_STR("Version",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_circuit_pack, version),
			 14,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 5. Vendor id */
		ATTR_STR("Vendor id",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_circuit_pack, vendor_id),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 6. Administrative state */
		ATTR_BOOL("Administrative state",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_circuit_pack,
				   admin_state),
			  1,
			  OMCI_ATTR_PROP_RD
			  | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			  NULL),
		/* 7. Operational state */
		ATTR_UINT("Operational state",
			  ATTR_SUPPORTED,
			  0,
			  2,
			  offsetof(struct omci_me_circuit_pack, oper_state),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			  OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 8. Bridged or IP ind */
		ATTR_ENUM("Bridged or IP ind",
			  ATTR_SUPPORTED,
			  bridged_or_ip_cp,
			  offsetof(struct omci_me_circuit_pack,
				   bridged_or_ip),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 9. Equipment id */
		ATTR_STR("Equipment id",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_circuit_pack,
				  equipment_id),
			 20,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 10. Card configuration */
		ATTR_UINT("Card configuration",
			  ATTR_SUPPORTED,
			  0,
			  2,
			  offsetof(struct omci_me_circuit_pack,
				   card_configuration),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 11. Total T-CONT buffer number */
		ATTR_UINT("Total T-CONT buffer num",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_circuit_pack,
				   total_tcont_buffer_num),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 12. Total priority queue number */
		ATTR_UINT("Total priority queue num",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_circuit_pack,
				   total_priority_queue_num),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 13. Total traffic scheduler number */
		ATTR_UINT("Total traffic sched num",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_circuit_pack,
				   total_traffic_scheduler_num),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 14. Power shed override - optional */
		ATTR_UINT("Power shed override",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_circuit_pack,
				   power_shed_override),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 15-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
	},
	/* Actions */
	{
		NULL, NULL, NULL, NULL,
		/* Create */
		/* don't support pluggable */
		NULL,
		NULL,
		/* Delete */
		/* don't support pluggable */
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
		/* don't support circuit pack testing */
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
		reboot_acion_handle,
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
#ifdef INCLUDE_PM
	/* Counters get Handler */
	NULL,
	/* Thresholds set Handler */
	NULL,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_me_circuit_pack),
	/* Properties */
	OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Circuit pack",
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
