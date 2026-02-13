/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_onu2_g.c
*/
#include "ifxos_time.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_onu2_g.h"

/** \addtogroup OMCI_ME_ONU2_G
   @{
*/

/** Get SysUpTime

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error sys_uptime_get(struct omci_context *context,
				      struct me *me,
				      void *data,
				      size_t data_size)
{
	time_t tm;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 4);

	tm = IFXOS_ElapsedTimeMSecGet((IFX_time_t) context->startup_time) / 10;

	memcpy(data, (uint8_t *)&tm, 4);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static uint16_t omci_version_cp[] = { 0x80, 0x84, 0x85, 0x86, 0x96, 0xa0 };
static uint16_t security_capability_cp[] = { 1 };
static uint16_t security_mode_cp[] = { 1 };
static uint16_t mode_cp[] = { 1 };

/** Managed Entity class */
struct me_class me_onu2_g_class = {
	/* Class ID */
	OMCI_ME_ONU2_G,
	/* Attributes */
	{
		/* 1. Equipment id */
		ATTR_STR("Equipment id",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_onu2_g,
				  equipment_id),
			 20,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 2. OMCC version */
		ATTR_ENUM("OMCC version",
			  ATTR_SUPPORTED,
			  omci_version_cp,
			  offsetof(struct omci_me_onu2_g,
				   omci_version),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			  OMCI_ATTR_PROP_PARTLY,
			  NULL),
		/* 3. Vendor product code */
		ATTR_UINT("Vendor product code",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu2_g,
				   vendor_product_code),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 4. Security capability */
		ATTR_ENUM("Security capability",
			  ATTR_SUPPORTED,
			  security_capability_cp,
			  offsetof(struct omci_me_onu2_g,
				   security_capability),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 5. Security mode */
		ATTR_ENUM("Security mode",
			  ATTR_SUPPORTED,
			  security_mode_cp,
			  offsetof(struct omci_me_onu2_g,
				   security_mode),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 6. Total priority queue number */
		ATTR_UINT("Total priority queue num",
			  ATTR_SUPPORTED,
			  0x0000,
			  0x0fff,
			  offsetof(struct omci_me_onu2_g,
				   total_priority_queue_num),
			  2,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 7. Total traffic scheduler number */
		ATTR_UINT("Total traffic scheduler",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_onu2_g,
				   total_traffic_scheduler_num),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 8. Mode */
		ATTR_ENUM("Mode",
			  ATTR_SUPPORTED,
			  mode_cp,
			  offsetof(struct omci_me_onu2_g,
				   mode),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 9. Total GEM port-ID number */
		ATTR_UINT("Total GEM port-ID number",
			  ATTR_SUPPORTED,
			  0x0000,
			  0x0fff,
			  offsetof(struct omci_me_onu2_g,
				   total_gem_port_id_num),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 10. SysUpTime */
		ATTR_UINT("SysUpTime",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_onu2_g,
				   sys_uptime),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  sys_uptime_get),
		/* 11. Connectivity capability */
		ATTR_UINT("Connectivity capability",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu2_g,
				   connectivity_capability),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 12. Current connectivity mode */
		ATTR_UINT("Current connectivity mode",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_onu2_g,
				   current_connectivity_mode),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 13. QoS configuration flexibility */
		ATTR_UINT("QoS configuration flex",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu2_g,
				   qos_configuration_flexibility),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
		/* 14. Priority queue scale factor */
		ATTR_UINT("Prio queue scale factor",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_onu2_g,
				   priority_queue_scale_factor),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_OPTIONAL,
			  NULL),
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
	sizeof(struct omci_me_onu2_g),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"ONU2-G",
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
