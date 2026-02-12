/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_olt_g.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_olt_g.h"

#ifdef INCLUDE_G984_4_AMENDMENT_2
#include "me/omci_api_olt_g.h"
#endif

/** \addtogroup OMCI_ME_OLT_G
   @{
*/

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
#ifdef INCLUDE_G984_4_AMENDMENT_2
	enum omci_api_return ret;
	uint32_t multiframe_count;
	uint16_t tod_extended_seconds;
	uint32_t tod_seconds;
	uint32_t tod_nano_seconds;
#endif

	struct omci_me_olt_g *upd_data;
	struct omci_me_olt_g *me_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context,
	       (void *)me, (void *)data, attr_mask);

	upd_data = (struct omci_me_olt_g *) data;
	me_data = (struct omci_me_olt_g *) me->data;

#ifdef INCLUDE_G984_4_AMENDMENT_2
	multiframe_count = upd_data->tod_info[0] << 24 |
		upd_data->tod_info[1] << 16 |
		upd_data->tod_info[2] << 8 |
		upd_data->tod_info[3];
	multiframe_count = ntoh32(multiframe_count);

	memcpy(&tod_extended_seconds, &upd_data->tod_info[4], sizeof(uint16_t));
	tod_extended_seconds = ntoh16(tod_extended_seconds);

	memcpy(&tod_seconds, &upd_data->tod_info[6], sizeof(uint32_t));
	tod_seconds = ntoh32(tod_seconds);

	memcpy(&tod_nano_seconds, &upd_data->tod_info[10], sizeof(uint32_t));
	tod_nano_seconds = ntoh32(tod_nano_seconds);

	ret = omci_api_olt_g_update(context->api,
				    me->instance_id, multiframe_count,
				    tod_extended_seconds, tod_seconds,
				    tod_nano_seconds);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't update Managed Entity", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}
#endif

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	struct omci_me_olt_g data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	if (init_data) {
		memcpy(&data, init_data, sizeof(data));
	} else {
		memset(data.olt_vendor_id, ' ',
		       sizeof(data.olt_vendor_id));
		memset(data.olt_equipment_id, ' ',
		       sizeof(data.olt_equipment_id));
		memset(data.olt_version, ' ', sizeof(data.olt_version));
	}

	error = me_data_write(context, me, &data, sizeof(data),
			      ~me->class->inv_attr_mask, suppress_avc);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_olt_g_class = {
	/* Class ID */
	OMCI_ME_OLT_G,
	/* Attributes */
	{
		/* 1. OLT Vendor Id */
		ATTR_STR("OLT vendor id",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_olt_g,
				  olt_vendor_id),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 2. Equipment Id */
		ATTR_STR("Equipment id",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_olt_g,
				  olt_equipment_id),
			 20,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 3. Version */
		ATTR_STR("Version",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_olt_g,
				  olt_version),
			 14,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
#ifdef INCLUDE_G984_4_AMENDMENT_2
		/* 4. Time of day information */
		ATTR_STR("Time of day information",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_olt_g,
				  tod_info),
			 14,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
#else
		/* 4-16. Doesn't exist */
		ATTR_NOT_DEF(),
#endif
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
	NULL,
	/* Validate Handler */
	NULL,
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
	sizeof(struct omci_me_olt_g),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"OLT-G",
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
