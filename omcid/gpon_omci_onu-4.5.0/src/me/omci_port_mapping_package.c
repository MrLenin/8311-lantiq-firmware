/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_port_mapping_package.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_port_mapping_package.h"

/** \addtogroup OMCI_ME_PORT_MAPPING_PACKAGE
   @{
*/

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	struct omci_me_port_mapping_package *upd_data;
	struct omci_me_port_mapping_package *me_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_port_mapping_package *) data;
	me_data = (struct omci_me_port_mapping_package *) me->data;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_port_mapping_package_class = {
	/* Class ID */
	OMCI_ME_PORT_MAPPING_PACKAGE,
	/* Attributes */
	{
		/* 1. Maximum Port Number */
		ATTR_UINT("Max ports",
			  ATTR_SUPPORTED,
			  0,
			  0xff,
			  offsetof(struct omci_me_port_mapping_package,
				   max_port_num),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 2. Port list 1 */
		ATTR_STR("Port list 1",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_port_mapping_package,
				  port_list1),
			 16,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 3. Port list 2 */
		ATTR_STR("Port list 2",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_port_mapping_package,
				  port_list2),
			 16,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 4. Port list 3 */
		ATTR_STR("Port list 3",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_port_mapping_package,
				  port_list3),
			 16,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 5. Port list 4 */
		ATTR_STR("Port list 4",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_port_mapping_package,
				  port_list4),
			 16,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 6. Port list 5 */
		ATTR_STR("Port list 5",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_port_mapping_package,
				  port_list5),
			 16,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 7. Port list 6 */
		ATTR_STR("Port list 6",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_port_mapping_package,
				  port_list6),
			 16,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 8. Port list 7 */
		ATTR_STR("Port list 7",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_port_mapping_package,
				  port_list7),
			 16,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 9. Port list 8 */
		ATTR_STR("Port list 8",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_port_mapping_package,
				  port_list8),
			 16,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
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
		NULL,
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
	sizeof(struct omci_me_port_mapping_package),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Port mapping pkg",
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
