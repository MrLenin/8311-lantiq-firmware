/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_large_string.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_large_string.h"

/** \addtogroup OMCI_ME_LARGE_STRING
   @{
*/

void large_string_get(struct omci_context *context,
		      struct me *me,
		      char buf[OMCI_ME_LARGE_STRING_SIZE])
{
	int i;
	struct omci_me_large_string *data = me->data;
	char *p = buf;

	assert(me->class->class_id == OMCI_ME_LARGE_STRING);

	*p = '\0';

	for (i = 0; i < data->number_of_parts; i++) {
		memcpy(p, &data->part[i], sizeof(data->part[0]));
		p += sizeof(data->part[0]);
	}

	*++p = '\0';
}

static enum omci_error omci_large_string_shutdown(struct omci_context *context,
						  struct me *me)
{
	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	/** \todo ensure that this Managed Entity is not deleted while it is
	   still linked */

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_large_string_class = {
	/* Class ID */
	OMCI_ME_LARGE_STRING,
	/* Attributes */
	{
		/* 1. Number of Parts */
		ATTR_UINT("Number of parts",
			  ATTR_SUPPORTED,
			  0,
			  15,
			  offsetof(struct omci_me_large_string,
				   number_of_parts),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),
		/* 2. Part 1 */
		ATTR_STR("Part 1",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[0]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 3. Part 2 */
		ATTR_STR("Part 2",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[1]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 4. Part 3 */
		ATTR_STR("Part 3",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[2]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 5. Part 4 */
		ATTR_STR("Part 4",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[3]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 6. Part 5 */
		ATTR_STR("Part 5",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[4]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 7. Part 6 */
		ATTR_STR("Part 6",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[5]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 8. Part 7 */
		ATTR_STR("Part 7",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[6]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 9. Part 8 */
		ATTR_STR("Part 8",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[7]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 10. Part 9 */
		ATTR_STR("Part 9",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[8]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 11. Part 10 */
		ATTR_STR("Part 10",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[9]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 12. Part 11 */
		ATTR_STR("Part 11",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[10]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 13. Part 12 */
		ATTR_STR("Part 12",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[11]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 14. Part 13 */
		ATTR_STR("Part 13",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[12]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 15. Part 14 */
		ATTR_STR("Part 14",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[13]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 16. Part 15 */
		ATTR_STR("Part 15",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_large_string,
				  part[14]),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL)
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
	omci_large_string_shutdown,
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
	sizeof(struct omci_me_large_string),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Large string",
		/* Access */
		ME_CREATED_BY_OLT,
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
