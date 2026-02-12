/******************************************************************************

                              Copyright (c) 2010
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_foo.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_foo.h"

/** \addtogroup OMCI_ME_FOO
   @{
*/

static enum omci_error me_tbl_copy(struct omci_context *context,
				   struct me *me,
				   unsigned int attr,
				   struct tbl_copy_entry *tbl_copy)
{
	enum omci_error error;
	char dummy[] = "dummy table data";

	switch (attr) {
	case omci_me_foo_table:
		tbl_copy->data_size = sizeof(dummy);

		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);

		memcpy(tbl_copy->data, dummy, tbl_copy->data_size);

		break;

	default:
		error = OMCI_ERROR_INVALID_ME_ATTR;
		break;
	}

	return error;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	struct omci_me_foo *upd_data, *me_data;

	upd_data = (struct omci_me_foo *)data;
	me_data = (struct omci_me_foo *)me->data;

	if (attr_mask & omci_attr2mask(omci_me_foo_table)) {
		/* handle table entry set */
	}

	/* TODO */

	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	struct omci_me_foo data;
	enum omci_error error;

	if (init_data) {
		memcpy(&data, init_data, sizeof(data));
	} else {
		/* set default values */
		data.flag = false;
		data.number = 1234;
		strcpy(data.string, "hello");
	}

	error = me_data_write(context, me, &data, sizeof(data),
			      ~me->class->inv_attr_mask,
			      suppress_avc);
	return error;
}

static enum omci_error number_get(
				  struct omci_context *context,
				  struct me *me,
				  void *data,
				  size_t data_size)
{
	uint16_t number;

	assert(data_size == 2);

	number = 0; /* some external volatile value */

	memcpy(data, &number, sizeof(number));

	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_foo_class = {
	/* Class ID */
	OMCI_ME_FOO,
	/* Attributes */
	{
		/* 1. Boolean attribute */
		ATTR_BOOL("Flag",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_foo,
				   flag),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			  NULL),

		/* 2. Integer attribute */
		ATTR_UINT("Number",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_foo,
				   number),
			  2,
			  OMCI_ATTR_PROP_RD,
			  number_get), /* here */

		/* 3. String attribute */
		ATTR_STR("String",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_foo,
				  string),
			 10,
			 OMCI_ATTR_PROP_RD,
			 NULL),

		/* 4. Table attribyte */
		ATTR_STR("Table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_foo,
				  table),
			 sizeof(struct omci_me_foo_table), /* table entry size, not entire table size!!! */
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR /* writable table */
			 | OMCI_ATTR_PROP_TABLE,
			 NULL),

		/* 5 - 16. Put a placeholder for unused attributes */
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
	default_me_validate,
	/* Update Handler */
	me_update,
	/* Table Attribute Copy Handler */
	me_tbl_copy,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	NULL,
	/* Thresholds set Handler */
	NULL,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_me_foo),
	/* Properties */
	OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Foo",
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
