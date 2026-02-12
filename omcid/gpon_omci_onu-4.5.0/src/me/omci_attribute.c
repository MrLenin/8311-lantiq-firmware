/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_attribute.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_attribute.h"

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION

/** \addtogroup OMCI_ME_ATTRIBUTE
    @{
*/

/** Get Name

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error name_get(struct omci_context *context,
				struct me *me,
				void *data,
				size_t data_size)
{
	const struct me_class *related_me_class;
	unsigned int attr = (me->instance_id >> 12) & 0xff;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 25);

	error = mib_me_class_resolve(context,
				     0x0fff & me->instance_id,
				     &related_me_class);
	RETURN_IF_ERROR(error);

	if (related_me_class->attrs[attr].prop == OMCI_ATTR_PROP_NONE) {
		dbg_out_ret(__func__, OMCI_ERROR_ME_NOT_FOUND);
		return OMCI_ERROR_ME_NOT_FOUND;
	}

	memcpy(data, related_me_class->attrs[attr].desc.name, 25);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get Size

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error size_get(struct omci_context *context,
				struct me *me,
				void *data,
				size_t data_size)
{
	const struct me_class *related_me_class;
	unsigned int attr = (me->instance_id >> 12) & 0xff;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 2);

	error = mib_me_class_resolve(context,
				     0x0fff & me->instance_id,
				     &related_me_class);
	RETURN_IF_ERROR(error);

	if (related_me_class->attrs[attr].prop == OMCI_ATTR_PROP_NONE) {
		dbg_out_ret(__func__, OMCI_ERROR_ME_NOT_FOUND);
		return OMCI_ERROR_ME_NOT_FOUND;
	}

	if (related_me_class->attrs[attr].prop & OMCI_ATTR_PROP_TABLE)
		/* for all table attributes return unknown size */
		memset(data, 0, sizeof(uint16_t));
	else {
		uint16_t tmp = related_me_class->attrs[attr].size;
		memcpy(data, &tmp, sizeof(uint16_t));
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get Access

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error access_get(struct omci_context *context,
				  struct me *me,
				  void *data,
				  size_t data_size)
{
	const struct me_class *related_me_class;
	unsigned int attr = (me->instance_id >> 12) & 0xff;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 1);

	error = mib_me_class_resolve(context,
				     0x0fff & me->instance_id,
				     &related_me_class);
	RETURN_IF_ERROR(error);

	if (related_me_class->attrs[attr].prop == OMCI_ATTR_PROP_NONE) {
		dbg_out_ret(__func__, OMCI_ERROR_ME_NOT_FOUND);
		return OMCI_ERROR_ME_NOT_FOUND;
	}

	if (related_me_class->attrs[attr].prop & OMCI_ATTR_PROP_RD)
		*(uint8_t *)data |= 1;

	if (related_me_class->attrs[attr].prop & OMCI_ATTR_PROP_WR)
		*(uint8_t *)data |= 2;

	if (related_me_class->attrs[attr].prop & OMCI_ATTR_PROP_SBC)
		*(uint8_t *)data |= 4;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get Format

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error format_get(struct omci_context *context,
				  struct me *me,
				  void *data,
				  size_t data_size)
{
	const struct me_class *related_me_class;
	unsigned int attr = (me->instance_id >> 12) & 0xff;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 1);

	error = mib_me_class_resolve(context,
				     0x0fff & me->instance_id,
				     &related_me_class);
	RETURN_IF_ERROR(error);

	if (related_me_class->attrs[attr].prop == OMCI_ATTR_PROP_NONE) {
		dbg_out_ret(__func__, OMCI_ERROR_ME_NOT_FOUND);
		return OMCI_ERROR_ME_NOT_FOUND;
	}

	*(uint8_t *)data = (uint8_t)related_me_class->attrs[attr].format;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get Lower limit

   \param[in]  context  OMCI context pointer
   \param[in]  me       Managed Entity pointer
   \param[out] data     Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error lower_limit_get(struct omci_context *context,
				       struct me *me,
				       void *data,
				       size_t data_size)
{
	const struct me_class *related_me_class;
	unsigned int attr = (me->instance_id >> 12) & 0xff;
	enum omci_error error;
	uint32_t tmp32;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 4);

	error = mib_me_class_resolve(context,
				     0x0fff & me->instance_id,
				     &related_me_class);
	RETURN_IF_ERROR(error);

	switch (related_me_class->attrs[attr].format) {
	case OMCI_ATTR_TYPE_PTR:
	case OMCI_ATTR_TYPE_INT:
	case OMCI_ATTR_TYPE_UINT:
		break;

	default:
		dbg_out_ret(__func__, OMCI_ERROR_INVALID_ME_ATTR);
		return OMCI_ERROR_INVALID_ME_ATTR;
	}

	if (related_me_class->attrs[attr].prop == OMCI_ATTR_PROP_NONE) {
		dbg_out_ret(__func__, OMCI_ERROR_ME_NOT_FOUND);
		return OMCI_ERROR_ME_NOT_FOUND;
	}

	/** \todo make compliant with the ITU!!! (p 292) */

	memcpy(data, &related_me_class->attrs[attr].lower_limit, sizeof(tmp32));

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get Upper limit

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error upper_limit_get(struct omci_context *context,
				       struct me *me,
				       void *data,
				       size_t data_size)
{
	const struct me_class *related_me_class;
	unsigned int attr = (me->instance_id >> 12) & 0xff;
	enum omci_error error;
	uint32_t tmp32;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 4);

	error = mib_me_class_resolve(context,
				     0x0fff & me->instance_id,
				     &related_me_class);
	RETURN_IF_ERROR(error);

	switch (related_me_class->attrs[attr].format) {
	case OMCI_ATTR_TYPE_PTR:
	case OMCI_ATTR_TYPE_INT:
	case OMCI_ATTR_TYPE_UINT:
		break;

	default:
		dbg_out_ret(__func__, OMCI_ERROR_INVALID_ME_ATTR);
		return OMCI_ERROR_INVALID_ME_ATTR;
	}

	if (related_me_class->attrs[attr].prop == OMCI_ATTR_PROP_NONE) {
		dbg_out_ret(__func__, OMCI_ERROR_ME_NOT_FOUND);
		return OMCI_ERROR_ME_NOT_FOUND;
	}

	/** \todo make compliant with the ITU!!! (p 292) */

	memcpy(data, &related_me_class->attrs[attr].upper_limit, sizeof(tmp32));

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get Bit field

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error bit_field_get(struct omci_context *context,
				     struct me *me,
				     void *data,
				     size_t data_size)
{
	const struct me_class *related_me_class;
	unsigned int attr = (me->instance_id >> 12) & 0xff;
	enum omci_error error;
	uint32_t tmp32;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 4);

	error = mib_me_class_resolve(context,
				     0x0fff & me->instance_id,
				     &related_me_class);
	RETURN_IF_ERROR(error);

	if (related_me_class->attrs[attr].format != OMCI_ATTR_TYPE_BF) {
		dbg_out_ret(__func__, OMCI_ERROR_INVALID_ME_ATTR);
		return OMCI_ERROR_INVALID_ME_ATTR;
	}

	if (related_me_class->attrs[attr].prop == OMCI_ATTR_PROP_NONE) {
		dbg_out_ret(__func__, OMCI_ERROR_ME_NOT_FOUND);
		return OMCI_ERROR_ME_NOT_FOUND;
	}

	memcpy(data, &related_me_class->attrs[attr].bit_field, sizeof(tmp32));

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get Support

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error support_get(struct omci_context *context,
				   struct me *me,
				   void *data,
				   size_t data_size)
{
	const struct me_class *related_me_class;
	unsigned int attr = (me->instance_id >> 12) & 0xff;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 1);

	error = mib_me_class_resolve(context,
				     0x0fff & me->instance_id,
				     &related_me_class);
	RETURN_IF_ERROR(error);

	if (related_me_class->attrs[attr].prop == OMCI_ATTR_PROP_NONE) {
		dbg_out_ret(__func__, OMCI_ERROR_ME_NOT_FOUND);
		return OMCI_ERROR_ME_NOT_FOUND;
	}

	*(uint8_t *)data = (uint8_t)related_me_class->attrs[attr].desc.support;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_tbl_copy(struct omci_context *context,
				   struct me *me,
				   unsigned int attr,
				   struct tbl_copy_entry *tbl_copy)
{
	unsigned int related_attr = (me->instance_id >> 12) & 0xff;
	const struct me_class *related_me_class;
	uint16_t *data16, tmp16;
	unsigned int i;
	size_t required_data_size;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	error = mib_me_class_resolve(context,
				     0x0fff & me->instance_id,
				     &related_me_class);
	RETURN_IF_ERROR(error);

	switch (attr) {
	case omci_me_attribute_code_point_table:

		if (related_me_class->attrs[related_attr].code_points == NULL
		    || related_me_class->attrs[related_attr].code_points_num
		    == 0
		    || related_me_class->attrs[related_attr].format
		    != OMCI_ATTR_TYPE_ENUM) {
			dbg_out_ret(__func__, OMCI_ERROR_INVALID_ME_ATTR);
			return OMCI_ERROR_INVALID_ME_ATTR;
		}

		required_data_size = sizeof(uint16_t)
		    * related_me_class->attrs[related_attr].code_points_num;
		tbl_copy->data = IFXOS_MemAlloc(required_data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);

		tbl_copy->data_size = required_data_size;

		data16 = (uint16_t *)tbl_copy->data;

		for (i = 0;
		     i < related_me_class->attrs[related_attr].code_points_num;
		     i++) {
			tmp16 = hton16(related_me_class->
					   attrs[related_attr].code_points[i]);
			memcpy(&data16[i], &tmp16, sizeof(uint16_t));
		}

		break;

	default:
		error = OMCI_ERROR_INVALID_ME_ATTR;
		break;
	}

	dbg_out_ret(__func__, error);
	return error;
}

static uint16_t access_cp[] = { 1, 2, 3, 5, 6, 7 };
static uint16_t format_cp[] = { 1, 2, 3, 4, 5, 6, 7 };
static uint16_t support_cp[] = { 1, 2, 3, 4 };

/** Managed Entity class */
struct me_class me_attribute_class = {
	/* Class ID */
	OMCI_ME_ATTRIBUTE,
	/* Attributes */
	{
		/* 1. Name */
		ATTR_STR("Name",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_attribute,
				  name),
			 25,
			 OMCI_ATTR_PROP_RD,
			 name_get),
		/* 2. Size */
		ATTR_UINT("Size",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_attribute,
				   size),
			  2,
			  OMCI_ATTR_PROP_RD,
			  size_get),
		/* 3. Access */
		ATTR_ENUM("Access",
			  ATTR_SUPPORTED,
			  access_cp,
			  offsetof(struct omci_me_attribute,
				   access),
			  1,
			  OMCI_ATTR_PROP_RD,
			  access_get),
		/* 4. Format */
		ATTR_ENUM("Format",
			  ATTR_SUPPORTED,
			  format_cp,
			  offsetof(struct omci_me_attribute,
				   format),
			  1,
			  OMCI_ATTR_PROP_RD,
			  format_get),
		/* 5. Lower limit */
		ATTR_UINT("Lower limit",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_attribute,
				   lower_limit),
			  4,
			  OMCI_ATTR_PROP_RD,
			  lower_limit_get),
		/* 6. Upper limit */
		ATTR_UINT("Upper limit",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_attribute,
				   upper_limit),
			  4,
			  OMCI_ATTR_PROP_RD,
			  upper_limit_get),
		/* 7. Bit field */
		ATTR_BF("Bit field",
			ATTR_SUPPORTED,
			0xffffffff,
			offsetof(struct omci_me_attribute,
				 bit_field),
			4,
			OMCI_ATTR_PROP_RD,
			bit_field_get),
		/* 8. Code points table */
		ATTR_TBL("Code points table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_attribute,
				  code_points_table),
			 2,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 9. Support */
		ATTR_ENUM("Support",
			  ATTR_SUPPORTED,
			  support_cp,
			  offsetof(struct omci_me_attribute,
				   support),
			  1,
			  OMCI_ATTR_PROP_RD,
			  support_get),
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
		get_next_action_handle,
		/* Test result */
		NULL,
		/* Get current data */
		NULL
	},
	/* Init Handler */
	NULL,
	/* Shutdown Handler */
	NULL,
	/* Validate Handler */
	NULL,
	/* Update Handler */
	default_me_update,
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
	sizeof(struct omci_me_attribute),
	/* Properties */
	OMCI_ME_PROP_NO_UPLOAD,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Attribute",
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

#endif
