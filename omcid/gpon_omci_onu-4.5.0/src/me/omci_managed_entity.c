/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_managed_entity.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_managed_entity.h"

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION


/** \addtogroup OMCI_ME_MANAGED_ENTITY
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
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 25);

	error = mib_me_class_resolve(context,
				     me->instance_id, &related_me_class);
	RETURN_IF_ERROR(error);

	memcpy(data, related_me_class->desc.name, 25);

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
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 1);

	error = mib_me_class_resolve(context,
				     me->instance_id, &related_me_class);
	RETURN_IF_ERROR(error);

	*(uint8_t *)data = (uint8_t)related_me_class->desc.access;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get Actions

   \param[in]  context   OMCI context pointer
   \param[in]  me        Managed Entity pointer
   \param[out] data      Pointer to data which will be filled up within the
                         function
   \param[in]  data_size Data size
*/
static enum omci_error actions_get(struct omci_context *context,
				   struct me *me,
				   void *data,
				   size_t data_size)
{
	const struct me_class *related_me_class;
	unsigned int i;
	enum omci_error error;
	uint32_t tmp32;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 4);

	error = mib_me_class_resolve(context,
				     me->instance_id, &related_me_class);
	RETURN_IF_ERROR(error);

	tmp32 = 0;

	for (i = 0; i < ACTIONS_NUM; i++) {
		if (related_me_class->actions[i] != NULL)
			tmp32 |= 1 << i;
	}
	memcpy(data, &tmp32, sizeof(tmp32));

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
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       (void *)data, data_size);

	assert(data_size == 1);

	error = mib_me_class_resolve(context,
				     me->instance_id, &related_me_class);
	RETURN_IF_ERROR(error);

	*(uint8_t *)data = (uint8_t)related_me_class->desc.support;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get Attributes table

   \param[in] context          OMCI context pointer
   \param[in] me               Managed Entity pointer
   \param[in] attr             Attribute position
   \param[in] tbl_copy         Attribute copy pointer
   \param[in] related_me_class Related Managed Entity pointer
*/
static enum omci_error attr_tbl_get(struct omci_context *context,
				    struct me *me,
				    unsigned int attr,
				    struct tbl_copy_entry *tbl_copy,
				    const struct me_class *related_me_class)
{
	unsigned int attr_count = 0;
	uint16_t *data16, tmp16;
	unsigned int i;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	if (related_me_class == NULL) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	/* count number of the attributes */
	for (i = 0; i < OMCI_ATTRIBUTES_NUM; i++) {
		if (related_me_class->attrs[i].prop == OMCI_ATTR_PROP_NONE)
			break;
		attr_count = i;
	}

	if (attr_count == 0) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	attr_count++;

	tbl_copy->data = IFXOS_MemAlloc(attr_count * sizeof(uint16_t));
	RETURN_IF_MALLOC_ERROR(tbl_copy->data);
	tbl_copy->data_size = attr_count * sizeof(uint16_t);

	data16 = (uint16_t *)tbl_copy->data;
	for (i = 0; i < attr_count; i++) {
		tmp16 = hton16((i << 12) | related_me_class->class_id);
		memcpy(&data16[i], &tmp16, sizeof(uint16_t));
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get Alarms table

   \param[in] context          OMCI context pointer
   \param[in] me               Managed Entity pointer
   \param[in] attr             Attribute position
   \param[in] tbl_copy         Attribute copy pointer
   \param[in] related_me_class Related Managed Entity pointer
*/
static enum omci_error alarm_tbl_get(struct omci_context *context,
				     struct me *me,
				     unsigned int attr,
				     struct tbl_copy_entry *tbl_copy,
				     const struct me_class *related_me_class)
{
	uint8_t *data8;
	unsigned int i;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	if (related_me_class == NULL) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	if (related_me_class->desc.alarm_table == NULL
	    || related_me_class->desc.alarm_table_size == 0) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	tbl_copy->data =
		IFXOS_MemAlloc(related_me_class->desc.alarm_table_size);
	RETURN_IF_MALLOC_ERROR(tbl_copy->data);
	tbl_copy->data_size = related_me_class->desc.alarm_table_size;

	data8 = (uint8_t *)tbl_copy->data;
	for (i = 0; i < related_me_class->desc.alarm_table_size; i++) {
		data8[i] = related_me_class->desc.alarm_table[i];
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get AVC table

   \param[in] context          OMCI context pointer
   \param[in] me               Managed Entity pointer
   \param[in] attr             Attribute position
   \param[in] tbl_copy         Attribute copy pointer
   \param[in] related_me_class Related Managed Entity pointer
*/
static enum omci_error avc_tbl_get(struct omci_context *context,
				   struct me *me,
				   unsigned int attr,
				   struct tbl_copy_entry *tbl_copy,
				   const struct me_class *related_me_class)
{
	unsigned int attr_count = 0;
	uint8_t *data8;
	unsigned int i;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	if (related_me_class == NULL) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	/* count number of the AVCs */
	for (i = 0; i < OMCI_ATTRIBUTES_NUM; i++) {
		if (related_me_class->attrs[i].prop & OMCI_ATTR_PROP_AVC)
			attr_count++;
	}

	if (attr_count == 0) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	tbl_copy->data = IFXOS_MemAlloc(attr_count);
	RETURN_IF_MALLOC_ERROR(tbl_copy->data);
	tbl_copy->data_size = attr_count;

	data8 = (uint8_t *)tbl_copy->data;
	attr_count = 0;
	for (i = 0; i < OMCI_ATTRIBUTES_NUM; i++) {
		if (related_me_class->attrs[i].prop
		    & OMCI_ATTR_PROP_AVC) {
			data8[attr_count] = (uint8_t)i + 1;
			attr_count++;
		}
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Get Instances table

   \param[in] context          OMCI context pointer
   \param[in] me               Managed Entity pointer
   \param[in] attr             Attribute position
   \param[in] tbl_copy         Attribute copy pointer
   \param[in] related_me_class Related Managed Entity pointer
*/
static enum omci_error inst_tbl_get(struct omci_context *context,
				    struct me *me,
				    unsigned int attr,
				    struct tbl_copy_entry *tbl_copy,
				    const struct me_class *related_me_class)
{
	unsigned int inst;
	unsigned int inst_count;
	unsigned int mib_class_idx;
	unsigned int i;
	unsigned int j;
	uint16_t *data16, tmp16;
	size_t required_data_size;
	struct mib_me_list_entry *me_entry;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	/* workaround for self description MEs */
	if (me->instance_id == OMCI_ME_OMCI) {
		required_data_size = sizeof(uint16_t);
		tbl_copy->data = IFXOS_MemAlloc(required_data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);
		tbl_copy->data_size = required_data_size;

		data16 = (uint16_t *)tbl_copy->data;
		tmp16 = 0;
		memcpy(&data16[0], &tmp16, sizeof(uint16_t));

	} else if (me->instance_id == OMCI_ME_MANAGED_ENTITY) {
		required_data_size = OMCI_ME_CLASS_NUM * sizeof(uint16_t);
		tbl_copy->data = IFXOS_MemAlloc(required_data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);
		tbl_copy->data_size = required_data_size;

		data16 = (uint16_t *)tbl_copy->data;
		for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
			tmp16 =
				hton16(context->mib.me_class_array[i].class_id);
			memcpy(&data16[i], &tmp16, sizeof(uint16_t));

		}
	} else if ((me->instance_id & 0x0fff) == OMCI_ME_ATTRIBUTE) {
		/* count instances number */
		inst_count = 0;
		for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
			for (me_entry =
			     context->mib.me_class_array[i].me_list;
			     me_entry != NULL;
			     me_entry = me_entry->next) {
				for (j = 0; j < OMCI_ATTRIBUTES_NUM; j++) {
					if (me_entry->me.class->attrs[j].prop
					    != OMCI_ATTR_PROP_NONE) {
						inst_count++;
					}
				}
			}
		}

		/* allocate memory */
		required_data_size = inst_count * sizeof(uint16_t);
		tbl_copy->data = IFXOS_MemAlloc(required_data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);
		tbl_copy->data_size = required_data_size;

		data16 = (uint16_t *)tbl_copy->data;

		/* fill data */
		inst = 0;
		for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
			for (me_entry = context->mib.me_class_array[i].me_list;
			     me_entry != NULL;
			     me_entry = me_entry->next) {
				for (j = 0; j < OMCI_ATTRIBUTES_NUM; j++) {
					if (me_entry->me.class->attrs[j].prop
					    != OMCI_ATTR_PROP_NONE) {
						tmp16 =
							hton16((j << 12) |
							       context->
							       mib.
							       me_class_array
							       [i].
							       class_id);
						memcpy(&data16[inst], &tmp16,
						       sizeof(uint16_t));
						inst++;
					}
				}
			}
		}
	} else {
		/** \todo check this */
		assert(related_me_class);

		inst_count = 0;
		mib_class_idx = OMCI_ME_CLASS_NUM;
		for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
			if (context->mib.me_class_array[i].class_id
			    == related_me_class->class_id) {
				mib_class_idx = i;

				for (me_entry =
				     context->mib.me_class_array[i].me_list;
				     me_entry != NULL;
				     me_entry = me_entry->next) {
					inst_count++;
				}

				break;
			}
		}

		if (inst_count == 0 || mib_class_idx == OMCI_ME_CLASS_NUM) {
			dbg_out_ret(__func__, OMCI_SUCCESS);
			return OMCI_SUCCESS;
		}

		required_data_size = inst_count * sizeof(uint16_t);
		tbl_copy->data = IFXOS_MemAlloc(required_data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);
		tbl_copy->data_size = required_data_size;

		data16 = (uint16_t *)tbl_copy->data;

		inst = 0;
		for (me_entry =
		     context->mib.me_class_array[mib_class_idx].me_list;
		     me_entry != NULL; me_entry = me_entry->next) {
			tmp16 = hton16(me_entry->me.instance_id);
			memcpy(&data16[inst], &tmp16, sizeof(uint16_t));
			inst++;
		}
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_tbl_copy(struct omci_context *context,
				   struct me *me,
				   unsigned int attr,
				   struct tbl_copy_entry *tbl_copy)
{
	const struct me_class *related_me_class;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	if (me->instance_id != OMCI_ME_OMCI
	    && me->instance_id != OMCI_ME_MANAGED_ENTITY
	    && (me->instance_id & 0x0fff) != OMCI_ME_ATTRIBUTE) {
		error = mib_me_class_resolve(context,
					     me->instance_id,
					     &related_me_class);

		RETURN_IF_ERROR(error);
	} else {
		related_me_class = NULL;
	}

	switch (attr) {
	case omci_me_managed_entity_attr_table:
		error = attr_tbl_get(context, me,
				     attr,
				     tbl_copy,
				     related_me_class);
		break;

	case omci_me_managed_entity_alarm_table:
		error = alarm_tbl_get(context, me,
				      attr,
				      tbl_copy,
				      related_me_class);
		break;

	case omci_me_managed_entity_avc_table:
		error = avc_tbl_get(context, me,
				    attr,
				    tbl_copy,
				    related_me_class);
		break;

	case omci_me_managed_entity_inst_table:
		error = inst_tbl_get(context, me,
				     attr,
				     tbl_copy,
				     related_me_class);
		break;

	default:
		error = OMCI_ERROR_INVALID_ME_ATTR;
		break;
	}

	dbg_out_ret(__func__, error);
	return error;
}

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
static uint16_t access_cp[] = { 1, 2, 3 };
static uint16_t support_cp[] = { 1, 2, 3, 4 };
#endif

/** Managed Entity class */
struct me_class me_managed_entity_class = {
	/* Class ID */
	OMCI_ME_MANAGED_ENTITY,
	/* Attributes */
	{
		/* 1. Name */
		ATTR_STR("Name",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_managed_entity,
				  name),
			 25,
			 OMCI_ATTR_PROP_RD,
			 name_get),
		/* 2. Attributes table */
		ATTR_TBL("Attributes table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_managed_entity,
				  attr_table),
			 2,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 3. Access */
		ATTR_ENUM("Access",
			  ATTR_SUPPORTED,
			  access_cp,
			  offsetof(struct omci_me_managed_entity,
				   access),
			  1,
			  OMCI_ATTR_PROP_RD,
			  access_get),
		/* 4. Alarms table */
		ATTR_TBL("Alarms table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_managed_entity,
				  alarm_table),
			 1,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 5. AVCs table */
		ATTR_TBL("AVCs table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_managed_entity,
				  avc_table),
			 1,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 6. Actions */
		ATTR_BF("Actions",
			ATTR_SUPPORTED,
			0x1fffffff,
			offsetof(struct omci_me_managed_entity,
				 actions),
			4,
			OMCI_ATTR_PROP_RD,
			actions_get),
		/* 7. Instances table */
		ATTR_TBL("Instances table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_managed_entity,
				  inst_table),
			 2,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 8. Support */
		ATTR_ENUM("Support",
			  ATTR_SUPPORTED,
			  support_cp,
			  offsetof(struct omci_me_managed_entity,
				   support),
			  1,
			  OMCI_ATTR_PROP_RD,
			  support_get),
		/* 9-16. Doesn't exist */
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
	sizeof(struct omci_me_managed_entity),
	/* Properties */
	OMCI_ME_PROP_NO_UPLOAD | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Managed entity",
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
