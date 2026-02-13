/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_MIB

#include "omci_core.h"
#include "omci_debug.h"
#include "me/omci_onu_data.h"

/** \addtogroup OMCI_MIB
   @{
*/

void mib_lock_read(struct omci_context *context)
{
	dbg_msg("[ LOCK   MIB RD (%p)", (void *)&context->mib.lock);
	if (rw_lock_get(&context->mib.lock, RW_LOCK_MODE_READ)
	    != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't lock MIB for read (%p)",
			OMCI_ERROR_LOCK,
			(void *)&context->mib.lock);
		abort();
	}
}

void mib_lock_write(struct omci_context *context)
{
	dbg_msg("[ LOCK   MIB WR (%p)", (void *)&context->mib.lock);
	if (rw_lock_get(&context->mib.lock, RW_LOCK_MODE_WRITE)
	    != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't lock MIB for write (%p)",
			OMCI_ERROR_LOCK,
			(void *)&context->mib.lock);
		abort();
	}
}

void mib_unlock(struct omci_context *context)
{
	dbg_msg("] UNLOCK MIB    (%p)", (void *)&context->mib.lock);
	if (rw_lock_release(&context->mib.lock) != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't unlock MIB (%p)",
			OMCI_ERROR_LOCK,
			(void *)&context->mib.lock);
		abort();
	}
}

enum omci_error mib_copy_init(struct omci_context *context)
{
	enum omci_error error;

	dbg_in(__func__, "%p", (void *)context);

	memset(&context->mib_copy, 0, sizeof(struct mib_copy));

	error = list_init(&context->mib_copy.list,
			  sizeof(struct mib_copy_entry));
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error mib_copy_shutdown(struct omci_context *context)
{
	dbg_in(__func__, "%p", (void *)context);

	list_delete(&context->mib_copy.list);
	if (context->mib_copy.timeout_id) {
		(void)timeout_event_remove(context,
					   context->mib_copy.timeout_id);
	}
	memset(&context->mib_copy, 0, sizeof(struct mib_copy));

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error mib_copy(struct omci_context *context)
{
	int i;
	struct mib_me_list_entry *me_entry;
	struct mib_copy_entry *mib_copy_entry = NULL;
	size_t attr_size;
	size_t attr_size_sum;
	size_t attr_off;
	unsigned int attr;
	enum omci_attr_prop attr_prop;
	bool entity_copy_created;
	struct list_entry *entry;
	uint8_t data[OMCI_ME_DATA_SIZE_MAX];
#if defined(OMCI_SWAP)
	enum omci_error error;
#endif

	/* remove old timeout event */
	if (context->mib_copy.timeout_id) {
		(void)timeout_event_remove(context,
					   context->mib_copy.timeout_id);
	}

	list_clear(&context->mib_copy.list);
	context->mib_copy.num = 0;
	context->mib_copy.timeout_id = 0;

	/* for each ME instance */
	for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
		for (me_entry = context->mib.me_class_array[i].me_list;
		     me_entry != NULL; me_entry = me_entry->next) {
			/* pass not uploadable MEs */
			/* pass PM MEs */
			if (me_entry->me.class->prop
			    & (OMCI_ME_PROP_NO_UPLOAD | OMCI_ME_PROP_PM))
				continue;

			attr_size_sum = 0;
			entity_copy_created = false;

			me_data_read(context, &me_entry->me, data,
				     me_entry->me.class->data_size,
				     OMCI_PM_INTERVAL_CURR);

			/* for each attribute */
			for (attr = 1; attr <= OMCI_ATTRIBUTES_NUM; attr++) {
				/* check if ME have this attribute */
				if (is_me_attr_exist(me_entry->me.class, attr)
				    == false)
					continue;

				/* get size and properties */
				attr_size = me_attr_size_get(me_entry->me.class,
							     attr);
				attr_prop = me_attr_prop_get(me_entry->me.class,
							     attr);
				attr_off = me_attr_offset_get(me_entry->me.class,
							      attr);

				/* pass not supported optional attributes */
				/* pass not uploaded attributes */
				/* pass table attributes */
				if (attr_prop &
					(OMCI_ATTR_PROP_NOT_SUPPORTED |
					OMCI_ATTR_PROP_NO_UPLOAD |
					OMCI_ATTR_PROP_TABLE))
					continue;

				/* pass not readable attributes */
				if (!(attr_prop & OMCI_ATTR_PROP_RD))
					continue;

				/* pass big attributes that doesn't fit in MSG
				   (to prevent looping) */
				if (attr_size_sum + attr_size
				    > MIB_UPLOAD_NEXT_RSP_VALUES_SIZE
				    && attr_size_sum == 0)
					continue;
				/* add new mib_copy_entry */
				if (attr_size_sum + attr_size
				    > MIB_UPLOAD_NEXT_RSP_VALUES_SIZE
				    || mib_copy_entry == NULL) {

					attr_size_sum = 0;

					if (mib_copy_entry != NULL)
						context->mib_copy.num++;

					entry = list_entry_alloc(&context->
								 mib_copy.list);
					if (!entry) {
						list_unlock(&context->
							    mib_copy.list);
						return OMCI_ERROR_MEMORY;
					}

					mib_copy_entry = list_entry_data(entry);

					memset(mib_copy_entry, 0,
					       sizeof(struct mib_copy_entry));

					list_entry_add_tail(&context->
							    mib_copy.list,
							    entry);

					mib_copy_entry->class_id =
						me_entry->me.class->class_id;
					mib_copy_entry->instance_id =
						me_entry->me.instance_id;

					entity_copy_created = true;
				}

				memcpy(mib_copy_entry->values + attr_size_sum,
						data + attr_off, attr_size);

#if defined(OMCI_SWAP)
				/* swap value if needed */
				if (!(attr_prop & OMCI_ATTR_PROP_NO_SWAP)) {
					error = data_swap(mib_copy_entry->
							  values +
							  attr_size_sum,
							  attr_size);
					if (error) {
						/* only display error */
						dbg_wrn("WARNING Can't "
							"swap attribute "
							"#%u data for "
							"%u@%u",
							attr,
							mib_copy_entry->
							class_id,
							mib_copy_entry->
							instance_id);
					}
				}
#endif

				/* update attr_mask */
				mib_copy_entry->attr_mask |=
					omci_attr2mask(attr);

				attr_size_sum += attr_size;
			}
			/* add Managed Entities with no attributes (to indicate
			   that it is presented in the MIB) */
			if (mib_copy_entry == NULL
			    && entity_copy_created == false) {

				entry = list_entry_alloc(&context->mib_copy.
							 list);
				if (!entry) {
					list_unlock(&context->mib_copy.list);
					return OMCI_ERROR_MEMORY;
				}

				mib_copy_entry = list_entry_data(entry);

				memset(mib_copy_entry, 0,
				       sizeof(struct mib_copy_entry));

				list_entry_add_tail(&context->mib_copy.list,
						    entry);

				mib_copy_entry->class_id =
					me_entry->me.class->class_id;
				mib_copy_entry->instance_id =
					me_entry->me.instance_id;
			}

			/* add mib_copy_entry to mib_copy */
			if (mib_copy_entry != NULL) {
				mib_copy_entry = NULL;
				context->mib_copy.num++;
			}
		}
	}

	return OMCI_SUCCESS;
}

/** qsort/bsearch MIB class array comparator */
static int mib_me_class_array_compare(const void *lhs, const void *rhs)
{
	const struct mib_me_class_array_entry *lhs_entry =
		(const struct mib_me_class_array_entry *)lhs;
	const struct mib_me_class_array_entry *rhs_entry =
		(const struct mib_me_class_array_entry *)rhs;

	if (lhs_entry->class_id < rhs_entry->class_id)
		return -1;
	else if (lhs_entry->class_id > rhs_entry->class_id)
		return 1;
	else
		return 0;
}

/** Find Class list entry for given Class Id

   \param[in]  mib         MIB pointer
   \param[in]  class_id    Class Id to find
   \param[out] class_entry Returns found entry pointer (or NULL)

   \return - \ref OMCI_ERROR_ME_NOT_SUPPORTED if ME class is not supported
           - \ref OMCI_SUCCESS otherwise
*/
static enum omci_error class_entry_find(struct mib *mib,
					uint16_t class_id,
					struct mib_me_class_array_entry
					**class_entry)
{
	void *result;
	struct mib_me_class_array_entry dummy;

	assert(mib && class_entry);

	dummy.class_id = class_id;

	result = bsearch(&dummy, mib->me_class_array,
			 ARRAY_SIZE(mib->me_class_array),
			 sizeof(mib->me_class_array[0]),
			 mib_me_class_array_compare);

	if (result) {
		if (class_entry)
			*class_entry =
				(struct mib_me_class_array_entry *)result;

		return OMCI_SUCCESS;
	}

	if (class_entry)
		*class_entry = NULL;

	return OMCI_ERROR_ME_NOT_SUPPORTED;
}

enum omci_error mib_me_find(struct omci_context *context,
			    uint16_t class_id,
			    uint16_t instance_id,
			    struct me **me)
{
	struct mib_me_list_entry *me_entry;
	struct mib_me_class_array_entry *class_entry;
	enum omci_error error;

	dbg_in(__func__, "%p, 0x%x, 0x%x, %p", (void *)context,
	       class_id, instance_id, me);

	assert(context);

	if (me)
		*me = NULL;

	error = class_entry_find(&context->mib, class_id, &class_entry);
	if (error)
		RETURN_IF_ERROR(OMCI_ERROR_ME_NOT_FOUND);

	assert(class_id == class_entry->class->class_id);

	for (me_entry = class_entry->me_list;
	     me_entry != NULL;
	     me_entry = me_entry->next) {
		if (me_entry->me.instance_id > instance_id) {
			break;
		} else if (me_entry->me.instance_id == instance_id) {
			if (me)
				*me = &me_entry->me;

			dbg_out_ret(__func__, OMCI_SUCCESS);
			return OMCI_SUCCESS;
		}
	}

	dbg_out_ret(__func__, OMCI_ERROR_ME_NOT_FOUND);
	return OMCI_ERROR_ME_NOT_FOUND;
}

enum omci_error mib_me_class_resolve(struct omci_context *context,
				     uint16_t class_id,
				     const struct me_class **me_class)
{
	enum omci_error error;
	struct mib_me_class_array_entry *class_entry;

	error = class_entry_find(&context->mib, class_id, &class_entry);
	RETURN_IF_ERROR(error);

	if (me_class)
		*me_class = class_entry->class;

	return OMCI_SUCCESS;
}

static void mib_me_add_to_class_entry(struct mib_me_class_array_entry
				      *class_entry,
				      struct mib_me_list_entry *me_entry)
{
	struct mib_me_list_entry *me_entry_iter;

	if (class_entry->me_list == NULL) {
		class_entry->me_list = me_entry;
	} else {
		if (class_entry->me_list->me.instance_id >
		    me_entry->me.instance_id) {
			me_entry->next = class_entry->me_list;
			class_entry->me_list = me_entry;
		} else {
			me_entry_iter = class_entry->me_list;

			while (me_entry_iter->next &&
			       me_entry_iter->next->me.instance_id <
			       me_entry->me.instance_id)
				me_entry_iter = me_entry_iter->next;

			me_entry->next = me_entry_iter->next;
			me_entry_iter->next = me_entry;
		}
	}
}

enum omci_error mib_me_create(struct omci_context *context,
			      const bool active,
			      const uint16_t class_id,
			      const uint16_t instance_id,
			      struct me **me,
			      void *init_data,
			      const uint16_t suppress_avc)
{
	const struct me_class *me_class = NULL;
	struct me *me_result = NULL;
	struct mib_me_class_array_entry *class_entry = NULL;
	struct mib_me_list_entry *me_entry = NULL;

	enum omci_error error;

	dbg_in(__func__, "%p, %u, %u, %p, %p, 0x%04x", (void *)context,
	       class_id, instance_id, (void *)me, (void *)init_data,
	       suppress_avc);

	assert(context);

	if (me != NULL)
		*me = NULL;

	/* check if ME instance doesn't exists */
	error = mib_me_find(context, class_id, instance_id, &me_result);

	if (error != OMCI_ERROR_ME_NOT_FOUND)
		RETURN_IF_ERROR(error);

	if (me_result != NULL) {
		dbg_err("ERROR(%d) ME with class id = "
			"%u and instance id = %u " "already exists",
			OMCI_ERROR_ME_EXISTS, class_id, instance_id);

		dbg_out_ret(__func__, OMCI_ERROR_ME_EXISTS);
		return OMCI_ERROR_ME_EXISTS;
	}

	/* resolve class by class_id */
	error = mib_me_class_resolve(context, class_id, &me_class);
	RETURN_IF_ERROR(error);

	assert(me_class->class_id == class_id);

	/* find class_entry for given class */
	error = class_entry_find(&context->mib, class_id, &class_entry);
	/* omit check, function always returns SUCCESS */
	/* RETURN_IF_ERROR(error); */

	/* if given class_entry doesn't exist, exit */
	if (error) {
		dbg_err("ERROR(%d) class id = %u is not "
			"presented at the ONU!", class_id, error);

		dbg_out_ret(__func__, OMCI_ERROR_ME_NOT_SUPPORTED);
		return OMCI_ERROR_ME_NOT_SUPPORTED;
	}

	/* allocate ME entry */
	me_entry = IFXOS_MemAlloc(sizeof(struct mib_me_list_entry));
	RETURN_IF_MALLOC_ERROR(me_entry);

	memset(me_entry, 0, sizeof(struct mib_me_list_entry));

	/* set class, instance */
	me_entry->me.class = me_class;
	me_entry->me.instance_id = instance_id;
	me_entry->me.active = active;

	/* allocate Alarms table if needed */
	if (me_class->prop & OMCI_ME_PROP_HAS_ALARMS) {
		error = alarm_bitmap_alloc(&me_entry->me);

		if (error) {
			dbg_err("ERROR(%d) Can't create alarm bitmap in %s",
				error, __func__);

			goto free_me_entry;
		}
	}

	/* allocate ARC context if needed */
	if (me_class->prop & OMCI_ME_PROP_HAS_ARC) {
		error = arc_context_alloc(&me_entry->me);

		if (error) {
			dbg_err("ERROR(%d) Can't create ARC context in %s",
				error, __func__);

			goto free_alarm_bitmap;
		}
	}

	/* allocate space for data */
	if (me_entry->me.class->data_size != 0) {
		me_entry->me.data =
			IFXOS_MemAlloc(me_entry->me.class->data_size);

		if (me_entry->me.data == NULL) {
			dbg_err("ERROR(%d) Memory allocation error for "
				"'me_entry->me.data' in %s",
				OMCI_ERROR_MEMORY, __func__);

			goto free_arc_context;
		}

		memset(me_entry->me.data, 0,
		       me_entry->me.class->data_size);
	}

#ifdef INCLUDE_PM
	error = pm_me_context_alloc(&me_entry->me);
	if (error) {
		dbg_err("ERROR(%d) can't allocate ME PM context", error);

		goto free_me_data;
	}
#endif

	/* init lock */
	error = me_lock_init(&me_entry->me);
	if (error) {
		dbg_err("ERROR(%d) ME lock init failed", error);

		goto free_pm_me_context;
	}

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	dbg_prn("Create \"%.25s\" (%u) with instance id = %u",
		me_entry->me.class->desc.name, class_id, instance_id);
#else
	dbg_prn("Create Managed Entity with class id = %u, instance id = %u",
		class_id, instance_id);
#endif

	me_entry->me.is_initialized = false;

	/* call init handler if any */
	if (me_entry->me.class->init != NULL) {
		if (me_entry->me.active) {
			error = me_entry->me.class->init(context,
							 &me_entry->me,
							 init_data,
							 suppress_avc);
		} else {
			omci_hook(context, "init", class_id, instance_id);
			dbg_wrn("ME class id=%u, instance id=%u skip "
				"init handler", class_id, instance_id);
			error = 0;
		}

		if (error) {
			dbg_err("ERROR(%d) ME %u@%u init handler error",
				error, class_id, instance_id);

			goto remove_lock;
		}
	}

	me_entry->me.is_initialized = true;

	/* assign to the MIB */
	mib_me_add_to_class_entry(class_entry, me_entry);

	if (me != NULL)
		*me = &me_entry->me;

	context_lock(context);
	context->mib.me_count++;
	context_unlock(context);

#ifdef INCLUDE_PM
	error = pm_me_add(context, &me_entry->me);
	if (error) {
		dbg_err("ERROR(%d) can't add ME to PM list", error);

		goto remove_lock;
	}
#endif

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;

remove_lock:
	if (me_entry->me.active) {
		if (me_entry->me.class->shutdown != NULL)
			(void)me_entry->me.class->shutdown(context,
							   &me_entry->me);
	} else {
		omci_hook(context, "shutdown", class_id, instance_id);
		dbg_wrn("ME class id=%u, instance id=%u skip "
			"shutdown handler", class_id,
			instance_id);
	}

	(void)me_lock_delete(&me_entry->me);

free_pm_me_context:
#ifdef INCLUDE_PM
	(void)pm_me_context_free(&me_entry->me);
#endif

free_me_data:
	IFXOS_MemFree(me_entry->me.data);

free_arc_context:
	(void)arc_context_free(&me_entry->me);

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	dbg_prn("Removed \"%.25s\" (%u) with "
		"instance id = %u",
		me_entry->me.class->desc.name,
		class_id, instance_id);
#else
	dbg_prn("Removed ME with class id = %u, "
		"instance id = %u", class_id,
		instance_id);
#endif

free_alarm_bitmap:
	(void)alarm_bitmap_free(&me_entry->me);

free_me_entry:
	IFXOS_MemFree(me_entry);

	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error mib_me_delete(struct omci_context *context,
			      struct me *me)
{
	struct mib_me_list_entry *me_entry;
	struct mib_me_list_entry *me_entry_prev;
	uint16_t class_id;
	uint16_t instance_id;
	enum omci_error error;
	struct mib_me_class_array_entry *class_entry;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	assert(context && me);

	class_id = me->class->class_id;
	instance_id = me->instance_id;

	error = class_entry_find(&context->mib, class_id, &class_entry);
	if (error)
		RETURN_IF_ERROR(OMCI_ERROR_ME_NOT_FOUND);

	me_entry_prev = NULL;
	for (me_entry = class_entry->me_list;
	     me_entry != NULL;
	     me_entry_prev = me_entry, me_entry = me_entry->next) {

		if (me_entry->me.instance_id != instance_id)
			continue;

#ifdef INCLUDE_PM
		(void)pm_me_remove(context, &me_entry->me);
#endif

		if (me_entry->me.class->shutdown != NULL) {
			if (me_entry->me.active)
				error = me_entry->me.class->shutdown(context,
								     &me_entry->
								     me);
			else {
				omci_hook(context, "shutdown",
					  me->class->class_id,
					  me->instance_id);
				dbg_wrn("ME class id=%u, instance "
					"id=%u skip shutdown handler",
					class_id, instance_id);
				error = 0;
			}
			if (error) {
				dbg_err("ERROR(%d) Managed Entity "
					"class id = %u "
					"instance id = %u "
					"termination error",
					error,
					me_entry->me.class->class_id,
					me_entry->me.instance_id);
			}
		}

		(void)alarm_bitmap_free(&me_entry->me);
		(void)arc_context_free(&me_entry->me);
#ifdef INCLUDE_PM
		(void)pm_me_context_free(&me_entry->me);
#endif

		if (me_entry_prev == NULL)
			class_entry->me_list = me_entry->next;
		else
			me_entry_prev->next = me_entry->next;

#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
		dbg_prn("Removed \"%.25s\" (%u) with "
			"instance id = %u",
			me_entry->me.class->desc.name,
			class_id, instance_id);
#else
		dbg_prn("Removed ME with class id = %u, "
			"instance id = %u", class_id,
			instance_id);
#endif

		(void)me_lock_delete(&me_entry->me);

		if (me_entry->me.data)
			IFXOS_MemFree(me_entry->me.data);

		IFXOS_MemFree(me_entry);

		context_lock(context);
		context->mib.me_count--;
		context_unlock(context);

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	dbg_out_ret(__func__, OMCI_ERROR_ME_NOT_FOUND);
	return OMCI_ERROR_ME_NOT_FOUND;
}

enum omci_error mib_create(struct omci_context *context)
{
	uint8_t i;
	unsigned int attr;
	enum omci_error error;
	struct me_class *me_class;
	size_t attr_sum;

	dbg_in(__func__, "%p", (void *)context);

	assert(context);

	memset(&context->mib, 0, sizeof(struct mib));

	dbg_prn("Classes correctness check...");

	if (OMCI_ME_CLASS_NUM != omci_me_def_class_array_size()) {
		dbg_err("Please correct the value of "
			"OMCI_ME_CLASS_NUM definition = %u; it should be %u",
			OMCI_ME_CLASS_NUM, omci_me_def_class_array_size());
		return OMCI_ERROR;
	}

	/* fill me_def_class_array array */
	for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
		me_class = me_def_class_array[i];

		if (!me_class) {
			dbg_err("Class pointer is null in the "
				"me_def_class_array array at index %u!", i);

			return OMCI_ERROR;
		}

		context->mib.me_class_array[i].class_id = me_class->class_id;
		context->mib.me_class_array[i].class = me_class;

		/* count Invalid, Unsupported optional, SBC attributes mask */
		me_class->inv_attr_mask = 0;
		me_class->opt_attr_mask = 0;
		me_class->sbc_attr_mask = 0;
		me_class->avc_attr_mask = 0;
		me_class->wr_attr_mask = 0;
		attr_sum = 0;
		for (attr = 0; attr < 16; attr++) {
			if (me_class->attrs[attr].prop == OMCI_ATTR_PROP_NONE)
				me_class->inv_attr_mask |=
				    omci_attr2mask(attr + 1);

			if (me_class->attrs[attr].prop
			    & OMCI_ATTR_PROP_NOT_SUPPORTED)
				me_class->opt_attr_mask |=
				    omci_attr2mask(attr + 1);

			if (me_class->attrs[attr].prop & OMCI_ATTR_PROP_SBC)
				me_class->sbc_attr_mask |=
				    omci_attr2mask(attr + 1);

			if (me_class->attrs[attr].prop & OMCI_ATTR_PROP_AVC)
				me_class->avc_attr_mask |=
				    omci_attr2mask(attr + 1);

			if (me_class->attrs[attr].prop & OMCI_ATTR_PROP_WR)
				me_class->wr_attr_mask |=
				    omci_attr2mask(attr + 1);

			if (me_class->attrs[attr].get)
				me_class->vol_attr_mask |=
				    omci_attr2mask(attr + 1);

			if (me_class->data_size &&
			    (me_class->attrs[attr].offset
			    + me_class->attrs[attr].size >
			    me_class->data_size ||
			    attr_sum + me_class->attrs[attr].size >
			    me_class->data_size)) {

				dbg_err("Please correct the offset/size of "
					"attribute #%u (class id = %u); data "
					"size is %u",
					attr + 1, me_class->class_id,
					me_class->data_size);

				return OMCI_ERROR;
			}

			attr_sum += me_class->attrs[attr].size;
		}

		if (attr_sum != me_class->data_size) {
			dbg_err("Attributes size sum (%u) is not equal to the "
				"data size (%u) for class id = %u",
				attr_sum,
				me_class->data_size, me_class->class_id);

			return OMCI_ERROR;
		}

		if (OMCI_ME_DATA_SIZE_MAX < me_class->data_size) {
			dbg_err("Please correct the value of "
				"OMCI_ME_DATA_SIZE_MAX definition; it should "
				"be %u (class id = %u)",
				me_class->data_size, me_class->class_id);

			return OMCI_ERROR;
		}

		if (!me_class->update) {
#  ifdef INCLUDE_OMCI_SELF_DESCRIPTION
			dbg_err("Update handler is not specified for "
				"\"%.25s\" (%u)",
				me_class->desc.name, me_class->class_id);
#  else
			dbg_err("Update handler is not specified for "
				"class id = %u", me_class->class_id);
#  endif

			return OMCI_ERROR;
		}
#ifdef INCLUDE_PM
		if (me_class->prop & OMCI_ME_PROP_PM) {
			if (!me_class->counters_get) {
#  ifdef INCLUDE_OMCI_SELF_DESCRIPTION
				dbg_wrn("WARNING "
					"Counters get handler is not specified "
					"for \"%.25s\" (%u)",
					me_class->desc.name, me_class->class_id);
#  else
				dbg_wrn("WARNING "
					"Counters get handler is not specified "
					"for class id = %u",
					me_class->class_id);
#  endif
			}

			if (!me_class->thr_set) {
#  ifdef INCLUDE_OMCI_SELF_DESCRIPTION
				dbg_wrn("WARNING "
					"Thresholds set handler is not "
					"specified for \"%.25s\" (%u)",
					me_class->desc.name,
					me_class->class_id);
#  else
				dbg_wrn("WARNING "
					"Thresholds set handler is not "
					"specified for class id = %u",
					me_class->class_id);
#  endif
			}

			if ((me_class->prop & OMCI_ME_PROP_HAS_ALARMS) == 0) {
#  ifdef INCLUDE_OMCI_SELF_DESCRIPTION
				dbg_wrn("WARNING "
					"PM Managed Entity without TCA support "
					"for \"%.25s\" (%u)",
					me_class->desc.name,
					me_class->class_id);
#  else
				dbg_wrn("WARNING "
					"PM Managed Entity without TCA support "
					"for class id = %u",
					me_class->class_id);
#  endif
			}
		}
#endif
	}

	/* sort mib.me_class_array[i] by class_id */
	qsort(context->mib.me_class_array,
	      ARRAY_SIZE(context->mib.me_class_array),
	      sizeof(context->mib.me_class_array[0]),
	      mib_me_class_array_compare);

	/* init MIB lock */
	error = rw_lock_init(&context->mib.lock);
	if (error) {
		dbg_err("ERROR(%d) Lock init failed", error);

		dbg_out_ret(__func__, OMCI_ERROR);
		return OMCI_ERROR;
	}

	/* create required MEs */
	error = mib_reset(context, true);
	if (error) {
		(void)rw_lock_delete(&context->mib.lock);
		RETURN_IF_ERROR(error);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error mib_reset(struct omci_context *context, bool force)
{
	enum omci_error error = OMCI_SUCCESS;
#ifndef OMCI_DEBUG_DISABLE
	struct dbg_module_level dbg_mods[OMCI_DBG_MODULE_NUM];
	unsigned int module;
	enum omci_dbg level;
#endif
	uint8_t seq=0;

	dbg_in(__func__, "%p", (void *)context);

	dbg_msg("MIB reset occurred");

	context->mib_reset_in_progress = true;

	retransmit_flush(context);

#ifndef OMCI_DEBUG_DISABLE
	error = omci_dbg_module_level_get(OMCI_DBG_MODULE_MIB_RESET, &level);
	if (error)
		level = OMCI_DBG_OFF;

	if (level == OMCI_DBG_OFF) {
		memcpy(dbg_mods, dbg_modules, sizeof(dbg_mods));

		for (module = (unsigned int)OMCI_DBG_MODULE_MIN;
		     module <= (unsigned int)OMCI_DBG_MODULE_MAX;
		     module++) {

			(void)omci_dbg_module_level_set(module, OMCI_DBG_ERR);
		}
	}
#endif

	mib_lock_write(context);
	error = mib_seq_num_get(context, &seq);
	if (force || seq != 0 || context->mib_copy.num == 0) {
		error = mib_destroy(context);

		if (error != OMCI_SUCCESS) {
			mib_unlock(context);
			goto exit;
		}

		mib_seq_num_clear(context);

		mib_unlock(context);

		error = context->mib_on_reset(context);

		list_lock(&context->mib_copy.list);
		mib_copy(context);
		list_unlock(&context->mib_copy.list);

	} else
		mib_unlock(context);

	context->mib_reset_in_progress = false;

exit:
#ifndef OMCI_DEBUG_DISABLE
	if (level == OMCI_DBG_OFF) {
		for (module = (unsigned int)OMCI_DBG_MODULE_MIN;
		     module <= (unsigned int)OMCI_DBG_MODULE_MAX;
		     module++) {

			(void)omci_dbg_module_level_set(module,
							dbg_mods[module].level);
		}
	}
#endif
	if (error)
		dbg_err("ERROR(%d) MIB reset failed", error);
	else
		dbg_prn("MIB reset complete");

	dbg_out_ret(__func__, error);
	return error;
}

enum omci_error mib_destroy(struct omci_context *context)
{
	int i;
	enum omci_error error;
	struct mib_me_class_array_entry *class_entry;

	dbg_in(__func__, "%p", (void *)context);

	assert(context);

	for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
		error = class_entry_find(&context->mib,
					 me_def_class_array[i]->class_id,
					 &class_entry);
		RETURN_IF_ERROR(error);

		while (class_entry->me_list != NULL)
			(void)mib_me_delete(context, &class_entry->me_list->me);

		class_entry->me_list = NULL;
	}

	(void)omci_api_mapper_reset(context->api);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error mib_seq_num_inc(struct omci_context *context)
{
	struct me *me;
	struct omci_me_onu_data *me_onu_data;
	enum omci_error error;

	dbg_in(__func__, "%p", (void *)context);

	error = mib_me_find(context, OMCI_ME_ONU_DATA, 0, &me);
	RETURN_IF_ERROR(error);

	me_lock(context, me);

	me_onu_data = me->data;

	if (me_onu_data->mib_data_sync == 255)
		me_onu_data->mib_data_sync = 1;
	else
		me_onu_data->mib_data_sync++;

	dbg_prn("Incremented MIB sequence number (%u)",
		me_onu_data->mib_data_sync);

	me_unlock(context, me);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error mib_seq_num_clear(struct omci_context *context)
{
	struct me *me;
	struct omci_me_onu_data *me_onu_data;
	enum omci_error error;

	dbg_in(__func__, "%p", (void *)context);

	error = mib_me_find(context, OMCI_ME_ONU_DATA, 0, &me);
	RETURN_IF_ERROR(error);

	me_lock(context, me);

	me_onu_data = me->data;

	me_onu_data->mib_data_sync = 0;

	dbg_err("Clear MIB sequence number (%u)",
		me_onu_data->mib_data_sync);

	me_unlock(context, me);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error mib_seq_num_get(struct omci_context *context, uint8_t *seq)
{
	struct me *me;
	struct omci_me_onu_data *me_onu_data;
	enum omci_error error;

	dbg_in(__func__, "%p", (void *)context);

	error = mib_me_find(context, OMCI_ME_ONU_DATA, 0, &me);
	RETURN_IF_ERROR(error);

	me_lock(context, me);

	me_onu_data = me->data;

	*seq = me_onu_data->mib_data_sync;

	dbg_prn("Get MIB sequence number (%u)",
		me_onu_data->mib_data_sync);

	me_unlock(context, me);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error mib_walk(struct omci_context *context,
			 mib_walk_handler *handler,
			 void *shared_data)
{
	int i;
	struct mib_me_list_entry *me_entry;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)handler,
	       (void *)shared_data);

	for (i = 0; i < OMCI_ME_CLASS_NUM; i++) {
		for (me_entry = context->mib.me_class_array[i].me_list;
		     me_entry != NULL; me_entry = me_entry->next) {

			me_lock(context, &me_entry->me);
			error = handler(context, &me_entry->me, shared_data);
			me_unlock(context, &me_entry->me);

			RETURN_IF_ERROR(error);
		}
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error mib_walk_by_class(struct omci_context *context,
				  uint16_t class_id,
				  mib_walk_handler *handler,
				  void *shared_data)
{
	struct mib_me_list_entry *me_entry;
	struct mib_me_class_array_entry *class_entry;
	enum omci_error error;

	dbg_in(__func__, "%p, %u, %p, %p", (void *)context, class_id,
	       (void *)handler, (void *)shared_data);

	error = class_entry_find(&context->mib,
				 class_id,
				 &class_entry);
	RETURN_IF_ERROR(error);

	for (me_entry = class_entry->me_list;
	     me_entry != NULL;
	     me_entry = me_entry->next) {

		me_lock(context, &me_entry->me);
		error = handler(context, &me_entry->me,
				shared_data);
		me_unlock(context, &me_entry->me);

		RETURN_IF_ERROR(error);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

struct mib_me_find_where_shared {
	struct me **found_me;
	unsigned int attr;
	void *data;
	unsigned int data_size;
	size_t num;
	size_t num_max;
};

static enum omci_error mib_me_find_where_walker(struct omci_context *context,
						struct me *me,
						void *shared_data)
{
	enum omci_error error;
	struct mib_me_find_where_shared *shared = shared_data;
	uint8_t data[OMCI_ME_DATA_SIZE_MAX];

	error = me_attr_read(context, me, shared->attr, &data,
			     shared->data_size);
	RETURN_IF_ERROR(error);

	if (memcmp(data, shared->data, shared->data_size) == 0) {
		if (shared->num >= shared->num_max)
			shared->num++;
		else
			shared->found_me[shared->num++] = me;
	}

	return OMCI_SUCCESS;
}

enum omci_error mib_me_find_where(struct omci_context *context,
				  uint16_t class_id,
				  unsigned int attr,
				  void *data,
				  size_t data_size,
				  struct me **found_me,
				  size_t found_me_size,
				  size_t *found_me_num)
{
	enum omci_error error;
	struct mib_me_find_where_shared shared;

	shared.found_me = found_me;
	shared.attr = attr;
	shared.data = data;
	shared.data_size = data_size;
	shared.num = 0;
	shared.num_max = found_me_size / sizeof(struct me*);

	memset(found_me, 0, found_me_size);

	error = mib_walk_by_class(context, class_id,
				  mib_me_find_where_walker, &shared);
	RETURN_IF_ERROR(error);

	if (found_me_num)
		*found_me_num = shared.num;

	if (shared.num)
		return OMCI_SUCCESS;

	return OMCI_ERROR_ME_NOT_FOUND;
}

bool mib_is_locked(struct omci_context *context)
{
	bool locked;
	enum omci_error error;

	error = rw_lock_is_locked(&context->mib.lock, &locked);
	if (error != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't lock MIB for lock check (%p)",
			OMCI_ERROR_LOCK,
			(void *)&context->mib.lock);
		abort();
	}

	return locked;
}

/** @} */
