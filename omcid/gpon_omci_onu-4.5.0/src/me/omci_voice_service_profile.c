/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_voice_service_profile.c
*/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "voip/omci_api_voip.h"
#include "me/omci_pptp_pots_uni.h"
#include "me/omci_voip_voice_ctp.h"
#include "me/omci_voip_media_profile.h"
#include "me/omci_voice_service_profile.h"

#ifdef INCLUDE_OMCI_ONU_VOIP

/** \addtogroup OMCI_ME_VOICE_SERVICE_PROFILE
   @{
*/

/** Structure that implements Tone Pattern Table */
struct tone_pattern_table_list_entry {
	/** Table entry */
	struct omci_tone_pattern_table table_entry;
	/** Next entry */
	struct tone_pattern_table_list_entry *next;
	/** Previous entry */
	struct tone_pattern_table_list_entry *prev;
};

/** Structure that implements Tone Event Table */
struct tone_event_table_list_entry {
	/** Table entry */
	struct omci_tone_event_table table_entry;
	/** Next entry */
	struct tone_event_table_list_entry *next;
	/** Previous entry */
	struct tone_event_table_list_entry *prev;
};

/** Structure that implements Ringing Pattern Table */
struct ringing_pattern_table_list_entry {
	/** Table entry */
	struct omci_ringing_pattern_table table_entry;
	/** Next entry */
	struct ringing_pattern_table_list_entry *next;
	/** Previous entry */
	struct ringing_pattern_table_list_entry *prev;
};

/** Structure that implements Ringing Event Table */
struct ringing_event_table_list_entry {
	/** Table entry */
	struct omci_ringing_event_table table_entry;
	/** Next entry */
	struct ringing_event_table_list_entry *next;
	/** Previous entry */
	struct ringing_event_table_list_entry *prev;
};

/** Internal data */
struct internal_data {
	/** Tone Pattern Table (list head) */
	struct tone_pattern_table_list_entry tone_pattern_list_head;
	/** Number of entries in the Tone Pattern Table */
	size_t tone_pattern_entries_num;

	/** Tone Event Table (list head) */
	struct tone_event_table_list_entry tone_event_list_head;
	/** Number of entries in the Tone Event Table */
	size_t tone_event_entries_num;

	/** Ringing Pattern Table (list head) */
	struct ringing_pattern_table_list_entry ringing_pattern_list_head;
	/** Number of entries in the Ringing Pattern Table */
	size_t ringing_pattern_entries_num;

	/** Ringing Event Table (list head) */
	struct ringing_event_table_list_entry ringing_event_list_head;
	/** Number of entries in the Ringing Event Table */
	size_t ringing_event_entries_num;
};


/** Add/Remove Tone Pattern Table Entry

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] entry   Table entry
*/
static inline enum omci_error tone_pattern_table_entry_set(
				struct omci_context *context,
				struct me *me,
				struct omci_tone_pattern_table *entry)
{
	struct internal_data *me_internal_data;
	struct tone_pattern_table_list_entry *list_entry;
	struct tone_pattern_table_list_entry *next_list_entry;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)entry);

	me_internal_data = (struct internal_data *) me->internal_data;

	entry->frequency1 = ntoh16(entry->frequency1);
	entry->frequency2 = ntoh16(entry->frequency2);
	entry->frequency3 = ntoh16(entry->frequency3);
	entry->frequency4 = ntoh16(entry->frequency4);
	entry->modulation_frequency = ntoh16(entry->modulation_frequency);
	entry->duration = ntoh16(entry->duration);

	if (entry->index == 0) {
		/* clear table */
		me_dbg_msg(me, "Table clear");

		DLIST_FOR_EACH_SAFE(list_entry,
				    next_list_entry,
				    &me_internal_data->tone_pattern_list_head) {
			/* remove entry */
			DLIST_REMOVE(list_entry);

			--me_internal_data->tone_pattern_entries_num;

			IFXOS_MemFree(list_entry);
			list_entry = NULL;

			me_dbg_prn(me, "Removed table entry "
				   "(entries num = %lu)",
				   me_internal_data->tone_pattern_entries_num);
		}
	} else {
		/* add entry */
		me_dbg_msg(me, "Entry add");

		/* insert new entry to the head */
		list_entry = IFXOS_MemAlloc(sizeof(*list_entry));
		RETURN_IF_MALLOC_ERROR(list_entry);

		++me_internal_data->tone_pattern_entries_num;

		memcpy(&list_entry->table_entry,
		       entry, sizeof(list_entry->table_entry));

		DLIST_ADD_TAIL(list_entry,
			       &me_internal_data->tone_pattern_list_head);

		me_dbg_prn(me, "Added table entry (entries num = %lu)",
			   me_internal_data->tone_pattern_entries_num);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Add/Remove Tone Event Table Entry

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] entry   Table entry
*/
static inline enum omci_error tone_event_table_entry_set(
				struct omci_context *context,
				struct me *me,
				struct omci_tone_event_table *entry)
{
	struct internal_data *me_internal_data;
	struct tone_event_table_list_entry *list_entry;
	struct tone_event_table_list_entry *next_list_entry;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)entry);

	me_internal_data = (struct internal_data *) me->internal_data;

	entry->tone_file = ntoh16(entry->tone_file);
	entry->reserved = ntoh16(entry->reserved);

	if (entry->event == 0) {
		/* clear table */
		me_dbg_msg(me, "Table clear");

		DLIST_FOR_EACH_SAFE(list_entry,
				    next_list_entry,
				    &me_internal_data->tone_event_list_head) {
			/* remove entry */
			DLIST_REMOVE(list_entry);

			--me_internal_data->tone_event_entries_num;

			IFXOS_MemFree(list_entry);
			list_entry = NULL;

			me_dbg_prn(me, "Removed table entry "
				   "(entries num = %lu)",
				   me_internal_data->tone_event_entries_num);
		}
	} else {
		/* add entry */
		me_dbg_msg(me, "Entry add");

		/* insert new entry to the head */
		list_entry = IFXOS_MemAlloc(sizeof(*list_entry));
		RETURN_IF_MALLOC_ERROR(list_entry);

		++me_internal_data->tone_event_entries_num;

		memcpy(&list_entry->table_entry,
		       entry, sizeof(list_entry->table_entry));

		DLIST_ADD_TAIL(list_entry,
			       &me_internal_data->tone_event_list_head);

		me_dbg_prn(me, "Added table entry (entries num = %lu)",
			   me_internal_data->tone_event_entries_num);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Add/Remove Ringing Pattern Table Entry

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] entry   Table entry
*/
static inline enum omci_error ringing_pattern_table_entry_set(
				struct omci_context *context,
				struct me *me,
				struct omci_ringing_pattern_table *entry)
{
	struct internal_data *me_internal_data;
	struct ringing_pattern_table_list_entry *list_entry;
	struct ringing_pattern_table_list_entry *next_list_entry;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)entry);

	me_internal_data = (struct internal_data *) me->internal_data;

	entry->duration = ntoh16(entry->duration);

	if (entry->index == 0) {
		/* clear table */
		me_dbg_msg(me, "Table clear");

		DLIST_FOR_EACH_SAFE(list_entry,
			next_list_entry,
			&me_internal_data->ringing_pattern_list_head) {
			/* remove entry */
			DLIST_REMOVE(list_entry);

			--me_internal_data->ringing_pattern_entries_num;

			IFXOS_MemFree(list_entry);
			list_entry = NULL;

			me_dbg_prn(me, "Removed table entry "
				 "(entries num = %lu)",
				 me_internal_data->ringing_pattern_entries_num);
		}
	} else {
		/* add entry */
		me_dbg_msg(me, "Entry add");

		/* insert new entry to the head */
		list_entry = IFXOS_MemAlloc(sizeof(*list_entry));
		RETURN_IF_MALLOC_ERROR(list_entry);

		++me_internal_data->ringing_pattern_entries_num;

		memcpy(&list_entry->table_entry,
		       entry, sizeof(list_entry->table_entry));

		DLIST_ADD_TAIL(list_entry,
			       &me_internal_data->ringing_pattern_list_head);

		me_dbg_prn(me, "Added table entry (entries num = %lu)",
			   me_internal_data->ringing_pattern_entries_num);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Add/Remove Ringing Event Table Entry

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
   \param[in] entry   Table entry
*/
static inline enum omci_error ringing_event_table_entry_set(
				struct omci_context *context,
				struct me *me,
				struct omci_ringing_event_table *entry)
{
	struct internal_data *me_internal_data;
	struct ringing_event_table_list_entry *list_entry;
	struct ringing_event_table_list_entry *next_list_entry;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)entry);

	me_internal_data = (struct internal_data *) me->internal_data;

	entry->ringing_file = ntoh16(entry->ringing_file);
	entry->ringing_text = ntoh16(entry->ringing_text);

	if (entry->event == 0) {
		/* clear table */
		me_dbg_msg(me, "Table clear");

		DLIST_FOR_EACH_SAFE(list_entry,
				  next_list_entry,
				  &me_internal_data->ringing_event_list_head) {
			/* remove entry */
			DLIST_REMOVE(list_entry);

			--me_internal_data->ringing_event_entries_num;

			IFXOS_MemFree(list_entry);
			list_entry = NULL;

			me_dbg_prn(me, "Removed table entry "
				   "(entries num = %lu)",
				   me_internal_data->ringing_event_entries_num);
		}
	} else {
		/* add entry */
		me_dbg_msg(me, "Entry add");

		/* insert new entry to the head */
		list_entry = IFXOS_MemAlloc(sizeof(*list_entry));
		RETURN_IF_MALLOC_ERROR(list_entry);

		++me_internal_data->ringing_event_entries_num;

		memcpy(&list_entry->table_entry,
		       entry, sizeof(list_entry->table_entry));

		DLIST_ADD_TAIL(list_entry,
			       &me_internal_data->ringing_event_list_head);

		me_dbg_prn(me, "Added table entry (entries num = %lu)",
			   me_internal_data->ringing_event_entries_num);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	enum omci_error error;
	struct omci_me_voice_service_profile *upd_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_voice_service_profile *)data;

	if (attr_mask &
	    omci_attr2mask(omci_me_voice_service_profile_tone_pattern_table)) {

		error = tone_pattern_table_entry_set(
				context, me, &upd_data->tone_pattern_table);
		RETURN_IF_ERROR(error);
	}

	if (attr_mask &
	       omci_attr2mask(omci_me_voice_service_profile_tone_event_table)) {

		error = tone_event_table_entry_set(
				context, me, &upd_data->tone_event_table);
		RETURN_IF_ERROR(error);
	}

	if (attr_mask &
	    omci_attr2mask(omci_me_voice_service_profile_ringing_pattern_table)) {
		error = ringing_pattern_table_entry_set(
				context, me, &upd_data->ringing_pattern_table);
		RETURN_IF_ERROR(error);
	}

	if (attr_mask &
	    omci_attr2mask(omci_me_voice_service_profile_ringing_event_table)) {
		error = ringing_event_table_entry_set(
				context, me, &upd_data->ringing_event_table);
		RETURN_IF_ERROR(error);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error tone_pattern_tbl_copy(struct omci_context *context,
					     struct me *me,
					     struct tbl_copy_entry *tbl_copy)
{
	struct internal_data *me_internal_data;
	struct tone_pattern_table_list_entry *list_entry;
	struct omci_tone_pattern_table *tbl_entry;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, 0x%p", (void *)context, (void *)me,
	       (void *)tbl_copy);

	me_internal_data = (struct internal_data *) me->internal_data;

	tbl_copy->data_size =
		sizeof(struct omci_tone_pattern_table)
			* me_internal_data->tone_pattern_entries_num;
	if (tbl_copy->data_size) {
		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);
	
		tbl_entry = (struct omci_tone_pattern_table *)tbl_copy->data;
		DLIST_FOR_EACH(list_entry,
			       &me_internal_data->tone_pattern_list_head) {

			memcpy(tbl_entry, &list_entry->table_entry,
			       sizeof(*tbl_entry));

			tbl_entry->frequency1 =
				ntoh16(tbl_entry->frequency1);
			tbl_entry->frequency2 =
				ntoh16(tbl_entry->frequency2);
			tbl_entry->frequency3 =
				ntoh16(tbl_entry->frequency3);
			tbl_entry->frequency4 =
				ntoh16(tbl_entry->frequency4);
			tbl_entry->modulation_frequency =
				ntoh16(tbl_entry->modulation_frequency);
			tbl_entry->duration =
				ntoh16(tbl_entry->duration);

			++tbl_entry;
		}
	}

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error tone_event_tbl_copy(struct omci_context *context,
					   struct me *me,
					   struct tbl_copy_entry *tbl_copy)
{
	struct internal_data *me_internal_data;
	struct tone_event_table_list_entry *list_entry;
	struct omci_tone_event_table *tbl_entry;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, 0x%p", (void *)context, (void *)me,
	       (void *)tbl_copy);

	me_internal_data = (struct internal_data *) me->internal_data;

	tbl_copy->data_size =
		sizeof(struct omci_tone_event_table)
			* me_internal_data->tone_event_entries_num;
	if (tbl_copy->data_size) {
		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);
	
		tbl_entry = (struct omci_tone_event_table *)tbl_copy->data;
		DLIST_FOR_EACH(list_entry,
			       &me_internal_data->tone_event_list_head) {

			memcpy(tbl_entry, &list_entry->table_entry,
			       sizeof(*tbl_entry));

			tbl_entry->tone_file =
				ntoh16(tbl_entry->tone_file);
			tbl_entry->reserved =
				ntoh16(tbl_entry->reserved);

			++tbl_entry;
		}
	}

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error ringing_pattern_tbl_copy(struct omci_context *context,
						struct me *me,
						struct tbl_copy_entry *tbl_copy)
{
	struct internal_data *me_internal_data;
	struct ringing_pattern_table_list_entry *list_entry;
	struct omci_ringing_pattern_table *tbl_entry;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, 0x%p", (void *)context, (void *)me,
	       (void *)tbl_copy);

	me_internal_data = (struct internal_data *) me->internal_data;

	tbl_copy->data_size =
		sizeof(struct omci_ringing_pattern_table)
			* me_internal_data->ringing_pattern_entries_num;
	if (tbl_copy->data_size) {
		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);
	
		tbl_entry = (struct omci_ringing_pattern_table *)tbl_copy->data;
		DLIST_FOR_EACH(list_entry,
			       &me_internal_data->ringing_pattern_list_head) {

			memcpy(tbl_entry, &list_entry->table_entry,
			       sizeof(*tbl_entry));

			tbl_entry->duration =
				ntoh16(tbl_entry->duration);

			++tbl_entry;
		}
	}

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error ringing_event_tbl_copy(struct omci_context *context,
					      struct me *me,
					      struct tbl_copy_entry *tbl_copy)
{
	struct internal_data *me_internal_data;
	struct ringing_event_table_list_entry *list_entry;
	struct omci_ringing_event_table *tbl_entry;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, 0x%p", (void *)context, (void *)me,
	       (void *)tbl_copy);

	me_internal_data = (struct internal_data *) me->internal_data;

	tbl_copy->data_size =
		sizeof(struct omci_ringing_event_table)
			* me_internal_data->ringing_event_entries_num;
	if (tbl_copy->data_size) {
		tbl_copy->data = IFXOS_MemAlloc(tbl_copy->data_size);
		RETURN_IF_MALLOC_ERROR(tbl_copy->data);
	
		tbl_entry = (struct omci_ringing_event_table *)tbl_copy->data;
		DLIST_FOR_EACH(list_entry,
			       &me_internal_data->ringing_event_list_head) {

			memcpy(tbl_entry, &list_entry->table_entry,
			       sizeof(*tbl_entry));

			tbl_entry->ringing_file =
				ntoh16(tbl_entry->ringing_file);
			tbl_entry->ringing_text =
				ntoh16(tbl_entry->ringing_text);

			++tbl_entry;
		}
	}

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error me_tbl_copy(struct omci_context *context,
				   struct me *me,
				   unsigned int attr,
				   struct tbl_copy_entry *tbl_copy)
{
	struct internal_data *me_internal_data;
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %u, 0x%p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	me_internal_data = (struct internal_data *) me->internal_data;

	switch (attr) {
	case omci_me_voice_service_profile_tone_pattern_table:
		error = tone_pattern_tbl_copy(context, me, tbl_copy);
		break;
	case omci_me_voice_service_profile_tone_event_table:
		error = tone_event_tbl_copy(context, me, tbl_copy);
		break;
	case omci_me_voice_service_profile_ringing_pattern_table:
		error = ringing_pattern_tbl_copy(context, me, tbl_copy);
		break;
	case omci_me_voice_service_profile_ringing_event_table:
		error = ringing_event_tbl_copy(context, me, tbl_copy);
		break;
	default:
		error = OMCI_ERROR_INVALID_ME_ATTR;
		break;
	}

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	struct internal_data *me_internal_data;
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	me->internal_data = IFXOS_MemAlloc(sizeof(*me_internal_data));
	RETURN_IF_MALLOC_ERROR(me->internal_data);

	me_internal_data = (struct internal_data *) me->internal_data;

	DLIST_HEAD_INIT(&me_internal_data->tone_pattern_list_head);
	me_internal_data->tone_pattern_entries_num = 0;

	DLIST_HEAD_INIT(&me_internal_data->tone_event_list_head);
	me_internal_data->tone_event_entries_num = 0;

	DLIST_HEAD_INIT(&me_internal_data->ringing_pattern_list_head);
	me_internal_data->ringing_pattern_entries_num = 0;

	DLIST_HEAD_INIT(&me_internal_data->ringing_event_list_head);
	me_internal_data->ringing_event_entries_num = 0;

	RETURN_IF_PTR_NULL(init_data);

	error = me_data_write(context, me, init_data, me->class->data_size,
			      me->class->sbc_attr_mask, suppress_avc);

	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	struct internal_data *me_internal_data;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	me_internal_data = (struct internal_data *) me->internal_data;

	{
		struct tone_pattern_table_list_entry *list_entry;
		struct tone_pattern_table_list_entry *next_list_entry;
	
		/* clear tone pattern table */
		DLIST_FOR_EACH_SAFE(list_entry,
				    next_list_entry,
				    &me_internal_data->tone_pattern_list_head) {
			/* remove entry */
			DLIST_REMOVE(list_entry);
	
			--me_internal_data->tone_pattern_entries_num;
	
			IFXOS_MemFree(list_entry);
			list_entry = NULL;
	
			me_dbg_prn(me, "Removed tone pattern table entry "
				       "(entries num = %lu)",
						me_internal_data->
						      tone_pattern_entries_num);
		}
	}

	{
		struct tone_event_table_list_entry *list_entry;
		struct tone_event_table_list_entry *next_list_entry;

		/* clear tone event table */
		DLIST_FOR_EACH_SAFE(list_entry,
				    next_list_entry,
				    &me_internal_data->tone_event_list_head) {
			/* remove entry */
			DLIST_REMOVE(list_entry);
	
			--me_internal_data->tone_event_entries_num;
	
			IFXOS_MemFree(list_entry);
			list_entry = NULL;
	
			me_dbg_prn(me, "Removed tone event table entry "
				       "(entries num = %lu)",
						me_internal_data->
						        tone_event_entries_num);
		}
	}

	{
		struct ringing_pattern_table_list_entry *list_entry;
		struct ringing_pattern_table_list_entry *next_list_entry;

		/* clear ringing pattern table */
		DLIST_FOR_EACH_SAFE(list_entry,
				    next_list_entry,
				    &me_internal_data->ringing_pattern_list_head) {
			/* remove entry */
			DLIST_REMOVE(list_entry);
	
			--me_internal_data->ringing_pattern_entries_num;
	
			IFXOS_MemFree(list_entry);
			list_entry = NULL;
	
			me_dbg_prn(me, "Removed ringing pattern table entry "
				       "(entries num = %lu)",
						me_internal_data->
						   ringing_pattern_entries_num);
		}
	}

	{
		struct ringing_event_table_list_entry *list_entry;
		struct ringing_event_table_list_entry *next_list_entry;

		/* clear ringing event table */
		DLIST_FOR_EACH_SAFE(list_entry,
				    next_list_entry,
				    &me_internal_data->ringing_event_list_head) {
			/* remove entry */
			DLIST_REMOVE(list_entry);
	
			--me_internal_data->ringing_event_entries_num;
	
			IFXOS_MemFree(list_entry);
			list_entry = NULL;
	
			me_dbg_prn(me, "Removed ringing event table entry "
				       "(entries num = %lu)",
						me_internal_data->
						     ringing_event_entries_num);
		}
	}

	IFXOS_MemFree(me->internal_data);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_voice_service_profile_class = {
	/* Class ID */
	OMCI_ME_VOICE_SERVICE_PROFILE_AAL,
	/* Attributes */
	{
		ATTR_UINT("Announcement type",
			  ATTR_SUPPORTED,
			  0x00,
			  0xFF,
			  offsetof(struct omci_me_voice_service_profile,
				   announcement_type),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("Jitter target",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xFFFF,
			  offsetof(struct omci_me_voice_service_profile,
				   jitter_target),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("Jitter buffer max",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_voice_service_profile,
				   jitter_buffer_max),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_BOOL("Echo cancel ind",
			  ATTR_SUPPORTED,
			  offsetof(struct omci_me_voice_service_profile,
				   echo_cancel_ind),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("PSTN protocol variant",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_voice_service_profile,
				   pstn_protocol_variant),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("DTMF digit levels",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_voice_service_profile,
				   dtmf_digit_levels),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("DTMF digit duration",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_voice_service_profile,
				   dtmf_digit_duration),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("Hook flash min time",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_voice_service_profile,
				   hook_flash_minimum_time),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_UINT("Hook flash max time",
			  ATTR_SUPPORTED,
			  0x0000,
			  0xffff,
			  offsetof(struct omci_me_voice_service_profile,
				   hook_flash_maximum_time),
			  2,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_SBC,
			  NULL),
		ATTR_TBL("Tone pattern table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_voice_service_profile,
				  tone_pattern_table),
			 20,	/* size of one table entry */
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		ATTR_TBL("Tone event table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_voice_service_profile,
				  tone_event_table),
			 7,	/* size of one table entry */
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		ATTR_TBL("Ringing pattern table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_voice_service_profile,
				  ringing_pattern_table),
			 5,	/* size of one table entry */
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		ATTR_TBL("Ringing event table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_voice_service_profile,
				  ringing_event_table),
			 7,	/* size of one table entry */
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
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
		get_next_action_handle,
		/* Test result */
		NULL,
		/* Get current data */
		NULL
	},
	/* Init Handler */
	me_init,
	/* Shutdown Handler */
	me_shutdown,
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
	sizeof(struct omci_me_voice_service_profile),
	/* Properties */
	OMCI_ME_PROP_NONE,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Voice service profile",
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
#endif
