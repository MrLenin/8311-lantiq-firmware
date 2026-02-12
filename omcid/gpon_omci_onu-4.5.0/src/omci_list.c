/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_memory_alloc.h"

#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_CORE

#include "omci_list.h"
#include "omci_core.h"
#include "omci_debug.h"

/** \addtogroup OMCI_LIST
   @{
*/

#if 0
/** Whether to debug lists implementation */
#define LIST_DEBUG
#endif

#if !defined(OMCI_DEBUG_DISABLE) && defined(LIST_DEBUG)
static void list_dump(struct list *list, const char *prefix)
{
	struct list_entry *entry, *tmp_entry;

	dbg_err("List %p dump (%s):", list, prefix);
	dbg_err("\tused entries:");
	dbg_err("\t\t[%p next=%p prev=%p]*",
		&list->used, list->used.next, list->used.prev);

	foreach_list_entry_safe_ll(&list->used, entry, tmp_entry) {
		dbg_err("\t\t[%p next=%p prev=%p]", entry,
			entry->next, entry->prev);
	}

#ifdef OMCI_LIST_NO_FREE
	dbg_err("\tfree entries:");

	dbg_err("\t\t[%p next=%p prev=%p]*",
		&list->free, list->free.next, list->free.prev);

	foreach_list_entry_safe_ll(&list->free, entry, tmp_entry) {
		dbg_err("\t\t[%p next=%p prev=%p]",
			entry, entry->next, entry->prev);
	}
#endif
}

#endif

enum omci_error list_init(struct list *list, size_t entry_size)
{
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %lu", (void *)list, entry_size);

	list->used.next = &list->used;
	list->used.prev = &list->used;

#ifdef OMCI_LIST_NO_FREE
	list->free.next = &list->free;
	list->free.prev = &list->free;
#endif

	list->entry_size = entry_size;

	error = lock_init(&list->lock);

#if !defined(OMCI_DEBUG_DISABLE) && defined(LIST_DEBUG)
	list_dump(list, "after init");
#endif

	dbg_out_ret(__func__, error);
	return error;
}

void list_clear(struct list *list)
{
	struct list_entry *entry, *tmp_entry;

	dbg_in(__func__, "%p", (void *)list);

#if !defined(OMCI_DEBUG_DISABLE) && defined(LIST_DEBUG)
	list_dump(list, "before clear");
#endif

	foreach_list_entry_safe(list, entry, tmp_entry) {
		list_entry_free(list, entry);
	}

#if !defined(OMCI_DEBUG_DISABLE) && defined(LIST_DEBUG)
	list_dump(list, "after clear");
#endif

	dbg_out(__func__);
}

void list_delete(struct list *list)
{
	struct list_entry *entry, *tmp_entry;

	dbg_in(__func__, "%p", (void *)list);

#if !defined(OMCI_DEBUG_DISABLE) && defined(LIST_DEBUG)
	list_dump(list, "before delete");
#endif

	foreach_list_entry_safe_ll(&list->used, entry, tmp_entry) {
		IFXOS_MemFree(entry);
	}

	list->used.next = &list->used;
	list->used.prev = &list->used;

#ifdef OMCI_LIST_NO_FREE
	foreach_list_entry_safe_ll(&list->free, entry, tmp_entry) {
		IFXOS_MemFree(entry);
	}

	list->free.next = &list->free;
	list->free.prev = &list->free;
#endif

	(void)lock_delete(&list->lock);

#if !defined(OMCI_DEBUG_DISABLE) && defined(LIST_DEBUG)
	list_dump(list, "after delete");
#endif

	dbg_out(__func__);
}

void list_lock(struct list *list)
{
	if (lock_get(&list->lock) != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't lock list (%p)",
			OMCI_ERROR_LOCK,
			(void *)&list->lock);
		abort();
	}
}

void list_unlock(struct list *list)
{
	if (lock_release(&list->lock) != OMCI_SUCCESS) {
		dbg_err("ERROR(%d) Can't unlock list (%p)",
			OMCI_ERROR_LOCK,
			(void *)&list->lock);
		abort();
	}
}

bool is_list_empty(struct list *list)
{
	if (list->used.next == &list->used)
		return true;
	else
		return false;
}

void list_entry_add_after(struct list *list,
			  struct list_entry *entry,
			  struct list_entry *new_entry)
{
	dbg_in(__func__, "%p, %p", (void *)entry, (void *)new_entry);

#if !defined(OMCI_DEBUG_DISABLE) && defined(LIST_DEBUG)
	list_dump(list, "before add (after)");
#endif

	entry->next->prev = new_entry;
	new_entry->next = entry->next;
	entry->next = new_entry;
	new_entry->prev = entry;

#if !defined(OMCI_DEBUG_DISABLE) && defined(LIST_DEBUG)
	list_dump(list, "after add (after)");
#endif

	dbg_out(__func__);
}

void list_entry_add_before(struct list *list,
			   struct list_entry *entry,
			   struct list_entry *new_entry)
{
	dbg_in(__func__, "%p, %p", (void *)entry, (void *)new_entry);

#if !defined(OMCI_DEBUG_DISABLE) && defined(LIST_DEBUG)
	list_dump(list, "before add (before)");
#endif

	entry->prev->next = new_entry;
	new_entry->prev = entry->prev;
	new_entry->next = entry;
	entry->prev = new_entry;

#if !defined(OMCI_DEBUG_DISABLE) && defined(LIST_DEBUG)
	list_dump(list, "after add (before)");
#endif

	dbg_out(__func__);
}

void list_entry_free(struct list *list,
			    struct list_entry *entry)
{
	dbg_in(__func__, "%p, %p", (void *)list, (void *)entry);

#if !defined(OMCI_DEBUG_DISABLE) && defined(IST_DEBUG)
	list_dump(list, "before entry free");
#endif

	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;

#ifdef OMCI_LIST_NO_FREE
	list_entry_add_before(list, list->free.prev, entry);
#else
	IFXOS_MemFree(entry);
#endif

#if !defined(OMCI_DEBUG_DISABLE) && defined(LIST_DEBUG)
	list_dump(list, "after entry free");
#endif

	dbg_out(__func__);
}

struct list_entry *list_entry_alloc(struct list *list)
{
	struct list_entry *entry;

	dbg_in(__func__, "%p", (void *)list);

#if !defined(OMCI_DEBUG_DISABLE) && defined(LIST_DEBUG)
	list_dump(list, "before entry alloc");
#endif

#ifdef OMCI_LIST_NO_FREE
	if (list->free.next != &list->free) {

		entry = list->free.next;

		entry->next->prev = entry->prev;
		entry->prev->next = entry->next;
	} else {
		entry = IFXOS_MemAlloc(sizeof(struct list_entry)
				       + list->entry_size);
	}
#else
	entry = IFXOS_MemAlloc(sizeof(struct list_entry) + list->entry_size);
#endif

#if !defined(OMCI_DEBUG_DISABLE) && defined(LIST_DEBUG)
	list_dump(list, "after entry alloc");
#endif

	dbg_out(__func__);
	return entry;
}

/** @} */
