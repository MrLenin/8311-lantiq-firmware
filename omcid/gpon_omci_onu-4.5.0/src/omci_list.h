/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_list_h
#define _omci_list_h

#include "ifxos_lock.h"

#include "omci_common.h"

/** \defgroup OMCI_LIST Optical Network Unit - Lists with free entries management

    This module contains lists support (with optional feature to
    maintain list of freed entries to reduce memory fragmentation and locking)
   @{
*/

/** List entry */
struct list_entry {
	/** Previous list entry */
	struct list_entry *next;

	/** Next list entry */
	struct list_entry *prev;
};

/** List structure */
struct list {
	/** Used list entries */
	struct list_entry used;
#ifdef OMCI_LIST_NO_FREE
	/** Free list entries */
	struct list_entry free;
#endif
	/** Size of list entry data */
	size_t entry_size;

	/** List lock */
	IFXOS_lock_t lock;
};

/** Initialize list

   \param[in] list       List pointer
   \param[in] entry_size List entry size
*/
enum omci_error list_init(struct list *list, size_t entry_size);

/** Free (or move to free list) all list entries

   \param[in] list List pointer
*/
void list_clear(struct list *list);

/** Free all list entries and delete lock

   \param[in] list List pointer
*/
void list_delete(struct list *list);

/** Lock list

   \param[in] list List pointer
*/
void list_lock(struct list *list);

/** Unlock list

   \param[in] list List pointer
*/
void list_unlock(struct list *list);

/** Check if list is empty

   \param[in] list List pointer

   \return
      - true when the list is empty
      - false when the list is not empty
*/
bool is_list_empty(struct list *list);

/** Add new_entry after entry

   \param[in] list      List pointer
   \param[in] entry     Existing entry pointer
   \param[in] new_entry New entry pointer
*/
void list_entry_add_after(struct list *list,
			  struct list_entry *entry,
			  struct list_entry *new_entry);

/** Add new_entry before entry

   \param[in] list      List pointer
   \param[in] entry     Existing entry pointer
   \param[in] new_entry New entry pointer
*/
void list_entry_add_before(struct list *list,
			   struct list_entry *entry,
			   struct list_entry *new_entry);

/** Add entry to the end of the list

   \param[in] list      List pointer
   \param[in] new_entry New entry pointer
*/
static inline void list_entry_add_tail(struct list *list,
				       struct list_entry *new_entry)
{
	list_entry_add_after(list, list->used.prev, new_entry);
}

/** Add entry to the beginning of the list

   \param[in] list      List pointer
   \param[in] new_entry New entry pointer
*/
static inline void list_entry_add_head(struct list *list,
				       struct list_entry *new_entry)
{
	list_entry_add_before(list, list->used.next, new_entry);
}

/** Free entry (or move to free list)

   \param[in] list  List pointer
   \param[in] entry List entry (linked in given list)
*/
void list_entry_free(struct list *list, struct list_entry *entry);

/** Allocate (or take from free list) new list entry

   \param[in] list List pointer

   \return New (unlinked) list entry
*/
struct list_entry *list_entry_alloc(struct list *list);

/** Iterate for each list entry (please, don't remove list layout in this
   loop) */
#define foreach_list_entry(PLIST, ENTRY) \
	for ((ENTRY) = (PLIST)->used.next; \
	     (ENTRY)->next != (PLIST)->used.next; \
	     (ENTRY) = (ENTRY)->next)

/** Iterate for each list entry (with ability to remote entries) */
#define foreach_list_entry_safe(list, ENTRY, NEXT_ENTRY) \
	foreach_list_entry_safe_ll(&(list)->used, ENTRY, NEXT_ENTRY)

/** Low level for each implementation */
#define foreach_list_entry_safe_ll(PLIST, ENTRY, NEXT_ENTRY) \
	for ((ENTRY) = (PLIST)->next, (NEXT_ENTRY) = (ENTRY)->next; \
	     (ENTRY)->next != (PLIST)->next; \
	     (ENTRY) = (NEXT_ENTRY), (NEXT_ENTRY) = (ENTRY)->next)

/** Retrieve list entry data */
static inline void *list_entry_data(struct list_entry *entry)
{
	return (void *)((char *)entry + sizeof(struct list_entry));
}

/* @} */

/** \defgroup OMCI_DLIST Optical Network Unit - Double-linked lists

   @{
*/

/** Iterate for each PLIST element using ENTRY as iterator

   \warning Don't add/remove items in this loop!
   Use \ref DLIST_FOR_EACH_SAFE instead! */
#define DLIST_FOR_EACH(ENTRY, PLIST) \
	for ((ENTRY) = (PLIST)->next; \
	     (ENTRY)->next != (PLIST)->next; \
	     (ENTRY) = (ENTRY)->next)

/** Iterate for each PLIST element using ENTRY as iterator */
#define DLIST_FOR_EACH_SAFE(ENTRY, NEXT_ENTRY, PLIST) \
	for ((ENTRY) = (PLIST)->next, (NEXT_ENTRY) = (ENTRY)->next; \
	     (ENTRY)->next != (PLIST)->next; \
	     (ENTRY) = (NEXT_ENTRY), (NEXT_ENTRY) = (ENTRY)->next)

/** Add ENTRY after LISTENTRY */
#define DLIST_ADD(ENTRY, LISTENTRY) \
	do { \
		(LISTENTRY)->next->prev = (ENTRY); \
		(ENTRY)->next = (LISTENTRY)->next; \
		(LISTENTRY)->next = (ENTRY); \
		(ENTRY)->prev = (LISTENTRY); \
	} while (0)

/** Add ENTRY to the PLIST tail (or before entry if PLIST points to the entry) */
#define DLIST_ADD_TAIL(ENTRY, PLIST) \
	do { \
		(PLIST)->prev->next = (ENTRY); \
		(ENTRY)->prev = (PLIST)->prev; \
		(ENTRY)->next = (PLIST); \
		(PLIST)->prev = (ENTRY); \
	} while (0)

/** Remove ENTRY from the list */
#define DLIST_REMOVE(ENTRY) \
	do { \
		(ENTRY)->next->prev = (ENTRY)->prev; \
		(ENTRY)->prev->next = (ENTRY)->next; \
	} while (0)

/** Initialize list */
#define DLIST_HEAD_INIT(PLIST) \
	do { \
		(PLIST)->next = (PLIST); \
		(PLIST)->prev = (PLIST); \
	} while (0)

/** Check if list is empty */
#define IS_DLIST_EMPTY(PLIST) \
	(PLIST)->next == (PLIST)->prev

/** @} */

#endif
