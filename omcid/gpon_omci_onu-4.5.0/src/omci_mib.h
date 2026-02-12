/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_mib_h
#define _omci_mib_h

#include "omci_core.h"
#include "omci_me_def.h"

/** \defgroup OMCI_MIB Optical Network Unit - MIB

    This module contains MIB related functionality.

    \section OMCI_MIB_LOCK MIB locking

    When dealing with the MIB pointers one should be concerned about loosing
    them because of 'delete ME' request from another thread.
    Thus, whenever you need to deal with pointers from the MIB you have to
    lock it properly beforehand. When the MIB is locked its guaranteed that
    it will not add/remove MEs, so ME pointers are consistent and valid
    while you're holding the MIB lock. After releasing the lock, your pointers
    are garbage.

    The difference between 'read' and 'write' lock is that while holding the
    'write' lock you are given the exclusive access (other readers are knocked
    off and are waiting) and thereby you're allowed to change the structure of
    the MIB (add/remove MEs).

    When the action handler of the ME is called, you don't need to lock MIB
    by hand. It's done already by the message handling thread and locking type
    depends on the OMCI message type: if it's create, delete, MIB upload or
    Get all alarms, them MIB is write locked, otherwise read locked.

    When the PM handler of the ME is called, the MIB is also already read
    locked.

    For ME init, shutdown, update, tbl_copy handlers MIB is also read locked.

    Therefore the places where one needs to lock MIB by hand are:
    - Timeout handlers
    - API routines
    - Callbacks
    - Other non-generic threads which may be created for any particular task

    \section OMCI_MIB_SEARCH MIB ME class or instance search

    The \ref me_def_class_array array defined in omci_me_def.c file determines
    the dependencies between the MEs. If some ME (master) creates or uses
    some other ME (slave), then master ME should be defined _before_ slave ME
    in the mentioned list.

    To improve the search speed of the ME instance or class we use binary
    search. Because MIB contains the sorted version of \ref me_def_class_array
    (named me_class_array) we always use this list in every search related to
    the ME instance or class.

    Entities inside the \ref mib_me_class_array_entry (me_list) are also
    sorted.

   @{
*/

/** Space available in the "MIB upload next rsp" message for the values */
#define MIB_UPLOAD_NEXT_RSP_VALUES_SIZE                 26

/** Lock MIB for reading (shared access) */
void mib_lock_read(struct omci_context *context);

/** Lock MIB for writing (exclusive access) */
void mib_lock_write(struct omci_context *context);

/** Unlock MIB */
void mib_unlock(struct omci_context *context);

/** MIB Managed Entity entry */
struct mib_me_list_entry {
	/** Managed Entity pointer */
	struct me me;

	/** Next \ref mib_me_list_entry item */
	struct mib_me_list_entry *next;
};

/** MIB Managed Entity class entry */
struct mib_me_class_array_entry {
	/** Managed Entity class identifier */
	uint16_t class_id;

	/** Managed Entity class pointer */
	const struct me_class *class;

	/** Sorted list of all Managed Entity instances with this class_id */
	struct mib_me_list_entry *me_list;
};

/** MIB structure */
struct mib {
	/** Array of sorted Managed Entity classes presented at the ONU */
	struct mib_me_class_array_entry me_class_array[OMCI_ME_CLASS_NUM];

	/** Alarm sequence number \see ITU-T.G.984.4 */
	uint8_t alarm_seq_num;

	/** Number of Managed Entities in the MIB */
	size_t me_count;

	/** MIB read-write lock.

	    Please refer to \ref rw_lock for the details */
	struct rw_lock lock;
};

/** MIB copy entry */
struct mib_copy_entry {
	/** Managed Entity class identifier */
	uint16_t class_id;

	/** Managed Entity instance identifier */
	uint16_t instance_id;

	/** Managed Entity attributes mask */
	uint16_t attr_mask;

	/** Managed Entity attributes values (in compliance with attr_mask) */
	uint8_t values[MIB_UPLOAD_NEXT_RSP_VALUES_SIZE];

	/** Next \ref mib_copy_entry entry */
	struct mib_copy_entry *next;
};

/** MIB copy context */
struct mib_copy {

	/** number of entries in the list */
	unsigned int num;

	/** ID of the timeout which should clean copy list */
	unsigned long timeout_id;

	/** MIB copy list */
	struct list list;
};

/** Initialize MIB copy

   \param[in] context OMCI context pointer
*/
enum omci_error mib_copy_init(struct omci_context *context);

/** Shutdown MIB copy

   \param[in] context OMCI context pointer
*/
enum omci_error mib_copy_shutdown(struct omci_context *context);

/** Copy the MIB for upload

   \param[in] context OMCI context pointer
*/
enum omci_error mib_copy(struct omci_context *context);

/** Find Managed Entity instance

   \param[in]  context     OMCI context pointer
   \param[in]  class_id    Managed Entity instance class identifier
   \param[in]  instance_id Managed Entity instance identifier
   \param[out] me          Returns Managed Entity pointer (may be NULL)

   \return
      - \ref omci_error::OMCI_ERROR_ME_NOT_FOUND when the
           Managed Entity is not found
      - \ref omci_error::OMCI_SUCCESS on success
*/
enum omci_error mib_me_find(struct omci_context *context,
			    uint16_t class_id,
			    uint16_t instance_id,
			    struct me **me);

/** Resolve class structure pointer

   \param[in]  context     OMCI context pointer
   \param[in]  class_id Managed Entity class identifier
   \param[out] me_class Returns Managed Entity class pointer (may be NULL)

   \return
      - \ref omci_error::OMCI_ERROR_ME_NOT_SUPPORTED if
        specified class ID is not supported
      - \ref omci_error::OMCI_SUCCESS on success
*/
enum omci_error mib_me_class_resolve(struct omci_context *context,
				     uint16_t class_id,
				     const struct me_class **me_class);

/** Create Managed Entity instance

   \param[in]  context     OMCI context pointer
   \param[in]  active      Use implementation of Managed Entity
   \param[in]  class_id    Managed Entity class identifier
   \param[in]  instance_id Managed Entity instance identifier
   \param[out] me          Returns Managed Entity pointer
   \param[in]  init_data   Initial data
                           NULL - Initialize handler will use it's default data
                           non-NULL - Initialize handler will use provided data
                           NOTE! Managed Entity initialize handler is responsible
                           for handling provided data! Therefore some Managed
                           Entities could silently pass specified values!
   \param[in] suppress_avc Suppress AVC for given attributes
*/
enum omci_error mib_me_create(struct omci_context *context,
			      const bool active,
			      const uint16_t class_id,
			      const uint16_t instance_id,
			      struct me **me,
			      void *init_data,
			      const uint16_t suppress_avc);

/** Delete Managed Entity instance

   \param[in] context OMCI context pointer
   \param[in] me      Managed Entity pointer
*/
enum omci_error mib_me_delete(struct omci_context *context, struct me *me);

/** Create MIB and required Managed Entities

   \param[in] context OMCI context pointer
*/
enum omci_error mib_create(struct omci_context *context);

/** Reset MIB (remove and then create all required Managed Entities)

   \param[in] context OMCI context pointer
   \param[in] force if false do only a complete reset if data sequence
                    counter is zero

   \remark MIB should be unlocked prior to this routine call
           (it locks MIB for write itself)!
*/
enum omci_error mib_reset(struct omci_context *context, bool force);

/** Destroy MIB and all its data

   \param[in] context OMCI context pointer
*/
enum omci_error mib_destroy(struct omci_context *context);

/** Increment MIB sequence number

   \param[in] context OMCI context pointer
*/
enum omci_error mib_seq_num_inc(struct omci_context *context);

/** Clear MIB sequence number

   \param[in] context OMCI context pointer
*/
enum omci_error mib_seq_num_clear(struct omci_context *context);

/** Retrieve MIB sequence number

   \param[in]  context OMCI context pointer
   \param[out] seq     Returned sequence number
*/
enum omci_error mib_seq_num_get(struct omci_context *context, uint8_t *seq);


/** MIB walker handler */
typedef enum omci_error (mib_walk_handler) (struct omci_context *context,
					    struct me *me,
					    void *shared_data);

/** Walk through the all Managed Entities

   \param[in]     context     OMCI context pointer
   \param[in]     handler     Handler which is called for each Managed Entity
   \param[in,out] shared_data Data shared between all calls

   \note \ref mib_walk_handler locks ME itself, you only have to keep MIB lock!
*/
enum omci_error mib_walk(struct omci_context *context,
			 mib_walk_handler *handler,
			 void *shared_data);

/** Walk through the all Managed Entities of given class

   \param[in]     context     OMCI context pointer
   \param[in]     class_id    Managed Entities class identifier
   \param[in]     handler     Handler which is called for each Managed Entity
   \param[in,out] shared_data Data shared between all calls

   \note \ref mib_walk_handler locks ME itself, you only have to keep MIB lock!
*/
enum omci_error mib_walk_by_class(struct omci_context *context,
				  uint16_t class_id,
				  mib_walk_handler *handler,
				  void *shared_data);

/** Find Managed Entities with class_id whose attribute \#attr contains given
    data

   \param[in]     context       OMCI context pointer
   \param[in]     class_id      Managed Entities class identifier
   \param[in]     attr          Attribute number
   \param[in]     data          Data to find
   \param[in]     data_size     Attribute data size
   \param[in,out] found_me      Array to fill in with Managed Entity pointers
   \param[in]     found_me_size sizeof(found_me) array (maximum number of
				Managed Entities which could be found)
   \param[out]    found_me_num  Actual number of Managed Entities in found_me

   \return
      - \ref omci_error::OMCI_ERROR_ME_NOT_FOUND when the
           Managed Entity is not found
      - \ref omci_error::OMCI_SUCCESS on success

   \code
   uint16_t ptr = 0x1234;
   struct me *me[5]; // maximum 5 me to search for
   size_t num; // will contain number of found entities in me array

   error = mib_me_find_where(context,
			     278, 1,
			     &ptr, sizeof(ptr),
			     me, sizeof(me),
			     &num);
   RETURN_IF_ERROR(error); // return here if nothing found

   for (i = 0; i < num && i < ARRAY_SIZE(me); i++) {
	me_lock(context, me[i]);
	me_attr_read(xxx);
	me_unlock(context, me[i]);
   }
   \endcode
*/
enum omci_error mib_me_find_where(struct omci_context *context,
				  uint16_t class_id, unsigned int attr,
				  void *data, size_t data_size,
				  struct me **found_me, size_t found_me_size,
				  size_t *found_me_num);

/** Check whether anybody holds MIB read or write lock

   \param[in] context OMCI context pointer

   \return
   - true: some thread holds read or write lock
   - false: nobody holds this lock
*/
bool mib_is_locked(struct omci_context *context);

/** @} */

#endif
