/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_os_h
#define _omci_os_h

#include <stdarg.h>

#ifndef SWIG
#  include "ifxos_print.h"
#endif

#include "omci_common.h"
#include "ifxos_thread.h"
#include "ifxos_event.h"

/** \defgroup OMCI_OS Optical Network Unit - Operating System wrappers

   @{
*/

/** \defgroup OMCI_OS_RECURISVE_LOCK Recursive lock

   @{
*/

#ifdef IFXOS_HAVE_THREAD
struct recursive_lock {
	/** PThread reentrant mutex */
	pthread_mutex_t mutex;
};
#else
struct recursive_lock {
	/** Actual lock */
	IFXOS_lock_t lock;
	/** Number of recursive acquisitions */
	int count;
	/** Owner thread */
	IFXOS_thread_t owner;
};
#endif

/** Init recursive lock.
   Please refer to \ref recursive_lock for the details

   \param[in] lock recursive lock pointer
*/
enum omci_error recursive_lock_init(struct recursive_lock *lock);
/** Delete recursive lock.
   Please refer to \ref recursive_lock for the details

   \param[in] lock recursive lock pointer
*/
enum omci_error recursive_lock_delete(struct recursive_lock *lock);

/** Get recursive lock.
   Please refer to \ref recursive_lock for the details

   \param[in] lock recursive lock pointer
*/
enum omci_error recursive_lock_get(struct recursive_lock *lock);
/** Release recursive lock.
   Please refer to \ref recursive_lock for the details

   \param[in] lock recursive lock pointer
*/
enum omci_error recursive_lock_release(struct recursive_lock *lock);

/** @} */

/** \defgroup OMCI_OS_RW_LOCK Read/write lock

   @{
*/

/** Read-write lock implementation.

   Multiple threads may take RW lock for read but only one can take it for
   write.

   This lock is used for MIB.
*/
#ifdef IFXOS_HAVE_THREAD
struct rw_lock {
	/** PThread RW lock */
	pthread_rwlock_t rwlock;
};
#else
struct rw_lock {
	/** IFXOS lock */
	IFXOS_lock_t lock;

	/** Number of readers */
	unsigned int read;
	/** Number of writers (1 or 0) */
	unsigned int write;

	/** Writer is pending, readers should not start read */
	bool pending_write;
};
#endif

/** RW lock mode */
enum rw_lock_mode {
	/** Read mode: multiple readers may acquire the lock in parallel */
	RW_LOCK_MODE_READ,

	/** Write mode: only a single writer can hold the lock at any one
	    time (other readers or writers are waiting) */
	RW_LOCK_MODE_WRITE
};

/** Init RW lock.
   Please refer to \ref rw_lock for the details

   \param[in] lock RW lock pointer
*/
enum omci_error rw_lock_init(struct rw_lock *lock);

/** Delete RW lock.
   Please refer to \ref rw_lock for the details

   \param[in] lock RW lock pointer
*/
enum omci_error rw_lock_delete(struct rw_lock *lock);

/** Get RW lock.
   Please refer to \ref rw_lock for the details

   \param[in] lock RW lock pointer
   \param[in] mode Lock mode (Read/Write)
*/
enum omci_error rw_lock_get(struct rw_lock *lock, enum rw_lock_mode mode);

/** Release RW lock.
   Please refer to \ref rw_lock for the details

   \param[in] lock RW lock pointer
*/
enum omci_error rw_lock_release(struct rw_lock *lock);

/** Check whether anybody holds read or write lock

   \param[in]  lock RW lock pointer
   \param[out] locked  True if somebody holds lock

   \return
   - true: some thread holds read or write lock
   - false: nobody holds this lock
*/
enum omci_error rw_lock_is_locked(struct rw_lock *lock, bool *locked);

/** @} */

/** \defgroup OMCI_OS_LOCK Lock

   @{
*/

/** Init lock

   \param[in] lock Lock pointer

   \remarks This is a IFXOS_LockInit wrapper
*/
enum omci_error lock_init(IFXOS_lock_t *lock);

/** Delete lock

   \param[in] lock Lock pointer

   \remarks This is a IFXOS_LockDelete wrapper
*/
enum omci_error lock_delete(IFXOS_lock_t *lock);

/** Get lock

   \param[in] lock Lock pointer

   \remarks This is a IFXOS_LockGet wrapper
*/
enum omci_error lock_get(IFXOS_lock_t *lock);

/** Release lock

   \param[in] lock Lock pointer

   \remarks This is a IFXOS_LockRelease wrapper
*/
enum omci_error lock_release(IFXOS_lock_t *lock);

/** @} */

/** @} */

#endif
