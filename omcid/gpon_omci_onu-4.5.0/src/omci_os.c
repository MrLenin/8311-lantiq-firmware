/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include <stdio.h>

#include "ifxos_time.h"

#define OMCI_DBG_MODULE OMCI_DBG_MODULE_CORE

#include "omci_core.h"
#include "omci_debug.h"

#ifdef IFXOS_HAVE_THREAD
#include <pthread.h>
#endif

/** \addtogroup OMCI_OS
   @{
*/

/* #define OMCI_LOCK_DEBUG */

static IFXOS_File_t *dbg_file = NULL;

enum omci_error omci_dbg_file_set(IFXOS_File_t *file)
{
	RETURN_IF_PTR_NULL(file);

	dbg_file = file ? file : IFXOS_STDOUT;

	return OMCI_SUCCESS;
}

void omci_vprintf(const char *fmt, va_list args)
{
	vfprintf(dbg_file ? dbg_file : stdout, fmt, args);
}

void omci_printf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	omci_vprintf(fmt, args);
	va_end(args);
}

void omci_printfe(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(dbg_file ? dbg_file : stderr, fmt, args);
	va_end(args);
}

#ifndef IFXOS_HAVE_THREAD
static inline enum
omci_error generic_recursive_lock_init(struct recursive_lock *lock)
{
	return lock_init(&lock->lock);
}

static inline
enum omci_error recursive_lock_delete(struct recursive_lock *lock)
{
	return lock_delete(&lock->lock);
}

static inline
enum omci_error generic_recursive_lock_get(struct recursive_lock *lock)
{
	bool locked = false;

	while (locked == false) {
		if (lock_get(&lock->lock) != OMCI_SUCCESS)
			return OMCI_ERROR_LOCK;

		if (lock->count == 0) {
			lock->owner = IFXOS_ThreadIdGet();
			lock->count++;

			locked = true;

#ifdef OMCI_LOCK_DEBUG
			dbg_prn("REC Take %d in %u",
				lock->count, lock->owner);
#endif
		} else {
			if (lock->owner == IFXOS_ThreadIdGet()) {
				lock->count++;

				locked = true;

#ifdef OMCI_LOCK_DEBUG
				dbg_prn("REC Take again %d in %u",
					lock->count, lock->owner);
#endif
			} else {
				if (lock_release(&lock->lock) != OMCI_SUCCESS)
					return OMCI_ERROR_LOCK;

#ifdef OMCI_LOCK_DEBUG
				dbg_prn("REC spin with %d in %u (our %u)",
					lock->count, lock->owner,
					IFXOS_ThreadIdGet());
#endif

				IFXOS_MSecSleep(1);

				continue;
			}
		}

		if (lock_release(&lock->lock) != OMCI_SUCCESS)
			return OMCI_ERROR_LOCK;
	}

	return OMCI_SUCCESS;
}

static inline
enum omci_error generic_recursive_lock_release(struct recursive_lock *lock)
{
	if (lock_get(&lock->lock) != OMCI_SUCCESS)
		return OMCI_ERROR_LOCK;

	if (lock->owner == IFXOS_ThreadIdGet()) {
		if (lock->count) {
			lock->count--;

#ifdef OMCI_LOCK_DEBUG
			dbg_prn("REC Free %d in %u",
				lock->count, lock->owner);
#endif
		} else {
			return OMCI_ERROR_LOCK;
		}
	} else {
		return OMCI_ERROR_LOCK;
	}

	if (lock_release(&lock->lock) != OMCI_SUCCESS)
		return OMCI_ERROR_LOCK;

	return OMCI_SUCCESS;
}
#endif

enum omci_error recursive_lock_init(struct recursive_lock *lock)
{
#ifdef IFXOS_HAVE_THREAD
	int ret;
	pthread_mutexattr_t attr;

	ret = pthread_mutexattr_init(&attr);
	if (ret)
		return OMCI_ERROR;
	ret = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	if (ret) {
		pthread_mutexattr_destroy(&attr);
		return OMCI_ERROR;
	}
	ret = pthread_mutex_init(&lock->mutex, &attr) != 0;
	pthread_mutexattr_destroy(&attr);
	return ret;
#else
	return generic_recursive_lock_init(lock);
#endif
}

enum omci_error recursive_lock_delete(struct recursive_lock *lock)
{
#ifdef IFXOS_HAVE_THREAD
	return pthread_mutex_destroy(&lock->mutex) != 0;
#else
	return generic_recursive_lock_delete(lock);
#endif
}

enum omci_error recursive_lock_get(struct recursive_lock *lock)
{
#ifdef IFXOS_HAVE_THREAD
	return pthread_mutex_lock(&lock->mutex) != 0;
#else
	return generic_recursive_lock_get(lock);
#endif
}

enum omci_error recursive_lock_release(struct recursive_lock *lock)
{
#ifdef IFXOS_HAVE_THREAD
	return pthread_mutex_unlock(&lock->mutex) != 0;
#else
	return generic_recursive_lock_release(lock);
#endif
}

#ifndef IFXOS_HAVE_THREAD
static inline
enum omci_error generic_rw_lock_init(struct rw_lock *lock)
{
	return lock_init(&lock->lock);
}

static inline
enum omci_error generic_rw_lock_delete(struct rw_lock *lock)
{
	return lock_delete(&lock->lock);
}

/** Get Read-Write lock for read

   \param[in] lock Lock pointer
*/
static inline
enum omci_error generic_rw_lock_get_rd(struct rw_lock *lock)
{
	bool locked = false;
	enum omci_error error;

	while (locked == false) {
		error = lock_get(&lock->lock);
		RETURN_IF_ERROR(error);

		if (lock->write == 0 && lock->pending_write == false) {
			++lock->read;
#ifdef OMCI_LOCK_DEBUG
			dbg_prn("RWL RD Take [R%d W%d P%d]",
				lock->read, lock->write, lock->pending_write);
#endif

			locked = true;
		}

		error = lock_release(&lock->lock);
		RETURN_IF_ERROR(error);

		if (locked == false) {
#ifdef OMCI_LOCK_DEBUG
			dbg_prn("RWL RD Spin [R%d W%d P%d]",
				lock->read, lock->write, lock->pending_write);
#endif
			IFXOS_MSecSleep(1);
		}
	}

	return OMCI_SUCCESS;
}

/** Get Read-Write lock for write

   \param[in] lock Lock pointer
*/
static inline
enum omci_error generic_rw_lock_get_wr(struct rw_lock *lock)
{
	bool pending = false;
	bool locked = false;
	enum omci_error error;

	/* set write pending */
	while (pending == false) {
		error = lock_get(&lock->lock);
		RETURN_IF_ERROR(error);

		if (lock->write == 0 && lock->pending_write == false) {
			lock->pending_write = true;
			pending = true;
#ifdef OMCI_LOCK_DEBUG
			dbg_prn("RWL WR Pend [R%d W%d P%d]",
				lock->read, lock->write, lock->pending_write);
#endif
		}

		error = lock_release(&lock->lock);
		RETURN_IF_ERROR(error);

		if (pending == false) {
#ifdef OMCI_LOCK_DEBUG
			dbg_prn("RWL WR Spin pend [R%d W%d P%d]",
				lock->read, lock->write, lock->pending_write);
#endif
			IFXOS_MSecSleep(1);
		}
	}

	/* wait for readers to exit */
	while (locked == false) {
		error = lock_get(&lock->lock);
		RETURN_IF_ERROR(error);

		if (lock->read == 0) {
			lock->write = 1;
			lock->pending_write = false;
			locked = true;

#ifdef OMCI_LOCK_DEBUG
			dbg_prn("RWL WR Take [R%d W%d P%d]",
				lock->read, lock->write, lock->pending_write);
#endif
		}

		error = lock_release(&lock->lock);
		RETURN_IF_ERROR(error);

		if (locked == false) {
#ifdef OMCI_LOCK_DEBUG
			dbg_prn("RWL WR Spin [R%d W%d P%d]",
				lock->read, lock->write,
				lock->pending_write);
#endif
			IFXOS_MSecSleep(1);
		}
	}

	return OMCI_SUCCESS;
}

static inline
enum omci_error generic_rw_lock_get(struct rw_lock *lock, enum rw_lock_mode mode)
{
	if (mode == RW_LOCK_MODE_READ)
		return generic_rw_lock_get_rd(lock);
	else
		return generic_rw_lock_get_wr(lock);
}

static inline
enum omci_error generic_rw_lock_release(struct rw_lock *lock)
{
	enum omci_error error;

	error = lock_get(&lock->lock);
	RETURN_IF_ERROR(error);

	if (lock->write != 0) {
		lock->write = 0;
#ifdef OMCI_LOCK_DEBUG
		dbg_prn("RWL WR Free [R%d W%d P%d]",
			lock->read, lock->write, lock->pending_write);
#endif
	} else {
		--lock->read;
#ifdef OMCI_LOCK_DEBUG
		dbg_prn("RWL RD Free [R%d W%d P%d]",
			lock->read, lock->write, lock->pending_write);
#endif
	}

	error = lock_release(&lock->lock);
	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}

static inline
enum omci_error generic_rw_lock_is_locked(struct rw_lock *lock, bool *locked)
{
	enum omci_error error;

	error = lock_get(&lock->lock);
	RETURN_IF_ERROR(error);

	*locked = lock->write != 0 || lock->read != 0;

	error = lock_release(&lock->lock);
	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}
#endif

enum omci_error rw_lock_init(struct rw_lock *lock)
{
#ifdef IFXOS_HAVE_THREAD
	return pthread_rwlock_init(&lock->rwlock, NULL) != 0;
#else
	return generic_rw_lock_init(lock);
#endif
}

enum omci_error rw_lock_delete(struct rw_lock *lock)
{
#ifdef IFXOS_HAVE_THREAD
	return pthread_rwlock_destroy(&lock->rwlock) != 0;
#else
	return generic_rw_lock_delete(lock);
#endif
}

enum omci_error rw_lock_get(struct rw_lock *lock, enum rw_lock_mode mode)
{
#ifdef IFXOS_HAVE_THREAD
	if (mode == RW_LOCK_MODE_READ)
		return pthread_rwlock_rdlock(&lock->rwlock) != 0;
	else
		return pthread_rwlock_wrlock(&lock->rwlock) != 0;
#else
	return generic_rw_lock_get(lock, mode);
#endif
}

enum omci_error rw_lock_release(struct rw_lock *lock)
{
#ifdef IFXOS_HAVE_THREAD
	return pthread_rwlock_unlock(&lock->rwlock) != 0;
#else
	return generic_rw_lock_release(lock);
#endif
}

enum omci_error rw_lock_is_locked(struct rw_lock *lock, bool *locked)
{
#ifdef IFXOS_HAVE_THREAD
	int ret = pthread_rwlock_trywrlock(&lock->rwlock);
	if (ret == EBUSY) {
		*locked = true;
		return OMCI_SUCCESS;
	} else if (ret == 0) {
		*locked = false;
		return pthread_rwlock_unlock(&lock->rwlock) != 0;
	} else {
		return OMCI_ERROR;
	}
#else
	return generic_rw_lock_is_locked(lock, locked);
#endif
}

enum omci_error lock_init(IFXOS_lock_t *lock)
{
	int ret;

	dbg_msg("Lock init %p", (void *)lock);

	ret = (int)IFXOS_LockInit(lock);

	if (ret) {
		dbg_err("ERROR(%d) IFXOS_LockInit returned %d",
			OMCI_ERROR_LOCK, ret);
		return OMCI_ERROR_LOCK;
	}

	return OMCI_SUCCESS;
}

enum omci_error lock_delete(IFXOS_lock_t *lock)
{
	int ret;

	dbg_msg("Lock delete %p", (void *)lock);

	ret = (int)IFXOS_LockDelete(lock);

	if (ret) {
		dbg_err("ERROR(%d) IFXOS_LockDelete returned %d",
			OMCI_ERROR_LOCK, ret);
		return OMCI_ERROR_LOCK;
	}

	return OMCI_SUCCESS;
}

enum omci_error lock_get(IFXOS_lock_t *lock)
{
	int ret;

#ifdef OMCI_LOCK_DEBUG
	dbg_prn("Lock get %p", (void *)lock);
#endif

	ret = (int)IFXOS_LockGet(lock);

	if (ret) {
		dbg_err("ERROR(%d) IFXOS_LockGet returned %d",
			 OMCI_ERROR_LOCK, ret);
		return OMCI_ERROR_LOCK;
	}

	return OMCI_SUCCESS;
}

enum omci_error lock_release(IFXOS_lock_t *lock)
{
	int ret;

#ifdef OMCI_LOCK_DEBUG
	dbg_prn("Lock release %p", (void *)lock);
#endif

	ret = (int)IFXOS_LockRelease(lock);

	if (ret) {
		dbg_err("ERROR(%d) IFXOS_LockRelease returned %d",
			OMCI_ERROR_LOCK, ret);
		return OMCI_ERROR_LOCK;
	}

	return OMCI_SUCCESS;
}

/** @} */
