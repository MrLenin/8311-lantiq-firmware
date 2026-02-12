/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS

/** \file
   This file contains the IFXOS Layer implementation for GENERIC_OS 
   Lock and Protection.
*/

/* ============================================================================
   IFX GENERIC_OS Adaptation Frame - Global Includes
   ========================================================================= */

/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_lock.h"

#include "ifxos_sys_show.h"

/* ============================================================================
   IFX GENERIC_OS Adaptation Frame - LOCK handling
   ========================================================================= */

/** \addtogroup IFXOS_LOCK_GENERIC_OS
@{ */

#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) )
/**
   GENERIC_OS - Initialize a Lock Object for protection and lock.
   The lock is based on binary semaphores, recursive calls are not allowded.

\par Implementation
   - the binary semaphore is initialized.
   - init state unlocked.

\param
   lockId   Provides the pointer to the Lock Object.

\return      
   IFX_SUCCESS if initialization was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int32_t IFXOS_LockInit(
               IFXOS_lock_t *lockId)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         lockId->object = semBCreate(SEM_Q_FIFO, SEM_EMPTY);
         lockId->bValid = IFX_TRUE;
   */

   IFXOS_RETURN_IF_POINTER_NULL(lockId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_VALID(lockId, IFX_ERROR);

   lockId->pSysObject = (IFX_void_t*)IFXOS_SYS_OBJECT_GET(IFXOS_SYS_OBJECT_LOCK);
   IFXOS_SYS_LOCK_INIT_COUNT_INC(lockId->pSysObject);

   lockId->bValid = IFX_TRUE;

   return IFX_SUCCESS;
}

/**
   GENERIC_OS - Delete the given Lock Object.

\par Implementation
   - delete the semaphore object (see "semDelete").

\param
   lockId   Provides the pointer to the Lock Object.

\return
   IFX_SUCCESS if delete was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int32_t IFXOS_LockDelete(
               IFXOS_lock_t *lockId)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         semDelete(lockId->object);
         lockId->bValid = IFX_FALSE;
   */

   IFXOS_RETURN_IF_POINTER_NULL(lockId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_INVALID(lockId, IFX_ERROR);

   lockId->bValid = IFX_FALSE;
   IFXOS_SYS_OBJECT_RELEASE(lockId->pSysObject);

   return IFX_SUCCESS;
}

/**
   GENERIC_OS - Get the Lock (not interuptable).

\par Implementation
   - Take the given semaphore --> LOCKED (see "semTake").
   - no timeout, wait for ever

\param
   lockId   Provides the pointer to the Lock Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error.

\remarks
   Cannot be used on interrupt level.
*/
IFX_int32_t IFXOS_LockGet(
               IFXOS_lock_t *lockId)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         semTake(lockId->object, WAIT_FOREVER);
   */

   IFXOS_RETURN_IF_POINTER_NULL(lockId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_INVALID(lockId, IFX_ERROR);

   IFXOS_SYS_LOCK_RECURSIVE_CALL_COUNT_INC(lockId->pSysObject);
   /* set the thread ID of the thread which what's to get the lock */
   IFXOS_SYS_LOCK_REQ_THREAD_ID_SET(lockId->pSysObject);

   /* lock catched - set the own thread ID as owner and increment the counter */
   IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
   IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

   /* increment the counter in case of error 
   IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
   */

   return IFX_SUCCESS;
}

/**
   Generic OS - Release the Lock.

\par Implementation
   - Give the semaphore --> UNLOCKED (see "semGive").

\param
   lockId   Provides the pointer to the Lock Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error or timeout.
*/
IFX_int32_t IFXOS_LockRelease(
               IFXOS_lock_t *lockId)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         semGive(lockId->object);
   */

   IFXOS_RETURN_IF_POINTER_NULL(lockId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_INVALID(lockId, IFX_ERROR);

   IFXOS_SYS_LOCK_RELEASE_COUNT_INC(lockId->pSysObject);
   IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(lockId->pSysObject);


   return IFX_SUCCESS;
}


#if ( defined(IFXOS_HAVE_NAMED_LOCK) && (IFXOS_HAVE_NAMED_LOCK == 1) )
/**
   Generic OS - Initialize a Named Lock Object for protection and lock.
   The lock is based on binary semaphores, recursive calls are not allowded.

\remark
   The name will be set within the internal lock object. 
   Currently used for debugging.

\param
   lockId      Provides the pointer to the Lock Object.
\param
   pLockName   Points to the LOCK name
\param
   lockIdx     additional index which is used to generate the lock name

\return      
   IFX_SUCCESS if initialization was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int32_t IFXOS_NamedLockInit(
               IFXOS_lock_t      *lockId,
               const IFX_char_t  *pLockName,
               const IFX_int_t   lockIdx)
{
   IFX_int32_t retVal = IFX_SUCCESS;

   retVal = IFXOS_LockInit(lockId);

   IFXOS_SYS_OBJECT_USER_DESRC_SET( lockId->pSysObject, 
                                    (pLockName) ? pLockName : "lock", 
                                    lockIdx);

   return retVal;
}
#endif      /* #if ( defined(IFXOS_HAVE_NAMED_LOCK) && (IFXOS_HAVE_NAMED_LOCK == 1) ) */
#endif      /* #if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) ) */


#if ( defined(IFXOS_HAVE_LOCK_TIMEOUT) && (IFXOS_HAVE_LOCK_TIMEOUT == 1) )
/**
   Generic OS - Get the Lock with timeout.

\par Implementation

\param
   lockId   Provides the pointer to the Lock Object.

\param
   timeout_ms  Timeout value [ms]
               - 0: no wait
               - -1: wait forever
               - any other value: waiting for specified amount of milliseconds
\param
   pRetCode    Points to the return code variable. [O]
               - If the pointer is NULL the return code will be ignored, else
                 the corresponding return code will be set
               - For timeout the return code is set to 1.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error or timeout.

\note
   To detect timeouts provide the return code varibale, in case of timeout
   the return code is set to 1.
*/
IFX_int32_t IFXOS_LockTimedGet(
               IFXOS_lock_t *lockId,
               IFX_uint32_t timeout_ms,
               IFX_int32_t  *pRetCode)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         semGive(pEventId->object);
   */

   IFXOS_RETURN_IF_POINTER_NULL(lockId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_INVALID(lockId, IFX_ERROR);

   IFXOS_SYS_LOCK_RECURSIVE_CALL_COUNT_INC(lockId->pSysObject);
   /* set the thread ID of the thread which what's to get the lock */
   IFXOS_SYS_LOCK_REQ_THREAD_ID_SET(lockId->pSysObject);

   /* lock catched - set the own thread ID as owner and increment the counter */
   IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
   IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

   /* increment the counter in case of error 
   IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
   IFXOS_SYS_LOCK_GET_TOUT_COUNT_INC(lockId->pSysObject);
   */


   /*
      - in case of timeout, signal the timeout via the *pRetCode 
        (if the variable is given).
   */

   return IFX_SUCCESS;
}

#endif      /* #if ( defined(IFXOS_HAVE_LOCK_TIMEOUT) && (IFXOS_HAVE_LOCK_TIMEOUT == 1) ) */

/** @} */

#endif      /* #ifdef GENERIC_OS */

