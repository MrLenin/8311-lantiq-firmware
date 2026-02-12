/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains the IFXOS Layer implementation for RTEMS
   Lock and Protection.
*/

/* ============================================================================
   RTEMS Adaptation Frame - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_lock.h"
#include "ifxos_mutex.h"

/* ============================================================================
   RTEMS Adaptation Frame - LOCK handling
   ========================================================================= */

/** \addtogroup IFXOS_LOCK_RTEMS
@{ */

#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) )
/**
   RTEMS - Initialize a Lock Object for protection and lock.
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


    if(IFXOS_MutexInit((IFXOS_mutex_t *)lockId) == IFX_ERROR)
  	 return IFX_ERROR;

   return IFX_SUCCESS;
}

/**
   RTEMS - Delete the given Lock Object.

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

   if(IFXOS_MutexDelete((IFXOS_mutex_t *)lockId) == IFX_ERROR)
  	 return IFX_ERROR;

   return IFX_SUCCESS;
}

/**
   RTEMS - Get the Lock (not interuptable).

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
    if(IFXOS_MutexGet((IFXOS_mutex_t *)lockId) == IFX_ERROR)
  	 return IFX_ERROR;
   return IFX_SUCCESS;
}

/**
   RTEMS - Release the Lock.

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
     if(IFXOS_MutexRelease((IFXOS_mutex_t *)lockId) == IFX_ERROR)
  	 return IFX_ERROR;
   return IFX_SUCCESS;
}

#endif      /* #if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) ) */


#if ( defined(IFXOS_HAVE_LOCK_TIMEOUT) && (IFXOS_HAVE_LOCK_TIMEOUT == 1) )
/**
   RTEMS - Get the Lock with timeout.

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

   /*
      - in case of timeout, signal the timeout via the *pRetCode
        (if the variable is given).
   */

   return IFX_SUCCESS;
}

#endif      /* #if ( defined(IFXOS_HAVE_LOCK_TIMEOUT) && (IFXOS_HAVE_LOCK_TIMEOUT == 1) ) */

/** @} */

#endif      /* #ifdef RTEMS */

