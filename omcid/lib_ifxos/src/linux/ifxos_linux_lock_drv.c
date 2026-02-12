/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation - lock handling (Kernel Space)
   Remark: based on "binary semaphore"
   ========================================================================= */

#ifdef LINUX
#ifdef __KERNEL__

/** \file
   This file contains the IFXOS Layer implementation for LINUX Kernel
   Lock and Protection.
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes - Kernel
   ========================================================================= */

#include <linux/kernel.h>
#ifdef MODULE
   #include <linux/module.h>
#endif
#include <linux/sched.h>

#include "ifx_types.h"
#include "ifxos_memory_alloc.h"
#include "ifxos_lock.h"
#include "ifxos_event.h"

/* ============================================================================
   IFX Linux adaptation - Kernel LOCK handling
   ========================================================================= */

/** \addtogroup IFXOS_LOCK_LINUX_DRV
@{ */
#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) )


/**
   LINUX Kernel - Intialize a Lock Object for protection and lock.
   The lock is based on binary semaphores, recursive calls are not allowded.

\param
   lockId   Provides the pointer to the Lock Object.

\par Implementation
   - Init the LINUX kernel semaphore as "UNLOCKED" (see "sema_init").
*/
IFX_int32_t IFXOS_LockInit(
               IFXOS_lock_t *lockId)
{
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_FALSE)
      {
         sema_init(&lockId->object, 1);
         lockId->bValid = IFX_TRUE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   LINUX Kernel - Delete the given Lock Object.

\param
   lockId   Provides the pointer to the Lock Object.

\return
   IFX_SUCCESS if delete was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int32_t IFXOS_LockDelete(
               IFXOS_lock_t *lockId)
{
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         lockId->bValid = IFX_FALSE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   LINUX Kernel - Get the Lock (not interuptable).

\par Implementation
   Decrement the Kernel semaphore counter to "0" --> LOCKED (see "down").

\param
   lockId   Provides the pointer to the Lock Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error (currently not used).

\remarks
   - Cannot be used on interrupt level.
   - Blocking call, not interruptible.
*/
IFX_int32_t IFXOS_LockGet(
               IFXOS_lock_t *lockId)
{
#if 1
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         down(&lockId->object);
         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
#else
/*
   ToDo: Use interruptible down to get the semaphore.
         ==> try to avoid the usage of blocking function
*/
   int retVal = 0;

   if ( (retVal = down_interruptible(lockId)) != 0)
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - get lock object - down_interruptible(0x%X) = %d" IFXOS_CRLF,
           (IFX_uint32_t)lockId, retVal));

      return IFX_ERROR;
   }
   else
   {
      return IFX_SUCCESS;
   }
#endif

}

/**
   LINUX Kernel - Release the Lock.

\par Implementation
   Increment the Kernel semaphore counter to "1" --> UNLOCKED (see "up").

\param
   lockId   Provides the pointer to the Lock Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error or timeout.
*/
IFX_int32_t IFXOS_LockRelease(
               IFXOS_lock_t *lockId)
{
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         up(&lockId->object);
         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

#if ( defined(IFXOS_HAVE_NAMED_LOCK) && (IFXOS_HAVE_NAMED_LOCK == 1) )
/**
   LINUX Kernel - Intialize a Lock Object for protection and lock.
   The lock is based on IFXOS_Locks.

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

#if 0
   IFXOS_SYS_OBJECT_USER_DESRC_SET( lockId->pSysObject, 
                                    (pLockName) ? pLockName : "lock", 
                                    lockIdx);
#endif

   return retVal;
}
#endif

#endif      /* #if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) ) */


#if ( defined(IFXOS_HAVE_LOCK_TIMEOUT) && (IFXOS_HAVE_LOCK_TIMEOUT == 1) )
/**
   Linux Kernel - Get the Lock with timeout.

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
   IFXOS_event_t timeoutEvent;
   IFX_uint32_t timeCnt;

   if (pRetCode)
   {
      *pRetCode = 0;
   }

   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         switch(timeout_ms)
         {
            case 0xFFFFFFFF:
               /* Blocking call */
               down(&lockId->object);

               return IFX_SUCCESS;
            break;

            case 0:
               /* Non Blocking */
               if (down_trylock(&lockId->object) == 0)
               {
                  return IFX_SUCCESS;
               }
               break;

            default:
               /* Blocking call with timeout */
               /* Initialize timeout event */
               if (IFXOS_EventInit(&timeoutEvent) != IFX_SUCCESS)
               {
                  return IFX_ERROR;
               }
               /* Try to aquire a non-blocking lock.
                * If it fails, wait minimum 10 ms and try again until
                * the timeout_ms is expired.
                */
               for (timeCnt = 0; ; timeCnt+=10)
               {
                  if (down_trylock(&lockId->object) == 0)
                  {
                     return IFX_SUCCESS;
                  }

                  if (timeCnt > timeout_ms)
                  {
                     if (pRetCode)
                     {
                        *pRetCode = 1; /* TIMEOUT */
                     }
                     return IFX_ERROR;
                  }

                  /* Start sleeping on timeout */
                  if (IFXOS_EventWait (&timeoutEvent, 10, IFX_NULL) != IFX_SUCCESS)
                  {
                     return IFX_ERROR;
                  }
               }
               break;
         }
      }
   }

   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_LOCK_TIMEOUT) && (IFXOS_HAVE_LOCK_TIMEOUT == 1) ) */
/** @} */

#ifdef MODULE

#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) )
EXPORT_SYMBOL(IFXOS_LockInit);
EXPORT_SYMBOL(IFXOS_LockDelete);
EXPORT_SYMBOL(IFXOS_LockGet);
EXPORT_SYMBOL(IFXOS_LockTimedGet);
EXPORT_SYMBOL(IFXOS_LockRelease);
#endif

#if ( defined(IFXOS_HAVE_NAMED_LOCK) && (IFXOS_HAVE_NAMED_LOCK == 1) )
EXPORT_SYMBOL(IFXOS_NamedLockInit);
#endif

#endif

#endif      /* #ifdef __KERNEL__ */
#endif      /* #ifdef LINUX */
