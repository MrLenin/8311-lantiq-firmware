/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(WIN32) && !defined(NUCLEUS_PLUS)

/** \file
   This file contains the IFXOS Layer implementation for Win32 - 
   Lock and Protection.
*/

/* ============================================================================
   IFX Win32 adaptation - Global Includes
   ========================================================================= */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_lock.h"

#include "ifxos_sys_show.h"

/* ============================================================================
   IFX Win32 adaptation - Lock and Protection
   ========================================================================= */
/** \addtogroup IFXOS_LOCK_WIN32
@{ */

#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) )
/**
   Win32 - Initialize a Lock Object for protection and lock.
   The lock is based on binary semaphores, recursive calls are not allowded.

\return
   IFX_SUCCESS if initailization was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int32_t IFXOS_LockInit(
               IFXOS_lock_t *lockId)
{
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_FALSE)
      {
         lockId->object = CreateSemaphore( 
                                 NULL,    /* no security attributes */
                                 1,       /* initial count */
                                 1,       /* maximum count */
                                 NULL /* pName */);  /* named semaphore */
         lockId->bValid = IFX_TRUE;

         lockId->pSysObject = (IFX_void_t*)IFXOS_SYS_OBJECT_GET(IFXOS_SYS_OBJECT_LOCK);
         IFXOS_SYS_LOCK_INIT_COUNT_INC(lockId->pSysObject);

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   Win32 - Delete the given Lock Object.

\par Implementation
   - close the semaphore object.

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
         CloseHandle(lockId->object);
         lockId->bValid = IFX_FALSE;

         IFXOS_SYS_OBJECT_RELEASE(lockId->pSysObject);
         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   Win32 - Get the Lock (not interuptable).

\par Implementation
   - Take the given semaphore --> LOCKED (see "WaitForSingleObject").
   - no timeout, wait for ever

\param
   lockId   Provides the pointer to the Lock Object.

\return
   None

\remarks
   Cannot be used on interrupt level.
*/
IFX_int32_t IFXOS_LockGet(
               IFXOS_lock_t *lockId)
{
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         IFXOS_SYS_LOCK_RECURSIVE_CALL_COUNT_INC(lockId->pSysObject);
         IFXOS_SYS_LOCK_REQ_THREAD_ID_SET(lockId->pSysObject);

         /* Blocking call */
         if (WaitForSingleObject(lockId->object, INFINITE) == WAIT_OBJECT_0)
         {
            IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
            IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

            return IFX_SUCCESS;
         }

         IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
      }
   }

   return IFX_ERROR;
}

/**
   Win32 - Release the Lock.

\par Implementation
   - Give the semaphore --> UNLOCKED (see "ReleaseSemaphore").

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
         if (ReleaseSemaphore( 
                     lockId->object,   /* handle to semaphore */
                     1,         /* increase count by one */
                     NULL) )    /* not interested in previous count */
         {
            IFXOS_SYS_LOCK_RELEASE_COUNT_INC(lockId->pSysObject);
            IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(lockId->pSysObject);

            return IFX_SUCCESS;
         }
      }
   }

   IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
      ("IFXOS ERROR - release lock object - ReleaseSemaphore(%x)" IFXOS_CRLF,
         lockId ? lockId->object : 0));

   return IFX_ERROR;
}

#if ( defined(IFXOS_HAVE_NAMED_LOCK) && (IFXOS_HAVE_NAMED_LOCK == 1) )
/**
   Win32 - Initialize a Named Lock Object for protection and lock.
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
   Win32 - Get the Lock with timeout.

\par Implementation

\param
   lockId      Provides the pointer to the Lock Object.
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
   if (pRetCode)
   {
      *pRetCode = 0;
   }

   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         IFXOS_SYS_LOCK_RECURSIVE_CALL_COUNT_INC(lockId->pSysObject);
         IFXOS_SYS_LOCK_REQ_THREAD_ID_SET(lockId->pSysObject);

         switch(timeout_ms)
         {
            case 0xFFFFFFFF:
               /* Blocking call */
               if(WaitForSingleObject(lockId->object, INFINITE) == WAIT_OBJECT_0)
               {
                  IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
                  IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

                  return IFX_SUCCESS;
               }

               IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
               break;

            case 0:
               /* Non Blocking */
               if(WaitForSingleObject(lockId->object, 0L) == WAIT_OBJECT_0)
               {
                  IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
                  IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

                  return IFX_SUCCESS;
               }

               IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
               break;

            default:
               /* Blocking call */
               switch (WaitForSingleObject(lockId->object, timeout_ms)) 
               { 
                  case WAIT_OBJECT_0: 
                     IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
                     IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

                     return IFX_SUCCESS;

                  case WAIT_TIMEOUT: 
                     if (pRetCode)
                     {
                        IFXOS_SYS_LOCK_GET_TOUT_COUNT_INC(lockId->pSysObject);

                        *pRetCode = 1 /* DSL_ERR_TIMEOUT */;
                     }
                     break;
                  default:
                     IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
                     break;
               }
               break;
         }
      }
   }

   return IFX_ERROR;
}
#endif      /* #if ( defined(IFXOS_HAVE_LOCK_TIMEOUT) && (IFXOS_HAVE_LOCK_TIMEOUT == 1) ) */

/** @} */

#endif      /* #ifdef WIN32 */

