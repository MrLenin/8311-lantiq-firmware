/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS

/** \file
   This file contains the IFXOS Layer implementation for VxWorks
   Lock and Protection.
*/

/* ============================================================================
   IFX VxWorks adaptation - Global Includes
   ========================================================================= */

#include <vxWorks.h>
#include <semLib.h>
#include <sysLib.h>
#include <errno.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_lock.h"

#include "ifxos_sys_show.h"

/* ============================================================================
   IFX VxWorks adaptation - LOCK handling
   ========================================================================= */

/** \addtogroup IFXOS_LOCK_VXWORKS
@{ */

#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) )
/**
   VxWorks - Initialize a Lock Object for protection and lock.
   The lock is based on binary semaphores, recursive calls are not allowded.

\par Implementation
   - the semaphore is created (see "semBCreate").
   - init state is "FULL" - unlocked.
   - the queuing is priority based

\param
   lockId   Provides the pointer to the Lock Object.

\return
   IFX_SUCCESS if initialization was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int32_t IFXOS_LockInit(
               IFXOS_lock_t *lockId)
{
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_FALSE)
      {
         lockId->object = semBCreate(SEM_Q_PRIORITY, SEM_FULL);
         lockId->bValid = IFX_TRUE;

         lockId->pSysObject = (IFX_void_t*)IFXOS_SYS_OBJECT_GET(IFXOS_SYS_OBJECT_LOCK);
         IFXOS_SYS_LOCK_INIT_COUNT_INC(lockId->pSysObject);

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   VxWorks - Delete the given Lock Object.

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
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         semDelete(lockId->object);
         lockId->bValid = IFX_FALSE;

         IFXOS_SYS_OBJECT_RELEASE(lockId->pSysObject);

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   VxWorks - Get the Lock (not interuptable).

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
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         IFXOS_SYS_LOCK_RECURSIVE_CALL_COUNT_INC(lockId->pSysObject);
         IFXOS_SYS_LOCK_REQ_THREAD_ID_SET(lockId->pSysObject);

         if (semTake(lockId->object, WAIT_FOREVER) == OK)
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
   VxWorks - Release the Lock.

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
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         if (semGive(lockId->object) == OK)
         {
            IFXOS_SYS_LOCK_RELEASE_COUNT_INC(lockId->pSysObject);
            IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(lockId->pSysObject);

            return IFX_SUCCESS;
         }
      }
   }

   IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
      ("IFXOS ERROR - release lock object - semGive(0x%X) = %d" IFXOS_CRLF,
         (IFX_uint32_t)lockId ? lockId->object : 0));

   return IFX_ERROR;
}

#if ( defined(IFXOS_HAVE_NAMED_LOCK) && (IFXOS_HAVE_NAMED_LOCK == 1) )
/**
   VxWorks - Initialize a Named Lock Object for protection and lock.
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
   VxWorks - Get the Lock with timeout.

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
               if (semTake(lockId->object, WAIT_FOREVER) == OK)
               {
                  IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
                  IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

                  return IFX_SUCCESS;
               }

               IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
               break;

            case 0:
               /* Non Blocking */
               if (semTake(lockId->object, NO_WAIT) == OK)
               {
                  IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
                  IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

                  return IFX_SUCCESS;
               }

               IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
               break;

            default:
               /* Blocking call */
               if (semTake(lockId->object, (timeout_ms * sysClkRateGet())/1000) == OK)
               {
                  IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
                  IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

                  return IFX_SUCCESS;
               }
               if (errno == S_objLib_OBJ_TIMEOUT)
               {
                  IFXOS_SYS_LOCK_GET_TOUT_COUNT_INC(lockId->pSysObject);

                  if (pRetCode)
                  {
                     *pRetCode = 1 /* DSL_ERR_TIMEOUT */;
                  }

                  IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
                     ("IFXOS ERROR - timed lock[%d] get - failed (timeout = %d ms)" IFXOS_CRLF,
                       lockId->object, timeout_ms));

                  IFXOS_SYS_OBJECT_SHOW(lockId->pSysObject);

                  return IFX_ERROR;
               }

               IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);

               break;
         }
      }
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - timed lock[--] get - missing lockId" IFXOS_CRLF));

      return IFX_ERROR;
   }

   if (timeout_ms != 0)
   {
      /* timeout_ms 0 is a valid case and do not need any
       * error or warning messages.
       */
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - timed lock[%d] get - failed (errno = %d)" IFXOS_CRLF,
             lockId->object, errno));
   }

   IFXOS_SYS_OBJECT_SHOW(lockId->pSysObject);


   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_LOCK_TIMEOUT) && (IFXOS_HAVE_LOCK_TIMEOUT == 1) ) */

/** @} */

#endif      /* #ifdef VXWORKS */

