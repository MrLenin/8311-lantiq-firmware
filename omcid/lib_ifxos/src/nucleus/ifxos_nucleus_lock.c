/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS

/** \file
   This file contains the IFXOS Layer implementation for Nucleus 
   Lock and Protection.
*/

/* ============================================================================
   IFX Nucleus adaptation - Global Includes
   ========================================================================= */

#include <nucleus.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_lock.h"

#include "ifxos_sys_show.h"

/* ============================================================================
   IFX Nucleus adaptation - LOCK handling
   ========================================================================= */

/** \addtogroup IFXOS_LOCK_NUCLEUS
@{ */

#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) )
/**
   Nucleus - Initialize a Lock Object for protection and lock.
   The lock is based on binary semaphores, recursive calls are not allowded.

\par Implementation
   - the semaphore is created (see "NU_Create_Semaphore").
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
         if (NU_Create_Semaphore(&lockId->object, "sem", 1, NU_PRIORITY) == NU_SUCCESS)
         {
            lockId->bValid = IFX_TRUE;

            lockId->pSysObject = (IFX_void_t*)IFXOS_SYS_OBJECT_GET(IFXOS_SYS_OBJECT_LOCK);
            IFXOS_SYS_LOCK_INIT_COUNT_INC(lockId->pSysObject);

            return IFX_SUCCESS;
         }
      }
   }
   
   return IFX_ERROR;
}

/**
   Nucleus - Delete the given Lock Object.

\par Implementation
   - delete the semaphore object (see "NU_Delete_Semaphore").
   - if the OS call was successfull the memory object will be freed

\param
   lockId   Provides the pointer to the Lock Object.

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
         if (NU_Delete_Semaphore(&lockId->object) != NU_SUCCESS)
         {
            lockId->bValid = IFX_FALSE;
            return IFX_ERROR;
         }

         lockId->bValid = IFX_FALSE;
         IFXOS_SYS_OBJECT_RELEASE(lockId->pSysObject);
      }
   }

   return IFX_SUCCESS;
}

/**
   Nucleus - Get the Lock (not interuptable).

\par Implementation
   - Take the specified semaphore --> LOCKED (see "NU_Obtain_Semaphore").
   - no timeout, wait for ever

\param
   lockId   Provides the pointer to the Lock Object.

\return
   IFX_SUCCESS if getting was successful, else
   IFX_ERROR if something was wrong

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
         if (NU_Obtain_Semaphore(&lockId->object, NU_SUSPEND) == NU_SUCCESS)
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
   Nucleus - Release the Lock.

\par Implementation
   - Release the specified semaphore --> UNLOCKED (see "NU_Release_Semaphore").

\param
   lockId   Provides the pointer to the Lock Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error.
*/
IFX_int32_t IFXOS_LockRelease(
               IFXOS_lock_t *lockId)
{
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         if (NU_Release_Semaphore(&lockId->object) == NU_SUCCESS)
         {
            IFXOS_SYS_LOCK_RELEASE_COUNT_INC(lockId->pSysObject);
            IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(lockId->pSysObject);

            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}

#if ( defined(IFXOS_HAVE_NAMED_LOCK) && (IFXOS_HAVE_NAMED_LOCK == 1) )
/**
   Nucleus - Initialize a Named Lock Object for protection and lock.
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
   Nucleus - Get the Lock with timeout.

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
   STATUS sts;

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
               sts = NU_Obtain_Semaphore(&lockId->object, NU_SUSPEND);
               /* Blocking call */
               if(sts == NU_SUCCESS)
               {
                  IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
                  IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

                  return IFX_SUCCESS;
               }

               IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
               break;

            case 0:
               sts = NU_Obtain_Semaphore(&lockId->object, NU_NO_SUSPEND);
               /* Non Blocking */
               if(sts == NU_SUCCESS)
               {
                  IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
                  IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

                  return IFX_SUCCESS;
               }

               IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
               break;

            default:
               sts = NU_Obtain_Semaphore(&lockId->object, IFXOS_MSEC_TO_TICK(timeout_ms));
               /* Blocking call */
               switch (sts) 
               { 
                  case NU_SUCCESS: 
                     IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
                     IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

                     return IFX_SUCCESS;
                  case NU_TIMEOUT: 
                     if (pRetCode)
                     {
                        *pRetCode = 1;
                     }

                     IFXOS_SYS_LOCK_GET_TOUT_COUNT_INC(lockId->pSysObject);

                     return IFX_ERROR;
                  default:
                     IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
                     break;            
               }
               break;
         }

         switch(sts)
         {
            case NU_INVALID_SUSPEND:
            break;
         };

      }
   }

   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_LOCK_TIMEOUT) && (IFXOS_HAVE_LOCK_TIMEOUT == 1) ) */

/** @} */

#endif      /* #ifdef NUCLEUS_PLUS */

