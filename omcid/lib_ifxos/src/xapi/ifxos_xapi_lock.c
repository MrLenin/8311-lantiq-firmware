/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef XAPI

/** \file
   This file contains the IFXOS Layer implementation for XAPI
   Lock and Protection.
*/

/* ============================================================================
   IFX XAPI adaptation - Global Includes
   ========================================================================= */

#include <xapi.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_lock.h"

/* ============================================================================
   IFX XAPI adaptation - LOCK handling
   ========================================================================= */

/** \addtogroup IFXOS_LOCK_XAPI
@{ */

#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) )
/**
   XAPI - Initialize a Lock Object for protection and lock.
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
         xsm_create ("IFS", 1L, 0, &(lockId->object));
         lockId->bValid = IFX_TRUE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   XAPI - Delete the given Lock Object.

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
   /* Does nothing */
   return IFX_SUCCESS;
}

/**
   XAPI - Get the Lock (not interuptable).

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
         if (xsm_p(lockId->object, 0, 0) == 0)
         {
            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}

/**
   XAPI - Release the Lock.

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
         if (!xsm_v(lockId->object))
         {
            return IFX_SUCCESS;
         }
      }
   }

   IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
      ("IFXOS ERROR - release lock object - semGive(0x%X) = %d" IFXOS_CRLF,
         (IFX_uint32_t)lockId ? lockId->object : 0));

   return IFX_ERROR;
}
#endif      /* #if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) ) */


#if ( defined(IFXOS_HAVE_LOCK_TIMEOUT) && (IFXOS_HAVE_LOCK_TIMEOUT == 1) )
/**
   XAPI - Get the Lock with timeout.

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
   IFX_ulong_t errCode;

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
             if (xsm_p(lockId->object, 0, 0) == 0)
             {
                return IFX_SUCCESS;
             }
             break;

           case 0:
             /* Non Blocking */
             if (xsm_p(lockId->object, 1, 0) == 0)
             {
                return IFX_SUCCESS;
             }
             break;

           default:
             /* Blocking call */
             errCode = xsm_p(lockId->object, 0, timeout_ms);
             if (errCode == 0)
             {
                return IFX_SUCCESS;
             }
             else
             {
                if (pRetCode)
                {
                   *pRetCode = 1 /* ERR_TIMEOUT */;
                }
                return IFX_ERROR;
             }
         }
      }
   }

   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_LOCK_TIMEOUT) && (IFXOS_HAVE_LOCK_TIMEOUT == 1) ) */

/** @} */

#endif      /* #ifdef XAPI */

