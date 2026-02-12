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
   Mutex.
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
#include "ifxos_mutex.h"

/* ============================================================================
   IFX Win32 adaptation - Mutex and Protection
   ========================================================================= */
/** \addtogroup IFXOS_MUTEX_WIN32
@{ */

#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) )
/**
   Win32 - Mutex initialization

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error.
*/
IFX_int32_t IFXOS_MutexInit(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_FALSE)
      {
         InitializeCriticalSection(&mutexId->object);
         mutexId->bValid = IFX_TRUE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   Win32 - Get the Mutex (not interruptible).

\par Implementation
   - Take the specified mutex --> LOCKED (see "EnterCriticalSection").

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error.

\remarks
   Cannot be used on interrupt level.
*/
IFX_int32_t IFXOS_MutexGet(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_TRUE)
      {
         EnterCriticalSection(&mutexId->object);

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   Win32 - Release the Mutex.

\par Implementation
   - Release the specified mutex --> UNLOCKED (see "LeaveCriticalSection").

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error.
*/
IFX_int32_t IFXOS_MutexRelease(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_TRUE)
      {
         LeaveCriticalSection(&mutexId->object);

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   win32 - Delete the Mutex Object.

\par Implementation
   - Delete the mutex --> UNLOCKED (see "LeaveCriticalSection, DeleteCriticalSection").

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR on failure

\remarks
   Cannot be used on interrupt level.

*/
IFX_int32_t IFXOS_MutexDelete(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_TRUE)
      {
         LeaveCriticalSection(&mutexId->object);
         DeleteCriticalSection(&mutexId->object);
         mutexId->bValid = IFX_FALSE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) ) */

/** @} */

#endif      /* #ifdef WIN32 */

