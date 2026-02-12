/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation - lock handling (Application Space)
   ========================================================================= */

#ifdef LINUX

/** \file
   This file contains the IFXOS Layer implementation for LINUX Application Space 
   Mutex.
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes - Application
   ========================================================================= */
#define _GNU_SOURCE     1
#include <features.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_time.h"
#include "ifxos_mutex.h"

#ifdef IFXOS_STATIC
#undef IFXOS_STATIC
#endif

#ifdef IFXOS_DEBUG
#define IFXOS_STATIC
#else
#define IFXOS_STATIC   static
#endif


/* ============================================================================
   IFX Linux adaptation - Kernel MUTEX handling
   ========================================================================= */

/** \addtogroup IFXOS_MUTEX_LINUX_APPL
@{ */
#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) )

/**
   IFX Linux adaptation  - Mutex Object init

\param
   mutexId   Pointer to the Mutex Object.
   
\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error or timeout.
 */
IFX_int32_t IFXOS_MutexInit(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_FALSE)
      {
         if(pthread_mutex_init (&mutexId->object , NULL ) == 0)
         {
            mutexId->bValid = IFX_TRUE;

            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}

/**
   LINUX Application - Get the Mutex (not interruptible).

\par Implementation

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error.
*/
IFX_int32_t IFXOS_MutexGet(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_TRUE)
      {
         if(pthread_mutex_lock( &mutexId->object ) == 0)
         {
            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}

/**
   LINUX Application - Release the Mutex.

\par Implementation

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error or timeout.
*/
IFX_int32_t IFXOS_MutexRelease(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_TRUE)
      {
         if(pthread_mutex_unlock( &mutexId->object ) == 0)
         {
            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}

/**
   eCos - Delete the Mutex Object.
   
\par Implementation
      - Delete the mutex --> UNLOCKED (see "cyg_mutex_destroy, cyg_mutex_release").
      
\param
   mutexId   Pointer to the Mutex Object.
	 
\return
   IFX_SUCCESS on success.
   IFX_ERROR on failure
	       
*/
IFX_int32_t IFXOS_MutexDelete(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_TRUE)
      {
         pthread_mutex_unlock(&mutexId->object);
         pthread_mutex_destroy(&mutexId->object);
         mutexId->bValid = IFX_FALSE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) ) */

/** @} */

#endif      /* #ifdef LINUX */


