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
   Mutex.
*/

/* ============================================================================
   IFX GENERIC_OS adaptation - Global Includes
   ========================================================================= */

/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_mutex.h"

/* ============================================================================
   IFX GENERIC_OS adaptation - MUTEX handling
   ========================================================================= */

/** \addtogroup IFXOS_MUTEX_GENERIC_OS
@{ */

#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) )
/**
   GENERIC_OS - Mutex init

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error.
*/
IFX_int32_t IFXOS_MutexInit(
               IFXOS_mutex_t *mutexId)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         mutexId->object = semMCreate(SEM_Q_PRIORITY | SEM_INVERSION_SAFE | SEM_DELETE_SAFE);
         mutexId->bValid = IFX_TRUE;
   */

   IFXOS_RETURN_IF_POINTER_NULL(mutexId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_VALID(mutexId, IFX_ERROR);

   mutexId->bValid = IFX_TRUE;

   return IFX_SUCCESS;
}

/**
   GENERIC_OS - Delete the Mutex Object.

\par Implementation
   - Delete the mutex --> UNLOCKED (see "semDelete").

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         semDelete(mutexId->object);
         mutexId->bValid = IFX_FALSE;
   */

   IFXOS_RETURN_IF_POINTER_NULL(mutexId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_INVALID(mutexId, IFX_ERROR);

   mutexId->bValid = IFX_FALSE;

   return IFX_SUCCESS;
}

/**
   GENERIC_OS - Get the Mutex (not interruptible).

\par Implementation
   - Get the mutex object (see "semTake")

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         semTake(mutexId->object, WAIT_FOREVER);
   */

   IFXOS_RETURN_IF_POINTER_NULL(mutexId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_INVALID(mutexId, IFX_ERROR);

   return IFX_SUCCESS;
}

/**
   GENERIC_OS - Release the Mutex.

\par Implementation
   - Release the mutex object (see "semGive")

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error.
*/
IFX_int32_t IFXOS_MutexRelease(
               IFXOS_mutex_t *mutexId)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         semGive(mutexId->object);
   */

   IFXOS_RETURN_IF_POINTER_NULL(mutexId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_INVALID(mutexId, IFX_ERROR);

   return IFX_SUCCESS;
}

#endif      /* #if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) ) */

/** @} */

#endif      /* #ifdef GENERIC_OS */

