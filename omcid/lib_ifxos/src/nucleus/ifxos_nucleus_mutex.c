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
   Mutex.
*/

/* ============================================================================
   IFX Nucleus adaptation - Global Includes
   ========================================================================= */

#include <nucleus.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_mutex.h"

/* ============================================================================
   IFX Nucleus adaptation - MUTEX handling
   ========================================================================= */

/** \addtogroup IFXOS_MUTEX_NUCLEUS
@{ */

#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) )
/**
   Nucleus - Mutex init
*/
IFX_int32_t IFXOS_MutexInit(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_FALSE)
      {
         if(NU_Create_Semaphore(&mutexId->object, "sem", 1, NU_PRIORITY) == NU_SUCCESS)
         {
            mutexId->bValid = IFX_TRUE;

            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}

/**
   Nucleus - Get the Mutex (not interruptible).

\par Implementation

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
         /* Blocking call */
         if(NU_Obtain_Semaphore(&mutexId->object, NU_SUSPEND) == NU_SUCCESS)
         {
            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}

/**
   Nucleus - Release the Mutex.

\par Implementation

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
         if (NU_Release_Semaphore(&mutexId->object) == NU_SUCCESS)
         {
            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}


/**
   Nucleus - Delete the Mutex Object.

\par Implementation
   - Delete the mutex --> UNLOCKED (see "cyg_mutex_destroy, cyg_mutex_release").

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
         /* FIXME - delete the mutex under Nucleus */
         mutexId->bValid = IFX_FALSE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}


#endif      /* #if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) ) */


/** @} */

#endif      /* #ifdef NUCLEUS_PLUS */

