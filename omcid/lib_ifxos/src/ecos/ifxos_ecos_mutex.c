/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains the IFXOS Layer implementation for eCos 
   Mutex.
*/

/* ============================================================================
   IFX eCos adaptation - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_mutex.h"

/* ============================================================================
   IFX eCos adaptation - MUTEX handling
   ========================================================================= */

/** \addtogroup IFXOS_MUTEX_ECOS
@{ */

#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) )
/**
   eCos - Mutex initialization
*/
IFX_int32_t IFXOS_MutexInit(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_FALSE)
      {
         cyg_mutex_init(&mutexId->object);
         mutexId->bValid = IFX_TRUE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   eCos - Get the Mutex.

\par Implementation
   - Take the specified mutex --> LOCKED (see "cyg_mutex_lock").

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS if operation was successful, else
   IFX_ERROR if something went wrong

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
         if(cyg_mutex_lock(&mutexId->object))
         {
            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}

/**
   eCos - Release the Mutex.

\par Implementation
   - Release the mutex --> UNLOCKED (see "cyg_mutex_unlock").

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR on failure

\remarks
   Cannot be used on interrupt level.

*/
IFX_int32_t IFXOS_MutexRelease(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_TRUE)
      {
         cyg_mutex_unlock(&mutexId->object);

         return IFX_SUCCESS;
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
         cyg_mutex_release(&mutexId->object);
         cyg_mutex_destroy(&mutexId->object);
         mutexId->bValid = IFX_FALSE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) ) */

/** @} */

#endif      /* #ifdef ECOS */

