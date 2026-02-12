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
   Mutex.
*/

/* ============================================================================
   IFX XAPI adaptation - Global Includes
   ========================================================================= */

#include <xapi.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_mutex.h"

/* ============================================================================
   IFX XAPI adaptation - MUTEX handling
   ========================================================================= */

/** \addtogroup IFXOS_MUTEX_XAPI
@{ */

#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) )
/**
   XAPI - Mutex init
*/
IFX_int32_t IFXOS_MutexInit(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_FALSE)
      {
         xsm_create ("IFU", 1L, 0, &(mutexId->object));
         mutexId->bValid = IFX_TRUE;
         
         return IFX_SUCCESS;
         
      }
   }

   return IFX_ERROR;
}

/**
   XAPI - Get the Mutex (not interruptible).

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
         if (xsm_p(mutexId->object, 0, 0) == 0)
         {
            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}

/**
   XAPI - Release the Mutex.

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
         if (!xsm_v(mutexId->object))
         {
            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}


/**
   XAPI - Delete the Mutex Object.

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
         /* FIXME - delete the mutex under XAPI */
         mutexId->bValid = IFX_FALSE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}


#endif      /* #if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) ) */


/** @} */

#endif      /* #ifdef XAPI */

