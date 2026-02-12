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
   Mutex.
*/

/* ============================================================================
   IFX VxWorks adaptation - Global Includes
   ========================================================================= */

#include <vxWorks.h>
#include <intLib.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_mutex.h"

/* ============================================================================
   IFX VxWorks adaptation - MUTEX handling
   ========================================================================= */

/** \addtogroup IFXOS_MUTEX_VXWORKS
@{ */

#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) )
/**
   VxWorks - Mutex init

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
         mutexId->object = semMCreate(SEM_Q_PRIORITY | SEM_INVERSION_SAFE | SEM_DELETE_SAFE);
         mutexId->bValid = IFX_TRUE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   VxWorks - Get the Mutex (not interruptible).

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
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_TRUE)
      {
         if(semTake(mutexId->object, WAIT_FOREVER) == OK)
         {
            return IFX_SUCCESS;
         }
         switch(errno)
         {
            case S_intLib_NOT_ISR_CALLABLE:
            printf("S_intLib_NOT_ISR_CALLABLE\n");
            break;

            case S_objLib_OBJ_ID_ERROR:
            printf("S_objLib_OBJ_ID_ERROR\n");
            break;
            
            case S_objLib_OBJ_UNAVAILABLE:
            printf("S_objLib_OBJ_UNAVAILABLE\n");
            break;
            
            default:
            break;
         }
      }
   }

   return IFX_ERROR;
}

/**
   VxWorks - Release the Mutex.

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
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_TRUE)
      {
         semGive(mutexId->object);

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   VxWorks - Delete the Mutex Object.

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
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_TRUE)
      {
         semDelete(mutexId->object);
         mutexId->bValid = IFX_FALSE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}


#endif      /* #if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) ) */


/** @} */

#endif      /* #ifdef VXWORKS */

