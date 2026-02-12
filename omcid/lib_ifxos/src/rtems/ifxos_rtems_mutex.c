/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains the IFXOS Layer implementation for RTEMS
   Mutex.
*/

/* ============================================================================
   RTEMS adaptation - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_mutex.h"

/* ============================================================================
   RTEMS adaptation - MUTEX handling
   ========================================================================= */

/** \addtogroup IFXOS_MUTEX_RTEMS
@{ */

#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) )

static unsigned int  numName = 0;


/**
   RTEMS - Mutex init

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error.
*/

IFX_int32_t IFXOS_MutexInit(
               IFXOS_mutex_t *mutexId)
{
   char name[4];
   IFXOS_RETURN_IF_POINTER_NULL(mutexId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_VALID(mutexId, IFX_ERROR);

   if(mutexId->object !=0 )
		xsm_delete(mutexId->object);
  xt_entercritical();
  numName++;
  xt_exitcritical();
  sprintf(name, "%x", numName);
  //Q-Type set to FIFO
  if( xsm_create (name, 1L, SM_FIFO, (unsigned long *) &mutexId->object) )
  {
    //xt_exitcritical();
    return IFX_ERROR;
   }
   mutexId->bValid = IFX_TRUE;
   //xt_exitcritical();
   return IFX_SUCCESS;

}

/**
   RTEMS - Delete the Mutex Object.

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
   IFXOS_RETURN_IF_POINTER_NULL(mutexId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_INVALID(mutexId, IFX_ERROR);

  // xt_entercritical();
   if(xsm_delete(mutexId->object))
   {
    //    xt_exitcritical();
        mutexId->bValid = IFX_FALSE;
        return IFX_ERROR;
    }

   //xt_exitcritical();
   return IFX_SUCCESS;
}

/**
   RTEMS - Get the Mutex (not interruptible).

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
   IFXOS_RETURN_IF_POINTER_NULL(mutexId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_INVALID(mutexId, IFX_ERROR);

   if(xsm_p(mutexId->object,SM_WAIT,0))
   {
        return IFX_ERROR;
   }

   return IFX_SUCCESS;
}

/**
   RTEMS - Release the Mutex.

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
   IFXOS_RETURN_IF_POINTER_NULL(mutexId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_INVALID(mutexId, IFX_ERROR);

   if(xsm_v(mutexId->object))
   {
        return IFX_ERROR;
   }
   return IFX_SUCCESS;
}

#endif      /* #if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) ) */

/** @} */

#endif      /* #ifdef RTEMS */

