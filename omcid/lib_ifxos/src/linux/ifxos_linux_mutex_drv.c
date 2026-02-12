/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation - lock handling (Kernel Space)
   ========================================================================= */

#ifdef LINUX
#ifdef __KERNEL__

/** \file
   This file contains the IFXOS Layer implementation for LINUX Kernel 
   Mutex.
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes - Kernel
   ========================================================================= */

#include <linux/kernel.h>
#ifdef MODULE
   #include <linux/module.h>
#endif
#include <linux/sched.h>

#include "ifx_types.h"
#include "ifxos_mutex.h"

/* ============================================================================
   IFX Linux adaptation - Kernel MUTEX handling
   ========================================================================= */

/** \addtogroup IFXOS_MUTEX_LINUX_DRV
@{ */
#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) )

/**
   IFX Linux adaptation  - Mutex Object init

\param
   mutexId   Pointer to the Mutex Object.
*/
IFX_int32_t IFXOS_MutexInit(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_FALSE)
      {
         sema_init(&mutexId->object, 1);
         mutexId->bValid = IFX_TRUE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}


/**
   LINUX Kernel - Get the Mutex (not interruptible).

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error.

\remarks
   - Cannot be used on interrupt level.
   - Blocking call, not interruptible.
*/
IFX_int32_t IFXOS_MutexGet(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_TRUE)
      {
         down(&mutexId->object);

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   LINUX Kernel - Release the Mutex.

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
         up(&mutexId->object);

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}


/**
   LINUX Kernel - Delete the given Mutex Object.

\param
   mutexId   Provides the pointer to the Mutex Object.

\return
   IFX_SUCCESS if delete was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int32_t IFXOS_MutexDelete(
               IFXOS_mutex_t *mutexId)
{
   if(mutexId)
   {
      if (IFXOS_MUTEX_INIT_VALID(mutexId) == IFX_TRUE)
      {
         mutexId->bValid = IFX_FALSE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) ) */
/** @} */

#ifdef MODULE
EXPORT_SYMBOL(IFXOS_MutexInit);
EXPORT_SYMBOL(IFXOS_MutexGet);
EXPORT_SYMBOL(IFXOS_MutexRelease);
EXPORT_SYMBOL(IFXOS_MutexDelete);
#endif

#endif      /* #ifdef __KERNEL__ */
#endif      /* #ifdef LINUX */


