#ifndef _IFXOS_MUTEX_H
#define _IFXOS_MUTEX_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for Mutex handling for driver and 
   user (application) space.
*/

/** \defgroup IFXOS_IF_MUTEX Mutex / Protection.

   This Group contains the Mutex and Protection definitions and function. 

   The current implementation is based on a binary semaphore and does 
   not allow recursive calls.

\attention
   A call to get the MUTEX is not interuptible.

\attention
   Do not use get MUTEX on interrupt level.

\ingroup IFXOS_IF_SYNC
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Includes
   ========================================================================= */
#if ( !defined(IFXOS_FLAT_HIRACHY) || (IFXOS_FLAT_HIRACHY == 0) )
#  if defined(LINUX)
#     include "linux/ifxos_linux_mutex.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_mutex.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_mutex.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_mutex.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_mutex.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_mutex.h"
#  elif defined(XAPI)
#     include "xapi/ifxos_xapi_mutex.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_mutex.h"
#  else
#     error "Mutex Adaptation - Please define your OS"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_mutex.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_mutex.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_mutex.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_mutex.h"
#  elif defined(WIN32)
#     include "ifxos_win32_mutex.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_mutex.h"
#  elif defined(XAPI)
#     include "ifxos_xapi_mutex.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_mutex.h"
#  else
#     error "Mutex Adaptation - Please define your OS"
#  endif
#endif

#include "ifx_types.h"


/* ============================================================================
   IFX OS adaptation - MUTEX handling, functions
   ========================================================================= */

/** \addtogroup IFXOS_IF_MUTEX
@{ */

#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) )

/**
   Check the init status of the given mutex object
*/
#define IFXOS_MUTEX_INIT_VALID(P_MUTEX_ID)\
   (((P_MUTEX_ID)) ? (((P_MUTEX_ID)->bValid == IFX_TRUE) ? IFX_TRUE : IFX_FALSE) : IFX_FALSE)

/**
   IFX OS adaptation - MUTEX Init

\param
   mutexId   Pointer to the Mutex Object.
   
*/
IFX_int32_t IFXOS_MutexInit(
               IFXOS_mutex_t *mutexId);

/**
   Delete the Mutex.

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error or timeout.
*/
IFX_int32_t IFXOS_MutexDelete(
               IFXOS_mutex_t *mutexId);

/**
   Get the Mutex (not interruptible).

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error.
*/
IFX_int32_t IFXOS_MutexGet(
               IFXOS_mutex_t *mutexId);

/**
   Release the Mutex.

\param
   mutexId   Pointer to the Mutex Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error or timeout.
*/
IFX_int32_t IFXOS_MutexRelease(
               IFXOS_mutex_t *mutexId);


#endif      /* #if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) ) */

/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_MUTEX_H */

