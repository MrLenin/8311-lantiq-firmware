#ifndef _IFXOS_LINUX_MUTEX_H
#define _IFXOS_LINUX_MUTEX_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX

/** \file
   This file contains LINUX definitions for Mutex handling 
   for kernel and user space.
*/

/** \defgroup IFXOS_MUTEX_LINUX Mutex(Linux).

   This Group contains the LINUX Mutex definition.

\ingroup IFXOS_SYNC_LINUX
*/

/** \defgroup IFXOS_MUTEX_LINUX_APPL Mutex(Linux User Space).

   This Group contains the LINUX Mutex definition (User Space).

\ingroup IFXOS_MUTEX_LINUX
*/

/** \defgroup IFXOS_MUTEX_LINUX_DRV Mutex(Linux Kernel).

   This Group contains the LINUX Mutex definition (Kernel Space).

\par Implementation
   The current implementation is based on a binary semaphore and does 
   not allow recursive calls.

\attention
   A call to get the MUTEX is not interuptible.
\attention
   Do not use create and get MUTEX on interrupt level.

\ingroup IFXOS_MUTEX_LINUX
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX LINUX adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

#ifdef __KERNEL__
#  include <linux/version.h>
#  if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26))
#     include <asm/semaphore.h>
#  else
#     include <linux/semaphore.h>
#  endif
#else
#endif

/* ============================================================================
   IFX LINUX adaptation - supported features
   ========================================================================= */
#ifdef __KERNEL__

   /** IFX LINUX adaptation - support "MUTEX feature" */
#  ifndef IFXOS_HAVE_MUTEX
#     define IFXOS_HAVE_MUTEX                         1
#  endif

#else

   /** IFX LINUX adaptation - support "MUTEX feature" */
#  ifndef IFXOS_HAVE_MUTEX
#     define IFXOS_HAVE_MUTEX                         1
#  endif

#endif      /* #ifdef __KERNEL__ */

#ifdef __KERNEL__
/* ============================================================================
   IFX LINUX adaptation - MUTEX types, Kernel
   ========================================================================= */

/** \addtogroup IFXOS_MUTEX_LINUX_DRV
@{ */

/** LINUX Kernel - MUTEX, type kernel semaphore for synchronisation. */
typedef struct
{
   /** mutex identifier */
   struct semaphore object;
   /** valid flag */
   IFX_boolean_t bValid;
} IFXOS_mutex_t;

/** @} */

#else
/* ============================================================================
   IFX LINUX adaptation - MUTEX types, User
   ========================================================================= */

#include <pthread.h>

/** \addtogroup IFXOS_MUTEX_LINUX_APPL
@{ */

/** LINUX User - MUTEX, type kernel semaphore for synchronisation. */
typedef struct
{
   /** mutex identifier */
   pthread_mutex_t object;
   /** valid flag */
   IFX_boolean_t bValid;
} IFXOS_mutex_t;
/** @} */

#endif      /* #ifdef __KERNEL__ */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef LINUX */
#endif      /* #ifndef _IFXOS_LINUX_MUTEX_H */

