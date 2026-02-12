#ifndef _IFXOS_LINUX_LOCK_H
#define _IFXOS_LINUX_LOCK_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX

/** \file
   This file contains LINUX definitions for Lock / Protect handling 
   for kernel and user space.
*/

/** \defgroup IFXOS_LOCK_LINUX Lock / Protection (Linux).

   This Group contains the LINUX Lock and Protection definition.

\ingroup IFXOS_SYNC_LINUX
*/

/** \defgroup IFXOS_LOCK_LINUX_APPL Lock / Protection (Linux User Space).

   This Group contains the LINUX Lock and Protection definition (User Space).

\par Implementation
   t.b.d

\ingroup IFXOS_LOCK_LINUX
*/

/** \defgroup IFXOS_LOCK_LINUX_DRV Lock / Protection (Linux Kernel).

   This Group contains the LINUX Lock and Protection definition (Kernel Space).

\par Implementation
   The current implementation is based on a binary semaphore and does 
   not allow recursive calls.

\attention
   A call to get the LOCK is not interuptible.
\attention
   Do not use create and get LOCK on interrupt level.

\ingroup IFXOS_LOCK_LINUX
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

   /** IFX LINUX adaptation - support "LOCK feature" */
#  ifndef IFXOS_HAVE_LOCK
#     define IFXOS_HAVE_LOCK                         1
#  endif

   /** IFX LINUX adaptation - support "named LOCK feature" (requires LOCK) */
#  if defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1)
#     ifndef IFXOS_HAVE_NAMED_LOCK
#        define IFXOS_HAVE_NAMED_LOCK                 1
#     endif
#  else
#     ifdef IFXOS_HAVE_NAMED_LOCK
#        undef IFXOS_HAVE_NAMED_LOCK
#     endif
#     define IFXOS_HAVE_NAMED_LOCK                    0
#endif

   /** IFX LINUX adaptation - support "LOCK with timeout feature" */
#  ifndef IFXOS_HAVE_LOCK_TIMEOUT
#     define IFXOS_HAVE_LOCK_TIMEOUT                 1
#  endif


#else

   /** IFX LINUX adaptation - support "LOCK feature" */
#  ifndef IFXOS_HAVE_LOCK
#     define IFXOS_HAVE_LOCK                         1
#  endif

   /** IFX LINUX adaptation - support "LOCK with timeout feature" */
#  ifndef IFXOS_HAVE_LOCK_TIMEOUT
#     define IFXOS_HAVE_LOCK_TIMEOUT                 1
#  endif

   /** IFX LINUX adaptation - support "named LOCK feature" (requires LOCK) */
#  if defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1)
#     ifndef IFXOS_HAVE_NAMED_LOCK
#        define IFXOS_HAVE_NAMED_LOCK                 1
#     endif
#  else
#     ifdef IFXOS_HAVE_NAMED_LOCK
#        undef IFXOS_HAVE_NAMED_LOCK
#     endif
#     define IFXOS_HAVE_NAMED_LOCK                    0
#endif

   /** IFX LINUX adaptation - support "Global LOCK feature" */
#  ifndef IFXOS_HAVE_LOCK_GLOBAL
#     define IFXOS_HAVE_LOCK_GLOBAL                  0
#  endif

#endif      /* #ifdef __KERNEL__ */

#ifdef __KERNEL__
/* ============================================================================
   IFX LINUX adaptation - LOCK types, Kernel
   ========================================================================= */

/** \addtogroup IFXOS_LOCK_LINUX_DRV
@{ */

/** LINUX Kernel - LOCK, type kernel semaphore for synchronisation. */
typedef struct
{
   /** lock id */
   struct semaphore object;
   /** valid flag */
   IFX_boolean_t bValid;
} IFXOS_lock_t;

/** @} */

#else
/* ============================================================================
   IFX LINUX adaptation - LOCK types, User
   ========================================================================= */

/** \addtogroup IFXOS_LOCK_LINUX_APPL
@{ */

#if !defined(USE_PHTREAD_SEM)
#define USE_PHTREAD_SEM 1
#endif

#if (USE_PHTREAD_SEM == 1)
#include <semaphore.h>
#endif

/** LINUX User - LOCK, type kernel semaphore for synchronisation. */
typedef struct
{
   /** lock id */
#if (USE_PHTREAD_SEM == 1)
   sem_t object;  
#else
   int object;
#endif
   /** valid flag */
   IFX_boolean_t bValid;

   /** points to the internal system object - for debugging */
   IFX_void_t  *pSysObject;
} IFXOS_lock_t; 

/** @} */

#endif      /* #ifdef __KERNEL__ */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef LINUX */
#endif      /* #ifndef _IFXOS_LINUX_LOCK_H */

