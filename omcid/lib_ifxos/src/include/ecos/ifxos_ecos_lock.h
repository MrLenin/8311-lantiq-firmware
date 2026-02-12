#ifndef _IFXOS_ECOS_LOCK_H
#define _IFXOS_ECOS_LOCK_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains eCos definitions for Lock / Protect handling.
*/

/** \defgroup IFXOS_LOCK_ECOS Lock / Protection (eCos).

   This Group contains the eCos Lock and Protection definition.

\par Implementation
   The current implementation is based on a binary semaphore and does 
   not allow recursive calls.

\attention
   A call to get the LOCK is not interuptible.
\attention
   Do not use create and get LOCK on interrupt level.

\ingroup IFXOS_SYNC_ECOS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX eCos adaptation - Includes
   ========================================================================= */
#include <cyg/kernel/kapi.h>  /* All the kernel specific stuff like cyg_flag_t, ... */


/* ============================================================================
   IFX eCos adaptation - supported features
   ========================================================================= */

/** IFX eCos adaptation - support "LOCK feature" */
#ifndef IFXOS_HAVE_LOCK
#  define IFXOS_HAVE_LOCK                             1
#endif

/** IFX eCos adaptation - support "LOCK with timeout feature" */
#ifndef IFXOS_HAVE_LOCK_TIMEOUT
#  define IFXOS_HAVE_LOCK_TIMEOUT                     1
#endif

   /** IFX eCos adaptation - support "named LOCK feature" (requires LOCK) */
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

/** IFX eCos adaptation - support "Global LOCK feature" */
#ifndef IFXOS_HAVE_LOCK_GLOBAL
#  define IFXOS_HAVE_LOCK_GLOBAL                      0
#endif

/* ============================================================================
   IFX eCos adaptation - LOCK types
   ========================================================================= */
/** \addtogroup IFXOS_LOCK_ECOS
@{ */


/** eCos - Identifier for not initialized lock object */
#define IFXOS_LOCK_NOT_INIT         IFX_NULL

/** eCos - LOCK, type for synchronisation. */
typedef struct
{
   /** lock id */
   cyg_sem_t object;
   /** valid flag */
   IFX_boolean_t bValid;

   /** points to the internal system object - for debugging */
   IFX_void_t  *pSysObject;
} IFXOS_lock_t; 

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef ECOS */
#endif      /* #ifndef _IFXOS_ECOS_LOCK_H */

