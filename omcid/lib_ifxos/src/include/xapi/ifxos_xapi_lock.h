#ifndef _IFXOS_XAPI_LOCK_H
#define _IFXOS_XAPI_LOCK_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef XAPI

/** \file
   This file contains XAPI definitions for Lock / Protect handling.
*/

/** \defgroup IFXOS_LOCK_XAPI Lock / Protection (XAPI).

   This Group contains the XAPI Lock and Protection definition.

\par Implementation
   The current implementation is based on a binary semaphore and does 
   not allow recursive calls.

\attention
   A call to get the LOCK is not interuptible.
\attention
   Do not use create and get LOCK on interrupt level.

\ingroup IFXOS_SYNC_XAPI
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX XAPI adaptation - Includes
   ========================================================================= */
#include <xapi.h>

#include "ifx_types.h"

/* ============================================================================
   IFX XAPI adaptation - supported features
   ========================================================================= */

/** IFX XAPI adaptation - support "LOCK feature" */
#ifndef IFXOS_HAVE_LOCK
#  define IFXOS_HAVE_LOCK                             1
#endif

/** IFX XAPI adaptation - support "LOCK with timeout feature" */
#ifndef IFXOS_HAVE_LOCK_TIMEOUT
#  define IFXOS_HAVE_LOCK_TIMEOUT                     1
#endif

   /** IFX XAPI adaptation - support "named LOCK feature" (requires LOCK) */
#  if defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1)
#     ifndef IFXOS_HAVE_NAMED_LOCK
#        define IFXOS_HAVE_NAMED_LOCK                 0
#     endif
#  else
#     ifdef IFXOS_HAVE_NAMED_LOCK
#        undef IFXOS_HAVE_NAMED_LOCK
#     endif
#     define IFXOS_HAVE_NAMED_LOCK                    0
#endif

/** IFX XAPI adaptation - support "Global LOCK feature" */
#ifndef IFXOS_HAVE_LOCK_GLOBAL
#  define IFXOS_HAVE_LOCK_GLOBAL                      0
#endif

/* ============================================================================
   IFX XAPI adaptation - LOCK types
   ========================================================================= */
/** \addtogroup IFXOS_LOCK_XAPI
@{ */


/** XAPI - LOCK, type for synchronisation. */
typedef struct
{
   /** lock id */
   IFX_ulong_t object;
   /** valid flag */
   IFX_boolean_t bValid;
} IFXOS_lock_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef XAPI */
#endif      /* #ifndef _IFXOS_XAPI_LOCK_H */

