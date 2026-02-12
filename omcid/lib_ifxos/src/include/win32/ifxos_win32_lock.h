#ifndef _IFXOS_WIN32_LOCK_H
#define _IFXOS_WIN32_LOCK_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32

/** \defgroup IFXOS_LOCK_WIN32 Lock / Protection (Win32).

   This Group contains the VxWorks Lock and Protection definition.

\par Implementation
   The current implementation is based on a binary semaphore and does 
   not allow recursive calls.

\attention
   A call to get the LOCK is not interuptible.
\attention
   Do not use create and get LOCK on interrupt level.

\ingroup IFXOS_LAYER_WIN32
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Win32 adaptation - Includes
   ========================================================================= */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "ifx_types.h"
#include "ifxos_thread.h"

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

/** IFX Win32 adaptation - support "LOCK feature" */
#ifndef IFXOS_HAVE_LOCK
#  define IFXOS_HAVE_LOCK                             1
#endif

/** IFX Win32 adaptation - support "LOCK feature with timeout" */
#ifndef IFXOS_HAVE_LOCK_TIMEOUT
#  define IFXOS_HAVE_LOCK_TIMEOUT                     1
#endif

   /** IFX Win32 adaptation - support "named LOCK feature" (requires LOCK) */
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

   /** IFX Win32 adaptation - support "Global LOCK feature" */
#  ifndef IFXOS_HAVE_LOCK_GLOBAL
#     define IFXOS_HAVE_LOCK_GLOBAL                   0
#  endif

/* ============================================================================
   IFX Win32 adaptation - types
   ========================================================================= */
/** \addtogroup IFXOS_LOCK_WIN32
@{ */

/** Win32 - LOCK, type for synchronisation. */
typedef struct
{
   /** lock id */
   HANDLE object;
   /** valid flag */
   IFX_boolean_t bValid;

   /** points to the internal system object - for debugging */
   IFX_void_t  *pSysObject;
} IFXOS_lock_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_WIN32_LOCK_H */

