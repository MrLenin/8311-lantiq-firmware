#ifndef _IFXOS_WIN32_MUTEX_H
#define _IFXOS_WIN32_MUTEX_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32

/** \defgroup IFXOS_MUTEX_WIN32 Mutex(Win32).

   This Group contains the Win32 Mutex definition.

\par Implementation
   The current implementation is based on a CriticalSection handling.

\attention
   A call to get the MUTEX is not interuptible.
\attention
   Do not use create and get MUTEX on interrupt level.

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

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

/** IFX Win32 adaptation - support "MUTEX feature" */
#ifndef IFXOS_HAVE_MUTEX
#  define IFXOS_HAVE_MUTEX                            1
#endif

/* ============================================================================
   IFX Win32 adaptation - types
   ========================================================================= */
/** \addtogroup IFXOS_MUTEX_WIN32
@{ */

/** Win32 - MUTEX, type for synchronisation. */
typedef struct
{
   /** mutex identifier */
   CRITICAL_SECTION object;
   /** valid flag */
   IFX_boolean_t bValid;
} IFXOS_mutex_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_WIN32_MUTEX_H */

