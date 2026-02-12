#ifndef _IFXOS_WIN32_TIME_H
#define _IFXOS_WIN32_TIME_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32

/** \file
   This file contains Win32 definitions for timer and wait handling.
*/

/** \defgroup IFXOS_TIME_WIN32 Time and Wait (Win32).

   This Group contains the Win32 time and wait definitions. 

\ingroup IFXOS_LAYER_WIN32
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Win32 adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

/** IFX Win32 adaptation - support "sleep in us" */
#ifndef IFXOS_HAVE_TIME_SLEEP_US
#  define IFXOS_HAVE_TIME_SLEEP_US                1
#endif

/** IFX Win32 adaptation - support "sleep in ms" */
#ifndef IFXOS_HAVE_TIME_SLEEP_MS
#  define IFXOS_HAVE_TIME_SLEEP_MS                1
#endif

/** IFX Win32 adaptation - support "sleep in sec" */
#ifndef IFXOS_HAVE_TIME_SLEEP_SEC
#  define IFXOS_HAVE_TIME_SLEEP_SEC               1
#endif

/** IFX Win32 adaptation - support "get elapesed time in ms" */
#ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS
#  define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS     1
#endif

/** IFX Win32 adaptation - support "get elapesed time in sec" */
#ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC
#  define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC    1
#endif

/** IFX Win32 adaptation - support "get system time in sec" */
#ifndef IFXOS_HAVE_TIME_SYS_TIME_GET
#  define IFXOS_HAVE_TIME_SYS_TIME_GET            1
#endif

/* ============================================================================
   IFX Win32 adaptation - types
   ========================================================================= */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_WIN32_TIME_H */

