#ifndef _IFXOS_NUCLEUS_TIME_H
#define _IFXOS_NUCLEUS_TIME_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS
/** \file
   This file contains Nucleus definitions for timer and wait handling.
*/

/** \defgroup IFXOS_TIME_NUCLEUS Time and Wait (Nucleus).

   This Group contains the Nucleus time and wait definitions. 

\ingroup IFXOS_LAYER_NUCLEUS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Nucleus adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   IFX Nucleus adaptation - supported features
   ========================================================================= */

/** IFX Nucleus adaptation - support "sleep in us" */
#ifndef IFXOS_HAVE_TIME_SLEEP_US
#  define IFXOS_HAVE_TIME_SLEEP_US                1
#endif

/** IFX Nucleus adaptation - support "sleep in ms" */
#ifndef IFXOS_HAVE_TIME_SLEEP_MS
#  define IFXOS_HAVE_TIME_SLEEP_MS                1
#endif

/** IFX Nucleus adaptation - support "sleep in sec" */
#ifndef IFXOS_HAVE_TIME_SLEEP_SEC
#  define IFXOS_HAVE_TIME_SLEEP_SEC               1
#endif

/** IFX Nucleus adaptation - support "get elapesed time in ms" */
#ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS
#  define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS     1
#endif

/** IFX Nucleus adaptation - support "get elapesed time in sec" */
#ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC
#  define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC    1
#endif

/** IFX Nucleus adaptation - support "get system time in sec" */
#ifndef IFXOS_HAVE_TIME_SYS_TIME_GET
#  define IFXOS_HAVE_TIME_SYS_TIME_GET            1
#endif

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef NUCLEUS_PLUS */
#endif      /* #ifndef _IFXOS_NUCLEUS_TIME_H */

