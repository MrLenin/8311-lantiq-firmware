#ifndef _IFXOS_VXWORKS_TIME_H
#define _IFXOS_VXWORKS_TIME_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS
/** \file
   This file contains VxWorks definitions for timer and wait handling.
*/

/** \defgroup IFXOS_TIME_VXWORKS Time and Wait (VxWorks).

   This Group contains the VxWorks time and wait definitions. 

\ingroup IFXOS_LAYER_VXWORKS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX VxWorks adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   IFX VxWorks adaptation - supported features
   ========================================================================= */

/** IFX VxWorks adaptation -  support "sleep in us" */
#ifndef IFXOS_HAVE_TIME_SLEEP_US
#  define IFXOS_HAVE_TIME_SLEEP_US                1
#endif

/** IFX VxWorks adaptation - support "sleep in ms" */
#ifndef IFXOS_HAVE_TIME_SLEEP_MS
#  define IFXOS_HAVE_TIME_SLEEP_MS                1
#endif

/** IFX VxWorks adaptation - support "sleep in sec" */
#ifndef IFXOS_HAVE_TIME_SLEEP_SEC
#  define IFXOS_HAVE_TIME_SLEEP_SEC               1
#endif

/** IFX VxWorks adaptation - support "get elapesed time in us" */
#ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_US
#  define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_US     1
#endif

/** IFX VxWorks adaptation - support "get elapesed time in ms" */
#ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS
#  define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS     1
#endif

/** IFX VxWorks adaptation - support "get elapesed time in sec" */
#ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC
#  define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC    1
#endif

/** IFX VxWorks adaptation - support "get system time in sec" */
#ifndef IFXOS_HAVE_TIME_SYS_TIME_GET
#  define IFXOS_HAVE_TIME_SYS_TIME_GET            1
#endif

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef VXWORKS */
#endif      /* #ifndef _IFXOS_VXWORKS_TIME_H */

