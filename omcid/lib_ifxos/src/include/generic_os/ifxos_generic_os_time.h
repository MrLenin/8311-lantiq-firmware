#ifndef _IFXOS_GENERIC_OS_TIME_H
#define _IFXOS_GENERIC_OS_TIME_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS
/** \file
   This file contains Generic OS definitions for timer and wait handling.
*/

/** \defgroup IFXOS_TIME_GENERIC_OS Time and Wait (Generic OS).

   This Group contains the Generic OS time and wait definitions. 

\ingroup IFXOS_LAYER_GENERIC_OS
*/

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
   IFX Generic OS adaptation - Includes
   ========================================================================= */


/* ============================================================================
   IFX Generic OS adaptation - supported features
   ========================================================================= */

/** IFX Generic OS adaptation -  support "sleep in us" */
#ifndef IFXOS_HAVE_TIME_SLEEP_US
#define IFXOS_HAVE_TIME_SLEEP_US                1
#endif

/** IFX Generic OS adaptation - support "sleep in ms" */
#ifndef IFXOS_HAVE_TIME_SLEEP_MS
#define IFXOS_HAVE_TIME_SLEEP_MS                1
#endif

/** IFX Generic OS adaptation - support "sleep in sec" */
#ifndef IFXOS_HAVE_TIME_SLEEP_SEC
#define IFXOS_HAVE_TIME_SLEEP_SEC               1
#endif

/** IFX Generic OS adaptation - support "get elapesed time in us" */
#ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_US
#define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_US     1
#endif

/** IFX Generic OS adaptation - support "get elapesed time in ms" */
#ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS
#define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS     1
#endif

/** IFX Generic OS adaptation - support "get elapesed time in sec" */
#ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC
#define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC    1
#endif

/** IFX Generic OS adaptation - support "get system time in sec" */
#ifndef IFXOS_HAVE_TIME_SYS_TIME_GET
#define IFXOS_HAVE_TIME_SYS_TIME_GET            1
#endif

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef GENERIC_OS */
#endif      /* #ifndef _IFXOS_GENERIC_OS_TIME_H */

