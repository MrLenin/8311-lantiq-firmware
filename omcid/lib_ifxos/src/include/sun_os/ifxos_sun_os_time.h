#ifndef _IFXOS_SUN_OS_TIME_H
#define _IFXOS_SUN_OS_TIME_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(SUN_OS)

/** \file
   This file contains SunOS definitions for timer and wait handling within driver and 
   user (application) space.
*/

/** \defgroup IFXOS_TIME_SUN_OS Time and Wait Functions (Linux).

   This Group contains the SunOS time and wait definitions.


\ingroup IFXOS_LAYER_SUN_OS
*/


/** \defgroup IFXOS_TIME_SUN_OS_APPL Time and Wait Functions (SunOS User Space).

   This Group contains the SunOS time and Sleep definitions used on 
   application level (Application Space). 

\ingroup IFXOS_TIME_SUN_OS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX SunOS adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX SunOS adaptation - supported features
   ========================================================================= */
#ifdef __KERNEL__
   /** IFX SunOS adaptation - Kernel support "sleep in us" */
#  ifndef IFXOS_HAVE_TIME_SLEEP_US
#     define IFXOS_HAVE_TIME_SLEEP_US                0
#  endif

   /** IFX SunOS adaptation - Kernel support "sleep in ms" */
#  ifndef IFXOS_HAVE_TIME_SLEEP_MS
#     define IFXOS_HAVE_TIME_SLEEP_MS                0
#  endif
   /** IFX SunOS adaptation - Kernel support "get elapesed time in ms" */
#  ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS
#     define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS     0
#  endif

   /** IFX SunOS adaptation - Kernel support "sleep in sec" */
#  ifndef IFXOS_HAVE_TIME_SLEEP_SEC
#     define IFXOS_HAVE_TIME_SLEEP_SEC               0
#  endif

   /** IFX SunOS adaptation - Kernel support "get elapesed time in sec" */
#  ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC
#     define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC    0 
#  endif

   /** IFX SunOS adaptation - support "get system time in sec" */
#  ifndef IFXOS_HAVE_TIME_SYS_TIME_GET             
#     define IFXOS_HAVE_TIME_SYS_TIME_GET            0
#  endif

#else

   /** IFX SunOS adaptation - User support "sleep in ms" */
#  ifndef IFXOS_HAVE_TIME_SLEEP_MS
#     define IFXOS_HAVE_TIME_SLEEP_MS                1
#  endif

   /** IFX SunOS adaptation - User support "get elapesed time in ms" */
#  ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS
#     define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS     1
#  endif

   /** IFX SunOS adaptation - User support "sleep in sec" */
#  ifndef IFXOS_HAVE_TIME_SLEEP_SEC
#     define IFXOS_HAVE_TIME_SLEEP_SEC               1
#  endif

   /** IFX SunOS adaptation - User support "get elapesed time in sec" */
#  ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC
#     define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC    1
#  endif

   /** IFX SunOS adaptation - support "get system time in sec" */
#  ifndef IFXOS_HAVE_TIME_SYS_TIME_GET
#     define IFXOS_HAVE_TIME_SYS_TIME_GET            1
#  endif

#endif

#ifdef __cplusplus
}
#endif
#endif      /* #if defined(SUN_OS) */
#endif      /* #ifndef _IFXOS_SUN_OS_TIME_H */

