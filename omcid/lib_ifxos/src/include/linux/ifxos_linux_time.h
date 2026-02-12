#ifndef _IFXOS_LINUX_TIME_H
#define _IFXOS_LINUX_TIME_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX

/** \file
   This file contains LINUX definitions for timer and wait handling within driver and 
   user (application) space.
*/

/** \defgroup IFXOS_TIME_LINUX Time and Wait Functions (Linux).

   This Group contains the LINUX time and wait definitions.

\note
   Depending on the functionality dedicated defines are available for kernel
   and / or user space.

\ingroup IFXOS_LAYER_LINUX
*/


/** \defgroup IFXOS_TIME_LINUX_DRV Time and Wait Functions (Linux Kernel).

   This Group contains the LINUX time and Sleep definitions used on driver level
   (Kernel Space). 

\ingroup IFXOS_TIME_LINUX
*/

/** \defgroup IFXOS_TIME_LINUX_APPL Time and Wait Functions (Linux User Space).

   This Group contains the LINUX time and Sleep definitions used on 
   application level (Application Space). 

\ingroup IFXOS_TIME_LINUX
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX LINUX adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX LINUX adaptation - supported features
   ========================================================================= */
#ifdef __KERNEL__
   /** IFX LINUX adaptation - Kernel support "sleep in us" */
#  ifndef IFXOS_HAVE_TIME_SLEEP_US
#     define IFXOS_HAVE_TIME_SLEEP_US                1
#  endif

   /** IFX LINUX adaptation - Kernel support "sleep in ms" */
#  ifndef IFXOS_HAVE_TIME_SLEEP_MS
#     define IFXOS_HAVE_TIME_SLEEP_MS                1
#  endif
   /** IFX LINUX adaptation - Kernel support "get elapesed time in ms" */
#  ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS
#     define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS     1
#  endif

   /** IFX LINUX adaptation - Kernel support "sleep in sec" */
#  ifndef IFXOS_HAVE_TIME_SLEEP_SEC
#     define IFXOS_HAVE_TIME_SLEEP_SEC               0
#  endif

   /** IFX LINUX adaptation - Kernel support "get elapesed time in sec" */
#  ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC
#     define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC    0 
#  endif

   /** IFX LINUX adaptation - support "get system time in sec" */
#  ifndef IFXOS_HAVE_TIME_SYS_TIME_GET             
#     define IFXOS_HAVE_TIME_SYS_TIME_GET            0
#  endif

#else

   /** IFX LINUX adaptation - User support "sleep in ms" */
#  ifndef IFXOS_HAVE_TIME_SLEEP_MS
#     define IFXOS_HAVE_TIME_SLEEP_MS                1
#  endif

   /** IFX LINUX adaptation - User support "get elapesed time in ms" */
#  ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS
#     define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_MS     1
#  endif

   /** IFX LINUX adaptation - User support "sleep in sec" */
#  ifndef IFXOS_HAVE_TIME_SLEEP_SEC
#     define IFXOS_HAVE_TIME_SLEEP_SEC               1
#  endif

   /** IFX LINUX adaptation - User support "get elapesed time in sec" */
#  ifndef IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC
#     define IFXOS_HAVE_TIME_ELAPSED_TIME_GET_SEC    1
#  endif

   /** IFX LINUX adaptation - support "get system time in sec" */
#  ifndef IFXOS_HAVE_TIME_SYS_TIME_GET
#     define IFXOS_HAVE_TIME_SYS_TIME_GET            1
#  endif

#endif

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef LINUX */
#endif      /* #ifndef _IFXOS_LINUX_TIME_H */

