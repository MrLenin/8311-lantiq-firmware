#ifndef _IFXOS_LINUX_PRINT_H
#define _IFXOS_LINUX_PRINT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX
/** \file
   This file contains LINUX definitions for Printout.
*/

/** \defgroup IFXOS_PRINT_LINUX Printout Defines (Linux)

   This Group contains the LINUX Printout definitions.

   Here we have to differ between:\n
   - printout from user space (application code).
   - printout form kernel space (driver code).

\ingroup IFXOS_LAYER_LINUX
*/

/** \defgroup IFXOS_PRINT_LINUX_APPL Printout Defines (Linux User Space)

   This Group contains the LINUX Printout definitions.

\par Implementation
   Printout from user space (application) will use the standard printf function

\ingroup IFXOS_PRINT_LINUX
*/

/** \defgroup IFXOS_PRINT_LINUX_DRV Printout Defines (Linux Kernel)

   This Group contains the LINUX Kernel Printout definitions.

\par Implementation
   Printout from kernel space is done via the printk funciton

   For enable kernel printouts on the console you have to make sure that the 
   printout is enabled on system level. For enable use the following command:
   # echo 8 > /proc/sys/kernel/printk

\ingroup IFXOS_PRINT_LINUX
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX LINUX adaptation - Includes
   ========================================================================= */

#ifdef __KERNEL__
#include <linux/kernel.h>
#else
#include <stdio.h>
#endif

/* ============================================================================
   IFX LINUX adaptation - supported features
   ========================================================================= */
#ifdef __KERNEL__
   /** IFX LINUX adaptation - Kernel space, support "PRINT feature" */
#  ifndef IFXOS_HAVE_PRINT
#     define IFXOS_HAVE_PRINT                         1
#  endif
   /** IFX LINUX adaptation - User space, support "PRINT via output stream" */
#  ifndef IFXOS_HAVE_PRINT_STREAM
#     define IFXOS_HAVE_PRINT_STREAM                  0
#  endif

   /** IFX LINUX adaptation - Kernel space, support "PRINT External debug function" */
#  ifndef IFXOS_HAVE_PRINT_EXT_DBG_FCT
#     define IFXOS_HAVE_PRINT_EXT_DBG_FCT             0
#  endif

   /** IFX LINUX adaptation - Kernel space, support "PRINT External error function" */
#  ifndef IFXOS_HAVE_PRINT_EXT_ERR_FCT
#     define IFXOS_HAVE_PRINT_EXT_ERR_FCT             0
#  endif

#else

   /** IFX LINUX adaptation - User space, support "PRINT feature" */
#  ifndef IFXOS_HAVE_PRINT
#     define IFXOS_HAVE_PRINT                         1
#  endif

   /** IFX LINUX adaptation - User space, support "PRINT via output stream" */
#  ifndef IFXOS_HAVE_PRINT_STREAM
#     define IFXOS_HAVE_PRINT_STREAM                  1
#  endif

   /** IFX LINUX adaptation - Kernel space, support "PRINT External debug function" */
#  ifndef IFXOS_HAVE_PRINT_EXT_DBG_FCT
#     define IFXOS_HAVE_PRINT_EXT_DBG_FCT             1
#  endif

   /** IFX LINUX adaptation - Kernel space, support "PRINT External error function" */
#  ifndef IFXOS_HAVE_PRINT_EXT_ERR_FCT
#     define IFXOS_HAVE_PRINT_EXT_ERR_FCT             1
#  endif

#endif      /* #ifdef __KERNEL__ */


#ifdef __KERNEL__
/* ============================================================================
   IFX LINUX adaptation - Kernel Space, PRINT defines
   ========================================================================= */
/** \addtogroup IFXOS_PRINT_LINUX_DRV
@{ */

/** Define the used CR/LF sequence */
#define IFXOS_CRLF                              "\n"

   /** Kernel - Debug Print on Int-Level (formated) */
#define IFXOS_DBG_PRINT_INT(fmt, args...)       printk(KERN_DEBUG fmt "\n", ##args)
   /** Kernel - Debug Print on Appl-Level (formated) */
#define IFXOS_DBG_PRINT_USR(fmt, args...)       printk(KERN_DEBUG fmt "\n", ##args)

   /** Kernel - Error Print on Int-Level (formated) */
#define IFXOS_ERR_PRINT_INT(fmt, args...)       printk(KERN_DEBUG fmt "\n", ##args)
   /** Kernel - Error Print on Appl-Level (formated) */
#define IFXOS_ERR_PRINT_USR(fmt, args...)       printk(KERN_DEBUG fmt "\n", ##args)


   /** Kernel - Print on Int-Level (unformated) */
#define IFXOS_PRINT_INT_RAW(fmt, args...)       printk(fmt, ##args)
   /** Kernel - Print on Appl-Level (unformated) */
#define IFXOS_PRINT_USR_RAW(fmt, args...)       printk(fmt, ##args)

/** @} */

#else       /* #ifdef __KERNEL__ */
/* ============================================================================
   IFX LINUX adaptation - User Space, PRINT defines
   ========================================================================= */
/** \addtogroup IFXOS_PRINT_LINUX_APPL
@{ */

/** Define the used CR/LF sequence */
#  define IFXOS_CRLF                            "\n"

   /** User - Debug Print on Int-Level (formated) */
#  define IFXOS_DBG_PRINT_INT                   IFXOS_fctDbgPrintf
   /** User - Debug Print on Appl-Level (formated) */
#  define IFXOS_DBG_PRINT_USR                   IFXOS_fctDbgPrintf

   /** User - Error Print on Int-Level (formated) */
#  define IFXOS_ERR_PRINT_INT                   IFXOS_fctErrPrintf
   /** User - Error Print on Appl-Level (formated) */
#  define IFXOS_ERR_PRINT_USR                   IFXOS_fctErrPrintf

   /** User - Print on Int-Level (unformated) */
#  define IFXOS_PRINT_INT_RAW                   IFXOS_fctDbgPrintf
   /** User - Print on Appl-Level (unformated) */
#  define IFXOS_PRINT_USR_RAW                   IFXOS_fctDbgPrintf

/** @} */

#endif      /* #ifdef __KERNEL__ */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef LINUX */
#endif      /* #ifndef _IFXOS_LINUX_PRINT_H */

