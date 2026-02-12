#ifndef _IFXOS_LINUX_DRV_H
#define _IFXOS_LINUX_DRV_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX
#ifdef __KERNEL__

/** \file
   This file contains common definitions used for the Linux OS adaptation for Kernel Space
*/

/** \defgroup IFXOS_IF_DRV_LINUX Defines for Linux Kernel Adaptaion

   This Group contains the Linux specific definitions and function.

\par Linux Kernel Endianess
   Under Linux in Kernel space the Endianess is defined within the corresponding
   architetcture header files.
   The plattform endianess is mapped to the internal used IFXOS endianess definitons.

\attention
   Under Linux only the _LITTLE_ENDIAN or the __BIG_ENDIAN is set, so avoid 
   to use this settings directly !!!

\par Linux Kernel Printouts
   For enable kernel printouts on the console use the following command
   echo 8 > /proc/sys/kernel/printk

\ingroup IFXOS_INTERFACE
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Linux adaptation - Global Includes
   ========================================================================= */

#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/byteorder.h>

#include "ifxos_common.h"

/* ============================================================================
   IFX Linux adaptation - Macro definitions
   ========================================================================= */

/** \addtogroup IFXOS_IF_DRV_LINUX
@{ */

#ifndef KERNEL_VERSION
   /** Macro do interprete the Linux Kernel version. */
#  define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#if defined ( __LITTLE_ENDIAN )
   /** set the internal endianess macro for LITTLE endian */
#  define __BYTE_ORDER                       __LITTLE_ENDIAN
   /** set the common IFXOS byte order for LITTLE endian */
#  define IFXOS_BYTE_ORDER                   IFXOS_LITTLE_ENDIAN
#elif defined ( __BIG_ENDIAN )
   /** set the internal endianess macro for BIG endian */
#  define __BYTE_ORDER                       __BIG_ENDIAN
   /** set the common IFXOS byte order for BIG endian */
#  define IFXOS_BYTE_ORDER                   IFXOS_BIG_ENDIAN
#endif

/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifdef __KERNEL__ */
#endif      /* #ifdef Linux */

#endif      /* #ifndef _IFXOS_LINUX_DRV_H */

