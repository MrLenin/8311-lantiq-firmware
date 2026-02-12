#ifndef _IFXOS_WIN32_DEVICE_ACCESS_H
#define _IFXOS_WIN32_DEVICE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32

/** \file
   This file contains VxWorks definitions for Device Access.
*/

/** \defgroup IFXOS_DEVICE_ACCESS_WIN32_APPL Device Access (Win32)

   This Group contains the Win32 Device Access definitions and function. 

   The standard system calles (open, close, etc) are mapped to devcie specific
   functions.

   The poll/select mechanism is supported. This requires OS support and a
   corresponding implementation on application and driver side.

\ingroup IFXOS_LAYER_WIN32
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Win32 adaptation - Includes
   ========================================================================= */
#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))
#include "ifxos_device_io.h"
#endif
#include <Winsock2.h>         /* _IO define */

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))
/** IFX Win32 adaptation - User support "device access" */
#define IFXOS_HAVE_DEVICE_ACCESS                1
/** IFX Win32 adaptation - User support "device access - select" */
#define IFXOS_HAVE_DEVICE_ACCESS_SELECT         1
#else
/** IFX Win32 adaptation - User support "device access" */
#define IFXOS_HAVE_DEVICE_ACCESS                0
/** IFX Win32 adaptation - User support "device access - select" */
#define IFXOS_HAVE_DEVICE_ACCESS_SELECT         0
#endif

/* ============================================================================
   IFX Win32 adaptation - types
   ========================================================================= */

#ifndef _IO
   /** IO-control macro (under Win32 defined in winsock-header) */
#  define IFXOS_IOC_VOID                  0x20000000      /* no parameters */
#  define IFXOS_DEFMACRO_IO(x,z)          (IFXOS_IOC_VOID|((x)<<8)|(z))

#  pragma message("Use own _IO definitions")
#endif


#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))

/** Win32 User - select, type fd_set for device select. */
typedef DEVIO_fd_set_t     IFXOS_devFd_set_t;

#else
#  error "device access for Win32 not supported"
#endif

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_WIN32_DEVICE_ACCESS_H */

