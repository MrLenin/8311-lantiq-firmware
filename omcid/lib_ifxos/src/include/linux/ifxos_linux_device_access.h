#ifndef _IFXOS_LINUX_DEVICE_ACCESS_H
#define _IFXOS_LINUX_DEVICE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX

/** \file
   This file contains LINUX definitions for Device Access.
*/

/** \defgroup IFXOS_DEVICE_ACCESS_LINUX_APPL Device Access (Linux User Space)

   This Group contains the LINUX Device Access definitions and function. 

   The standard system calles (open, close, etc) are mapped to devcie specific
   functions.

   The poll/select mechanisme is supported. This requires OS support and a
   corresponding implementation on user and driver side.

\ingroup IFXOS_LAYER_LINUX
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX LINUX adaptation - Includes
   ========================================================================= */
#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))
#  include "ifxos_device_io.h"
#else
#  include <sys/select.h>
#endif

#include <sys/ioctl.h>

/* ============================================================================
   IFX LINUX adaptation - supported features
   ========================================================================= */

/** IFX LINUX adaptation - User support "device access" */
#ifndef IFXOS_HAVE_DEVICE_ACCESS                  
#  define IFXOS_HAVE_DEVICE_ACCESS                 1
#endif

/** IFX LINUX adaptation - User support "device access - select" */
#ifndef IFXOS_HAVE_DEVICE_ACCESS_SELECT           
#  define IFXOS_HAVE_DEVICE_ACCESS_SELECT          1
#endif

/* ============================================================================
   IFX LINUX adaptation - types
   ========================================================================= */

#ifndef _IO
   /** required form OS headers */
#  error "missing _IO definiton"
#endif

#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))

/** eCos User - select, type fd_set for device select. */
typedef DEVIO_fd_set_t       IFXOS_devFd_set_t;

#else

/** LINUX User - select, type fd_set for device select. */
typedef fd_set       IFXOS_devFd_set_t;

#endif

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef LINUX */
#endif      /* #ifndef _IFXOS_LINUX_DEVICE_ACCESS_H */


