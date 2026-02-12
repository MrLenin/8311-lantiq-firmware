#ifndef _IFXOS_ECOS_DEVICE_ACCESS_H
#define _IFXOS_ECOS_DEVICE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains eCos definitions for Device Access.
*/

/** \defgroup IFXOS_DEVICE_ACCESS_ECOS_APPL Device Access (eCos)

   This Group contains the eCos Device Access definitions and function. 

   The standard system calles (open, close, etc) are mapped to devcie specific
   functions.

   The poll/select mechanism is supported. This requires OS support and a
   corresponding implementation on application and driver side.

\ingroup IFXOS_LAYER_ECOS
*/

#ifdef __cplusplus
   extern "C" {
#endif


/* ============================================================================
   IFX eCos adaptation - Includes
   ========================================================================= */
#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))
#  include "ifxos_device_io.h"
#endif

#include <network.h>     /* _IO macro sys/ioccom.h or lwip/sockets.h */

/* ============================================================================
   IFX eCos adaptation - supported features
   ========================================================================= */

#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))
   /** IFX eCos adaptation - User support "device access" */
#  define IFXOS_HAVE_DEVICE_ACCESS                 1
   /** IFX eCos adaptation - User support "device access - select" */
#  define IFXOS_HAVE_DEVICE_ACCESS_SELECT          1
#else
   /** IFX eCos adaptation - User support "device access" */
#  define IFXOS_HAVE_DEVICE_ACCESS                 0
   /** IFX eCos adaptation - User support "device access - select" */
#  define IFXOS_HAVE_DEVICE_ACCESS_SELECT          0
#endif

/* ============================================================================
   IFX eCos adaptation - types
   ========================================================================= */

#ifndef _IO
   /** required form OS headers */
#  error "missing _IO definiton"
#endif

#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))

/** eCos User - select, type fd_set for device select. */
typedef DEVIO_fd_set_t       IFXOS_devFd_set_t;

#else
/* not implemented yet */
#  error "device access for ECOS not supported"

#endif


#ifdef __cplusplus
}
#endif
#endif      /* #ifdef ECOS */
#endif      /* #ifndef _IFXOS_ECOS_DEVICE_ACCESS_H */


