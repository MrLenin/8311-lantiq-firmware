#ifndef _IFXOS_XAPI_DEVICE_ACCESS_H
#define _IFXOS_XAPI_DEVICE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef XAPI

/** \file
   This file contains XAPI definitions for Device Access.
*/

/** \defgroup IFXOS_DEVICE_ACCESS_XAPI_APPL Device Access (XAPI)

   This Group contains the XAPI Device Access definitions and function. 

   The standard system calles (open, close, etc) are mapped to devcie specific
   functions.

   The poll/select mechanism is supported. This requires OS support and a
   corresponding implementation on application and driver side.

\ingroup IFXOS_LAYER_XAPI
*/

#ifdef __cplusplus
   extern "C" {
#endif


/* ============================================================================
   IFX XAPI adaptation - Includes
   ========================================================================= */
#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))
#  include "ifxos_device_io.h"
#endif

/* ============================================================================
   IFX XAPI adaptation - supported features
   ========================================================================= */

#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))
   /** IFX XAPI adaptation - User support "device access" */
#  define IFXOS_HAVE_DEVICE_ACCESS                 1
   /** IFX XAPI adaptation - User support "device access - select" */
#  define IFXOS_HAVE_DEVICE_ACCESS_SELECT          1
#else
   /** IFX XAPI adaptation - User support "device access" */
#  define IFXOS_HAVE_DEVICE_ACCESS                 0
   /** IFX XAPI adaptation - User support "device access - select" */
#  define IFXOS_HAVE_DEVICE_ACCESS_SELECT          0
#endif

/* ============================================================================
   IFX XAPI adaptation - types
   ========================================================================= */

#ifndef _IO
   /** required form OS headers */
#  define IFXOS_DEFMACRO_IO(x,z)          (((x)<<8)|(z))
#endif

#if (defined(IFXOS_USE_DEV_IO) && (IFXOS_USE_DEV_IO == 1))

/** XAPI User - select, type fd_set for device select. */
typedef DEVIO_fd_set_t       IFXOS_devFd_set_t;

#else
/* not implemented yet */
#  error "device access for XAPI not supported"

#endif


#ifdef __cplusplus
}
#endif
#endif      /* #ifdef XAPI */
#endif      /* #ifndef _IFXOS_XAPI_DEVICE_ACCESS_H */


