#ifndef _IFXOS_VXWORKS_DEVICE_ACCESS_H
#define _IFXOS_VXWORKS_DEVICE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS

/** \file
   This file contains VxWorks definitions for Device Access.
*/

/** \defgroup IFXOS_DEVICE_ACCESS_VXWORKS_APPL Device Access (VxWorks)

   This Group contains the VxWorks Device Access definitions and function. 

   The standard system calles (open, close, etc) are mapped to devcie specific
   functions.

   The poll/select mechanism is supported. This requires OS support and a
   corresponding implementation on application and driver side.

\ingroup IFXOS_LAYER_VXWORKS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX VxWorks adaptation - Includes
   ========================================================================= */
#include <vxWorks.h>
#include <ioctl.h>
#include <selectLib.h>
#if 0	/* fix it VxWorks 6.4 ? */
#	include <vxWorksCommon.h>
#endif

/* ============================================================================
   IFX VxWorks adaptation - supported features
   ========================================================================= */

/** IFX VxWorks adaptation - User support "device access" */
#ifndef IFXOS_HAVE_DEVICE_ACCESS
#  define IFXOS_HAVE_DEVICE_ACCESS                 1
#endif

/** IFX VxWorks adaptation - User support "device access - select" */
#ifndef IFXOS_HAVE_DEVICE_ACCESS_SELECT
#  define IFXOS_HAVE_DEVICE_ACCESS_SELECT          1
#endif

/* ============================================================================
   IFX VxWorks adaptation - types
   ========================================================================= */

#ifndef _IO
   /** required form OS headers */
#  error "missing _IO definiton"
#endif

/** VxWorks User - select, type fd_set for device select. */
typedef fd_set       IFXOS_devFd_set_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef VXWORKS */
#endif      /* #ifndef _IFXOS_VXWORKS_DEVICE_ACCESS_H */


