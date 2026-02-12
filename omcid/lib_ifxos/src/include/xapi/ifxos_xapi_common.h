#ifndef _IFXOS_XAPI_COMMON_H
#define _IFXOS_XAPI_COMMON_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef XAPI
/** \file
   This file contains common definitions used for the XAPI OS adaption
*/

/* ============================================================================
   IFX XAPI adaptation
   ========================================================================= */

/** \defgroup IFXOS_IF_XAPI Defines for VxWorks Adaptaion

   This Group contains the VxWorks specific definitions and function.

\par XAPI Endianess
   Under VxWorks the following macros must be set form outside or by
   external VxW headers (see <netinet/in.h>)
   _LITTLE_ENDIAN,  _BIG_ENDIAN, _BYTE_ORDER

\attention
   The "__LITTLE_ENDIAN", "__BIG_ENDIAN" and "__BYTE_ORDER" are currently used
   within some external header files.

\ingroup IFXOS_INTERFACE
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX XAPI adaptation - Includes
   ========================================================================= */
#if 0
#include <vxworks.h>
#include <iosLib.h>        /* DEV_HDR */
#include <sys/ioctl.h>     /* _IO */
#include <netinet/in.h>
#endif

/* ============================================================================
   IFX XAPI adaptation - Macro definitions
   ========================================================================= */

/** \addtogroup IFXOS_IF_XAPI
@{ */
#ifndef _IFXOS_COMMON_H
#  error "missing IFXOS endian defines, include 'ifx_common.h' at first"
#endif

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
#  define IFXOS_BYTE_ORDER                IFXOS_LITTLE_ENDIAN
#elif (__BYTE_ORDER == __BIG_ENDIAN )
#  define IFXOS_BYTE_ORDER                IFXOS_BIG_ENDIAN
#else
#  error "no matching __BYTE_ORDER found"
#endif

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef XAPI */
#endif      /* #ifndef _IFXOS_XAPI_COMMON_H */

