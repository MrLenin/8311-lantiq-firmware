#ifndef _IFXOS_VXWORKS_COMMON_H
#define _IFXOS_VXWORKS_COMMON_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS
/** \file
   This file contains common definitions used for the VxWorks OS adaption
*/

/* ============================================================================
   IFX VxWorks adaptation
   ========================================================================= */

/** \defgroup IFXOS_IF_VXWORKS Defines for VxWorks Adaptaion

   This Group contains the VxWorks specific definitions and function.

\par VxWorks Endianess
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
   IFX VxWorks adaptation - Includes
   ========================================================================= */
#include <vxWorks.h>
#include <iosLib.h>        /* DEV_HDR */
#include <sys/ioctl.h>     /* _IO */
#include <netinet/in.h>

/* ============================================================================
   IFX VxWorks adaptation - Macro definitions
   ========================================================================= */

/** \addtogroup IFXOS_IF_VXWORKS
@{ */

#if !defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
#  error "Missing definition for Little and Big Endian"
#endif

#ifndef _BYTE_ORDER
#  error "Missing definition for Byte Order"
#endif


#if !defined(__LITTLE_ENDIAN)
#  if defined(_LITTLE_ENDIAN)
#     define __LITTLE_ENDIAN        _LITTLE_ENDIAN
#  endif
#else
#  if !defined(_LITTLE_ENDIAN) || (__LITTLE_ENDIAN != _LITTLE_ENDIAN)
#     error "macro define __LITTLE_ENDIAN missmatch"
#  endif
#endif

#if !defined(__BIG_ENDIAN)
#  if defined(_BIG_ENDIAN)
#     define __BIG_ENDIAN        _BIG_ENDIAN
#  endif
#else
#  if !defined(_BIG_ENDIAN) || (__BIG_ENDIAN != _BIG_ENDIAN)
#     error "macro define __BIG_ENDIAN missmatch"
#  endif
#endif

#if !defined(__BYTE_ORDER)
#  if defined(_LITTLE_ENDIAN) && defined(__LITTLE_ENDIAN)
#     if (_BYTE_ORDER == _LITTLE_ENDIAN)
#        define __BYTE_ORDER                 __LITTLE_ENDIAN
#     endif
#  endif
#  if defined(_BIG_ENDIAN) && defined(__BIG_ENDIAN)
#     if (_BYTE_ORDER == _BIG_ENDIAN)
#        define __BYTE_ORDER                 __BIG_ENDIAN
#     endif
#  endif
#endif

#if !defined(__BYTE_ORDER)
#  error "Unknown System Byteorder!"
#endif

#ifndef _IFXOS_COMMON_H
#  error "missing IFXOS endian defines, include 'ifx_common.h' at first"
#endif

#if defined(__LITTLE_ENDIAN) && (__BYTE_ORDER == __LITTLE_ENDIAN)
#  define IFXOS_BYTE_ORDER                IFXOS_LITTLE_ENDIAN
#elif defined(__BIG_ENDIAN) && (__BYTE_ORDER == __BIG_ENDIAN )
#  define IFXOS_BYTE_ORDER                IFXOS_BIG_ENDIAN
#else
#  error "no matching __BYTE_ORDER found"
#endif

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef VXWORKS */
#endif      /* #ifndef _IFXOS_VXWORKS_COMMON_H */

