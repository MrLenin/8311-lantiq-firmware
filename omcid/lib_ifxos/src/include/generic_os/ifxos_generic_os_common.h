#ifndef _IFXOS_GENERIC_OS_COMMON_H
#define _IFXOS_GENERIC_OS_COMMON_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS
/** \file
   This file contains common definitions used for the Generic OS OS adaption
*/

/* ============================================================================
   IFX Generic OS adaptation
   ========================================================================= */

/** \defgroup IFXOS_IF_GENERIC_OS Defines for Generic OS Adaptaion

   This Group contains the Generic OS specific definitions and function.

\par Generic OS Endianess
   Under Generic OS the following macros must be set form outside or by
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
   IFX Generic OS adaptation - Includes
   ========================================================================= */
/*
   Customer-ToDo:
   Include your customer OS header required for getting the endianess of the system.
*/

#ifndef __LITTLE_ENDIAN
#  define _LITTLE_ENDIAN     0x1234
#else
#  define _LITTLE_ENDIAN     __LITTLE_ENDIAN
#endif

#ifndef __BIG_ENDIAN
#  define _BIG_ENDIAN        0x4321
#else
#  define _BIG_ENDIAN        __BIG_ENDIAN
#endif

#ifndef __BYTE_ORDER
#  define _BYTE_ORDER        _LITTLE_ENDIAN
#else
#  define _BYTE_ORDER        __BYTE_ORDER
#endif

/* ============================================================================
   IFX Generic OS adaptation - Macro definitions
   ========================================================================= */

/** \addtogroup IFXOS_IF_GENERIC_OS
@{ */
#ifndef _LITTLE_ENDIAN
#  error "Missing definition for Little Endian"
#endif

#ifndef _BIG_ENDIAN
#  error "Missing definition for Big Endian"
#endif

#ifndef _BYTE_ORDER
#  error "Missing definition for Byte Order"
#endif

#ifndef __LITTLE_ENDIAN
#  define __LITTLE_ENDIAN _LITTLE_ENDIAN
#else
#  if (__LITTLE_ENDIAN != _LITTLE_ENDIAN)
#     error "macro define __LITTLE_ENDIAN missmatch"
#  endif
#endif

#ifndef __BIG_ENDIAN
#  define __BIG_ENDIAN    _BIG_ENDIAN
#else
#  if (__BIG_ENDIAN != _BIG_ENDIAN)
#     error "macro define __BIG_ENDIAN missmatch"
#  endif
#endif

#ifndef __BYTE_ORDER
#  if (_BYTE_ORDER == _LITTLE_ENDIAN)
#     define __BYTE_ORDER                 __LITTLE_ENDIAN
#  elif (_BYTE_ORDER == _BIG_ENDIAN )
#     define __BYTE_ORDER                 __BIG_ENDIAN
#  else
#     error "Unknown System Byteorder!"
#  endif
#endif

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
#endif      /* #ifdef GENERIC_OS */
#endif      /* #ifndef _IFXOS_GENERIC_OS_COMMON_H */

