#ifndef _IFXOS_NUCLEUS_COMMON_H
#define _IFXOS_NUCLEUS_COMMON_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS
/** \file
   This file contains common definitions used for the Nucleus OS adaption
*/

/* ============================================================================
   IFX Nucleus adaptation
   ========================================================================= */

/** \defgroup IFXOS_IF_NUCLEUS Defines for Nucleus Adaptaion

   This Group contains the Nucleus specific definitions and function.

\par Nucleus Endianess
   Under Nucleus the following macros must be set form outside or by
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
   IFX Nucleus adaptation - Includes
   ========================================================================= */
#include <nucleus.h>

#ifndef _BIG_ENDIAN
   #define _BIG_ENDIAN       1
   #define _LITTLE_ENDIAN    2
#endif

#ifndef _BYTE_ORDER
   #define _BYTE_ORDER       __LITTLE_ENDIAN
#endif

/* ============================================================================
   IFX Nucleus adaptation - Macro definitions
   ========================================================================= */

/** \addtogroup IFXOS_IF_NUCLEUS
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

#define IFXOS_TICKS_PER_SECOND   10
#define IFXOS_TICK_TO_MSEC(tick)	(((tick)*100)) 
#define IFXOS_MSEC_TO_TICK(msec)	((msec)/100)

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef NUCLEUS_PLUS */
#endif      /* #ifndef _IFXOS_NUCLEUS_COMMON_H */

