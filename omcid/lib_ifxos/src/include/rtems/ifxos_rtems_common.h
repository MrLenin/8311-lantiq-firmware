#ifndef _IFXOS_RTEMS_COMMON_H
#define _IFXOS_RTEMS_COMMON_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS
/** \file
   This file contains common definitions used for the RTEMS OS adaption
*/

/* ============================================================================
   RTEMS adaptation
   ========================================================================= */

/** \defgroup IFXOS_IF_RTEMS Defines for RTEMS OS Adaptaion

   This Group contains the RTEMS OS specific definitions and function.

\par RTEMS OS Endianess
   Under RTEMS OS the following macros must be set form outside or by
   external VxW headers (see <netinet/in.h>)
   _LITTLE_ENDIAN,  _BIG_ENDIAN, _BYTE_ORDER

\attention
   The "__LITTLE_ENDIAN", "__BIG_ENDIAN" and "__BYTE_ORDER" are currently used
   within some external header files.

\ingroup IFXOS_INTERFACE
*/

//#define _BIG_ENDIAN       1
//#define _LITTLE_ENDIAN    2
#define _BYTE_ORDER       __BIG_ENDIAN


#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   RTEMS adaptation - Includes
   ========================================================================= */

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <limits.h>
#include "types.h"
#include "bsperr.h"
#include "bspcfg.h"
#include "board.h"
#include "mips_macros.h"
#include "sbmips.h"


/* End of definition */
#include "asmmacros.h"
#ifdef sbx   /* Define in the file build\prj\cpe2\sbx\board\xant-a\Makefile */
#include "sbx_map.h"
#endif

/* For System Call */
#include "xapi.h"


/* For MEI Related Data Structure Definition or Function Prototype */
#include "list.h"
#include "errno.h"
#include "ioctl.h"   // defines _IOWR
#include "psos.h"
#include "bsperr.h"
#include "sys/types.h"

// Declarations of functions in /dsl
#include "amazon_mei_rtems.h"

//#include "amazon_se_mei_bsp.h"


#define ssize_t unsigned long
#define wait_queue_head_t unsigned long


//********************************************

#ifdef _lint
   /* for LINT processing - add std-defines */
#  include "ifxos_lint_std_defs.h"
#endif



/* ============================================================================
   RTEMS OS adaptation - Macro definitions
   ========================================================================= */

/** \addtogroup IFXOS_IF_RTEMS
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
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_COMMON_H */

