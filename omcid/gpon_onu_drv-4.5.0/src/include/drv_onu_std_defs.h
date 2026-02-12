/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/**
   \file drv_onu_std_defs.h
   This is a common header file, providing the globally used type definitions.
*/
#ifndef _drv_onu_std_defs_h
#define _drv_onu_std_defs_h

#ifndef _drv_gpon_std_defs_h
#define _drv_gpon_std_defs_h

#if defined(__LINUX__) && !defined(__KERNEL__)
/* include __WORDSIZE */
#  include <bits/wordsize.h>
#endif

#if defined(__KERNEL__)
/* use linux kernel types */
#  include <linux/kernel.h>
#endif				/* __KERNEL__ */

#if !defined(__KERNEL__)

#if defined(__GNUC__) || (defined(__STDC_VERSION__) && \
			    (__STDC_VERSION__ >= 199901L))
/* use standard C99 types */
#  include <stdint.h>
#  include <stdbool.h>
#endif				/* __STDC_VERSION__ */

#if (!defined(__STDC_VERSION__) || \
			    (__STDC_VERSION__ < 199901L)) && (!defined(__GNUC__))
/* standard C99 types not available */

/** C99 type */
typedef signed char int8_t;
/** C99 type */
typedef unsigned char uint8_t;
/** C99 type */
typedef signed short int16_t;
/** C99 type */
typedef unsigned short uint16_t;
/** C99 type */
typedef signed int int32_t;
/** C99 type */
typedef unsigned int uint32_t;

#  if defined(__WORDSIZE) && (__WORDSIZE == 64)
/** C99 type */
typedef unsigned long int uint64_t;
/** C99 type */
typedef long int intptr_t;
/** C99 type */
typedef unsigned long int uintptr_t;
#  else
/** C99 type */
typedef unsigned long long int uint64_t;
/** C99 type */
typedef int intptr_t;
/** C99 type */
typedef unsigned int uintptr_t;
#  endif
#  if !defined(__cplusplus) && !defined(bool)
#     ifndef SWIG
/** C99 type */
typedef char bool;
#     endif
#  define false 0
#  define true 1
#  endif
#endif

#endif /* !defined(__KERNEL__) */

/** C99 type */
#ifndef HAVE_ULONG_T
typedef unsigned long int ulong_t;
#endif

/** This is the volatile unsigned 8-bit datatype. */
typedef volatile uint8_t vuint8_t;
/** This is the volatile signed 8-bit datatype. */
typedef volatile int8_t vint8_t;
/** This is the volatile unsigned 16-bit datatype. */
typedef volatile uint16_t vuint16_t;
/** This is the volatile signed 16-bit datatype. */
typedef volatile int16_t vint16_t;
/** This is the volatile unsigned 32-bit datatype. */
typedef volatile uint32_t vuint32_t;
/** This is the volatile signed 32-bit datatype. */
typedef volatile int32_t vint32_t;
/** This is the volatile unsigned 64-bit datatype. */
typedef volatile uint64_t vuint64_t;

#ifndef UINT64_MAX
#   define UINT64_MAX   (((uint64_t)(-1)))
#endif

#ifndef UINT32_MAX
#   define UINT32_MAX   (((uint32_t)(-1)))
#endif

#ifndef UINT16_MAX
#   define UINT16_MAX   (((uint16_t)(-1)))
#endif

#if defined(LINUX)
#   ifdef __KERNEL__
#      include <linux/kernel.h>
#      include <linux/string.h>	/* memset */
#      include <asm/div64.h>	/* do_div */
#   else
#      include <stdio.h>
#      include <stdlib.h>
#      include <string.h>
#      include <ctype.h>
#      include <errno.h>
/*#      include "ifxos_std_defs.h"*/
#   endif
#else
#   include "ifxos_std_defs.h"
#endif
#ifndef ULONG_MAX
#   define ULONG_MAX   (~((unsigned long)0))
#endif

#ifdef WIN32
#  define inline __inline
#endif

#ifndef INLINE
#  define INLINE inline
#endif

#ifdef __cplusplus
#  ifndef EXTERN_C_BEGIN
/** Extern C block begin macro */
#     define EXTERN_C_BEGIN extern "C" {
#  endif
#  ifndef EXTERN_C_END
/** Extern C block end macro */
#     define EXTERN_C_END }
#  endif
#else
#  ifndef EXTERN_C_BEGIN
/** Extern C block begin macro */
#     define EXTERN_C_BEGIN
#  endif
#  ifndef EXTERN_C_END
/** Extern C block end macro */
#     define EXTERN_C_END
#  endif
#endif

#endif

#endif
