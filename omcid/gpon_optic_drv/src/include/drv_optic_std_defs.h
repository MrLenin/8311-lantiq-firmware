/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_std_defs.h
   This file contains standard definitions
   used by the FALC(tm) ON Optic Driver.
*/
#ifndef _drv_optic_std_defs_h
#define _drv_optic_std_defs_h

#ifndef _drv_gpon_std_defs_h
#define _drv_gpon_std_defs_h

#if !defined(LINUX) || !defined(__KERNEL__)
#include "ifxos_std_defs.h"
#endif

#if defined(__GNUC__) && ! defined(__KERNEL__)
#include <stdarg.h>
#endif

#ifndef SWIG
#include <stddef.h>
#endif

#if defined(__KERNEL__)
/* use linux kernel types */
#  include <linux/kernel.h>
#endif                          /* __KERNEL__ */

#if !defined(__KERNEL__)

#if defined(__GNUC__) || (defined(__STDC_VERSION__) && \
			    (__STDC_VERSION__ >= 199901L))
/* use standard C99 types */
#  include <stdint.h>
#  include <stdbool.h>
#endif                          /* __STDC_VERSION__ */

#ifdef WIN32
#  define inline __inline
#endif

#if (!defined(__STDC_VERSION__) || \
			    (__STDC_VERSION__ < 199901L)) && (!defined(__GNUC__))
/* standard C99 types not available */

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef signed short int16_t;
typedef unsigned short uint16_t;
typedef signed int int32_t;
typedef unsigned int uint32_t;

#  if defined(__WORDSIZE) && (__WORDSIZE == 64)
typedef unsigned long int uint64_t;
#  else
typedef unsigned long long int uint64_t;
typedef long long int int64_t;
#  endif
#  if !defined(__cplusplus) && !defined(bool)
#     ifndef SWIG
typedef char bool;
#     endif
#  define false 0
#  define true 1
#  endif
#endif

#endif /* !defined(__KERNEL__) */

#ifndef HAVE_ULONG_T
typedef unsigned long int ulong_t;
#endif

/** This is the volatile unsigned 8-bit datatype. */
typedef volatile uint8_t  vuint8_t;
/** This is the volatile signed 8-bit datatype. */
typedef volatile int8_t   vint8_t;
/** This is the volatile unsigned 16-bit datatype. */
typedef volatile uint16_t vuint16_t;
/** This is the volatile signed 16-bit datatype. */
typedef volatile int16_t  vint16_t;
/** This is the volatile unsigned 32-bit datatype. */
typedef volatile uint32_t vuint32_t;
/** This is the volatile signed 32-bit datatype. */
typedef volatile int32_t  vint32_t;
/** This is the volatile unsigned 64-bit datatype. */
typedef volatile uint64_t vuint64_t;

#ifndef SYSTEM_SIMULATION
#if defined(LINUX)
#   ifdef __KERNEL__
#      include <linux/kernel.h>
#      include <linux/string.h> /* memset */
#   endif
#endif
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

#ifndef SWIG
#include "ifxos_memory_alloc.h"
#include "ifxos_time.h"
#endif

#endif /* _drv_gpon_std_defs_h */

#endif
