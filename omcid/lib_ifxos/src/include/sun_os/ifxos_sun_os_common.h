#ifndef _IFXOS_SUN_OS_COMMON_H
#define _IFXOS_SUN_OS_COMMON_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(SUN_OS)
/** \file
   This file contains common definitions used for the Sun OS adaptation
*/

#ifdef __cplusplus
   extern "C" {
#endif

#ifndef _IFXOS_COMMON_H
#  error "missing IFXOS endian defines, include 'ifx_common.h' at first"
#endif

#if defined(_KERNEL)
/* ============================================================================
   IFX Sun OS adaptation - Sun OS Kernel Space
   ========================================================================= */

/** \defgroup IFXOS_IF_SUN_OS_DRV Defines for Sun OS Kernel Adaptaion

   This Group contains the Sun OS specific definitions and function.

\par Sun OS Kernel Endianess
   Under Sun OS in Kernel space the Endianess is defined within the corresponding
   architetcture header files.
   The plattform endianess is mapped to the internal used IFXOS endianess definitons.

\attention
   Under Sun OS only the _LITTLE_ENDIAN or the __BIG_ENDIAN is set, so avoid 
   to use this settings directly !!!

\ingroup IFXOS_INTERFACE
*/

/* ============================================================================
   IFX Sun OS adaptation - Includes (Sun OS Kernel)
   ========================================================================= */

/*
   ToDo:
   Include the necessary headers to get the following informations:
   - Endianess (BIG / LITTLE)
   - SunOS Version (?)
*/

/* ============================================================================
   IFX Sun OS adaptation - Macro definitions (Sun OS Kernel)
   ========================================================================= */

/** \addtogroup IFXOS_IF_SUN_OS_DRV
@{ */

#if defined(__LITTLE_ENDIAN) || defined(_LITTLE_ENDIAN)

   /** set the internal endianess macro for LITTLE endian */
#  if defined(__LITTLE_ENDIAN)
#     define __BYTE_ORDER                     __LITTLE_ENDIAN
#  else
#     define __BYTE_ORDER                     _LITTLE_ENDIAN
#  endif
   /** set the common IFXOS byte order for LITTLE endian */
#  define IFXOS_BYTE_ORDER                   IFXOS_LITTLE_ENDIAN

#elif defined(__BIG_ENDIAN) || defined(_BIG_ENDIAN)

   /** set the internal endianess macro for BIG endian */
#  if defined(__BIG_ENDIAN)
#     define __BYTE_ORDER                    __BIG_ENDIAN
#  else
#     define __BYTE_ORDER                    _BIG_ENDIAN
#  endif
   /** set the common IFXOS byte order for BIG endian */
#  define IFXOS_BYTE_ORDER                   IFXOS_BIG_ENDIAN

#else
#  error "missing endian definiton"
#endif

/** @} */

#else      /* #if defined(_KERNEL) */

/** \defgroup IFXOS_IF_SUN_OS_APPL Defines for Sun OS Application Adaptaion

   This Group contains the Sun OS specific definitions and function.

\par Sun OS Application Endianess
   Under Sun OS in user space the endianess is defined within the corresponding
   header file <endian.h>.
   The plattform endianess is mapped to the internal used IFXOS endianess definitons.

\ingroup IFXOS_INTERFACE
*/

/* ============================================================================
   IFX Sun OS adaptation - Includes (Sun OS Kernel)
   ========================================================================= */

/*
   ToDo:
   Include the necessary headers to get the following informations:
   - Endianess (BIG / LITTLE)
   - SunOS Version (?)
*/

/* ============================================================================
   IFX Sun OS adaptation - Macro definitions (Sun OS User Space)
   ========================================================================= */

/** \addtogroup IFXOS_IF_SUN_OS_APPL
@{ */
#if defined(__LITTLE_ENDIAN) || defined(_LITTLE_ENDIAN)

   /** set the internal endianess macro for LITTLE endian */
#  if defined(__LITTLE_ENDIAN)
#     define __BYTE_ORDER                     __LITTLE_ENDIAN
#  else
#     define __BYTE_ORDER                     _LITTLE_ENDIAN
#  endif
   /** set the common IFXOS byte order for LITTLE endian */
#  define IFXOS_BYTE_ORDER                   IFXOS_LITTLE_ENDIAN

#elif defined(__BIG_ENDIAN) || defined(_BIG_ENDIAN)

   /** set the internal endianess macro for BIG endian */
#  if defined(__BIG_ENDIAN)
#     define __BYTE_ORDER                    __BIG_ENDIAN
#  else
#     define __BYTE_ORDER                    _BIG_ENDIAN
#  endif
   /** set the common IFXOS byte order for BIG endian */
#  define IFXOS_BYTE_ORDER                   IFXOS_BIG_ENDIAN

#else
#  ifdef _MSC_VER
#     pragma message( "missing endian definiton" )
#  endif
#  if defined (__GNUC__) || defined (__GNUG__)
#     warning "missing endian definiton"
#  endif 

   /** set the common IFXOS byte order for BIG endian */
#  define IFXOS_BYTE_ORDER                   IFXOS_BIG_ENDIAN

#endif

/** @} */

#endif      /* #if defined(_KERNEL) */

#ifdef __cplusplus
}
#endif
#endif      /* #if defined(SUN_OS) */
#endif      /* #ifndef _IFXOS_SUN_OS_COMMON_H */

