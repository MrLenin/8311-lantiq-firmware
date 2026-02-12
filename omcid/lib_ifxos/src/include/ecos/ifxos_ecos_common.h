#ifndef _IFXOS_ECOS_COMMON_H
#define _IFXOS_ECOS_COMMON_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS
/** \file
   This file contains common definitions used for the eCos OS adaption
*/

/* ============================================================================
   IFX eCos adaptation
   ========================================================================= */

/** \defgroup IFXOS_IF_ECOS Defines for eCos Adaptaion

   This Group contains the eCos specific definitions and function.

\ingroup IFXOS_INTERFACE
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX eCos adaptation - Includes
   ========================================================================= */
#include <pkgconf/system.h>
//#include <cyg/kernel/kapi.h>  /* All the kernel specific stuff like cyg_flag_t, ... */
#include <stdlib.h>           /* malloc, free, CYG_BYTEORDER ... */
#include <string.h>           /* memcpy, memset, strcmp, memcmp ... */

#if defined(CYGPKG_NET) || defined(CYGPKG_NET_LWIP)
#  ifdef CYGPKG_NET_LWIP
#     include <time.h>
#  endif
#  include <network.h>        /* _IO */
#endif /* CYGPKG_NET || CYGPKG_NET_LWIP */

/* ============================================================================
   IFX eCos adaptation - Macro definitions
   ========================================================================= */

/* map the eCos defines to ours */
#define __BIG_ENDIAN      CYG_MSBFIRST
#define __LITTLE_ENDIAN   CYG_LSBFIRST
#define __BYTE_ORDER      CYG_BYTEORDER


/** \addtogroup IFXOS_IF_ECOS
@{ */

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
#  define IFXOS_BYTE_ORDER                IFXOS_LITTLE_ENDIAN
#elif (__BYTE_ORDER == __BIG_ENDIAN )
#  define IFXOS_BYTE_ORDER                IFXOS_BIG_ENDIAN
#else
#  error "no matching __BYTE_ORDER found"
#endif

#define IFXOS_TICKS_PER_SECOND   100
#define IFXOS_TICK_TO_MSEC(tick)	(((tick)*10)) 
#define IFXOS_MSEC_TO_TICK(msec)	((cyg_tick_count_t)(msec)/10)

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef ECOS */
#endif      /* #ifndef _IFXOS_ECOS_COMMON_H */

