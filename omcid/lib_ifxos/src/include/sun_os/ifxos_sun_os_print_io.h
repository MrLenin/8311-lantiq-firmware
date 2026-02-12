#ifndef _IFXOS_SUN_OS_IOPRINT_H
#define _IFXOS_SUN_OS_IOPRINT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(SUN_OS)

/** \file
   This file contains Sun OS definitions for I/O printout and get.
*/

/** \defgroup IFXOS_IOPRINT_SUN_OS_APPL I/O printout and get (Sun OS User Space)

   This Group contains the Sun OS I/O printout and get definitions and function. 

   Therefore the functions are splitted in groups concerning their functionality:
   - char handling, get, put
   - string handling, get/put
   - printf functions

\ingroup IFXOS_LAYER_SUN_OS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Sun OS adaptation - Includes
   ========================================================================= */
#include <stdio.h>
#include <stdarg.h>

/* ============================================================================
   IFX Sun OS adaptation - supported features
   ========================================================================= */

/** IFX Sun OS adaptation - User support "I/O printout and get - put/get char" */
#ifndef IFXOS_HAVE_IOPRINT_XCHAR
#  define IFXOS_HAVE_IOPRINT_XCHAR                 1
#endif

/** IFX Sun OS adaptation - User support "I/O printout and get - get string" */
#ifndef IFXOS_HAVE_IOPRINT_FGETS
#  define IFXOS_HAVE_IOPRINT_FGETS                 1
#endif

/** IFX Sun OS adaptation - User support "I/O printout and get - printf" */
#ifndef IFXOS_HAVE_IOPRINT_FPRINTF
#  define IFXOS_HAVE_IOPRINT_FPRINTF               1
#endif

/** IFX Sun OS adaptation - User support "I/O printout and get - snprintf" */
#ifndef IFXOS_HAVE_IOPRINT_SNPRINTF
#  define IFXOS_HAVE_IOPRINT_SNPRINTF              1
#endif

/** IFX Sun OS adaptation - User support "I/O printout and get - vsnprintf" */
#ifndef IFXOS_HAVE_IOPRINT_VSNPRINTF
#  define IFXOS_HAVE_IOPRINT_VSNPRINTF             1
#endif

/* ============================================================================
   IFX Sun OS adaptation - types
   ========================================================================= */

/** IFX Sun OS adaptation - wrap va_list to IFXOS type */
typedef va_list      IFXOS_valist_t;

#ifdef __cplusplus
}
#endif
#endif      /* #if defined(SUN_OS) */
#endif      /* #ifndef _IFXOS_SUN_OS_IOPRINT_H */


