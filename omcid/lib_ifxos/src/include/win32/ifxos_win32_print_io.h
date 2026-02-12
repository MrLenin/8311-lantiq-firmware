#ifndef _IFXOS_WIN32_IOPRINT_H
#define _IFXOS_WIN32_IOPRINT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32

/** \file
   This file contains VxWorks definitions for I/O printout and get.
*/

/** \defgroup IFXOS_IOPRINT_WIN32_APPL I/O printout and get (Win32)

   This Group contains the Win32 I/O printout and get definitions and function. 

   Therefore the functions are splitted in groups concerning their functionality:
   - char handling, get, put
   - string handling, get/put
   - printf functions

\ingroup IFXOS_LAYER_WIN32
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Win32 adaptation - Includes
   ========================================================================= */
#include <stdio.h>
#include <stdarg.h>

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

/** IFX Win32 adaptation - User support "I/O printout and get - put/get char" */
#ifndef IFXOS_HAVE_IOPRINT_XCHAR
#  define IFXOS_HAVE_IOPRINT_XCHAR                 1
#endif

/** IFX Win32 adaptation - User support "I/O printout and get - get string" */
#ifndef IFXOS_HAVE_IOPRINT_FGETS
#  define IFXOS_HAVE_IOPRINT_FGETS                 1
#endif

/** IFX Win32 adaptation - User support "I/O printout and get - printf" */
#ifndef IFXOS_HAVE_IOPRINT_FPRINTF
#  define IFXOS_HAVE_IOPRINT_FPRINTF               1
#endif

/** IFX Win32 adaptation - User support "I/O printout and get - snprintf" */
#ifndef IFXOS_HAVE_IOPRINT_SNPRINTF
#  define IFXOS_HAVE_IOPRINT_SNPRINTF              1
#endif

/** IFX Win32 adaptation - User support "I/O printout and get - vsnprintf" */
#ifndef IFXOS_HAVE_IOPRINT_VSNPRINTF
#  define IFXOS_HAVE_IOPRINT_VSNPRINTF             1
#endif

/* ============================================================================
   IFX Win32 adaptation - types
   ========================================================================= */
/** \addtogroup IFXOS_IOPRINT_WIN32_APPL
@{ */

/** IFX Win32 adaptation - wrap va_list to IFXOS type */
typedef va_list      IFXOS_valist_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_WIN32_IOPRINT_H */

