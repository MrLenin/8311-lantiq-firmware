#ifndef _IFXOS_NUCLEUS_IOPRINT_H
#define _IFXOS_NUCLEUS_IOPRINT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS

/** \file
   This file contains Nucleus definitions for I/O printout and get.
*/

/** \defgroup IFXOS_IOPRINT_NUCLEUS_APPL I/O printout and get (Nucleus)

   This Group contains the Nucleus I/O printout and get definitions and function. 

   Therefore the functions are splitted in groups concerning their functionality:
   - char handling, get, put
   - string handling, get/put
   - printf functions

\ingroup IFXOS_LAYER_NUCLEUS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Nucleus adaptation - Includes
   ========================================================================= */
#include <nucleus.h>
#include <stdio.h>
#include <stdarg.h>

/* ============================================================================
   IFX Nucleus adaptation - supported features
   ========================================================================= */

/** IFX Nucleus adaptation - User support "I/O printout and get - put/get char" */
#ifndef IFXOS_HAVE_IOPRINT_XCHAR
#  define IFXOS_HAVE_IOPRINT_XCHAR                 1
#endif

/** IFX Nucleus adaptation - User support "I/O printout and get - get string" */
#ifndef IFXOS_HAVE_IOPRINT_FGETS
#  define IFXOS_HAVE_IOPRINT_FGETS                 1
#endif

/** IFX Nucleus adaptation - User support "I/O printout and get - printf" */
#ifndef IFXOS_HAVE_IOPRINT_FPRINTF
#  define IFXOS_HAVE_IOPRINT_FPRINTF               1
#endif

/** IFX Nucleus adaptation - User support "I/O printout and get - snprintf" */
#ifndef IFXOS_HAVE_IOPRINT_SNPRINTF
#  define IFXOS_HAVE_IOPRINT_SNPRINTF              1
#endif

/** IFX Nucleus adaptation - User support "I/O printout and get - vsnprintf" */
#ifndef IFXOS_HAVE_IOPRINT_VSNPRINTF
#  define IFXOS_HAVE_IOPRINT_VSNPRINTF             1
#endif

/* ============================================================================
   IFX Nucleus adaptation - types
   ========================================================================= */

/** IFX Nucleus adaptation - wrap va_list to IFXOS type */
typedef va_list      IFXOS_valist_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef NUCLEUS_PLUS */
#endif      /* #ifndef _IFXOS_NUCLEUS_IOPRINT_H */

