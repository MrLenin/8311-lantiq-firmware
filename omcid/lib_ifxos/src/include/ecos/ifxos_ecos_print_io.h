#ifndef _IFXOS_ECOS_IOPRINT_H
#define _IFXOS_ECOS_IOPRINT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains eCos definitions for I/O printout and get.
*/

/** \defgroup IFXOS_IOPRINT_ECOS_APPL I/O printout and get (eCos)

   This Group contains the eCos I/O printout and get definitions and function. 

   Therefore the functions are splitted in groups concerning their functionality:
   - char handling, get, put
   - string handling, get/put
   - printf functions

\ingroup IFXOS_LAYER_ECOS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX eCos adaptation - Includes
   ========================================================================= */

#include "ifxos_file_access.h"
#include <stdarg.h>           /* va_start... */

/* ============================================================================
   IFX eCos adaptation - supported features
   ========================================================================= */

/** IFX eCos adaptation - User support "I/O printout and get - put/get char" */
#ifndef IFXOS_HAVE_IOPRINT_XCHAR
#  if IFXOS_HAVE_FILE_TYPE == 1
#     define IFXOS_HAVE_IOPRINT_XCHAR                 1
#  else
#     define IFXOS_HAVE_IOPRINT_XCHAR                 0
#  endif
#endif

/** IFX eCos adaptation - User support "I/O printout and get - get string" */
#ifndef IFXOS_HAVE_IOPRINT_FGETS
#  if IFXOS_HAVE_FILE_TYPE == 1
#     define IFXOS_HAVE_IOPRINT_FGETS                 1
#  else
#     define IFXOS_HAVE_IOPRINT_FGETS                 0
#  endif
#endif

/** IFX eCos adaptation - User support "I/O printout and get - printf" */
#ifndef IFXOS_HAVE_IOPRINT_FPRINTF
#  if IFXOS_HAVE_FILE_TYPE == 1
#     define IFXOS_HAVE_IOPRINT_FPRINTF                 1
#  else
#     define IFXOS_HAVE_IOPRINT_FPRINTF                 0
#  endif
#endif

/** IFX eCos adaptation - User support "I/O printout and get - snprintf" */
#ifndef IFXOS_HAVE_IOPRINT_SNPRINTF
#  define IFXOS_HAVE_IOPRINT_SNPRINTF              1
#endif

/** IFX eCos adaptation - User support "I/O printout and get - vsnprintf" */
#ifndef IFXOS_HAVE_IOPRINT_VSNPRINTF
#  define IFXOS_HAVE_IOPRINT_VSNPRINTF             1
#endif

/* ============================================================================
   IFX eCos adaptation - types
   ========================================================================= */

/** IFX eCos adaptation - wrap va_list to IFXOS type */
typedef va_list      IFXOS_valist_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef ECOS */
#endif      /* #ifndef _IFXOS_ECOS_IOPRINT_H */

