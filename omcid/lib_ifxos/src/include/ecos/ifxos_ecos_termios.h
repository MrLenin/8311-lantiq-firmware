#ifndef _IFXOS_ECOS_TERMIOS_H
#define _IFXOS_ECOS_TERMIOS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains eCos definitions for Terminal IO System.
*/

/** \defgroup IFXOS_TERMIOS_ECOS_APPL Terminal IO System (eCos)

   This Group contains the eCos "Terminal IO System" definitions and function. 


\ingroup IFXOS_LAYER_ECOS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX eCos adaptation - Includes
   ========================================================================= */

#include <pkgconf/isoinfra.h>

/* ============================================================================
   IFX eCos adaptation - supported features
   ========================================================================= */

/** IFX eCos adaptation - User support "Terminal IO System" */
#ifndef IFXOS_HAVE_TERMIOS
#  define IFXOS_HAVE_TERMIOS                       1
#endif

#if !defined(CYGINT_ISO_TERMIOS) || (defined(CYGINT_ISO_TERMIOS) && (CYGINT_ISO_TERMIOS == 0))
#undef IFXOS_HAVE_TERMIOS
#endif


/* ============================================================================
   IFX eCos adaptation - types
   ========================================================================= */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef ECOS */
#endif      /* #ifndef _IFXOS_ECOS_TERMIOS_H */


