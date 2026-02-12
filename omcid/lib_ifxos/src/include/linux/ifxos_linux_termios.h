#ifndef _IFXOS_LINUX_TERMIOS_H
#define _IFXOS_LINUX_TERMIOS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX

/** \file
   This file contains LINUX definitions for Terminal IO System.
*/

/** \defgroup IFXOS_TERMIOS_LINUX_APPL Terminal IO System (Linux User Space)

   This Group contains the LINUX "Terminal IO System" definitions and function. 


\ingroup IFXOS_LAYER_LINUX
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX LINUX adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX LINUX adaptation - supported features
   ========================================================================= */

/** IFX LINUX adaptation - User support "Terminal IO System" */
#ifndef IFXOS_HAVE_TERMIOS
#  define IFXOS_HAVE_TERMIOS                       1
#endif
/* ============================================================================
   IFX LINUX adaptation - types
   ========================================================================= */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef LINUX */
#endif      /* #ifndef _IFXOS_LINUX_TERMIOS_H */


