#ifndef _IFXOS_WIN32_TERMIOS_H
#define _IFXOS_WIN32_TERMIOS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32

/** \file
   This file contains Win32 definitions for Terminal IO System
*/

/** \defgroup IFXOS_TERMIOS_WIN32_APPL Terminal IO System (Win32)

   This Group contains the Win32 "Terminal IO System" definitions and function. 

\ingroup IFXOS_LAYER_WIN32
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Win32 adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

/** IFX Win32 adaptation - User support "Terminal IO System" */
#ifndef IFXOS_HAVE_TERMIOS
#define IFXOS_HAVE_TERMIOS                       1
#endif

/* ============================================================================
   IFX Win32 adaptation - types
   ========================================================================= */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_WIN32_TERMIOS_H */

