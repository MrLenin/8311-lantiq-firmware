#ifndef _IFXOS_GENERIC_OS_TERMIOS_H
#define _IFXOS_GENERIC_OS_TERMIOS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS

/** \file
   This file contains Generic OS definitions for Device Access.
*/

/** \defgroup IFXOS_TERMIOS_GENERIC_OS_APPL Terminal IO System (Generic OS)

   This Group contains the Generic OS "Terminal IO System" definitions and function. 


\ingroup IFXOS_LAYER_GENERIC_OS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Generic OS adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX Generic OS adaptation - supported features
   ========================================================================= */

/** IFX Generic OS adaptation - User support "Terminal IO System" */
#ifndef IFXOS_HAVE_TERMIOS
#define IFXOS_HAVE_TERMIOS                       1
#endif

/* ============================================================================
   IFX Generic OS adaptation - types
   ========================================================================= */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef GENERIC_OS */
#endif      /* #ifndef _IFXOS_GENERIC_OS_TERMIOS_H */


