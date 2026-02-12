#ifndef _IFXOS_VXWORKS_TERMIOS_H
#define _IFXOS_VXWORKS_TERMIOS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS

/** \file
   This file contains VxWorks definitions for Device Access.
*/

/** \defgroup IFXOS_TERMIOS_VXWORKS_APPL Terminal IO System (VxWorks)

   This Group contains the VxWorks "Terminal IO System" definitions and function. 


\ingroup IFXOS_LAYER_VXWORKS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX VxWorks adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX VxWorks adaptation - supported features
   ========================================================================= */

/** IFX VxWorks adaptation - User support "Terminal IO System" */
#ifndef IFXOS_HAVE_TERMIOS
#  define IFXOS_HAVE_TERMIOS                       1
#endif

/* ============================================================================
   IFX VxWorks adaptation - types
   ========================================================================= */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef VXWORKS */
#endif      /* #ifndef _IFXOS_VXWORKS_TERMIOS_H */


