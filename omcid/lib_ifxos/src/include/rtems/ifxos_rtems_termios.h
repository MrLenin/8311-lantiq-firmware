#ifndef _IFXOS_RTEMS_TERMIOS_H
#define _IFXOS_RTEMS_TERMIOS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains Generic OS definitions for Device Access.
*/

/** \defgroup IFXOS_TERMIOS_RTEMS_APPL Terminal IO System (Generic OS)

   This Group contains the Generic OS "Terminal IO System" definitions and function.


\ingroup IFXOS_LAYER_RTEMS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   RTEMS adaptation - Includes
   ========================================================================= */

/* ============================================================================
   RTEMS adaptation - supported features
   ========================================================================= */

/** RTEMS adaptation - User support "Terminal IO System" */
#ifndef IFXOS_HAVE_TERMIOS
#define IFXOS_HAVE_TERMIOS                       1
#endif

/* ============================================================================
   RTEMS adaptation - types
   ========================================================================= */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_TERMIOS_H */


