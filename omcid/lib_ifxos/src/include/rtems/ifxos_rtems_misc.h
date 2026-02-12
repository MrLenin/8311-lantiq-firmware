#ifndef _IFXOS_RTEMS_MISC_H
#define _IFXOS_RTEMS_MISC_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains RTEMS definitions of Miscellaneous functions.
*/

/** \defgroup IFXOS_MISC_RTEMS_APPL Miscellaneous functions (RTEMS)

   This Group contains the RTEMS "Miscellaneous" definitions and function.


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

/** IFX RTEMS adaptation - User support "Miscellaneous functions" */
#ifndef IFXOS_HAVE_MISC
#  define IFXOS_HAVE_MISC                       1
#endif

/* ============================================================================
   RTEMS adaptation - types
   ========================================================================= */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_MISC_H */


