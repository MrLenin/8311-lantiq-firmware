#ifndef _IFXOS_RTEMS_IOPRINT_H
#define _IFXOS_RTEMS_IOPRINT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains Generic OS definitions for I/O printout and get.
*/

/** \defgroup IFXOS_IOPRINT_RTEMS_APPL I/O printout and get (Generic OS)

   This Group contains the Generic OS I/O printout and get definitions and function.

   Therefore the functions are splitted in groups concerning their functionality:
   - char handling, get, put
   - string handling, get/put
   - printf functions

\ingroup IFXOS_LAYER_RTEMS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   RTEMS adaptation - Includes
   ========================================================================= */
/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

/* ============================================================================
   RTEMS adaptation - supported features
   ========================================================================= */

/** RTEMS adaptation - User support "I/O printout and get - put/get char" */
#define IFXOS_HAVE_IOPRINT_XCHAR                 1

/** RTEMS adaptation - User support "I/O printout and get - get string" */
#define IFXOS_HAVE_IOPRINT_FGETS                 1

/** RTEMS adaptation - User support "I/O printout and get - printf" */
#define IFXOS_HAVE_IOPRINT_FPRINTF               1

/** RTEMS adaptation - User support "I/O printout and get - snprintf" */
#define IFXOS_HAVE_IOPRINT_SNPRINTF              1

/** RTEMS adaptation - User support "I/O printout and get - vsnprintf" */
#define IFXOS_HAVE_IOPRINT_VSNPRINTF             1

/* ============================================================================
   RTEMS adaptation - types
   ========================================================================= */

/*
   Customer-ToDo:
   Define your OS specific va_list.
*/

/** RTEMS adaptation - wrap va_list to IFXOS type */
typedef int      IFXOS_valist_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_IOPRINT_H */

