#ifndef _IFXOS_RTEMS_PRINT_H
#define _IFXOS_RTEMS_PRINT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains Generic OS definitions for Printout.
*/

/** \defgroup IFXOS_PRINT_RTEMS Printout Defines (Generic OS)

   This Group contains the Generic OS Printout definitions.

   Here we have to differ between:\n
   - printout on interrupt level.
   - printout on application level.

\par Implementation
   Printouts on interrupt level will use the logMsg function

\par Implementation
   Printouts on application level will use the standard printf function

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

/** RTEMS adaptation - support "PRINT feature" */
#define IFXOS_HAVE_PRINT                              1
/** RTEMS adaptation - User space, support "PRINT via output stream" */
#define IFXOS_HAVE_PRINT_STREAM                       0

/** RTEMS adaptation - Kernel space, support "PRINT External debug function" */
#define IFXOS_HAVE_PRINT_EXT_DBG_FCT                  1
/** RTEMS adaptation - Kernel space, support "PRINT External error function" */
#define IFXOS_HAVE_PRINT_EXT_ERR_FCT                  1


/** \addtogroup IFXOS_PRINT_RTEMS
@{ */

/* ============================================================================
   RTEMS adaptation - PRINT defines
   ========================================================================= */

/** Define the used CR/LF sequence */
#define IFXOS_CRLF                                    "\n\r"

/** Debug Print on Int-Level (formated) */
#define IFXOS_DBG_PRINT_INT                           IFXOS_fctDbgPrintf
/** Debug Print on Appl-Level (formated) */
#define IFXOS_DBG_PRINT_USR                           IFXOS_fctDbgPrintf

/** Error Print on Int-Level (formated) */
#define IFXOS_ERR_PRINT_INT                           IFXOS_fctErrPrintf
/** Error Print on Appl-Level (formated) */
#define IFXOS_ERR_PRINT_USR                           IFXOS_fctErrPrintf

/** Print on Int-Level (unformated) */
#define IFXOS_PRINT_INT_RAW                           IFXOS_fctDbgPrintf
/** Print on Appl-Level (unformated) */
#define IFXOS_PRINT_USR_RAW                           IFXOS_fctDbgPrintf


/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_PRINT_H */

