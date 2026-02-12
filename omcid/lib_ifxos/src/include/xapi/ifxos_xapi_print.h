#ifndef _IFXOS_XAPI_PRINT_H
#define _IFXOS_XAPI_PRINT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef XAPI

/** \file
   This file contains XAPI definitions for Printout.
*/

/** \defgroup IFXOS_PRINT_XAPI Printout Defines (XAPI)

   This Group contains the XAPI Printout definitions.

   Here we have to differ between:\n
   - printout on interrupt level.
   - printout on application level.

\par Implementation
   Printouts on interrupt level will use the printf function

\par Implementation
   Printouts on application level will use the standard printf function

\ingroup IFXOS_LAYER_XAPI
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX XAPI adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX XAPI adaptation - supported features
   ========================================================================= */

/** IFX XAPI adaptation - support "PRINT feature" */
#ifndef IFXOS_HAVE_PRINT
#  define IFXOS_HAVE_PRINT                           0                           
#endif

#ifdef __GNUC__
   /** IFX XAPI adaptation - User space, support "PRINT via output stream" */
#  ifndef IFXOS_HAVE_PRINT_STREAM
#     define IFXOS_HAVE_PRINT_STREAM                 0
#  endif

#else

   /** IFX XAPI adaptation - User space, support "PRINT via output stream" */
#  ifndef IFXOS_HAVE_PRINT_STREAM
#     define IFXOS_HAVE_PRINT_STREAM                 0
#  endif

#endif

/** IFX XAPI adaptation - Kernel space, support "PRINT External debug function" */
#ifndef IFXOS_HAVE_PRINT_EXT_DBG_FCT
#  define IFXOS_HAVE_PRINT_EXT_DBG_FCT               0
#endif

/** IFX XAPI adaptation - Kernel space, support "PRINT External error function" */
#ifndef IFXOS_HAVE_PRINT_EXT_ERR_FCT
#  define IFXOS_HAVE_PRINT_EXT_ERR_FCT               0
#endif

/** \addtogroup IFXOS_PRINT_XAPI
@{ */

/* ============================================================================
   IFX XAPI adaptation - PRINT defines
   ========================================================================= */

/** Define the used CR/LF sequence */
#define IFXOS_CRLF                              "\n\r"

#ifdef __GNUC__
   /** Debug Print on Int-Level (formated) */
#  define IFXOS_DBG_PRINT_INT(fmt, args...)          printf(fmt, ##args)
   /** Debug Print on Appl-Level (formated) */
#  define IFXOS_DBG_PRINT_USR(fmt, args...)          IFXOS_fctDbgPrintf(fmt, ##args)

   /** Error Print on Int-Level (formated) */
#  define IFXOS_ERR_PRINT_INT(fmt, args...)          printf(fmt, ##args)
   /** Error Print on Appl-Level (formated) */
#  define IFXOS_ERR_PRINT_USR(fmt, args...)          IFXOS_fctErrPrintf(fmt, ##args)

   /** Print on Int-Level (unformated) */
#  define IFXOS_PRINT_INT_RAW(fmt, args...)          printf(fmt, ##args)
   /** Print on Appl-Level (unformated) */
#  define IFXOS_PRINT_USR_RAW(fmt, args...)          IFXOS_fctDbgPrintf(fmt, ##args)

#else
   /** Debug Print on Int-Level (formated) */
#  define IFXOS_DBG_PRINT_INT                        printf
   /** Debug Print on Appl-Level (formated) */
#  define IFXOS_DBG_PRINT_USR                        IFXOS_fctDbgPrintf
   /** Error Print on Int-Level (formated) */
#  define IFXOS_ERR_PRINT_INT                        printf
   /** Error Print on Appl-Level (formated) */
#  define IFXOS_ERR_PRINT_USR                        IFXOS_fctErrPrintf
   /** Print on Int-Level (unformated) */
#  define IFXOS_PRINT_INT_RAW                        printf
   /** Print on Appl-Level (unformated) */
#  define IFXOS_PRINT_USR_RAW                        IFXOS_fctDbgPrintf
#endif

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef XAPI */
#endif      /* #ifndef _IFXOS_XAPI_PRINT_H */

