#ifndef _IFXOS_WIN32_PRINT_H
#define _IFXOS_WIN32_PRINT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32

/** \defgroup IFXOS_PRINT_WIN32 Printout Defines (Win32)

   This Group contains the Win32 Printout definitions.

   Here we have to differ between:\n
   - printout on interrupt level.
   - printout on application level.

\par Implementation
   Printouts on interrupt level will use the logMsg function

\par Implementation
   Printouts on application level will use the standard printf function

\ingroup IFXOS_LAYER_WIN32
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Win32 adaptation - Includes
   ========================================================================= */
#include <stdio.h>

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

/** IFX Win32 adaptation - support "PRINT feature" */
#ifndef IFXOS_HAVE_PRINT
#  define IFXOS_HAVE_PRINT                           1
#endif

#ifdef __GNUC__
   /** IFX Win32 adaptation - support "PRINT via output stream" */
#  ifndef IFXOS_HAVE_PRINT_STREAM
#     define IFXOS_HAVE_PRINT_STREAM                 1
#  endif

#else

   /** IFX Win32 adaptation - support "PRINT via output stream" */
#  ifndef IFXOS_HAVE_PRINT_STREAM
#     define IFXOS_HAVE_PRINT_STREAM                 0
#  endif

#endif

/** IFX Win32 adaptation - support "PRINT External debug function" */
#ifndef IFXOS_HAVE_PRINT_EXT_DBG_FCT
#  define IFXOS_HAVE_PRINT_EXT_DBG_FCT               1
#endif

/** IFX Win32 adaptation - support "PRINT External error function" */
#ifndef IFXOS_HAVE_PRINT_EXT_ERR_FCT
#  define IFXOS_HAVE_PRINT_EXT_ERR_FCT               1
#endif

/* ============================================================================
   IFX Win32 adaptation - types
   ========================================================================= */

/* ============================================================================
   IFX Win32 adaptation - PRINT defines
   ========================================================================= */
/** \addtogroup IFXOS_PRINT_WIN32
@{ */

/** Define the used CR/LF sequence */
#define IFXOS_CRLF                                    "\n"

#ifdef __GNUC__
   /** Debug Print on Int-Level (formated) */
#  define IFXOS_DBG_PRINT_INT(fmt, args...)          IFXOS_fctDbgPrintf(fmt, ##args)
   /** Debug Print on Appl-Level (formated) */
#  define IFXOS_DBG_PRINT_USR(fmt, args...)          IFXOS_fctDbgPrintf(fmt, ##args)

   /** Error Print on Int-Level (formated) */
#  define IFXOS_ERR_PRINT_INT(fmt, args...)          IFXOS_fctErrPrintf(fmt, ##args)
   /** Error Print on Appl-Level (formated) */
#  define IFXOS_ERR_PRINT_USR(fmt, args...)          IFXOS_fctErrPrintf(fmt, ##args)

   /** Print on Int-Level (unformated) */
#  define IFXOS_PRINT_INT_RAW(fmt, args...)          IFXOS_fctDbgPrintf(fmt, ##args)
   /** Print on Appl-Level (unformated) */
#  define IFXOS_PRINT_USR_RAW(fmt, args...)          IFXOS_fctDbgPrintf(fmt, ##args)

#else
   /** Debug Print on Int-Level (formated) */
#  define IFXOS_DBG_PRINT_INT                        IFXOS_fctDbgPrintf
   /** Debug Print on Appl-Level (formated) */
#  define IFXOS_DBG_PRINT_USR                        IFXOS_fctDbgPrintf

   /** Error Print on Int-Level (formated) */
#  define IFXOS_ERR_PRINT_INT                        IFXOS_fctErrPrintf
   /** Error Print on Appl-Level (formated) */
#  define IFXOS_ERR_PRINT_USR                        IFXOS_fctErrPrintf

   /** Print on Int-Level (unformated) */
#  define IFXOS_PRINT_INT_RAW                        IFXOS_fctDbgPrintf
   /** Print on Appl-Level (unformated) */
#  define IFXOS_PRINT_USR_RAW                        IFXOS_fctDbgPrintf
#endif

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_WIN32_PRINT_H */


