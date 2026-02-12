/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation - Print Handling (Application Space)
   ========================================================================= */

#ifdef LINUX

/** \file
   This file contains the IFXOS Layer implementation for LINUX Application 
   Print Handling.
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes
   ========================================================================= */
#define _GNU_SOURCE     1
#include <features.h>

#include <stdio.h>
#include <stdarg.h>

#include "ifx_types.h"
#include "ifxos_print.h"

#if ( defined(IFXOS_HAVE_PRINT_STREAM) && (IFXOS_HAVE_PRINT_STREAM == 1) )
#include "ifxos_file_access.h"
#endif

#ifdef IFXOS_STATIC
#undef IFXOS_STATIC
#endif

#ifdef IFXOS_DEBUG
#define IFXOS_STATIC
#else
#define IFXOS_STATIC   static
#endif

/* ============================================================================
   IFX LINUX adaptation - Application Space, Print Handling
   ========================================================================= */
#if ( defined(IFXOS_HAVE_PRINT_STREAM) && (IFXOS_HAVE_PRINT_STREAM == 1) )

#define IFXOS_FCT_DBG_PRINTF_GET    IFXOS_LocalDbgPrintout
#define IFXOS_FCT_ERR_PRINTF_GET    IFXOS_LocalErrPrintout

IFXOS_STATIC IFX_int_t IFXOS_LocalDbgPrintout(const IFX_char_t *format, ...);
IFXOS_STATIC IFX_int_t IFXOS_LocalErrPrintout(const IFX_char_t *format, ...);

#else

#define IFXOS_FCT_DBG_PRINTF_GET    printf
#define IFXOS_FCT_ERR_PRINTF_GET    printf

#endif      /* #if ( defined(IFXOS_HAVE_PRINT_STREAM) && (IFXOS_HAVE_PRINT_STREAM == 1) ) */


/** \addtogroup IFXOS_PRINT_LINUX_APPL
@{ */
#if ( defined(IFXOS_HAVE_PRINT) && (IFXOS_HAVE_PRINT == 1) )

/** Debug printout function pointer - set used print function */
IFXOS_FCT_DbgPrintf IFXOS_fctDbgPrintf = IFXOS_FCT_DBG_PRINTF_GET;
/** Error printout function pointer - set used print function */
IFXOS_FCT_ErrPrintf IFXOS_fctErrPrintf = IFXOS_FCT_ERR_PRINTF_GET;


#if ( defined(IFXOS_HAVE_PRINT_STREAM) && (IFXOS_HAVE_PRINT_STREAM == 1) )
/** output stream for debug printouts */
IFXOS_File_t *pIFXOS_DbgPrintStream = IFX_NULL;
/** output stream for error printouts */
IFXOS_File_t *pIFXOS_ErrPrintStream = IFX_NULL;

/**
   Wrapper function for debug printout to change to out stream
   This function is form type "IFXOS_FCT_DbgPrintf" and wrap the default printf
   to use change the output stream.

\ret
   On success - number of written bytes.
*/
IFXOS_STATIC IFX_int_t IFXOS_LocalDbgPrintout(const IFX_char_t *format, ...)
{
   va_list     ap;
   IFX_int_t   nRet = 0;

   va_start(ap, format);
   nRet = vfprintf((pIFXOS_DbgPrintStream ? pIFXOS_DbgPrintStream : stdout), format, ap);
   va_end(ap);

   return nRet;
}

/**
   Wrapper function for error printout to change to out stream

   This function is form type "IFXOS_FCT_ErrPrintf" and wrap the default printf
   to use change the output stream.

\ret
   On success - number of written bytes.
*/
IFXOS_STATIC IFX_int_t IFXOS_LocalErrPrintout(const IFX_char_t *format, ...)
{
   va_list     ap;
   IFX_int_t   nRet = 0;

   va_start(ap, format);
   nRet = vfprintf((pIFXOS_ErrPrintStream ? pIFXOS_ErrPrintStream : stdout), format, ap);
   va_end(ap);

   return nRet;
}
#endif      /* #if ( defined(IFXOS_HAVE_PRINT_STREAM) && (IFXOS_HAVE_PRINT_STREAM == 1) ) */


#if ( defined(IFXOS_HAVE_PRINT_EXT_DBG_FCT) && (IFXOS_HAVE_PRINT_EXT_DBG_FCT == 1) )
/**
   LINUX Application - Set the user specific printout function for debug printouts.

\param
   fctExtDbg   - function pointer to the user debug print function

\return      
   NONE
*/
IFX_void_t IFXOS_PrintDbgFctSet(IFXOS_FCT_DbgPrintf fctExtDbg)
{
   if (fctExtDbg)
   {
      IFXOS_fctDbgPrintf = fctExtDbg;
   }
   else
   {
      IFXOS_fctDbgPrintf = IFXOS_FCT_DBG_PRINTF_GET;
   }
   return;
}
#endif

#if ( defined(IFXOS_HAVE_PRINT_EXT_ERR_FCT) && (IFXOS_HAVE_PRINT_EXT_ERR_FCT == 1) )
/**
   LINUX Application - Set the user specific printout function for error printouts.

\param
   fctExtErr   - function pointer to the user error print function

\return      
   NONE
*/
IFX_void_t IFXOS_PrintErrFctSet(IFXOS_FCT_ErrPrintf fctExtErr)
{
   if (fctExtErr)
   {
      IFXOS_fctErrPrintf = fctExtErr;
   }
   else
   {
      IFXOS_fctErrPrintf = IFXOS_FCT_ERR_PRINTF_GET;
   }
   return;
}
#endif

#endif      /* #if ( defined(IFXOS_HAVE_PRINT) && (IFXOS_HAVE_PRINT == 1) ) */

/** @} */

#endif      /* #ifdef LINUX */

