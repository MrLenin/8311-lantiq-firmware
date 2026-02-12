/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef XAPI

/** \file
   This file contains the IFXOS Layer implementation for VxWorks User
   Print Handling.
*/

/* ============================================================================
   IFX VxWorks adaptation - Global Includes
   ========================================================================= */

#include <error.h>
#include <trace.h>

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
   IFX VxWorks adaptation - User Space, Print Handling
   ========================================================================= */
#if ( defined(IFXOS_HAVE_PRINT_STREAM) && (IFXOS_HAVE_PRINT_STREAM == 1) )

#define IFXOS_FCT_DBG_PRINTF_GET    IFXOS_LocalDbgPrintout
#define IFXOS_FCT_ERR_PRINTF_GET    IFXOS_LocalErrPrintout

IFXOS_STATIC IFX_int_t IFXOS_LocalDbgPrintout(const IFX_char_t *format, ...);
IFXOS_STATIC IFX_int_t IFXOS_LocalErrPrintout(const IFX_char_t *format, ...);

#else

#define IFXOS_XAPI_DBG_PRINT_NAME   "IFXO"
#define IFXOS_FCT_DBG_PRINTF_GET    trc_def_printf
#define IFXOS_FCT_ERR_PRINTF_GET    IFXOS_LocalErrPrint

#if ( defined(IFXOS_HAVE_PRINT) && (IFXOS_HAVE_PRINT == 1) )
IFXOS_STATIC IFX_int_t IFXOS_LocalErrPrint(const IFX_char_t *format, ...);
#endif

#endif      /* #if ( defined(IFXOS_HAVE_PRINT_STREAM) && (IFXOS_HAVE_PRINT_STREAM == 1) ) */


/** \addtogroup IFXOS_PRINT_VXWORKS
@{ */
#if ( defined(IFXOS_HAVE_PRINT) && (IFXOS_HAVE_PRINT == 1) )
/** Debug printout function pointer - set used print function */
IFXOS_FCT_DbgPrintf IFXOS_fctDbgPrintf = IFXOS_FCT_DBG_PRINTF_GET;
/** Error printout function pointer - set used print function */
IFXOS_FCT_ErrPrintf IFXOS_fctErrPrintf = IFXOS_FCT_ERR_PRINTF_GET;

/**
   Wrapper function for error printout
   This function is form type "IFXOS_FCT_ErrPrintf" and wrap the error printf

\ret
   On success - 0.
*/
IFXOS_STATIC IFX_int_t IFXOS_LocalErrPrint(const IFX_char_t *format, ...)
{
   va_list     ap;
   IFX_int_t   nRet = 0;

   va_start(ap, format);
   nRet = (IFX_int_t)err_vprintf(0, ERR_CLASS_RECOV, IFXOS_XAPI_DBG_PRINT_NAME,
                                 __FILE__, __LINE__, format, ap);
   va_end(ap);

   return nRet;
}

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
   IFX_int_t   nRet = 0;

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
   IFX_int_t   nRet = 0;

   return nRet;
}
#endif

#if ( defined(IFXOS_HAVE_PRINT_EXT_DBG_FCT) && (IFXOS_HAVE_PRINT_EXT_DBG_FCT == 1) )
/**
   VxWorks User - Set the user specific printout function for debug printouts.

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
   VxWorks User - Set the user specific printout function for error printouts.

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

#endif      /* #ifdef XAPI */


