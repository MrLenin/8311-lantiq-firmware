/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX

/** \file
   This file contains the IFXOS Layer implementation for LINUX Application 
   I/O printout and get.
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes
   ========================================================================= */
#define _GNU_SOURCE     1
#include <features.h>

#include <stdio.h>
#include <stdarg.h>

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_file_access.h"
#include "ifxos_print_io.h"


/* ============================================================================
   IFX Linux adaptation - Application Space, I/O printout and get
   ========================================================================= */

/** \addtogroup IFXOS_IOPRINT_LINUX_APPL
@{ */

#if ( defined(IFXOS_HAVE_IOPRINT_XCHAR) && (IFXOS_HAVE_IOPRINT_XCHAR == 1) )
/**
   Get a char from stdin.

\return
   For success - return the character read or EOF
   No Success  - error
*/
IFX_int_t IFXOS_GetChar(void)
{
   return getchar();
}

/**
   Write a char to the given stream.

\param
   c        - Points to the file name.
\param
   stream   - Stream handle (file, stdout) which identify the destination.

\return
   For success - written char, or EOF
   No Success  - error
*/
IFX_int_t IFXOS_PutChar(
                     IFX_char_t     c, 
                     IFXOS_File_t   *stream)
{
   IFXOS_RETURN_IF_POINTER_NULL(stream, 0);
   return putc(c, stream);
}
#endif

#if ( defined(IFXOS_HAVE_IOPRINT_FGETS) && (IFXOS_HAVE_IOPRINT_FGETS == 1) )
/**
   Read a string from the file.

\param
   pStrBuf  - Points to the string buffer.
\param
   nCount   - max number of char to read (-1)
\param
   stream   - Stream handle (file, stdin) which identify the source.

\return
   For success - pStrBuf or NULL if EOF reached without receiving at least on char.
   No Success  - NULL in case of errors
*/
IFX_char_t *IFXOS_FGets(
                     IFX_char_t     *pStrBuf, 
                     IFX_int_t      nCount, 
                     IFXOS_File_t   *stream)
{
   IFXOS_RETURN_IF_POINTER_NULL(pStrBuf, IFX_NULL);
   IFXOS_RETURN_IF_POINTER_NULL(stream, IFX_NULL);

   return fgets(pStrBuf, nCount, stream);
}
#endif      /* #if ( defined(IFXOS_HAVE_IOPRINT_FGETS) && (IFXOS_HAVE_IOPRINT_FGETS == 1) ) */

#if ( defined(IFXOS_HAVE_IOPRINT_FPRINTF) && (IFXOS_HAVE_IOPRINT_FPRINTF == 1) )
/**
   Print to a file, (pipe,) stdout, stderr or memory file.

\param
   stream  - handle of the stream.
\param
   format  - points to the printf format string.
   
\return
   For success - Number of written bytes.
   For error   - negative value.
*/
IFX_int_t IFXOS_FPrintf(
                     IFXOS_File_t      *stream, 
                     const IFX_char_t  *format, ...)
{
   va_list     ap;         /* points to each unnamed arg in turn */
   IFX_int_t   nRet = 0;

   IFXOS_RETURN_IF_POINTER_NULL(stream, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(format, IFX_ERROR);

   va_start(ap, format);   /* set ap pointer to 1st unnamed arg */
   nRet = vfprintf(stream, format, ap);
   va_end(ap);

   return nRet;
}
#endif

#if ( defined(IFXOS_HAVE_IOPRINT_SNPRINTF) && (IFXOS_HAVE_IOPRINT_SNPRINTF == 1) )
/**
   Print to a buffer with length check

\param
   pStrBuf  - Points to the string buffer.
\param
   bufSize  - Size of the given buffer
\param
   format   - points to the printf format string.

\return
   For success - Number of written bytes.
   For error   - negative value.
*/
IFX_int_t IFXOS_SNPrintf (
                     IFX_char_t        *pStrBuf, 
                     IFX_int_t         bufSize, 
                     const IFX_char_t  *format, ...)
{
   int      retVal;
   va_list  arg;

   IFXOS_RETURN_IF_POINTER_NULL(pStrBuf, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(format, IFX_ERROR);

   va_start(arg, format);
   retVal = vsnprintf(pStrBuf, bufSize, format, arg);
   va_end(arg);
   return retVal;
}
#endif

#if ( defined(IFXOS_HAVE_IOPRINT_VSNPRINTF) && (IFXOS_HAVE_IOPRINT_VSNPRINTF == 1) )
/**
   Print to a buffer with length check

\param
   pStrBuf  - Points to the string buffer.
\param
   bufSize  - Size of the given buffer
\param
   format   - points to the printf format string.
\param
   vaList   - variable argument list for further parameters.

\return
   For success - Number of written bytes.
   For error   - negative value.
*/
IFX_int_t IFXOS_VSNPrintf (
                     IFX_char_t        *pStrBuf, 
                     IFX_int_t         bufSize, 
                     const IFX_char_t  *format, 
                     IFXOS_valist_t    vaList)
{
   IFXOS_RETURN_IF_POINTER_NULL(pStrBuf, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(format, IFX_ERROR);

   return vsnprintf(pStrBuf, bufSize, format, vaList);
}
#endif
/** @} */

#endif      /* #ifdef LINUX */

