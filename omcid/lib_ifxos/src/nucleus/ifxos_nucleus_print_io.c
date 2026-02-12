/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS

/** \file
   This file contains the IFXOS Layer implemantation for Nucleus User 
   I/O printout and get.
*/

/* ============================================================================
   IFX Nucleus adaptation - Global Includes
   ========================================================================= */
#include <nucleus.h>
#include <stdio.h>
#include <stdarg.h>

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_file_access.h"
#include "ifxos_print_io.h"

/* ============================================================================
   IFX Nucleus adaptation - User Space, I/O printout and get
   ========================================================================= */

/** \addtogroup IFXOS_IOPRINT_NUCLEUS_APPL
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
   /*lint -e666 -e611 *//* Warning 611 Suspicious cast */
   return getchar();
   /*lint -restore */
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

   /*lint -e611 *//* Warning 611 Suspicious cast */
   return putc(c, stream);
   /*lint -restore */
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

#  if ( defined(IFXOS_ADD_STATIC_MEMORY_FILE) && (IFXOS_ADD_STATIC_MEMORY_FILE == 1) )

/**
   Check if the given file fd points to a static memory file.
*/
static IFXOS_staticMemoryFile_t *IFXOS_IsStaticMemoryFile(
                                       IFXOS_File_t      *pFileFd)
{
   IFX_int_t i;
   IFXOS_staticMemoryFile_t *pprivMemFile = IFX_NULL;

   for (i= 0; i < IFXOS_MAX_NUM_OF_STATIC_MEMFILES; i++)
   {
      if (&IFXOS_privatMemoryFiles[i] == (IFXOS_staticMemoryFile_t *)pFileFd)
      {
         pprivMemFile = &IFXOS_privatMemoryFiles[i];
         break;
      }
   }

   return pprivMemFile;
}

#endif

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
#ifndef _lint
   va_list     ap;         /* points to each unnamed arg in turn */
   IFX_int_t   nRet = 0;

#if ( defined(IFXOS_ADD_STATIC_MEMORY_FILE) && (IFXOS_ADD_STATIC_MEMORY_FILE == 1) )
   IFXOS_staticMemoryFile_t *pprivMemFile = IFX_NULL;
#endif

   IFXOS_RETURN_IF_POINTER_NULL(stream, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(format, IFX_ERROR);

   va_start(ap, format);   /* set ap pointer to 1st unnamed arg */
#if ( defined(IFXOS_ADD_STATIC_MEMORY_FILE) && (IFXOS_ADD_STATIC_MEMORY_FILE == 1) )
   pprivMemFile = IFXOS_IsStaticMemoryFile(stream);
   if (pprivMemFile)
   {
      nRet = vsprintf(pprivMemFile->pBuffer + pprivMemFile->currPos, format, ap);
      pprivMemFile->currPos += nRet;
   }
   else
#endif
   {
      nRet = vfprintf(stream, format, ap);
   }
   va_end(ap);
#else
   IFX_int_t   nRet = 0;
#endif
   return nRet;
}
#endif

#if ( defined(IFXOS_HAVE_IOPRINT_SNPRINTF) && (IFXOS_HAVE_IOPRINT_SNPRINTF == 1) )
/**
   Print to a buffer with length check

\attention
   Does a (v)sprintf without length check!

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
#ifndef _lint
   int      retVal;
   va_list  arg;

   IFXOS_RETURN_IF_POINTER_NULL(pStrBuf, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(format, IFX_ERROR);

   va_start(arg, format);
   retVal = vsprintf(pStrBuf, format, arg);
   va_end(arg);
#else
   int      retVal = 0;
#endif
   return retVal;
}
#endif

#if ( defined(IFXOS_HAVE_IOPRINT_VSNPRINTF) && (IFXOS_HAVE_IOPRINT_VSNPRINTF == 1) )
/**
   Print to a buffer with length check

\attention
   Does a vsnprintf without length check!

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

#ifndef _lint
   IFXOS_RETURN_IF_POINTER_NULL(pStrBuf, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(format, IFX_ERROR);

   return vsprintf(pStrBuf, format, vaList);
#else
   return 0;
#endif         
}
#endif

/** @} */

#endif      /* #ifdef NUCLEUS_PLUS */

