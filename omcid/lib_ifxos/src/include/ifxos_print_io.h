#ifndef _IFXOS_IOPRINT_H
#define _IFXOS_IOPRINT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for the I/O printout and get.
*/

/** \defgroup IFXOS_IF_IOPRINT I/O Print and Get

   This Group contains the I/O Print and Get definitions and function. 

\ingroup IFXOS_INTERFACE
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Global Includes
   ========================================================================= */
#if ( !defined(IFXOS_FLAT_HIRACHY) || (IFXOS_FLAT_HIRACHY == 0) )
#  if defined(LINUX)
#     include "linux/ifxos_linux_print_io.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_print_io.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_print_io.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_print_io.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_print_io.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_print_io.h"
#  elif defined(SUN_OS)
#     include "sun_os/ifxos_sun_os_print_io.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_print_io.h"
#  else
#     error "IO xprintf Adaptation - Please define your OS"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_print_io.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_print_io.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_print_io.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_print_io.h"
#  elif defined(WIN32)
#     include "ifxos_win32_print_io.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_print_io.h"
#  elif defined(SUN_OS)
#     include "ifxos_sun_os_print_io.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_print_io.h"
#  else
#     error "IO xprintf Adaptation - Please define your OS"
#  endif
#endif

#include "ifx_types.h"
#include "ifxos_file_access.h"

/* ============================================================================
   IFX OS adaptation - I/O Print and Get
   ========================================================================= */

/** \addtogroup IFXOS_IF_IOPRINT
@{ */

#if ( defined(IFXOS_HAVE_IOPRINT_XCHAR) && (IFXOS_HAVE_IOPRINT_XCHAR == 1) )
/**
   Get a char from stdin.

\return
   For success - return the character read or EOF
   No Success  - error
*/
IFX_int_t IFXOS_GetChar(void);

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
                     IFXOS_File_t   *stream);
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
                     IFXOS_File_t   *stream);
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
#ifdef __GNUC__
   __attribute__ ((format (printf, 2, 3)))
#endif
   ;
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
#ifdef __GNUC__
   __attribute__ ((format (printf, 3, 4)))
#endif
   ;
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
#ifdef __GNUC__
   __attribute__ ((format (printf, 3, 0)))
#endif
   ;
#endif

/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_IOPRINT_H */



