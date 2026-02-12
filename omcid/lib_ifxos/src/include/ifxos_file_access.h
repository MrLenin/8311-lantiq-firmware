#ifndef _IFXOS_FILE_ACCESS_H
#define _IFXOS_FILE_ACCESS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for the file access on application level
*/

/** \defgroup IFXOS_IF_FILE_ACCESS File Access

   This Group contains the File Access definitions and function. 

   To access a file the standard C-lib functions for file handling are wrapped.

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
#     include "linux/ifxos_linux_file_access.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_file_access.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_file_access.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_file_access.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_file_access.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_file_access.h"
#  elif defined(SUN_OS)
#     include "sun_os/ifxos_sun_os_file_access.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_file_access.h"
#  else
#     error "File Access Adaptation - Please define your OS"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_file_access.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_file_access.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_file_access.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_file_access.h"
#  elif defined(WIN32)
#     include "ifxos_win32_file_access.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_file_access.h"
#  elif defined(SUN_OS)
#     include "ifxos_sun_os_file_access.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_file_access.h"
#  else
#     error "File Access Adaptation - Please define your OS"
#  endif
#endif

#include "ifx_types.h"

/* ============================================================================
   IFX OS adaptation - File Access
   ========================================================================= */

/** \addtogroup IFXOS_IF_FILE_ACCESS
@{ */

#if ( defined(IFXOS_HAVE_FILE_ACCESS) && (IFXOS_HAVE_FILE_ACCESS == 1) )

/**
   Open a file.

\param
   pName    - Points to the file name.
\param
   pMode    - Points to the open mode string. 
              Open Mode for "read" / "write" (binary), append.

\return
   For success - File handle
   No Success  - IFX_NULL
*/
IFXOS_File_t *IFXOS_FOpen(
                  const IFX_char_t *pName,  
                  const IFX_char_t *pMode);

/**
   Close the file or memory file.

\param
   pFileFd  - file handle from a previous file open command.

\return
   For Success - IFX_SUCCESS
   No Success  - IFX_ERROR
*/
IFX_int_t IFXOS_FClose(
                  IFXOS_File_t *pFileFd);

/**
   Read from a stream (file, stdin) number of elements with the given element size.

\param
   pDataBuf          - Points to the buffer used for get the data. [o]
\param
   elementSize_byte  - Element size of one element to read [byte]
\param
   elementCount      - Number of elements to read
\param
   stream            - Stream handle (file, stdin) which identify the source.

\return
   Number of read elements.

\attention
   This function does not distinguish between end-of-file and error, and callers
   must use IFXOS_FEof and IFXOS_FError to determine which occurred.
*/
IFX_size_t IFXOS_FRead(
                  IFX_void_t     *pDataBuf, 
                  IFX_size_t     elementSize_byte,  
                  IFX_size_t     elementCount, 
                  IFXOS_File_t   *stream);

/**
   Write to a stream (file, pipe, stdout) number of elements with the given element size.

\param
   pDataBuf          - Points to the buffer used for get the data. [I]
\param
   elementSize_byte  - Element size of one element to write [byte]
\param
   elementCount      - Number of elements to read
\param
   stream            - Stream handle (file, pipe, stdout) which identify the destination.

\return
   Number of written elements.
*/
IFX_size_t IFXOS_FWrite(
                  const IFX_void_t  *pDataBuf, 
                  IFX_size_t        elementSize_byte,  
                  IFX_size_t        elementCount, 
                  IFXOS_File_t      *stream);

/**
   Flush a stream (file or pipe).
   Force write of all user space buffered data.

\param
   stream      - Stream handle (file, pipe) which identify the destination.

\return
   For Success - IFX_SUCCESS
   No Success  - EOF and errno is set.
*/
IFX_int_t IFXOS_FFlush(
                  IFXOS_File_t *stream);

/**
   End of file test of a file.

\param
   stream      - Stream handle which identify the file.

\return
   "non zero value" if EOF is set.
*/
IFX_int_t IFXOS_FEof(
                  IFXOS_File_t *stream);

/**
  Get file status

\param
   pName       - Points to the file name.
\param
   pStatInfo   - Points to the file info struct. [O]

\return
   For Success - IFX_SUCCESS
   No Success  - neg. value (-1)
*/
IFX_int_t IFXOS_Stat(
                  IFX_char_t     *pName, 
                  IFXOS_stat_t   *pStatInfo);

/**
  Read a file from the OS specific medium.

\remarks
  The required data buffer is allocated and it is in the responsibility of the 
  user to free the buffer in a later step.

\param
   pName          - Points to the file name.
\param
   ppDataBuf      - Return Pointer of the allocated data buffer pointer. [O]
\param
   pBufSize_byte  - Points to return the size [byte] of the data buffer. [O]

\return
   - IFX_SUCCESS for successful load file
   - IFX_ERROR in case of errors
*/
IFX_return_t IFXOS_FileLoad (
                  IFX_char_t const  *pName, 
                  IFX_uint8_t       **ppDataBuf, 
                  IFX_size_t        *pBufSize_byte);

/**
  Write a file to the OS specific medium.

\param
   pName          - Points to the file name.
\param
   pDataBuf       - Points to the data buffer to write.
\param
   bufSize_byte   - Size [byte] of the data buffer.


\return
   - IFX_SUCCESS for successful load file
   - IFX_ERROR in case of errors
*/
IFX_return_t IFXOS_FileWrite (
                  IFX_char_t const  *pName, 
                  IFX_uint8_t       *pDataBuf, 
                  IFX_size_t        bufSize_byte);

#endif      /* #if ( defined(IFXOS_HAVE_FILE_ACCESS) && (IFXOS_HAVE_FILE_ACCESS == 1) ) */


#if ( defined(IFXOS_HAVE_MEMORY_FILE) && (IFXOS_HAVE_MEMORY_FILE == 1) )

/**
   Open a given memory buffer as stream (file). 
   - The size is limited to 32 kBytes.
   - The intention is to have a buffer where we can use the standard file 
     (stream) operations like fprintf etc.

\param 
   pMemBuf        - temporary buffer for fprintf operation.
\param 
   bufSize_byte   - size of the memory buffer
\param 
   pMode          - Points to the open mode string. 
                    Not used for mem files !

\return
   - pointer to FILE structure
   - in case of error the return value is NULL
*/
IFXOS_File_t *IFXOS_FMemOpen (
                  IFX_char_t        *pMemBuf, 
                  const IFX_uint_t  bufSize_byte, 
                  const IFX_char_t  *pMode);

/**
   Close the memory file.

\param
   pFileFd  - file handle from a previous file mem-file open command.

\return
   For Success - IFX_SUCCESS
   No Success  - IFX_ERROR
*/
IFX_int_t IFXOS_FMemClose(
                  IFXOS_File_t *pFileFd);

#endif      /* #if ( defined(IFXOS_HAVE_MEMORY_FILE) && (IFXOS_HAVE_MEMORY_FILE == 1) ) */


/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_FILE_ACCESS_H */

