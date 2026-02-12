/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(WIN32) && !defined(NUCLEUS_PLUS)

/** \file
   This file contains the IFXOS Layer implementation for Win32 - 
   File Access.
*/

/* ============================================================================
   IFX Win32 adaptation - Global Includes
   ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_file_access.h"
#include "ifxos_debug.h"
#if (IFXOS_HAVE_FILESYSTEM == 1)
#include "ifxos_memory_alloc.h"
#endif

/* ============================================================================
   IFX Win32 adaptation - defines
   ========================================================================= */
#ifdef IFXOS_STATIC
#undef IFXOS_STATIC
#endif

#ifdef IFXOS_DEBUG
#define IFXOS_STATIC
#else
#define IFXOS_STATIC   static
#endif


/* ============================================================================
   IFX Win32 adaptation - File Access
   ========================================================================= */
/** \addtogroup IFXOS_FILE_ACCESS_WIN32_APPL
@{ */
#if ( defined(IFXOS_HAVE_FILE_ACCESS) && (IFXOS_HAVE_FILE_ACCESS == 1) )
/**
   Win32 - Open a file.

\par Implementation
   - use the standard C-Lib function "fopen" for file open

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
                  const IFX_char_t *pMode)
{
   IFXOS_RETURN_IF_POINTER_NULL(pName, IFX_NULL);
   IFXOS_RETURN_IF_POINTER_NULL(pMode, IFX_NULL);

   return fopen(pName, pMode);
}

/**
   Win32 - Close the file or memory file.

\par Implementation
   - checks the input
   - use the standard C-Lib function "fclose" for file close

\param
   pFileFd  - file handle from a previous file open command.

\return
   For Success - IFX_SUCCESS
   No Success  - IFX_ERROR
*/
IFX_int_t IFXOS_FClose(
                  IFXOS_File_t *pFileFd)
{
   IFXOS_RETURN_IF_POINTER_NULL(pFileFd, IFX_ERROR);

   if(pFileFd != 0)
      return fclose(pFileFd);

   return -1;
}

/**
   Win32 - Read from a stream (file, stdin) number of elements with the 
   given element size.

\par Implementation
   - use the standard C-Lib function "fread" for read from stream

\param
   pDataBuf          - Points to the buffer used for get the data. [o]
\param
   elementSize_byte  - Element size of one element to write [byte]
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
                  IFXOS_File_t   *stream)
{
   IFXOS_RETURN_IF_POINTER_NULL(pDataBuf, 0);
   IFXOS_RETURN_IF_POINTER_NULL(stream, 0);

   return fread(pDataBuf, elementSize_byte, elementCount, stream);
}

/**
   Win32 - Write to a stream (file, pipe, stdout) number of elements with 
   the given element size.

\par Implementation
   - use the standard C-Lib function "fwrite" for write to stream

\param
   pDataBuf          - Points to the buffer used for get the data. [I]
\param
   elementSize_byte  - Element size of one element to write [byte]
\param
   elementCount      - Number of elements to read
\param
   stream            - Stream handle (file, pipe, stdout) which identify 
                       the destination.

\return
   Number of written elements.
*/
IFX_size_t IFXOS_FWrite(
                  const IFX_void_t  *pDataBuf, 
                  IFX_size_t        elementSize_byte,  
                  IFX_size_t        elementCount, 
                  IFXOS_File_t      *stream)
{
   IFXOS_RETURN_IF_POINTER_NULL(pDataBuf, 0);
   IFXOS_RETURN_IF_POINTER_NULL(stream, 0);

   return fwrite(pDataBuf, elementSize_byte, elementCount, stream);
}

/**
   Win32 - Flush a stream (file or pipe).
   Force write of all user space buffered data.

\par Implementation
   - use the standard C-Lib function "fflush" for flush the given stream

\param
   stream      - Stream handle (file, pipe) which identify the destination.

\return
   For Success - IFX_SUCCESS
   No Success  - IFX_ERROR
*/
IFX_int_t IFXOS_FFlush(
                  IFXOS_File_t *stream)
{
   IFXOS_RETURN_IF_POINTER_NULL(stream, 0);

   return (IFX_int_t)fflush(stream);
}

/**
   Win32 - End of file test of a file.

\param
   stream      - Stream handle which identify the file.

\return
   "non zero value" if EOF is set.
*/
IFX_int_t IFXOS_FEof(IFXOS_File_t *stream)
{
   IFXOS_RETURN_IF_POINTER_NULL(stream, 0);

   return (IFX_int_t)feof(stream);
}

/**
  Win32 - Get file status info.

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
                  IFXOS_stat_t   *pStatInfo)
{
   IFXOS_RETURN_IF_POINTER_NULL(pName, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(pStatInfo, IFX_ERROR);

   return (IFX_int_t)stat(pName, pStatInfo);
}

/**
  Read a file from the OS specific medium.

\remarks
  The required data buffer is allocated and it is in the responsibility of the 
  user to free the buffer in a later step.

\remarks
   Allocate file size + 1 to terminate the buffer with '\0'.
   This will allow other functions to parse the buffer without the size info.

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
                  IFX_size_t        *pBufSize_byte)
{
#if (IFXOS_HAVE_FILESYSTEM == 1)
   IFXOS_File_t   *fd = IFX_NULL;
   IFXOS_stat_t   stats;
   IFX_uint8_t    *pDataBuf;
   IFX_size_t    size, retVal;

   IFXOS_RETURN_IF_POINTER_NULL(pName, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(ppDataBuf, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(pBufSize_byte, IFX_ERROR);

   IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_LOW,
      ("IFXOS - loading file %s" IFXOS_CRLF,
        pName));

   if (IFXOS_Stat((IFX_char_t *)pName, &stats))
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Getting statistics on %s" IFXOS_CRLF,
           pName));

      return IFX_ERROR;
   }

   size = stats.st_size;

   if (size == 0)
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - File %s has zero size." IFXOS_CRLF,
           pName));

      return IFX_ERROR;
   }
   else
   {
      IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_LOW,
         ("IFXOS - file <%s>: size %d bytes" IFXOS_CRLF,
           pName, (int)size));
   }

   fd = IFXOS_FOpen(pName, "rb");
   if (fd == IFX_NULL)
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Load, opening file %s." IFXOS_CRLF,
           pName));

      return IFX_ERROR;
   }

   /* size + 1 - to add null termination */
   pDataBuf = (IFX_uint8_t*)IFXOS_MemAlloc(size + 1);
   if (pDataBuf == IFX_NULL)
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Cannot allocate memory for file %s." IFXOS_CRLF,
           pName));

      IFXOS_FClose(fd);
      return IFX_ERROR;
   }

   retVal = IFXOS_FRead(pDataBuf, 1, size, fd);
   if (retVal != size)
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Cannot read file %s." IFXOS_CRLF,
           pName));

      IFXOS_MemFree(pDataBuf);
      IFXOS_FClose(fd);
      return IFX_ERROR;
   }

   IFXOS_FClose(fd);

   pDataBuf[size] = '\0';
   *pBufSize_byte = (IFX_uint32_t)size;
   *ppDataBuf     = pDataBuf;

   return IFX_SUCCESS;

#else  /* IFXOS_HAVE_FILESYSTEM == 1 */
   IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
      ("IFXOS ERROR - Load from file system not supported." IFXOS_CRLF));

   return IFX_ERROR;
#endif /* IFXOS_HAVE_FILESYSTEM == 0 */
}

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
                  IFX_size_t        bufSize_byte)
{
#if (IFXOS_HAVE_FILESYSTEM == 1)
   IFXOS_File_t *fd = IFX_NULL;
   IFX_size_t retVal;

   IFXOS_RETURN_IF_POINTER_NULL(pName, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(pDataBuf, IFX_ERROR);

   IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_LOW,
      ("IFXOS - saving file %s, size %d [byte]" IFXOS_CRLF,
        pName, bufSize_byte));

   fd = IFXOS_FOpen(pName, "wb");
   if (fd == IFX_NULL)
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Write, opening file %s." IFXOS_CRLF,
           pName));

      return IFX_ERROR;
   }

   retVal = IFXOS_FWrite(pDataBuf, 1, bufSize_byte, fd);
   if (retVal != (IFX_int32_t)bufSize_byte)
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Cannot write file %s." IFXOS_CRLF,
           pName));

      IFXOS_FClose(fd);
      return IFX_ERROR;
   }

   IFXOS_FClose(fd);

   return IFX_SUCCESS;

#else  /* IFXOS_HAVE_FILESYSTEM == 1 */
   IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
      ("IFXOS ERROR - write to file system not supported." IFXOS_CRLF));

   return IFX_ERROR;
#endif /* IFXOS_HAVE_FILESYSTEM == 1 */
}

#endif      /* #if ( defined(IFXOS_HAVE_FILE_ACCESS) && (IFXOS_HAVE_FILE_ACCESS == 1) ) */
/** @} */


/** \addtogroup IFXOS_MEM_FILE_WIN32
@{ */
#if ( defined(IFXOS_ADD_LOCAL_FMEMOPEN) && (IFXOS_ADD_LOCAL_FMEMOPEN == 1) )
#warning "not required for win32"
#endif

#if ( defined(IFXOS_HAVE_MEMORY_FILE) && (IFXOS_HAVE_MEMORY_FILE == 1) )

#if ( defined(IFXOS_ADD_STATIC_MEMORY_FILE) && (IFXOS_ADD_STATIC_MEMORY_FILE == 1) )
/** private memory file control struct */
IFXOS_staticMemoryFile_t IFXOS_privatMemoryFiles[IFXOS_MAX_NUM_OF_STATIC_MEMFILES] = {{IFX_NULL, 0, 0}};

IFXOS_STATIC IFXOS_File_t *IFXOS_StaticMemoryFileOpen (
                              IFX_char_t        *pMemBuf, 
                              const IFX_uint_t  bufSize_byte);

IFXOS_STATIC IFX_int_t IFXOS_StaticMemoryFileClose(
                              IFXOS_File_t *pFileFd);

/**
   User - Open a given memory buffer as stream (file). 
   - The intention is to have a buffer where we can use the standard file 
     (stream) operations like fprintf etc.

\param 
   pMemBuf        - temporary buffer for for fprintf operation.
\param 
   bufSize_byte   - size of the memory buffer

\return
   - pointer to FILE structure
   - in case of error the return value is NULL
*/
IFXOS_STATIC IFXOS_File_t *IFXOS_StaticMemoryFileOpen (
                              IFX_char_t        *pMemBuf, 
                              const IFX_uint_t  bufSize_byte)
{
   IFX_int_t i;
   IFXOS_staticMemoryFile_t *pprivMemFile = IFX_NULL;
   IFXOS_File_t             *stream       = IFX_NULL;

   IFXOS_RETURN_IF_POINTER_NULL(pMemBuf, IFX_NULL);
   IFXOS_RETURN_IF_ARG_LE_ZERO(bufSize_byte, IFX_NULL);

   for (i= 0; i < IFXOS_MAX_NUM_OF_STATIC_MEMFILES; i++)
   {
      if (IFXOS_privatMemoryFiles[i].pBuffer == IFX_NULL)
      {
         pprivMemFile = &IFXOS_privatMemoryFiles[i];
         break;
      }
   }

   if (pprivMemFile)
   {
      pprivMemFile->pBuffer = pMemBuf;
      pprivMemFile->bufSize = bufSize_byte;
      pprivMemFile->currPos = 0;

      stream = (IFXOS_File_t *)pprivMemFile;
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - IFXOS_FMemOpen, all static memory files busy." IFXOS_CRLF));
   }

   return stream;
}


/**
   User - Close the memory file.

\par Implementation
   - checks the input
   - use the standard C-Lib function "fclose" for file close or
     cleanup the private memory file struct.

\param
   pFileFd  - file handle from a previous file open command.

\return
   For Success - IFX_SUCCESS
   No Success  - IFX_ERROR
*/
IFXOS_STATIC IFX_int_t IFXOS_StaticMemoryFileClose(
                           IFXOS_File_t *pFileFd)
{
   IFX_int_t i;
   IFXOS_staticMemoryFile_t *pprivMemFile = IFX_NULL;

   IFXOS_RETURN_IF_POINTER_NULL(pFileFd, IFX_ERROR);

   for (i= 0; i < IFXOS_MAX_NUM_OF_STATIC_MEMFILES; i++)
   {
      if (&IFXOS_privatMemoryFiles[i] == (IFXOS_staticMemoryFile_t *)pFileFd)
      {
         pprivMemFile = &IFXOS_privatMemoryFiles[i];
         break;
      }
   }

   if (pprivMemFile)
   {
      pprivMemFile->currPos = 0;
      pprivMemFile->bufSize = 0;
      pprivMemFile->pBuffer = IFX_NULL;

      return IFX_SUCCESS;
   }

   IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
      ("IFXOS ERROR - IFXOS_FMemClose, static memory file not found." IFXOS_CRLF));

   return IFX_ERROR;
}

#endif   /* #if ( defined(IFXOS_ADD_STATIC_MEMORY_FILE) && (IFXOS_ADD_STATIC_MEMORY_FILE == 1) ) */

/**
   Win32 - Open a given memory buffer as stream (file). 
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
                  const IFX_char_t  *pMode)
{
   IFXOS_File_t *stream = IFX_NULL;

   IFXOS_RETURN_IF_POINTER_NULL(pMemBuf, IFX_NULL);
   IFXOS_RETURN_IF_ARG_LE_ZERO(bufSize_byte, IFX_NULL);

#if ( defined(IFXOS_ADD_STATIC_MEMORY_FILE) && (IFXOS_ADD_STATIC_MEMORY_FILE == 1) )
   stream = IFXOS_StaticMemoryFileOpen(pMemBuf, bufSize_byte);
#else

   stream = tmpfile();
   if (stream == IFX_NULL)
   {
      IFX_char_t* pTempFileName = IFX_NULL;
      /* try to create temporary file in the c:\tmp folder 
       (or in directory specified by TMP environment variable) */
      pTempFileName = _tempnam( "c:\\tmp", "dslapitmp" );
      if( pTempFileName != IFX_NULL )
      {
         stream = fopen(pTempFileName, "w+b");
      }
      if(pTempFileName)
        free(pTempFileName);
   }
   if(stream && pMemBuf && bufSize_byte)
   {
      setvbuf( stream, pMemBuf, _IOFBF, bufSize_byte);
   }      
#endif

   return (IFXOS_File_t *)stream;
}


/**
   Win32 - Close the memory file.

\par Implementation
   - checks the input
   - use the standard C-Lib function "fclose" for file close or
     cleanup the private memory file struct.

\param
   pFileFd  - file handle from a previous file open command.

\return
   For Success - IFX_SUCCESS
   No Success  - IFX_ERROR
*/
IFX_int_t IFXOS_FMemClose(
                  IFXOS_File_t *pFileFd)
{
   IFXOS_RETURN_IF_POINTER_NULL(pFileFd, IFX_ERROR);

#if ( defined(IFXOS_ADD_STATIC_MEMORY_FILE) && (IFXOS_ADD_STATIC_MEMORY_FILE == 1) )
   return IFXOS_StaticMemoryFileClose(pFileFd);

#else
   if(pFileFd != 0)
      return fclose(pFileFd);

   return -1;
#endif
}

#endif

/** @} */

#endif      /* #ifdef WIN32 */


