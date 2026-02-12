/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS

/** \file
   This file contains the IFXOS Layer implementation for VxWorks 
   File Access.
*/

/* ============================================================================
   IFX VxWorks adaptation - Global Includes
   ========================================================================= */
#include <vxWorks.h>
#include <stdio.h>
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
   IFX VxWorks adaptation - defines
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
   IFX VxWorks adaptation - User Space, File Access
   ========================================================================= */

/** \addtogroup IFXOS_FILE_ACCESS_VXWORKS_APPL
@{ */
#if ( defined(IFXOS_HAVE_FILE_ACCESS) && (IFXOS_HAVE_FILE_ACCESS == 1) )
/**
   VxWorks User - Open a file.

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
   VxWorks User - Close the file or memory file.

\par Implementation
   - checks the input
   - use the standard C-Lib function "fclose" for file close

\param
   pFileFd  - file handle from a previous file open command.

\return
   For Success - IFX_SUCCESS
   No Success  - IFX_ERROR
*/
IFX_int_t IFXOS_FClose(IFXOS_File_t *pFileFd)
{
   IFXOS_RETURN_IF_POINTER_NULL(pFileFd, IFX_ERROR);
   return fclose(pFileFd);
}


/**
   VxWorks User - Read from a stream (file, stdin) number of elements with the 
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

   return fread(pDataBuf, elementSize_byte,  elementCount, stream);
}

/**
   VxWorks User - Write to a stream (file, pipe, stdout) number of elements with 
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
   VxWorks User - Flush a stream (file or pipe).
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

   return fflush(stream);
}

/**
   VxWorks User - End of file test of a file.

\param
   stream      - Stream handle which identify the file.

\return
   "non zero value" if EOF is set.
*/
IFX_int_t IFXOS_FEof(IFXOS_File_t *stream)
{
   /*lint -e611 *//* Warning 611 Suspicious cast */
   IFXOS_RETURN_IF_POINTER_NULL(stream, 0);

   return feof(stream);
   /*lint -restore */
}

/**
  VxWorks User - Get file status info.

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

   return stat(pName, pStatInfo);
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
   IFX_size_t     size, retVal;

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

   retVal = IFXOS_FRead(pDataBuf, 1,  size, fd);
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
   IFX_int32_t retVal;

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

#endif
/** @} */


/** \addtogroup IFXOS_MEM_FILE_VXWORKS
@{ */

#if ( defined(IFXOS_ADD_LOCAL_FMEMOPEN) && (IFXOS_ADD_LOCAL_FMEMOPEN == 1) )

#include <memDrv.h>

IFXOS_STATIC FILE *fmemopen (
                        void        *pMemBuf, 
                        size_t      bufSize_byte, 
                        const char  *pMode);


/** 
   VxWorks user - Implementation of the missing function "fmemopen".
   The implementation is based on the memDrv.c/h module.

\param 
   pMemBuf        - temporary buffer for for fprintf operation.
\param 
   bufSize_byte   - size of the memory buffer
\param 
   pMode          - Points to the open mode string. 
                    Not used for mem files !

*/
IFXOS_STATIC FILE *fmemopen (
                        void        *pMemBuf, 
                        size_t      bufSize_byte, 
                        const char  *pMode)
{
   char name1[30];
   char name2[30];
   int fd;
   STATUS status;

   sprintf(name1, "/mem/%08X_%08X/", (int)pMemBuf, bufSize_byte);
   sprintf(name2, "/mem/%08X_%08X/0", (int)pMemBuf, bufSize_byte);

   /* try to open memory device
    (NOT fopen: it returns an invalid FILE* if the file/device does not exist!)
   */
   fd = open(name2, O_RDWR, 0644);
   if (fd != ERROR)
      return fdopen(fd, pMode);

   /* create new device for buffer */
   status = memDevCreate (name1, pMemBuf, bufSize_byte);
   if (status == ERROR)
   {
      /* maybe driver not installed? */
      status = memDrv();
      if (status == ERROR)
         return NULL;
      /* try to create again */
      status = memDevCreate (name1, pMemBuf, bufSize_byte);
      if (status == ERROR)
         return NULL;
   }
   /* open again */
   fd = open(name2, O_RDWR, 0644);
   /* should succeed now, but test anyhow! */
   if (fd != ERROR)
      return fdopen(fd, pMode);

   return NULL;
}
#endif

#if ( defined(IFXOS_HAVE_MEMORY_FILE) && (IFXOS_HAVE_MEMORY_FILE == 1) )

/**
   VxWorks User - Open a given memory buffer as stream (file). 
   - The size is limited to 32 kBytes.
   - The intention is to have a buffer where we can use the standard file 
     (stream) operations like fprintf etc.

\param 
   pMemBuf        - temporary buffer for for fprintf operation.
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
   IFXOS_RETURN_IF_POINTER_NULL(pMemBuf, IFX_NULL);
   IFXOS_RETURN_IF_ARG_LE_ZERO(bufSize_byte, IFX_NULL);

   return fmemopen(pMemBuf, bufSize_byte, pMode);
}

/**
   VxWorks User - Close the memory file.

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
   return fclose(pFileFd);
}

#endif

/** @} */

#endif      /* #ifdef VXWORKS */


