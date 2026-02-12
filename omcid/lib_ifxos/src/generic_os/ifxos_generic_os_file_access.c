/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS

/** \file
   This file contains the IFXOS Layer implementation for 
   GENERIC_OS File Access.
*/

/* ============================================================================
   IFX GENERIC_OS Adaptation Frame - Global Includes
   ========================================================================= */
/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_file_access.h"
#include "ifxos_debug.h"

#if (IFXOS_HAVE_FILESYSTEM == 1)
#include "ifxos_memory_alloc.h"
#endif

/* ============================================================================
   IFX GENERIC_OS Adaptation Frame - defines
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
   IFX GENERIC_OS Adaptation Frame - User Space, File Access
   ========================================================================= */

/** \addtogroup IFXOS_FILE_ACCESS_GENERIC_OS_APPL
@{ */
#if ( defined(IFXOS_HAVE_FILE_ACCESS) && (IFXOS_HAVE_FILE_ACCESS == 1) )
/**
   GENERIC_OS User - Open a file.

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      return fopen(pName, pMode);
   */

   IFXOS_RETURN_IF_POINTER_NULL(pName, ((IFXOS_File_t *)IFX_NULL));
   IFXOS_RETURN_IF_POINTER_NULL(pMode, ((IFXOS_File_t *)IFX_NULL));

   return (IFXOS_File_t *)1;
}

/**
   GENERIC_OS User - Close the file or memory file.

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         return fclose(pFileFd);
   */

   IFXOS_RETURN_IF_POINTER_NULL(pFileFd, IFX_ERROR);

   return IFX_SUCCESS;
}


/**
   GENERIC_OS User - Read from a stream (file, stdin) number of elements with the 
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

*/
IFX_size_t IFXOS_FRead(
                  IFX_void_t     *pDataBuf, 
                  IFX_size_t     elementSize_byte,  
                  IFX_size_t     elementCount, 
                  IFXOS_File_t   *stream)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         return fread(pDataBuf, elementSize_byte,  elementCount, stream);
   */

   IFXOS_RETURN_IF_POINTER_NULL(pDataBuf, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(stream, IFX_ERROR);

   return elementCount;
}

/**
   GENERIC_OS User - Write to a stream (file, pipe, stdout) number of elements with 
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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         return fwrite(pDataBuf, elementSize_byte, elementCount, stream);
   */

   IFXOS_RETURN_IF_POINTER_NULL(pDataBuf, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(stream, IFX_ERROR);

   return elementCount;
}

/**
   GENERIC_OS User - Flush a stream (file or pipe).
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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         return fflush(stream);
   */

   IFXOS_RETURN_IF_POINTER_NULL(stream, IFX_ERROR);

   return IFX_SUCCESS;
}

/**
   GENERIC_OS User - End of file test of a file.

\param
   stream      - Stream handle which identify the file.

\return
   "non zero value" if EOF is set.
*/
IFX_int_t IFXOS_FEof(IFXOS_File_t *stream)
{

   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         return feof(stream);
   */

   IFXOS_RETURN_IF_POINTER_NULL(stream, 0);

   return 1;
}

/**
  GENERIC_OS User - Get file status info.

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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         return stat(pName, pStatInfo);
   */

   IFXOS_RETURN_IF_POINTER_NULL(pName, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(pStatInfo, IFX_ERROR);

   return IFX_SUCCESS;
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
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      - get the file statistics
      - allocate memory for load the file
        --> Allocate file size + 1 - to add null termination
        --> terminate the file buffer
      - open and load the file
      - close the file
      - set the return values
   */
   IFXOS_RETURN_IF_POINTER_NULL(pName, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(*ppDataBuf, IFX_ERROR);
   IFXOS_RETURN_IF_POINTER_NULL(pBufSize_byte, IFX_ERROR);

   *pBufSize_byte = 0;
   *ppDataBuf     = IFX_NULL;

   return IFX_ERROR;

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

   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      - open the file
      - write the data
      - close the file
   */
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


/** \addtogroup IFXOS_MEM_FILE_GENERIC_OS
@{ */

#if ( defined(IFXOS_ADD_LOCAL_FMEMOPEN) && (IFXOS_ADD_LOCAL_FMEMOPEN == 1) )


IFXOS_STATIC IFXOS_File_t *fmemopen (
                        void        *pMemBuf, 
                        int         bufSize_byte, 
                        const char  *pMode);


/** 
   GENERIC_OS user - Implementation of the missing function "fmemopen".

\param 
   pMemBuf        - temporary buffer for for fprintf operation.
\param 
   bufSize_byte   - size of the memory buffer
\param 
   pMode          - Points to the open mode string. 
                    Not used for mem files !

*/
IFXOS_STATIC IFXOS_File_t *fmemopen (
                        void        *pMemBuf, 
                        int         bufSize_byte, 
                        const char  *pMode)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      - get the file statistics
      - allocate memory for load the file
      - open and load the file
      - close the file
      - set the return values
   */
   IFXOS_RETURN_IF_POINTER_NULL(pMemBuf, IFX_NULL);
   IFXOS_RETURN_IF_POINTER_NULL(pMode, IFX_NULL);
   IFXOS_RETURN_IF_ARG_LE_ZERO(bufSize_byte, IFX_NULL);


   return IFX_NULL;
}
#endif

#if ( defined(IFXOS_HAVE_MEMORY_FILE) && (IFXOS_HAVE_MEMORY_FILE == 1) )

/**
   GENERIC_OS User - Open a given memory buffer as stream (file). 
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
   - pointer to IFXOS_File_t structure
   - in case of error the return value is NULL
*/
IFXOS_File_t *IFXOS_FMemOpen (
                  IFX_char_t        *pMemBuf, 
                  const IFX_uint_t  bufSize_byte, 
                  const IFX_char_t  *pMode)
{
   return fmemopen(pMemBuf, bufSize_byte, pMode);
}
#endif

/** @} */

#endif      /* #ifdef GENERIC_OS */


