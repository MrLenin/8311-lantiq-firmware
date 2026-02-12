/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation - Pipes (Application Space)
   ========================================================================= */

#ifdef LINUX

/** \file
   This file contains the IFXOS Layer implementation for LINUX Application 
   Pipes.
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes
   ========================================================================= */
#define _GNU_SOURCE     1
#include <features.h>

#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_memory_alloc.h"
#include "ifxos_print_io.h"
#include "ifxos_pipe.h"

/* ============================================================================
   IFX Linux adaptation - Application Space, Pipes
   ========================================================================= */

#ifndef PRJ_NAME_PREFIX
#define PRJ_NAME_PREFIX
#endif

#ifndef IFXOS_SYS_NAME_PREFIX
   /** define the system specific name prefix (base dir, name) */
#  define IFXOS_SYS_NAME_PREFIX  PRJ_NAME_PREFIX"/tmp"
#endif

/** define the pipe specific name (base dir, name) */
#define IFXOS_SYS_PIPE_PREFIX  IFXOS_SYS_NAME_PREFIX"/pipe"


/** \addtogroup IFXOS_PIPES_LINUX_APPL
@{ */

#if ( defined(IFXOS_HAVE_PIPE) && (IFXOS_HAVE_PIPE == 1) )

/** Points to the System specific pipe prefix string */
IFX_char_t *pIFXOSSysPipePrefix = IFXOS_SYS_PIPE_PREFIX;

#if ( defined(IFXOS_HAVE_PIPE_CREATE) && (IFXOS_HAVE_PIPE_CREATE == 1) )
/**
   Create a pipe.

\param
   pName - pipe name

\return
   - IFX_SUCCESS on success
   - IFX_ERROR on failure
*/
IFX_int_t IFXOS_PipeCreate(
                     IFX_char_t *pName)
{
   IFX_int_t   retVal = IFX_SUCCESS;
   IFX_char_t  *pipepath = NULL;

   IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_LOW,
      ("IFXOS - Pipe - create pipe %s" IFXOS_CRLF, pName));

   /* setup pipe path */
   pipepath = IFXOS_MemAlloc(strlen(IFXOS_SYS_PIPE_PREFIX"/") + strlen(pName) + 1);
   if ( !pipepath )
   {
      return IFX_ERROR;
   }
   strcpy(pipepath, IFXOS_SYS_PIPE_PREFIX"/");

   /* try to create directory, ignore error designedly */
   mkdir(pipepath, S_IFDIR | 0777);
   strcat(pipepath, pName);

   /*create a named pipe and check errors*/
   if ((mkfifo(pipepath, 0777) == -1) && (errno != EEXIST))
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Pipe - mkfifo %s failed (errno=%d)" IFXOS_CRLF, 
           pipepath, errno));

      /* delete named pipe */
      /* unlink(pipepath); */
      retVal = IFX_ERROR;
   }

   IFXOS_MemFree (pipepath);
   return retVal;
}
#endif

/**
   Open a pipe.

\param
   pName    - pipe name.
\param
   reading  - if set, open the pipe for read.
\param
   blocking - if set, open the pipe in blocking mode.

\return
   - pointer to IFXOS_Pipe_t structure
   - in case of error the return value is NULL
*/
IFXOS_Pipe_t *IFXOS_PipeOpen(
                     IFX_char_t     *pName, 
                     IFX_boolean_t  reading, 
                     IFX_boolean_t  blocking)
{
   int fd;
   int flags;
   IFXOS_Pipe_t   *pPipe = IFX_NULL;
   IFX_char_t     pipepath[256];

   IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_LOW,
      ("IFXOS - Pipe - open pipe %s/%s" IFXOS_CRLF, 
        IFXOS_SYS_PIPE_PREFIX, pName));

   IFXOS_SNPrintf(pipepath, sizeof(pipepath), IFXOS_SYS_PIPE_PREFIX"/%s", pName);

   /* only open allows the flag "O_NONBLOCK",
      so first open a fd and change it to a IFXOS_File_t* with fdopen() */
   if (reading == IFX_TRUE)
      flags = O_RDONLY;
   else
      flags = O_WRONLY;

   if (!blocking)
      flags |= O_NONBLOCK;

   fd = open(pipepath, flags);
   if (fd <= 0)
   {
      if (errno != ENXIO)
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - Pipe: open %s failed (errno=%d)" IFXOS_CRLF, 
              pipepath, errno));
      }

      switch(errno)
      {
         case EEXIST:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "pathname already exists and O_CREAT and O_EXCL were used" IFXOS_CRLF));
            break;

         case EISDIR:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "pathname refers to a directory and the access requested involved "
                "writing (that is, O_WRONLY or O_RDWR is set" IFXOS_CRLF));
            break;

         case EACCES:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "The requested access to the file is not allowed, or one  of  the "
                "directories  in  pathname did not allow search (execute) permission, "
                "or the file did not exist yet and write access to the parent directory is not allowed" IFXOS_CRLF));
            break;

         case ENAMETOOLONG:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "pathname was too long" IFXOS_CRLF));
            break;

         case ENOENT:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "O_CREAT  is  not  set  and the named file does not exist. "
                " Or, a directory component in pathname does not exist or is "
                "a dangling symbolic link." IFXOS_CRLF));
            break;

         case ENOTDIR:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "A  component  used as a directory in pathname is not, in fact, "
                "a directory, or O_DIRECTORY was specified and pathname was  not "
                "a directory." IFXOS_CRLF));
            break;

         case ENXIO:
            IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_NORMAL,
               ("IFXOS ERROR - Pipe - open: "
                "O_NONBLOCK  |  O_WRONLY  is set, the named file is a FIFO and "
                "no process has the file open for reading.  Or, the file is "
                "a device special file and no corresponding device exists." IFXOS_CRLF));
            break;

         case ENODEV:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "pathname  refers  to  a device special file and no corresponding "
                "device exists.  (This is a Linux kernel bug - in this  situation "
                "ENXIO must be returned.)" IFXOS_CRLF));
            break;

         case EROFS:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "pathname  refers  to  a file on a read-only filesystem and write "
                "access was requested." IFXOS_CRLF));
            break;

         case ETXTBSY:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "pathname refers to an executable image which is currently  being "
                "executed and write access was requested." IFXOS_CRLF));
            break;

         case EFAULT:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "pathname points outside your accessible address space." IFXOS_CRLF));
            break;
         case ELOOP:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "Too  many symbolic links were encountered in resolving pathname, "
                "or O_NOFOLLOW was specified but pathname was a symbolic link." IFXOS_CRLF));
            break;
         case ENOSPC:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "pathname was to be created but the  device  containing  pathname "
                "has no room for the new file." IFXOS_CRLF));
            break;
         case ENOMEM:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "Insufficient kernel memory was available." IFXOS_CRLF));
            break;

         case EMFILE:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "The process already has the maximum number of files open." IFXOS_CRLF));
            break;

         case ENFILE:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: "
                "The  limit  on  the total number of files open on the system has "
                "been reached." IFXOS_CRLF));
            break;

         default:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Pipe open: %s" IFXOS_CRLF, strerror(errno)));
            break;
      }

   }

   if (fd > 0)
   {
      if (reading == IFX_TRUE)
         pPipe = fdopen(fd, "r");
      else
         pPipe = fdopen(fd, "w");

      if (pPipe == IFX_NULL)
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - Pipe - fdopen %s failed (errno=%d)" IFXOS_CRLF, 
              pipepath, errno));
      }
   }

   return pPipe;
}

/**
   Close a pipe.

\param
   pPipe    - handle of the pipe stream

\return
   - IFX_SUCCESS on success
   - IFX_ERROR on failure
*/
IFX_int_t IFXOS_PipeClose(IFXOS_Pipe_t *pPipe)
{
   fflush(pPipe);
   return (fclose(pPipe)==0) ? IFX_SUCCESS : IFX_ERROR;
}

#if ( defined(IFXOS_HAVE_PIPE_WRITE) && (IFXOS_HAVE_PIPE_WRITE == 1) )
/**
   Print to a pipe.

\param
   streamPipe  - handle of the pipe stream.
\param
   format      - points to the printf format string.
   
\return
   For success - Number of written bytes.
   For error   - negative value.

*/
IFX_int_t IFXOS_PipePrintf(
                     IFXOS_Pipe_t      *streamPipe, 
                     const IFX_char_t  *format, ...)
{
   va_list     ap;         /* points to each unnamed arg in turn */
   IFX_int_t   retVal = 0;

   va_start(ap, format);   /* set ap pointer to 1st unnamed arg */

   retVal = vfprintf(streamPipe, format, ap);

   va_end(ap);

   return retVal;
}
#endif

#if ( defined(IFXOS_HAVE_PIPE_READ) && (IFXOS_HAVE_PIPE_READ == 1) )
/**
   Read from pipe .

\param
   pDataBuf          - Points to the buffer used for get the data. [o]
\param
   elementSize_byte  - Element size of one element to read [byte]
\param
   elementCount      - Number of elements to read
\param
   pPipe             - handle of the pipe stream.

\return
   Number of read elements

\attention
   If an error occurs, or the end-of-file is reached, the return value is
   a short item count (or zero) (see errno)
*/
IFX_int_t IFXOS_PipeRead(
                     IFX_void_t     *pDataBuf, 
                     IFX_uint32_t   elementSize_byte,  
                     IFX_uint32_t   elementCount, 
                     IFXOS_Pipe_t   *pPipe)
{
   return fread(pDataBuf, elementSize_byte,  elementCount, pPipe);
}
#endif

#endif      /* #if ( defined(IFXOS_HAVE_PIPE) && (IFXOS_HAVE_PIPE == 1) ) */

/** @} */

#endif      /* #ifdef LINUX */


