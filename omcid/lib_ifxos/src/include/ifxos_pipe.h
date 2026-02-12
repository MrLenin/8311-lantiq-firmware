#ifndef _IFXOS_PIPE_H
#define _IFXOS_PIPE_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for Pipes.
*/

/** \defgroup IFXOS_IF_PIPES Pipes

   This Group contains the Pipes definitions and function. 

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
#     include "linux/ifxos_linux_pipe.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_pipe.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_pipe.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_pipe.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_pipe.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_pipe.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_pipe.h"
#  else
#     error "Pipe Adaptation - Please define your OS"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_pipe.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_pipe.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_pipe.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_pipe.h"
#  elif defined(WIN32)
#     include "ifxos_win32_pipe.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_pipe.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_pipe.h"
#  else
#     error "Pipe Adaptation - Please define your OS"
#  endif
#endif

#include "ifx_types.h"

/* ============================================================================
   IFX OS adaptation - Pipes
   ========================================================================= */

/** \addtogroup IFXOS_IF_PIPES
@{ */

#if ( defined(IFXOS_HAVE_PIPE) && (IFXOS_HAVE_PIPE == 1) )

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
                     IFX_char_t *pName);
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
                     IFX_char_t *pName, 
                     IFX_boolean_t reading, 
                     IFX_boolean_t blocking);

/**
   Close a pipe.

\param
   pPipe    - handle of the pipe stream

\return
   - IFX_SUCCESS on success
   - IFX_ERROR on failure
*/
IFX_int_t IFXOS_PipeClose(IFXOS_Pipe_t *pPipe);

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
#ifdef __GNUC__
   __attribute__ ((format (printf, 2, 3)))
#endif
   ;
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
                     IFXOS_Pipe_t   *pPipe);   
#endif

#endif      /* #if ( defined(IFXOS_HAVE_PIPE) && (IFXOS_HAVE_PIPE == 1) ) */

/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_PIPE_H */

