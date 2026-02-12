#ifndef _IFXOS_LINUX_PIPE_H
#define _IFXOS_LINUX_PIPE_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX

/** \file
   This file contains LINUX definitions for Pipes.
*/

/** \defgroup IFXOS_PIPES_LINUX_APPL Pipes (Linux User Space)

   This Group contains the LINUX Pipes definitions and function. 

\remarks
   Because the pipe concept for other OS can be different the functions are 
   splitted in more detail.

\ingroup IFXOS_LAYER_LINUX
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX LINUX adaptation - Includes
   ========================================================================= */
#include <stdio.h>
#include <sys/types.h>

/* ============================================================================
   IFX LINUX adaptation - supported features
   ========================================================================= */

/** IFX LINUX adaptation - Application support "Pipes" */
#ifndef IFXOS_HAVE_PIPE
#  define IFXOS_HAVE_PIPE                          1
#endif

/** IFX LINUX adaptation - Application support "Pipe Create" */
#ifndef IFXOS_HAVE_PIPE_CREATE
#  define IFXOS_HAVE_PIPE_CREATE                   1
#endif

/** IFX LINUX adaptation - Application support "Pipe Write" */
#ifndef IFXOS_HAVE_PIPE_WRITE
#  define IFXOS_HAVE_PIPE_WRITE                    1
#endif

/** IFX LINUX adaptation - Application support "Pipe Read" */
#ifndef IFXOS_HAVE_PIPE_READ
#  define IFXOS_HAVE_PIPE_READ                     1
#endif

/* ============================================================================
   IFX LINUX adaptation - defines, types
   ========================================================================= */

#ifndef PRJ_NAME_PREFIX
   /** define a project specific name prefix for the pipe location */
#  define PRJ_NAME_PREFIX
#endif

#ifndef IFXOS_SYS_NAME_PREFIX
   /** define the system specific name prefix (base dir, name) */
#  define IFXOS_SYS_NAME_PREFIX  PRJ_NAME_PREFIX"/tmp"
#endif

/** define the pipe specific name (base dir, name) */
#define IFXOS_SYS_PIPE_PREFIX  IFXOS_SYS_NAME_PREFIX"/pipe"


/** LINUX User - pipe access, type pipe for pipe stream handling */
typedef FILE            IFXOS_Pipe_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef LINUX */
#endif      /* #ifndef _IFXOS_LINUX_PIPE_H */


