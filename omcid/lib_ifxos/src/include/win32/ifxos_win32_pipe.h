#ifndef _IFXOS_WIN32_PIPE_H
#define _IFXOS_WIN32_PIPE_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32

/** \file
   This file contains VxWorks definitions for Pipes.
*/

/** \defgroup IFXOS_PIPES_WIN32_APPL Pipes (Win32)

   This Group contains the Win32 Pipes definitions and function. 

\attention
   For Win32 - The "pipe" feature is currently not implemented yet!

\ingroup IFXOS_LAYER_WIN32
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Win32 adaptation - Includes
   ========================================================================= */
#include <stdio.h>

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

/** IFX Win32 adaptation - User support "Pipes" */
#ifndef IFXOS_HAVE_PIPE
#  define IFXOS_HAVE_PIPE                          0
#endif

/** IFX Win32 adaptation - User support "Pipe Create" */
#ifndef IFXOS_HAVE_PIPE_CREATE
#  define IFXOS_HAVE_PIPE_CREATE                   0
#endif

/** IFX Win32 adaptation - User support "Pipe Write" */
#ifndef IFXOS_HAVE_PIPE_WRITE
#  define IFXOS_HAVE_PIPE_WRITE                    0
#endif

/** IFX Win32 adaptation - User support "Pipe Read" */
#ifndef IFXOS_HAVE_PIPE_READ
#  define IFXOS_HAVE_PIPE_READ                     0
#endif

/* ============================================================================
   IFX Win32 adaptation - types
   ========================================================================= */
/** \addtogroup IFXOS_PIPES_WIN32_APPL
@{ */

/** Win32 User - pipe access, type pipe for pipe stream handling */
typedef FILE            IFXOS_Pipe_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_WIN32_PIPE_H */

