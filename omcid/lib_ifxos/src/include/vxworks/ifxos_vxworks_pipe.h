#ifndef _IFXOS_VXWORKS_PIPE_H
#define _IFXOS_VXWORKS_PIPE_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS

/** \file
   This file contains VxWorks definitions for Pipes.
*/

/** \defgroup IFXOS_PIPES_VXWORKS_APPL Pipes (VxWorks)

   This Group contains the VxWorks Pipes definitions and function. 

\attention
   For VxWorks - The "pipe" feature is currently not implemented yet!

\ingroup IFXOS_LAYER_VXWORKS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX VxWorks adaptation - Includes
   ========================================================================= */
#include <vxWorks.h>
#include <stdio.h>

/* ============================================================================
   IFX VxWorks adaptation - supported features
   ========================================================================= */

/** IFX VxWorks adaptation - User support "Pipes" */
#ifndef IFXOS_HAVE_PIPE
#  define IFXOS_HAVE_PIPE                          0
#endif

/** IFX VxWorks adaptation - User support "Pipe Create" */
#ifndef IFXOS_HAVE_PIPE_CREATE
#  define IFXOS_HAVE_PIPE_CREATE                   0
#endif

/** IFX VxWorks adaptation - User support "Pipe Write" */
#ifndef IFXOS_HAVE_PIPE_WRITE
#  define IFXOS_HAVE_PIPE_WRITE                    0
#endif

/** IFX VxWorks adaptation - User support "Pipe Read" */
#ifndef IFXOS_HAVE_PIPE_READ
#  define IFXOS_HAVE_PIPE_READ                     0
#endif

/* ============================================================================
   IFX VxWorks adaptation - types
   ========================================================================= */

/** VxWorks User - pipe access, type pipe for pipe stream handling */
typedef FILE            IFXOS_Pipe_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef VXWORKS */
#endif      /* #ifndef _IFXOS_VXWORKS_PIPE_H */


