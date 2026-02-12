#ifndef _IFXOS_NUCLEUS_PIPE_H
#define _IFXOS_NUCLEUS_PIPE_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS

/** \file
   This file contains Nucleus definitions for Pipes.
*/

/** \defgroup IFXOS_PIPES_NUCLEUS_APPL Pipes (Nucleus)

   This Group contains the Nucleus Pipes definitions and function. 

\attention
   For Nucleus - The "pipe" feature is currently not implemented yet!

\ingroup IFXOS_LAYER_NUCLEUS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Nucleus adaptation - Includes
   ========================================================================= */
#include <nucleus.h>
#include <stdio.h>

/* ============================================================================
   IFX Nucleus adaptation - supported features
   ========================================================================= */

/** IFX Nucleus adaptation - User support "Pipes" */
#ifndef IFXOS_HAVE_PIPE
#  define IFXOS_HAVE_PIPE                          0
#endif

/** IFX Nucleus adaptation - User support "Pipe Create" */
#ifndef IFXOS_HAVE_PIPE_CREATE
#  define IFXOS_HAVE_PIPE_CREATE                   0
#endif

/** IFX Nucleus adaptation - User support "Pipe Write" */
#ifndef IFXOS_HAVE_PIPE_WRITE
#  define IFXOS_HAVE_PIPE_WRITE                    0
#endif

/** IFX Nucleus adaptation - User support "Pipe Read" */
#ifndef IFXOS_HAVE_PIPE_READ
#  define IFXOS_HAVE_PIPE_READ                     0
#endif

/* ============================================================================
   IFX Nucleus adaptation - types
   ========================================================================= */

/** Nucleus User - pipe access, type pipe for pipe stream handling */
typedef FILE            IFXOS_Pipe_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef NUCLEUS_PLUS */
#endif      /* #ifndef _IFXOS_NUCLEUS_PIPE_H */


