#ifndef _IFXOS_ECOS_PIPE_H
#define _IFXOS_ECOS_PIPE_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains eCos definitions for Pipes.
*/

/** \defgroup IFXOS_PIPES_ECOS_APPL Pipes (eCos)

   This Group contains the eCos Pipes definitions and function. 

\attention
   For eCos - The "pipe" feature is currently not implemented yet!

\ingroup IFXOS_LAYER_ECOS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX eCos adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX eCos adaptation - supported features
   ========================================================================= */

/** IFX eCos adaptation - User support "Pipes" */
#ifndef IFXOS_HAVE_PIPE
#  define IFXOS_HAVE_PIPE                          0
#endif

/** IFX eCos adaptation - User support "Pipe Create" */
#ifndef IFXOS_HAVE_PIPE_CREATE
#  define IFXOS_HAVE_PIPE_CREATE                   0
#endif

/** IFX eCos adaptation - User support "Pipe Write" */
#ifndef IFXOS_HAVE_PIPE_WRITE
#  define IFXOS_HAVE_PIPE_WRITE                    0
#endif

/** IFX eCos adaptation - User support "Pipe Read" */
#ifndef IFXOS_HAVE_PIPE_READ
#  define IFXOS_HAVE_PIPE_READ                     0
#endif


/* ============================================================================
   IFX eCos adaptation - types
   ========================================================================= */
#if ( defined(IFXOS_HAVE_PIPE) && (IFXOS_HAVE_PIPE == 1) )

/** eCos User - pipe access, type pipe for pipe stream handling */
typedef FILE            IFXOS_Pipe_t;

#endif

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef ECOS */
#endif      /* #ifndef _IFXOS_ECOS_PIPE_H */


