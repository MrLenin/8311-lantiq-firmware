#ifndef _IFXOS_GENERIC_OS_PIPE_H
#define _IFXOS_GENERIC_OS_PIPE_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS

/** \file
   This file contains Generic OS definitions for Pipes.
*/

/** \defgroup IFXOS_PIPES_GENERIC_OS_APPL Pipes (Generic OS)

   This Group contains the Generic OS Pipes definitions and function. 

\attention
   For Generic OS - The "pipe" feature is currently not implemented yet!

\ingroup IFXOS_LAYER_GENERIC_OS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Generic OS Adaptation Frame - Includes
   ========================================================================= */
/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

/* ============================================================================
   IFX Generic OS Adaptation Frame - supported features
   ========================================================================= */

/** IFX Generic OS adaptation - User support "Pipes" */
#define IFXOS_HAVE_PIPE                          0

/** IFX Generic OS adaptation - User support "Pipe Create" */
#define IFXOS_HAVE_PIPE_CREATE                   0

/** IFX Generic OS adaptation - User support "Pipe Write" */
#define IFXOS_HAVE_PIPE_WRITE                    0

/** IFX Generic OS adaptation - User support "Pipe Read" */
#define IFXOS_HAVE_PIPE_READ                     0


/* ============================================================================
   IFX Generic OS adaptation - types
   ========================================================================= */

/** Generic OS User - pipe access, type pipe for pipe stream handling */
typedef IFX_int_t                IFXOS_Pipe_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef GENERIC_OS */
#endif      /* #ifndef _IFXOS_GENERIC_OS_PIPE_H */


