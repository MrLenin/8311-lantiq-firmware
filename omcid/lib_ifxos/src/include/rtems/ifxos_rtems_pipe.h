#ifndef _IFXOS_RTEMS_PIPE_H
#define _IFXOS_RTEMS_PIPE_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains Generic OS definitions for Pipes.
*/

/** \defgroup IFXOS_PIPES_RTEMS_APPL Pipes (Generic OS)

   This Group contains the Generic OS Pipes definitions and function.

\attention
   For Generic OS - The "pipe" feature is currently not implemented yet!

\ingroup IFXOS_LAYER_RTEMS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   RTEMS Adaptation Frame - Includes
   ========================================================================= */
/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

/* ============================================================================
   RTEMS Adaptation Frame - supported features
   ========================================================================= */

/** RTEMS adaptation - User support "Pipes" */
#define IFXOS_HAVE_PIPE                          0

/** RTEMS adaptation - User support "Pipe Create" */
#define IFXOS_HAVE_PIPE_CREATE                   0

/** RTEMS adaptation - User support "Pipe Write" */
#define IFXOS_HAVE_PIPE_WRITE                    0

/** RTEMS adaptation - User support "Pipe Read" */
#define IFXOS_HAVE_PIPE_READ                     0


/* ============================================================================
   RTEMS adaptation - types
   ========================================================================= */

/** Generic OS User - pipe access, type pipe for pipe stream handling */
typedef IFX_int_t                IFXOS_Pipe_t;

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_PIPE_H */


