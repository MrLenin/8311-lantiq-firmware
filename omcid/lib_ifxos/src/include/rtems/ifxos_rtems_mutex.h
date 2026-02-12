#ifndef _IFXOS_RTEMS_MUTEX_H
#define _IFXOS_RTEMS_MUTEX_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains Generic OS definitions for Mutex handling.
*/

/** \defgroup IFXOS_MUTEX_RTEMS Mutex (Generic OS).

   This Group contains the Generic OS Mutex definition.

\par Implementation


\attention
   A call to get the MUTEX is not interuptible.
\attention
   Do not use create and get MUTEX on interrupt level.

\ingroup IFXOS_LAYER_RTEMS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   RTEMS adaptation - Includes
   ========================================================================= */
/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

#include "ifx_types.h"

/* ============================================================================
   RTEMS adaptation - supported features
   ========================================================================= */

/** RTEMS adaptation - support "MUTEX feature" */
#define IFXOS_HAVE_MUTEX                            1


/* ============================================================================
   RTEMS adaptation - MUTEX types
   ========================================================================= */
/** \addtogroup IFXOS_MUTEX_RTEMS
@{ */

/** Generic OS - MUTEX, type for synchronisation. */
typedef struct
{
   /** mutex identifier */
   IFX_int_t      object;
   /** valid flag */
   IFX_boolean_t  bValid;
} IFXOS_mutex_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_MUTEX_H */

