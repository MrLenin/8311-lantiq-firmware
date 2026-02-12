#ifndef _IFXOS_NUCLEUS_MUTEX_H
#define _IFXOS_NUCLEUS_MUTEX_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS

/** \file
   This file contains Nucleus definitions for Mutex handling.
*/

/** \defgroup IFXOS_MUTEX_NUCLEUS Mutex (Nucleus).

   This Group contains the Nucleus Mutex definition.

\par Implementation


\attention
   A call to get the MUTEX is not interuptible.
\attention
   Do not use create and get MUTEX on interrupt level.

\ingroup IFXOS_LAYER_NUCLEUS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Nucleus adaptation - Includes
   ========================================================================= */
#include <nucleus.h>

#include "ifx_types.h"

/* ============================================================================
   IFX Nucleus adaptation - supported features
   ========================================================================= */

/** IFX Nucleus adaptation - support "MUTEX feature" */
#ifndef IFXOS_HAVE_MUTEX
#  define IFXOS_HAVE_MUTEX                            1
#endif

/* ============================================================================
   IFX Nucleus adaptation - MUTEX types
   ========================================================================= */
/** \addtogroup IFXOS_MUTEX_NUCLEUS
@{ */

/** Nucleus - MUTEX, type for synchronisation. */
typedef struct
{
   /** mutex identifier */
   NU_SEMAPHORE object;
   /** valid flag */
   IFX_boolean_t bValid;
} IFXOS_mutex_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef NUCLEUS_PLUS */
#endif      /* #ifndef _IFXOS_NUCLEUS_MUTEX_H */

