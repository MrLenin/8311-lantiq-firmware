#ifndef _IFXOS_XAPI_MUTEX_H
#define _IFXOS_XAPI_MUTEX_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef XAPI

/** \file
   This file contains XAPI definitions for Mutex handling.
*/

/** \defgroup IFXOS_MUTEX_XAPI Mutex (XAPI).

   This Group contains the XAPI Mutex definition.

\par Implementation


\attention
   A call to get the MUTEX is not interuptible.
\attention
   Do not use create and get MUTEX on interrupt level.

\ingroup IFXOS_LAYER_XAPI
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX XAPI adaptation - Includes
   ========================================================================= */
#include <xapi.h>

#include "ifx_types.h"

/* ============================================================================
   IFX XAPI adaptation - supported features
   ========================================================================= */

/** IFX XAPI adaptation - support "MUTEX feature" */
#ifndef IFXOS_HAVE_MUTEX
#  define IFXOS_HAVE_MUTEX                            1
#endif

/* ============================================================================
   IFX XAPI adaptation - MUTEX types
   ========================================================================= */
/** \addtogroup IFXOS_MUTEX_XAPI
@{ */

/** XAPI - MUTEX, type for synchronisation. */
typedef struct
{
   /** mutex identifier */
   IFX_ulong_t object;
   /** valid flag */
   IFX_boolean_t bValid;
} IFXOS_mutex_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef XAPI_PLUS */
#endif      /* #ifndef _IFXOS_XAPI_MUTEX_H */

