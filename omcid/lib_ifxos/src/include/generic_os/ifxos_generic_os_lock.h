#ifndef _IFXOS_GENERIC_OS_LOCK_H
#define _IFXOS_GENERIC_OS_LOCK_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS

/** \file
   This file contains Generic OS definitions for Lock / Protect handling.
*/

/** \defgroup IFXOS_LOCK_GENERIC_OS Lock / Protection (Generic OS).

   This Group contains the Generic OS Lock and Protection definition.

\par Implementation
   The current implementation is based on a binary semaphore and does 
   not allow recursive calls.

\attention
   A call to get the LOCK is not interuptible.
\attention
   Do not use create and get LOCK on interrupt level.

\ingroup IFXOS_LAYER_GENERIC_OS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Generic OS adaptation - Includes
   ========================================================================= */
/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

#include "ifx_types.h"

/* ============================================================================
   IFX Generic OS adaptation - supported features
   ========================================================================= */

/** IFX Generic OS adaptation - support "LOCK feature" */
#define IFXOS_HAVE_LOCK                            1

/** IFX Generic OS adaptation - support "LOCK with timeout feature" */
#define IFXOS_HAVE_LOCK_TIMEOUT                    1

   /** IFX Generic OS adaptation - support "named LOCK feature" */
#define IFXOS_HAVE_NAMED_LOCK                      0

/** IFX Generic OS adaptation - support "Global LOCK feature" */
#define IFXOS_HAVE_LOCK_GLOBAL                     0


/* ============================================================================
   IFX Generic OS adaptation - LOCK types
   ========================================================================= */
/** \addtogroup IFXOS_LOCK_GENERIC_OS
@{ */


/** Generic OS - LOCK, type for synchronisation. */
typedef struct
{
   /** lock id */
   IFX_int_t      object;
   /** valid flag */
   IFX_boolean_t  bValid;

   /** points to the internal system object - for debugging */
   IFX_void_t  *pSysObject;
} IFXOS_lock_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef GENERIC_OS */
#endif      /* #ifndef _IFXOS_GENERIC_OS_LOCK_H */

