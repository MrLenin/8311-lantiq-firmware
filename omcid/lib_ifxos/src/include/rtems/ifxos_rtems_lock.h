#ifndef _IFXOS_RTEMS_LOCK_H
#define _IFXOS_RTEMS_LOCK_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains Generic OS definitions for Lock / Protect handling.
*/

/** \defgroup IFXOS_LOCK_RTEMS Lock / Protection (Generic OS).

   This Group contains the Generic OS Lock and Protection definition.

\par Implementation
   The current implementation is based on a binary semaphore and does
   not allow recursive calls.

\attention
   A call to get the LOCK is not interuptible.
\attention
   Do not use create and get LOCK on interrupt level.

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

/** RTEMS adaptation - support "LOCK feature" */
#define IFXOS_HAVE_LOCK                            1

/** RTEMS adaptation - support "LOCK with timeout feature" */
#define IFXOS_HAVE_LOCK_TIMEOUT                    1

/** RTEMS adaptation - support "Global LOCK feature" */
#define IFXOS_HAVE_LOCK_GLOBAL                     0


/* ============================================================================
   RTEMS adaptation - LOCK types
   ========================================================================= */
/** \addtogroup IFXOS_LOCK_RTEMS
@{ */

// spin lock
typedef struct {
	volatile unsigned int lock;
} spinlock_t;
#define SPIN_LOCK_UNLOCKED (spinlock_t) { 0 }

static inline void spin_lock_irqsave(spinlock_t *lock, IFX_uint32_t flags)
{
}
static inline void spin_unlock_irqrestore(spinlock_t *lock, IFX_uint32_t flags)
{
}



/** Generic OS - LOCK, type for synchronisation. */
typedef struct
{
   /** lock id */
   IFX_int_t      object;
   /** valid flag */
   IFX_boolean_t  bValid;
} IFXOS_lock_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_LOCK_H */

