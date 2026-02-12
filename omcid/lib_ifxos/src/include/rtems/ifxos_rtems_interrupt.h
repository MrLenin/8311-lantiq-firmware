#ifndef _IFXOS_RTEMS_INTERRUPT_H
#define _IFXOS_RTEMS_INTERRUPT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS
/** \file
   This file contains Generic OS definitions for interrupt handling.
*/

/** \defgroup IFXOS_INTERRUPT_RTEMS Interrupt Sub System (Generic OS).

   This Group contains the Generic OS interrupt sub system definitions.

\ingroup IFXOS_LAYER_RTEMS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   RTEMS adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"
#include <intLib.h>

/* ============================================================================
   RTEMS adaptation - supported features
   ========================================================================= */

/** RTEMS adaptation - support interrupt subsystem */
#define IFXOS_HAVE_INTERRUPT                1

/** Lock interrupt handling
\param var - status variable of type IFXOS_INTSTAT
 */
#define IFXOS_LOCKINT(var) \
   var = intLock()

/** Unlock interrupt handling
\param var - interrupt status variable of type IFXOS_INTSTAT
 */
#define IFXOS_UNLOCKINT(var) \
   intUnlock(var)

/** Enable interrupt
\param irq - interrupt number
 */
#define IFXOS_IRQ_ENABLE(irq)      \
   intEnable(irq)

/** Disable interrupt.
\param irq - interrupt number
 */
#define IFXOS_IRQ_DISABLE(irq)      \
   intDisable(irq)

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_INTERRUPT_H */

