#ifndef _IFXOS_GENERIC_OS_INTERRUPT_H
#define _IFXOS_GENERIC_OS_INTERRUPT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS
/** \file
   This file contains Generic OS definitions for interrupt handling.
*/

/** \defgroup IFXOS_INTERRUPT_GENERIC_OS Interrupt Sub System (Generic OS).

   This Group contains the Generic OS interrupt sub system definitions.

\ingroup IFXOS_LAYER_GENERIC_OS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Generic OS adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   IFX Generic OS adaptation - supported features
   ========================================================================= */

/** IFX Generic OS adaptation - support interrupt subsystem */
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
#endif      /* #ifdef GENERIC_OS */
#endif      /* #ifndef _IFXOS_GENERIC_OS_INTERRUPT_H */

