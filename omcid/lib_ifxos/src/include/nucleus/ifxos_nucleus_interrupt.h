#ifndef _IFXOS_NUCLEUS_INTERRUPT_H
#define _IFXOS_NUCLEUS_INTERRUPT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS
/** \file
   This file contains Nucleus definitions for interrupt handling.
*/

/** \defgroup IFXOS_INTERRUPT_NUCLEUS Interrupt Sub System (Nucleus).

   This Group contains the Nucleus interrupt sub system definitions.

\ingroup IFXOS_LAYER_NUCLEUS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Nucleus adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   IFX Nucleus adaptation - supported features
   ========================================================================= */

/** IFX Nucleus adaptation - support interrupt subsystem */
#ifndef IFXOS_HAVE_INTERRUPT
#  define IFXOS_HAVE_INTERRUPT                1
#endif

#if (defined(IFXOS_HAVE_INTERRUPT) && (IFXOS_HAVE_INTERRUPT == 1))

typedef int IFXOS_INTSTAT;

#endif


/** Lock interrupt handling
\param var - status variable of type IFXOS_INTSTAT
 */
#define IFXOS_LOCKINT(var) \
   var = NU_Control_Interrupts(NU_DISABLE_INTERRUPTS)

/** Unlock interrupt handling
\param var - interrupt status variable of type IFXOS_INTSTAT
 */
#define IFXOS_UNLOCKINT(var) \
   NU_Control_Interrupts(var)

/** Enable interrupt
\param irq - interrupt number

\attention not implemented now
 */
#define IFXOS_IRQ_ENABLE(irq)      \
   irq = irq

/** Disable interrupt.
\param irq - interrupt number

\attention not implemented now
 */
#define IFXOS_IRQ_DISABLE(irq)      \
   irq = irq

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef NUCLEUS_PLUS */
#endif      /* #ifndef _IFXOS_NUCLEUS_INTERRUPT_H */

