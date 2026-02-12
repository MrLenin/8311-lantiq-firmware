#ifndef _IFXOS_LINUX_INTERRUPT_H
#define _IFXOS_LINUX_INTERRUPT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX
/** \file
   This file contains Linux definitions for interrupt handling.
*/

/** \defgroup IFXOS_INTERRUPT_LINUX Interrupt Sub System (Linux).

   This Group contains the Linux interrupt sub system definitions.

\ingroup IFXOS_LAYER_LINUX
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Linux adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"
#include <asm/irq.h>

/* ============================================================================
   IFX Linux adaptation - supported features
   ========================================================================= */

/** IFX Linux adaptation - support interrupt subsystem */
#ifndef IFXOS_HAVE_INTERRUPT                 
#  define IFXOS_HAVE_INTERRUPT                1
#endif

#if (defined(IFXOS_HAVE_INTERRUPT) && (IFXOS_HAVE_INTERRUPT == 1))

typedef unsigned long IFXOS_INTSTAT;

#endif


/** Lock interrupt handling
\param var - status variable of type IFXOS_INTSTAT
 */
#define IFXOS_LOCKINT(var) \
   local_irq_save(var)

/** Unlock interrupt handling
\param var - interrupt status variable of type IFXOS_INTSTAT
 */
#define IFXOS_UNLOCKINT(var) \
   local_irq_restore(var)

/** Enable interrupt
\param irq - interrupt number
 */
#define IFXOS_IRQ_ENABLE(irq)      \
   enable_irq(irq)

/** Disable interrupt.
\param irq - interrupt number
 */
#define IFXOS_IRQ_DISABLE(irq)      \
   disable_irq(irq)

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef LINUX */
#endif      /* #ifndef _IFXOS_LINUX_INTERRUPT_H */

