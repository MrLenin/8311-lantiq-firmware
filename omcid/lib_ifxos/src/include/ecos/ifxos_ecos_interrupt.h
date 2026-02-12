#ifndef _IFXOS_ECOS_INTERRUPT_H
#define _IFXOS_ECOS_INTERRUPT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS
/** \file
   This file contains eCos definitions for interrupt handling.
*/

/** \defgroup IFXOS_INTERRUPT_ECOS Interrupt Sub System (eCos).

   This Group contains the eCos interrupt sub system definitions.

\ingroup IFXOS_LAYER_ECOS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX eCos adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   IFX eCos adaptation - supported features
   ========================================================================= */

/** IFX eCos adaptation - support interrupt subsystem */
#ifndef IFXOS_HAVE_INTERRUPT
#  define IFXOS_HAVE_INTERRUPT                1
#endif

#if (defined(IFXOS_HAVE_INTERRUPT) && (IFXOS_HAVE_INTERRUPT == 1))

typedef unsigned int IFXOS_INTSTAT;

#endif


/** Lock interrupt handling
\param var - status variable of type IFXOS_INTSTAT
 */
#define IFXOS_LOCKINT(var) \
   var=var; cyg_interrupt_disable()

/** Unlock interrupt handling
\param var - interrupt status variable of type IFXOS_INTSTAT
 */
#define IFXOS_UNLOCKINT(var) \
   var=var; cyg_interrupt_enable()

/** Enable interrupt
\param irq - interrupt number
 */
#define IFXOS_IRQ_ENABLE(irq)      \
   cyg_interrupt_unmask(irq)

/** Disable interrupt.
\param irq - interrupt number
 */
#define IFXOS_IRQ_DISABLE(irq)      \
   cyg_interrupt_mask(irq)

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef ECOS */
#endif      /* #ifndef _IFXOS_ECOS_INTERRUPT_H */

