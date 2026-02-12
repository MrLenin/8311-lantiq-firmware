#ifndef _IFXOS_XAPI_INTERRUPT_H
#define _IFXOS_XAPI_INTERRUPT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef XAPI
/** \file
   This file contains XAPI definitions for interrupt handling.
*/

/** \defgroup IFXOS_INTERRUPT_XAPI Interrupt Sub System (XAPI).

   This Group contains the XAPI interrupt sub system definitions.

\ingroup IFXOS_LAYER_XAPI
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX XAPI adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"
#include <xapi.h>
#include <board.h>
/* ============================================================================
   IFX XAPI adaptation - supported features
   ========================================================================= */

/** IFX XAPI adaptation - support interrupt subsystem */
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
   var = var ; xi_mask()

/** Unlock interrupt handling
\param var - interrupt status variable of type IFXOS_INTSTAT
 */
#define IFXOS_UNLOCKINT(var) \
   var = var; xi_umask()

/** Enable interrupt
\param irq - interrupt number
 */
#define IFXOS_IRQ_ENABLE(irq)      \
   board_unmask_intr(irq)

/** Disable interrupt.
\param irq - interrupt number
 */
#define IFXOS_IRQ_DISABLE(irq)      \
   board_mask_intr(irq)

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef XAPI */
#endif      /* #ifndef _IFXOS_XAPI_INTERRUPT_H */

