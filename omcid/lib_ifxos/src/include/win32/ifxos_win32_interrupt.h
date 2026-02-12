#ifndef _IFXOS_WIN32_INTERRUPT_H
#define _IFXOS_WIN32_INTERRUPT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32
/** \file
   This file contains Win32 definitions for interrupt handling.
*/

/** \defgroup IFXOS_INTERRUPT_WIN32 Interrupt Sub System (Win32).

   This Group contains the Win32 interrupt sub system definitions.

\ingroup IFXOS_LAYER_WIN32
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Win32 adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

/** IFX Win32 adaptation - support interrupt subsystem */
#ifndef IFXOS_HAVE_INTERRUPT
#  define IFXOS_HAVE_INTERRUPT                1
#endif

#if (defined(IFXOS_HAVE_INTERRUPT) && (IFXOS_HAVE_INTERRUPT == 1))

typedef unsigned int IFXOS_INTSTAT;

#endif

/** Lock interrupt handling
\param var - status variable of type IFXOS_INTSTAT

\attention not implemented now
 */
#define IFXOS_LOCKINT(var)

/** Unlock interrupt handling
\param var - interrupt status variable of type IFXOS_INTSTAT

\attention not implemented now
 */
#define IFXOS_UNLOCKINT(var)

/** Enable interrupt
\param irq - interrupt number
 
\attention not implemented now
 */
#define IFXOS_IRQ_ENABLE(irq)

/** Disable interrupt.
\param irq - interrupt number

\attention not implemented now
 */
#define IFXOS_IRQ_DISABLE(irq)

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_WIN32_INTERRUPT_H */

