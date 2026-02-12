#ifndef _IFXOS_NUCLEUS_DRV_SELECT_H
#define _IFXOS_NUCLEUS_DRV_SELECT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS

/** \file
   This file contains Nucleus definitions for Select mechanism on Driver Side.
*/

/** \defgroup IFXOS_SELECT_NUCLEUS_DRV Poll/Select, Driver Side (Nucleus).

   This Group contains the Nucleus Synchronisation definitions and function
   on driver side for communication between driver and user code.

\note
   The intention of these signaling feature is to communicate between driver and 
   user parts.

\attention
   The driver part of the poll / select mechanism makes only sence for Driver Space. 
   So do not use these functions and defines in application space.

\ingroup IFXOS_SYNC_NUCLEUS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Nucleus adaptation - Includes
   ========================================================================= */
#include <nucleus.h>

/* ============================================================================
   IFX Nucleus adaptation - supported features
   ========================================================================= */

/** IFX Nucleus adaptation - support "Driver SELECT" feature */
#ifndef IFXOS_HAVE_DRV_SELECT
#  define IFXOS_HAVE_DRV_SELECT                          1
#endif

/* ============================================================================
   IFX Nucleus adaptation - Driver SELECT types
   ========================================================================= */

/** \addtogroup IFXOS_SELECT_NUCLEUS_DRV
@{ */

/** set if a option is not used for this OS adaptation */
#define IFXOS_DRV_SEL_NOT_USED_FOR_THIS_OS         0
/** wakeup on read, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_RD               1
/** wakeup on write, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_WR               2

/** Nucleus - Select, Wakeup List for select/poll handling. */
typedef int IFXOS_drvSelectQueue_t;

/** Nucleus - Select, Nucleus select argument node for select/poll handling. */
typedef int IFXOS_drvSelectOSArg_t;

/** Nucleus - Select, not used for Nucleus. */
typedef void IFXOS_drvSelectTable_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef NUCLEUS_PLUS */
#endif      /* #ifndef _IFXOS_NUCLEUS_DRV_SELECT_H */

