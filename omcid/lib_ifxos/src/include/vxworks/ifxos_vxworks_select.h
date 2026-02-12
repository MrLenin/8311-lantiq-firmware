#ifndef _IFXOS_VXWORKS_DRV_SELECT_H
#define _IFXOS_VXWORKS_DRV_SELECT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS

/** \file
   This file contains VxWorks definitions for Select mechanism on Driver Side.
*/

/** \defgroup IFXOS_SELECT_VXWORKS_DRV Poll/Select, Driver Side (VxWorks).

   This Group contains the VxWorks Synchronisation definitions and function
   on driver side for communication between driver and user code.

\note
   The intention of these signaling feature is to communicate between driver and 
   user parts.

\attention
   The driver part of the poll / select mechanism makes only sence for Driver Space. 
   So do not use these functions and defines in application space.

\ingroup IFXOS_SYNC_VXWORKS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX VxWorks adaptation - Includes
   ========================================================================= */
#include <vxWorks.h>
#include <selectLib.h>

/* ============================================================================
   IFX VxWorks adaptation - supported features
   ========================================================================= */

/** IFX VxWorks adaptation - support "Driver SELECT" feature */
#ifndef IFXOS_HAVE_DRV_SELECT
#  define IFXOS_HAVE_DRV_SELECT                          1
#endif
/* ============================================================================
   IFX VxWorks adaptation - Driver SELECT types
   ========================================================================= */

/** \addtogroup IFXOS_SELECT_VXWORKS_DRV
@{ */

/** set if a option is not used for this OS adaptation */
#define IFXOS_DRV_SEL_NOT_USED_FOR_THIS_OS         0
/** wakeup on read, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_RD               SELREAD
/** wakeup on write, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_WR               SELWRITE

/** VxWorks - Select, Wakeup List for select/poll handling. */
typedef SEL_WAKEUP_LIST             IFXOS_drvSelectQueue_t;

/** VxWorks - Select, VxWorks select argument node for select/poll handling. */
typedef SEL_WAKEUP_NODE             IFXOS_drvSelectOSArg_t;

/** VxWorks - Select, not used for VxWorks. */
typedef void                        IFXOS_drvSelectTable_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef VXWORKS */
#endif      /* #ifndef _IFXOS_VXWORKS_DRV_SELECT_H */

