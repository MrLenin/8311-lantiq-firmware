#ifndef _IFXOS_RTEMS_DRV_SELECT_H
#define _IFXOS_RTEMS_DRV_SELECT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains RTEMS definitions for Select mechanism on Driver Side.
*/

/** \defgroup IFXOS_SELECT_RTEMS_DRV Poll/Select, Driver Side (RTEMS).

   This Group contains the RTEMS Synchronisation definitions and function
   on driver side for communication between driver and user code.

\note
   The intention of these signaling feature is to communicate between driver and
   user parts.

\attention
   The driver part of the poll / select mechanism makes only sence for Driver Space.
   So do not use these functions and defines in application space.

\ingroup IFXOS_SYNC_RTEMS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   RTEMS adaptation - Includes
   ========================================================================= */

/* ============================================================================
   RTEMS adaptation - supported features
   ========================================================================= */

/** RTEMS adaptation - support "Driver SELECT" feature */
#ifndef IFXOS_HAVE_DRV_SELECT
#define IFXOS_HAVE_DRV_SELECT                          1
#endif

/* ============================================================================
   RTEMS adaptation - Driver SELECT types
   ========================================================================= */

/** \addtogroup IFXOS_SELECT_RTEMS_DRV
@{ */

/** set if a option is not used for this OS adaptation */
#define IFXOS_DRV_SEL_NOT_USED_FOR_THIS_OS         0
/** wakeup on read, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_RD               0
/** wakeup on write, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_WR               1

/** RTEMS - Select, Wakeup List for select/poll handling. */
typedef IFX_uint32_t*           IFXOS_drvSelectQueue_t;

/** RTEMS - Select, RTEMS select argument node for select/poll handling. */
typedef void*                   IFXOS_drvSelectOSArg_t;

/** RTEMS - Select, not used for RTEMS. */
typedef void                    IFXOS_drvSelectTable_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_DRV_SELECT_H */

