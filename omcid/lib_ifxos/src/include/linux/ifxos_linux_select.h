#ifndef _IFXOS_LINUX_DRV_SELECT_H
#define _IFXOS_LINUX_DRV_SELECT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX
/** \file
   This file contains LINUX Kernel definitions for Select mechanism on Driver Side.
*/

/** \defgroup IFXOS_DRV_SELECT_LINUX_KERNEL Poll/Select, Driver Side (Linux Kernel).

   This Group contains the LINUX Synchronisation definitions and function
   on driver side for communication between driver and user code.

\note
   The intention of these signaling feature is to communicate between driver and 
   user parts.

\attention
   Under LINUX the driver part of the poll / select mechanism is only available
   in Kernel Space. 
   For User Space (Simulation) see below.

\ingroup IFXOS_SYNC_LINUX
*/


/** \defgroup IFXOS_DRV_SELECT_LINUX_APPL Poll/Select, Driver Side.

   This Group contains the LINUX Synchronisation definitions and function
   on driver side for communication between driver and user code.

\note
   The intention of these signaling feature is to communicate between driver and 
   user parts.

\attention
   The intention of this layer is to allow a application / driver simulation
   within the LINUX user space
   The simulation is base on the IFXOS DevIo implementation.

\ingroup IFXOS_SYNC_LINUX
*/


#ifdef __cplusplus
   extern "C" {
#endif

#ifdef __KERNEL__
/* ============================================================================
   IFX LINUX adaptation - Includes
   ========================================================================= */
#include <linux/wait.h>
#include <linux/fs.h>
#include <linux/poll.h>

/* ============================================================================
   IFX LINUX adaptation - supported features
   ========================================================================= */

/** IFX LINUX Kernel adaptation - support "Driver SELECT" feature */
#ifndef IFXOS_HAVE_DRV_SELECT
#  define IFXOS_HAVE_DRV_SELECT                      1
#endif

/* ============================================================================
   IFX LINUX adaptation - Kernel SELECT types
   ========================================================================= */
/** \addtogroup IFXOS_DRV_SELECT_LINUX_KERNEL
@{ */

/** set if a option is not used for this OS adaptation */
#define IFXOS_DRV_SEL_NOT_USED_FOR_THIS_OS         0

/** select type read - not used for this LINUX adaptation */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_RD               IFXOS_DRV_SEL_NOT_USED_FOR_THIS_OS
/** select type write - not used for this LINUX adaptation */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_WR               IFXOS_DRV_SEL_NOT_USED_FOR_THIS_OS


/** Linux Kernel - Select, Wakeup List for select/poll handling. */
typedef wait_queue_head_t           IFXOS_drvSelectQueue_t;

/** Linux Kernel - Select, OS argument type (file) type for select/poll handling. */
typedef struct file                 IFXOS_drvSelectOSArg_t;

/** Linux Kernel - Select, poll table for select/poll handling. */
typedef poll_table                  IFXOS_drvSelectTable_t;

/** @} */

#else

/** IFX LINUX User adaptation - support "Driver SELECT" for user space (Simulation) */
#ifndef IFXOS_HAVE_DRV_SELECT
#  define IFXOS_HAVE_DRV_SELECT                    1
#endif

#if defined(IFXOS_HAVE_DRV_SELECT) && (IFXOS_HAVE_DRV_SELECT == 1)

/** set if a option is not used for this OS adaptation */
#define IFXOS_DRV_SEL_NOT_USED_FOR_THIS_OS         0
/** wakeup on read, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_RD               1
/** wakeup on write, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_WR               2

/** Linux Appl - Select, Wakeup List for select/poll handling. */
typedef int                         IFXOS_drvSelectQueue_t;

/** Linux Appl - Select, Linux Appl select argument node for select/poll handling. */
typedef int                         IFXOS_drvSelectOSArg_t;

/** Linux Appl - Select, not used for Linux Appl. */
typedef void                        IFXOS_drvSelectTable_t;

#endif

#endif      /* #ifdef __KERNEL__ */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef LINUX */
#endif      /* #ifndef _IFXOS_LINUX_DRV_SELECT_H */

