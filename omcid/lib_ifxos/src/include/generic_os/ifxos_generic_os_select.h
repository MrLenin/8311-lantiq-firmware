#ifndef _IFXOS_GENERIC_OS_DRV_SELECT_H
#define _IFXOS_GENERIC_OS_DRV_SELECT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS

/** \file
   This file contains Generic OS definitions for Select mechanism on Driver Side.
*/

/** \defgroup IFXOS_SELECT_GENERIC_OS_DRV Poll/Select, Driver Side (Generic OS).

   This Group contains the Generic OS Synchronisation definitions and function
   on driver side for communication between driver and user code.

\note
   The intention of these signaling feature is to communicate between driver and 
   user parts.

\attention
   The driver part of the poll / select mechanism makes only sence for Driver Space. 
   So do not use these functions and defines in application space.

\ingroup IFXOS_SYNC_GENERIC_OS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Generic OS adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX Generic OS adaptation - supported features
   ========================================================================= */

/** IFX Generic OS adaptation - support "Driver SELECT" feature */
#ifndef IFXOS_HAVE_DRV_SELECT
#define IFXOS_HAVE_DRV_SELECT                          1
#endif

/* ============================================================================
   IFX Generic OS adaptation - Driver SELECT types
   ========================================================================= */

/** \addtogroup IFXOS_SELECT_GENERIC_OS_DRV
@{ */

/** set if a option is not used for this OS adaptation */
#define IFXOS_DRV_SEL_NOT_USED_FOR_THIS_OS         0
/** wakeup on read, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_RD               0
/** wakeup on write, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_WR               1

/** Generic OS - Select, Wakeup List for select/poll handling. */
typedef void*                       IFXOS_drvSelectQueue_t;

/** Generic OS - Select, Generic OS select argument node for select/poll handling. */
typedef IFX_uint32_t                IFXOS_drvSelectOSArg_t;

/** Generic OS - Select, not used for Generic OS. */
typedef void                        IFXOS_drvSelectTable_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef GENERIC_OS */
#endif      /* #ifndef _IFXOS_GENERIC_OS_DRV_SELECT_H */

