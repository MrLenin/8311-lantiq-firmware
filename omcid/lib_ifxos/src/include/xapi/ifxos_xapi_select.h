#ifndef _IFXOS_XAPI_DRV_SELECT_H
#define _IFXOS_XAPI_DRV_SELECT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef XAPI

/** \file
   This file contains XAPI definitions for Select mechanism on Driver Side.
*/

/** \defgroup IFXOS_SELECT_XAPI_DRV Poll/Select, Driver Side (XAPI).

   This Group contains the XAPI Synchronisation definitions and function
   on driver side for communication between driver and user code.

\note
   The intention of these signaling feature is to communicate between driver and 
   user parts.

\attention
   The driver part of the poll / select mechanism makes only sence for Driver Space. 
   So do not use these functions and defines in application space.

\ingroup IFXOS_SYNC_XAPI
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX XAPI adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX XAPI adaptation - supported features
   ========================================================================= */

/** IFX XAPI adaptation - support "Driver SELECT" feature */
#ifndef IFXOS_HAVE_DRV_SELECT
#  define IFXOS_HAVE_DRV_SELECT                          1
#endif

/* ============================================================================
   IFX XAPI adaptation - Driver SELECT types
   ========================================================================= */

/** \addtogroup IFXOS_SELECT_XAPI_DRV
@{ */

#if defined(IFXOS_HAVE_DRV_SELECT) && (IFXOS_HAVE_DRV_SELECT == 1)

/** set if a option is not used for this OS adaptation */
#define IFXOS_DRV_SEL_NOT_USED_FOR_THIS_OS         0
/** wakeup on read, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_RD               1
/** wakeup on write, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_WR               2

/** XAPI - Select, Wakeup List for select/poll handling. */
typedef int                         IFXOS_drvSelectQueue_t;

/** XAPI - Select, XAPI select argument node for select/poll handling. */
typedef int                         IFXOS_drvSelectOSArg_t;

/** XAPI - Select, not used for XAPI. */
typedef void                        IFXOS_drvSelectTable_t;

#endif

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef XAPI */
#endif      /* #ifndef _IFXOS_XAPI_DRV_SELECT_H */

