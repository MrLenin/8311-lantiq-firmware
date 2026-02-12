#ifndef _IFXOS_ECOS_DRV_SELECT_H
#define _IFXOS_ECOS_DRV_SELECT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains eCos definitions for Select mechanism on Driver Side.
*/

/** \defgroup IFXOS_SELECT_ECOS_DRV Poll/Select, Driver Side (eCos).

   This Group contains the eCos Synchronisation definitions and function
   on driver side for communication between driver and user code.

\note
   The intention of these signaling feature is to communicate between driver and 
   user parts.

\attention
   The driver part of the poll / select mechanism makes only sence for Driver Space. 
   So do not use these functions and defines in application space.

\ingroup IFXOS_SYNC_ECOS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX eCos adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX eCos adaptation - supported features
   ========================================================================= */

/** IFX eCos adaptation - support "Driver SELECT" feature */
#ifndef IFXOS_HAVE_DRV_SELECT
#  define IFXOS_HAVE_DRV_SELECT                          1
#endif

/* ============================================================================
   IFX eCos adaptation - Driver SELECT types
   ========================================================================= */

/** \addtogroup IFXOS_SELECT_ECOS_DRV
@{ */

#if defined(IFXOS_HAVE_DRV_SELECT) && (IFXOS_HAVE_DRV_SELECT == 1)

/** set if a option is not used for this OS adaptation */
#define IFXOS_DRV_SEL_NOT_USED_FOR_THIS_OS         0
/** wakeup on read, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_RD               1
/** wakeup on write, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_WR               2

/** eCos - Select, Wakeup List for select/poll handling. */
typedef int                         IFXOS_drvSelectQueue_t;

/** eCos - Select, eCos select argument node for select/poll handling. */
typedef int                         IFXOS_drvSelectOSArg_t;

/** eCos - Select, not used for eCos. */
typedef void                        IFXOS_drvSelectTable_t;

#endif

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef ECOS */
#endif      /* #ifndef _IFXOS_ECOS_DRV_SELECT_H */

