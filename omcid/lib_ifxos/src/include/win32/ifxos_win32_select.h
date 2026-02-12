#ifndef _IFXOS_WIN32_DRV_SELECT_H
#define _IFXOS_WIN32_DRV_SELECT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32

/** \file
   This file contains VxWorks definitions for Driver SELECT handling.
*/

/** \defgroup IFXOS_SELECT_WIN32_DRV Poll/Select, Driver Side (Win32).

   This Group contains the VxWorks Synchronisation definitions and function
   on driver side for communication between driver and user code.

\note
   The intention of these signaling feature is to communicate between driver and 
   user parts.

\attention
   The driver part of the poll / select mechanism makes only sence for Driver Space. 
   So do not use these functions and defines in application space.

\ingroup IFXOS_SYNC_WIN32
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Win32 adaptation - Includes
   ========================================================================= */

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

/** IFX Win32 adaptation - support "Driver SELECT" feature */
#ifndef IFXOS_HAVE_DRV_SELECT
#  define IFXOS_HAVE_DRV_SELECT                    1
#endif

/* ============================================================================
   IFX Win32 adaptation - types
   ========================================================================= */

/** \addtogroup IFXOS_SELECT_WIN32_DRV
@{ */

/** set if a option is not used for this OS adaptation */
#define IFXOS_DRV_SEL_NOT_USED_FOR_THIS_OS         0
/** wakeup on read, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_RD               IFXOS_DRV_SEL_NOT_USED_FOR_THIS_OS
/** wakeup on write, define used for select wakeup */
#define IFXOS_DRV_SEL_WAKEUP_TYPE_WR               IFXOS_DRV_SEL_NOT_USED_FOR_THIS_OS

/** Win32 - Select, not used for Win32. */
typedef void*                       IFXOS_drvSelectQueue_t;

/** Win32 - Select, not used for Win32. */
typedef void*                       IFXOS_drvSelectOSArg_t;

/** Win32 - Select, not used for Win32. */
typedef void                        IFXOS_drvSelectTable_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_WIN32_DRV_SELECT_H */

