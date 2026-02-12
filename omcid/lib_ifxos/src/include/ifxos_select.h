#ifndef _IFXOS_DRV_SELECT_H
#define _IFXOS_DRV_SELECT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for Select Synchronisation and Signalisation on Driver Side.
*/

/** \defgroup IFXOS_IF_DRV_SELECT Poll/Select (Driver Side).

   This Group contains the Synchronisation and signalisation definitions and function
   on driver side for communication between driver and user code.

\note
   The intention of these signaling feature is to communicate between driver and 
   user parts.

\attention
   For the select feature the underlaying OS have corresponding support this.
   Further a corresponding adaptation on user and driver side is required.

\remarks
   For synchronisation between threads / Tasks please have a look for the 
   "event" feature.

\ingroup IFXOS_IF_SYNC
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

#if ( !defined(IFXOS_FLAT_HIRACHY) || (IFXOS_FLAT_HIRACHY == 0) )
#  if defined(LINUX)
#     include "linux/ifxos_linux_select.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_select.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_select.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_select.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_select.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_select.h"
#  elif defined(XAPI)
#     include "xapi/ifxos_xapi_select.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_select.h"
#  else
#     error "Poll/Select Adaptation - Please define your OS"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_select.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_select.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_select.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_select.h"
#  elif defined(WIN32)
#     include "ifxos_win32_select.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_select.h"
#  elif defined(XAPI)
#     include "ifxos_xapi_select.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_select.h"
#  else
#     error "Poll/Select Adaptation - Please define your OS"
#  endif
#endif


/* ============================================================================
   IFX OS adaptation - Driver SELECT handling, functions
   ========================================================================= */
/** \addtogroup IFXOS_IF_DRV_SELECT
@{ */

#if ( defined(IFXOS_HAVE_DRV_SELECT) && (IFXOS_HAVE_DRV_SELECT == 1) )

/**
   Initialize a Select Queue Object for synchronisation between user and driver space
   via the select / poll mechanism.

\param
   pDrvSelectQueue   Points to a Driver Select Queue object.

\return 
   None
*/
IFX_int32_t IFXOS_DrvSelectQueueInit(
               IFXOS_drvSelectQueue_t  *pDrvSelectQueue);

/**
   Wakeup from the Select Queue all added task. 
   This function is used from driver space to signal the occurance of an event 
   from driver space to one or several waiting user (poll / select mechanism).

\param
   pDrvSelectQueue   Points to used Select Queue object.
\param
   drvSelType        OS specific parameter.

\return
   None
*/
IFX_void_t IFXOS_DrvSelectQueueWakeUp(
               IFXOS_drvSelectQueue_t  *pDrvSelectQueue,
               IFX_uint32_t            drvSelType);

/**
   Add an user thread / task to a Select Queue
   This function is used from user space to add a thread / task to a corresponding
   Select Queue. The thread / task will be waked up if the event occures or if
   the time expires.

\note
   The add function is called by the corresponding OS system call.

\param
   pDrvSelectOsArg   OS specific parameter.
\param
   pDrvSelectQueue   Points to used Select Queue object.
\param
   pDrvSelectTable   OS specific parameter.

\return
   IFX_SUCCESS if the thread / task has been added, else
   IFX_ERROR.
*/
IFX_int32_t IFXOS_DrvSelectQueueAddTask(
               IFXOS_drvSelectOSArg_t  *pDrvSelectOsArg,
               IFXOS_drvSelectQueue_t  *pDrvSelectQueue,
               IFXOS_drvSelectTable_t  *pDrvSelectTable);

#endif      /* #if ( defined(IFXOS_HAVE_DRV_SELECT) && (IFXOS_HAVE_DRV_SELECT == 1) ) */

/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_DRV_SELECT_H */

