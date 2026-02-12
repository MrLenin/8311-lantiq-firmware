#ifndef _IFXOS_EVENT_H
#define _IFXOS_EVENT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for Event Synchronisation and Signalisation.
*/

/** \defgroup IFXOS_IF_SYNC Synchronisation.

   This Group collect the synchronisation and signaling mechanism used within 
   IFXOS.

   The IFX OS differs between the synchronisation on processes level 
   (threads / tasks) and between user and driver space.

\par processes level Syncronisation
   For synchronisation on thread / task level a "Event feature" is provided.
\note
   The intention of these signaling feature is to communicate between different
   threads / tasks on the same level.
   Here you should take care to keep the split between driver and user space and 
   so do not use this for signalisation between driver and user code.

\par User-Driver Syncronisation
   Therefore the poll/select mechanism is prepared. 

\attention
   For the select feature the underlaying OS have corresponding support this.
   Further a corresponding adaptation on user and driver side is required.

\ingroup IFXOS_INTERFACE
*/

/** \defgroup IFXOS_IF_EVENT Event Synchronisation.

   This Group contains the synchronisation and signalisation definitions and function
   for communication of threads and tasks

\note
   The intention of these signaling feature is to communicate between different
   threads / tasks on the same level.
   Here you should take care to keep the split between driver and user space and 
   so do not use this for signalisation between driver and user code.

\remarks
   For synchronisation between user and driver space please have a look for the 
   "select" feature.

\remarks
   Because of the above explation and on the underlaying OS (Linux) the 
   implementation of this feature may exist for driver and user space twice.

\ingroup IFXOS_IF_SYNC
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Includes
   ========================================================================= */
#if ( !defined(IFXOS_FLAT_HIRACHY) || (IFXOS_FLAT_HIRACHY == 0) )
#  if defined(LINUX)
#     include "linux/ifxos_linux_event.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_event.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_event.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_event.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_event.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_event.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_event.h"
#  elif defined(XAPI)
#     include "xapi/ifxos_xapi_event.h"
#  else
#     error "Event Syncr. Adaptation - Please define your OS"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_event.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_event.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_event.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_event.h"
#  elif defined(WIN32)
#     include "ifxos_win32_event.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_event.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_event.h"
#  elif defined(XAPI)
#     include "ifxos_xapi_event.h"
#  else
#     error "Event Syncr. Adaptation - Please define your OS"
#  endif
#endif

#include "ifx_types.h"

/* ============================================================================
   IFX OS adaptation - EVENT handling, functions
   ========================================================================= */

/** \addtogroup IFXOS_IF_EVENT
@{ */

#if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) )

/**
   Check the init status of the given event object
*/
#define IFXOS_EVENT_INIT_VALID(P_EVENT_ID)\
   (((P_EVENT_ID)) ? (((P_EVENT_ID)->bValid == IFX_TRUE) ? IFX_TRUE : IFX_FALSE) : IFX_FALSE)

/**
   Initialize a Event Object for synchronisation.

\param
   pEventId    Prointer to the Event Object.

\return      
   IFX_SUCCESS if the creation was successful, else
   IFX_ERROR in case of error.
*/
IFX_int_t IFXOS_EventInit(
               IFXOS_event_t  *pEventId);

/**
   Delete the given Event Object.

\param
   pEventId    Prointer to the Event Object.

\return
   IFX_SUCCESS if delete was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int_t IFXOS_EventDelete(
               IFXOS_event_t  *pEventId);

/**
   Wakeup a Event Object to signal the occurance of the "event" to 
   the waiting processes.

\param
   pEventId    Prointer to the Event Object.

\return
   IFX_SUCCESS if wakeup was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int_t IFXOS_EventWakeUp(
               IFXOS_event_t  *pEventId);
               
/**
   Wait for the occurance of an "event" with timeout.

\param
   pEventId       Prointer to the Event Object.
\param
   waitTime_ms    Max time to wait [ms].

\param
   pRetCode    Points to the return code variable. [O]
               - If the pointer is NULL the return code will be ignored, else
                 the corresponding return code will be set
               - For timeout the return code is set to 1.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error or timeout.

\remark
   This functions signals the return reason ("event occured" or "timeout") via the
   pRetCode variable. To differ between error or timeout the value is set to 1.
*/
IFX_int_t IFXOS_EventWait(
               IFXOS_event_t  *pEventId,
               IFX_uint32_t   waitTime_ms,
               IFX_int32_t    *pRetCode);

#endif      /* #if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) ) */

/* @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_EVENT_H */

