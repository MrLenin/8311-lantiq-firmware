#ifndef _IFXOS_WIN32_EVENT_H
#define _IFXOS_WIN32_EVENT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32

/** \file
   This file contains Win32 definitions for Event Synchronisation and Signalisation.
*/

/** \defgroup IFXOS_SYNC_WIN32 Synchronisation.

   This Group collect the Win32 synchronisation and signaling mechanism used within 
   IFXOS.

   The IFX OS differs between the synchronisation on processes level 
   (threads / tasks) and between user and driver space.

\par Task level Syncronisation
   For synchronisation on task level a "Event feature" is provided.

\note
   The intention of these signaling feature is to communicate between different
   tasks within the driver space or within the applicaton space.

\par Application-Driver Syncronisation
   Therefore the poll/select mechanism is prepared. 

\ingroup IFXOS_LAYER_WIN32
*/

/** \defgroup IFXOS_EVENT_WIN32 Event Synchronisation (Win32).

   This Group contains the VxWorks Event definitions and function for 
   communication of tasks.

\par Implementation
   The event handling is based on binary semaphores (FIFO queuing, with timeout).

\ingroup IFXOS_SYNC_WIN32
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Win32 adaptation - Includes
   ========================================================================= */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

/** IFX VxWorks adaptation - support "EVENT feature" */
#ifndef IFXOS_HAVE_EVENT
#  define IFXOS_HAVE_EVENT                           1
#endif

/* ============================================================================
   IFX Win32 adaptation - EVENT types
   ========================================================================= */
/** \addtogroup IFXOS_EVENT_WIN32
@{ */

/** Win32 - EVENT, type for synchronisation. */
typedef struct
{
   /** event object */
   HANDLE object;
   /** valid flag */
   IFX_boolean_t bValid;
} IFXOS_event_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_WIN32_EVENT_H */

