#ifndef _IFXOS_XAPI_EVENT_H
#define _IFXOS_XAPI_EVENT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef XAPI

/** \file
   This file contains XAPI definitions for Event Synchronisation and Signalisation.
*/

/** \defgroup IFXOS_SYNC_XAPI Synchronisation.

   This Group collect the XAPI synchronisation and signaling mechanism used within 
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

\ingroup IFXOS_LAYER_XAPI
*/

/** \defgroup IFXOS_EVENT_XAPI Event Synchronisation (XAPI).

   This Group contains the XAPI Event definitions and function for 
   communication of tasks.

\par Implementation
   The event handling is based on binary semaphores (FIFO queuing, with timeout).

\ingroup IFXOS_SYNC_XAPI
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX XAPI adaptation - Includes
   ========================================================================= */
#include <xapi.h>


/* ============================================================================
   IFX XAPI adaptation - supported features
   ========================================================================= */

/** IFX XAPI adaptation - support "EVENT feature" */
#ifndef IFXOS_HAVE_EVENT
#  define IFXOS_HAVE_EVENT                           1
#endif

/* ============================================================================
   IFX XAPI adaptation - EVENT types
   ========================================================================= */
/** \addtogroup IFXOS_EVENT_XAPI
@{ */

/** XAPI - EVENT, type for synchronisation. */
typedef struct
{
   /** event object */
   IFX_ulong_t object;
   /** valid flag */
   IFX_boolean_t bValid;
} IFXOS_event_t; 

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef XAPI */
#endif      /* #ifndef _IFXOS_XAPI_EVENT_H */

