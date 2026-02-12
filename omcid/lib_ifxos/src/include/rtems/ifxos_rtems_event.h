#ifndef _IFXOS_RTEMS_EVENT_H
#define _IFXOS_RTEMS_EVENT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains Generic OS definitions for Event Synchronisation and Signalisation.
*/

/** \defgroup IFXOS_SYNC_RTEMS Synchronisation.

   This Group collect the Generic OS synchronisation and signaling mechanism used within
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

\ingroup IFXOS_LAYER_RTEMS
*/

/** \defgroup IFXOS_EVENT_RTEMS Event Synchronisation (Generic OS).

   This Group contains the Generic OS Event definitions and function for
   communication of tasks.

\par Implementation
   The event handling is based on binary semaphores (FIFO queuing, with timeout).

\ingroup IFXOS_SYNC_RTEMS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   RTEMS adaptation - Includes
   ========================================================================= */

/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/
#include "ifx_types.h"

/* ============================================================================
   RTEMS adaptation - supported features
   ========================================================================= */

/** RTEMS adaptation - support "EVENT feature" */
#define IFXOS_HAVE_EVENT                           1


/* ============================================================================
   RTEMS adaptation - EVENT types
   ========================================================================= */
/** \addtogroup IFXOS_EVENT_RTEMS
@{ */

/** RTEMS - EVENT, type for synchronisation. */
typedef struct
{
   /** event object */
   IFX_int_t     object;
   /** valid flag */
   IFX_boolean_t bValid;

   unsigned long eventMask;
} IFXOS_event_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef RTEMS */
#endif      /* #ifndef _IFXOS_RTEMS_EVENT_H */

