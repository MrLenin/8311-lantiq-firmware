#ifndef _IFXOS_LINUX_EVENT_H
#define _IFXOS_LINUX_EVENT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX

/** \file
   This file contains LINUX definitions for Event Synchronisation and Signalisation.
*/

/** \defgroup IFXOS_SYNC_LINUX Synchronisation.

   This Group collect the LINUX synchronisation and signaling mechanism used within 
   IFXOS.

   The IFX OS differs between the synchronisation on processes level 
   (threads / tasks) and between user and driver space.

\par processes level Syncronisation
   For synchronisation on thread / task level a "Event feature" is provided.

\note
   The intention of these signaling feature is to communicate between different
   threads.
   The feature under LINUX is available in Kernel and User space.

\par Application-Driver Syncronisation
   Therefore the poll/select mechanism is prepared. 

\ingroup IFXOS_LAYER_LINUX
*/

/** \defgroup IFXOS_EVENT_LINUX_USER Event Synchronisation (Linux User Space).

   This Group contains the LINUX Event definitions and function for 
   communication of threads.

\note
   The intention of these signaling feature is to communicate between different
   threads within the driver.

\ingroup IFXOS_SYNC_LINUX
*/

/** \defgroup IFXOS_EVENT_LINUX_KERNEL Event Synchronisation (Linux Kernel).

   This Group contains the LINUX Kernel Event definitions and function for 
   communication within the driver code.

\note
   The intention of these signaling feature is to communicate between different
   threads and the ISR within the kernel.

\par Implementation
   The event handling is based on the kernel wait_queues.

\ingroup IFXOS_SYNC_LINUX
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX LINUX adaptation - Includes
   ========================================================================= */
#ifdef __KERNEL__
#  include <linux/kernel.h>
#  include <linux/poll.h> /* wait_queue_head_t */
#else
#endif

/* ============================================================================
   IFX LINUX adaptation - supported features
   ========================================================================= */
#ifdef __KERNEL__

   /** IFX LINUX adaptation - support "EVENT feature" */
#  ifndef IFXOS_HAVE_EVENT
#     define IFXOS_HAVE_EVENT                        1
#  endif

#else

#  ifndef IFXOS_HAVE_EVENT
#     define IFXOS_HAVE_EVENT                        1
#  endif

#endif      /* #ifdef __KERNEL__ */

/* ============================================================================
   IFX LINUX adaptation - EVENT types
   ========================================================================= */
#ifdef __KERNEL__
/** \addtogroup IFXOS_EVENT_LINUX_KERNEL
@{ */

/** LINUX Kernel - EVENT, type for event handling. */
typedef struct
{
   /** event object */
   wait_queue_head_t object;
   /** valid flag */
   IFX_boolean_t  bValid;

   /** wakeup condition flag (used for Kernel Version 2.6) */
   int            bConditionFlag;

} IFXOS_event_t; 

/** @} */

#else

#if !defined(USE_PHTREAD_SEM)
#define USE_PHTREAD_SEM 1
#endif

#if (USE_PHTREAD_SEM == 1)
#include <semaphore.h>
#endif

/** \addtogroup IFXOS_EVENT_LINUX_USER
@{ */

/** LINUX User - EVENT, type for event handling. */
typedef struct
{
   /** event object (based on semaphores */
#if (USE_PHTREAD_SEM == 1)
   sem_t object;  
#else
   int object;
#endif

   /** valid flag */
   IFX_boolean_t bValid;

   /** points to the internal system object - for debugging */
   IFX_void_t    *pSysObject;
} IFXOS_event_t; 

/** @} */

#endif      /* #ifdef __KERNEL__ */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef LINUX */
#endif      /* #ifndef _IFXOS_LINUX_EVENT_H */

