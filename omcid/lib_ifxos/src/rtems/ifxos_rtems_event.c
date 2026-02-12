/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains the IFXOS Layer Implementation frame
   for RTEMS Event Handling via XAPI.
*/

/* ============================================================================
   RTEMS adaptation frame - Global Includes
   ========================================================================= */

#include <xapi.h>
#include <stdio.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_time.h"
#include "ifxos_event.h"

/* ============================================================================
   RTEMS adaptation frame - EVENT handling
   ========================================================================= */
/** \addtogroup IFXOS_EVENT_RTEMS
@{ */


#if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) )

/**
   RTEMS - Initialize a Event Object for synchronisation.

\par Implementation
   - a semaphore is created
   - init state is "EMPTY" - locked.
   - the queuing is FIFO based

\param
   pEventId    Prointer to the Event Object.

\return
   IFX_SUCCESS if the creation was successful, else
   IFX_ERROR in case of error.
*/
IFX_int_t IFXOS_EventInit(
               IFXOS_event_t  *pEventId)
{
   static IFX_uint_t gSemId = 0;   /* unique semaphore index */
   IFX_char_t name[4];

   if (gSemId > 0xFF)
      return IFX_ERROR; /* not enough space in name[] */

   sprintf (name, "EV%02x", gSemId);
   gSemId++;

   if(pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_FALSE)
      {
         xsm_create (name, 0, 0, &(pEventId->object));
   pEventId->bValid = IFX_TRUE;

   return IFX_SUCCESS;
}
   }

   return IFX_ERROR;
}

/**
   RTEMS - Delete the given Event Object.

\par Implementation
   - delete the semaphore object (see "semDelete").

\param
   pEventId    Prointer to the Event Object.

\return
   IFX_SUCCESS if delete was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int_t IFXOS_EventDelete(
               IFXOS_event_t  *pEventId)
{
   /* Does nothing */
   return IFX_SUCCESS;
}

/**
   RTEMS - Wakeup a Event Object to signal the occurance of the "event" to
   the waiting processes.

\par Implementation
   - Release the semaphore to signal the event.

\param
   pEventId    Prointer to the Event Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error
*/
IFX_int_t IFXOS_EventWakeUp(
               IFXOS_event_t  *pEventId)
{
   if (pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_TRUE)
      {
         if (!xsm_v(pEventId->object))
         {
            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}

/**
   RTEMS - Wait for the occurance of an "event" with timeout.

\par Implementation
   - Take the semaphore with timeout [ms] for wait for the event.
   - timeout signaling currently not supported.

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
*/
IFX_int_t IFXOS_EventWait(IFXOS_event_t *pEventId,
               IFX_uint32_t   waitTime_ms,
               IFX_int32_t    *pRetCode)
{
   IFX_uint_t flags = SM_WAIT;

   if (pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_TRUE)
      {
         if (waitTime_ms == IFXOS_NO_WAIT)
            flags = SM_NOWAIT;

         if (waitTime_ms == IFXOS_WAIT_FOREVER) {
            flags = SM_WAIT;
            waitTime_ms = 0;
         }

         if (xsm_p(pEventId->object, flags, waitTime_ms) != 0)
         {
            if (pRetCode)
               *pRetCode = 1;
   }
   else
   {
            if (pRetCode)
               *pRetCode = 0;
            return IFX_SUCCESS;
       }
   }
   }
   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) ) */

/** @} */

#endif      /* #ifdef RTEMS */

