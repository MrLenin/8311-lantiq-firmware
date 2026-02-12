/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS

/** \file
   This file contains the IFXOS Layer Implementation frame 
   for GENERIC_OS Event Handling.
*/

/* ============================================================================
   IFX GENERIC_OS adaptation frame - Global Includes
   ========================================================================= */

/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_time.h"
#include "ifxos_event.h"

/* ============================================================================
   IFX GENERIC_OS adaptation frame - EVENT handling
   ========================================================================= */
/** \addtogroup IFXOS_EVENT_GENERIC_OS
@{ */


#if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) )

/**
   GENERIC_OS - Initialize a Event Object for synchronisation.

\par Implementation
   - initialize a binary semaphore.
   - init state is "unlocked".

\param
   pEventId    Prointer to the Event Object.

\return      
   IFX_SUCCESS if the creation was successful, else
   IFX_ERROR in case of error.
*/
IFX_int_t IFXOS_EventInit(
               IFXOS_event_t  *pEventId)
{

   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         pEventId->object = semBCreate(SEM_Q_FIFO, SEM_EMPTY);
         pEventId->bValid = IFX_TRUE;
    */

   IFXOS_RETURN_IF_POINTER_NULL(pEventId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_VALID(pEventId, IFX_ERROR);

   pEventId->bValid = IFX_TRUE;

   return IFX_SUCCESS;
}

/**
   GENERIC_OS - Delete the given Event Object.

\par Implementation
   - delete the semaphore object.

\param
   pEventId    Prointer to the Event Object.

\return
   IFX_SUCCESS if delete was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int_t IFXOS_EventDelete(
               IFXOS_event_t  *pEventId)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         semDelete(pEventId->object);
         pEventId->bValid = IFX_FALSE;
   */

   IFXOS_RETURN_IF_POINTER_NULL(pEventId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_INVALID(pEventId, IFX_ERROR);

   pEventId->bValid = IFX_FALSE;

   return IFX_SUCCESS;
}

/**
   GENERIC_OS - Wakeup a Event Object to signal the occurance of the "event" to 
   the waiting processes.

\par Implementation
   - Give the semaphore to signal the event.

\param
   pEventId    Prointer to the Event Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error
*/
IFX_int_t IFXOS_EventWakeUp(
               IFXOS_event_t  *pEventId)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         semGive(pEventId->object);
   */

   IFXOS_RETURN_IF_POINTER_NULL(pEventId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_INVALID(pEventId, IFX_ERROR);

   return IFX_SUCCESS;
}

/**
   GENERIC_OS - Wait for the occurance of an "event" with timeout.

\par Implementation
   - Take the semaphore with timeout [ms] for wait for the event.

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
IFX_int_t IFXOS_EventWait(
               IFXOS_event_t  *pEventId,
               IFX_uint32_t   waitTime_ms,
               IFX_int32_t    *pRetCode)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
         semGive(pEventId->object);
   */

   IFXOS_RETURN_IF_POINTER_NULL(pEventId, IFX_ERROR);
   IFXOS_RETURN_IF_OBJECT_IS_INVALID(pEventId, IFX_ERROR);

   /*
      - in case of timeout, signal the timeout via the *pRetCode 
        (if the variable is given).
   */

   return IFX_SUCCESS;
}

#endif      /* #if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) ) */

/** @} */

#endif      /* #ifdef GENERIC_OS */

