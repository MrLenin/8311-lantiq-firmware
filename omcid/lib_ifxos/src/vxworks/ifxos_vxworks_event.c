/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS

/** \file
   This file contains the IFXOS Layer implementation for VxWorks
   Event Handling.
*/

/* ============================================================================
   IFX VxWorks adaptation - Global Includes
   ========================================================================= */

#include <vxWorks.h>
#include <sysLib.h>
#include <semLib.h>
#include <objLib.h>

#include "ifx_types.h"
#include "ifxos_time.h"
#include "ifxos_event.h"

/* ============================================================================
   IFX VxWorks adaptation - EVENT handling
   ========================================================================= */
/** \addtogroup IFXOS_EVENT_VXWORKS
@{ */


#if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) )

/**
   VxWorks - Initialize a Event Object for synchronisation.

\par Implementation
   - the binary semaphore is created (see "semBCreate").
   - init state is "EMPTY" - unlocked.
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
   if(pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_FALSE)
      {
         pEventId->object = semBCreate(SEM_Q_FIFO, SEM_EMPTY);
         pEventId->bValid = IFX_TRUE;

         return IFX_SUCCESS;
      }
   }
   
   return IFX_ERROR;
}

/**
   VxWorks - Delete the given Event Object.

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
   if (pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_TRUE)
      {
         if (semDelete(pEventId->object) == OK) 
         {
            pEventId->bValid = IFX_FALSE;
            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}

/**
   VxWorks - Wakeup a Event Object to signal the occurance of the "event" to 
   the waiting processes.

\par Implementation
   - Give the semaphore to signal the event (see "semGive").

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
         semGive(pEventId->object);

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   VxWorks - Wait for the occurance of an "event" with timeout.

\par Implementation
   - Take the semaphore with timeout [ms] for wait for the event (see "semTake").
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
IFX_int_t IFXOS_EventWait(
               IFXOS_event_t  *pEventId,
               IFX_uint32_t   waitTime_ms,
               IFX_int32_t    *pRetCode)
{
   if (pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_TRUE)
      {
         if(semTake (pEventId->object, (((waitTime_ms * sysClkRateGet()) / 1000)+1)) == ERROR)
         {
            if(errno == S_objLib_OBJ_TIMEOUT)
            {
               if(pRetCode) 
                  *pRetCode = 1;
            }
            else
            {
               if(pRetCode) 
                  *pRetCode = 0;
            }
         }
         else
         {
            if(pRetCode) 
               *pRetCode = 0;

            return IFX_SUCCESS;
         }
      }
   }
   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) ) */

/** @} */

#endif      /* #ifdef VXWORKS */

