/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS

/** \file
   This file contains the IFXOS Layer implemantation for Nucleus
   Event Handling.
*/

/* ============================================================================
   IFX Nucleus adaptation - Global Includes
   ========================================================================= */

#include <nucleus.h>

#include "ifx_types.h"
#include "ifxos_common.h"
#include "ifxos_time.h"
#include "ifxos_event.h"

/* ============================================================================
   IFX Nucleus adaptation - EVENT handling
   ========================================================================= */
/** \addtogroup IFXOS_EVENT_NUCLEUS
@{ */


#if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) )

/**
   Nucleus - Initialize a Event Object for synchronisation.

\par Implementation
   - the binary semaphore is created (see "NU_Create_Event_Group").
   - init state is "EMPTY" - unlocked.

\param
   pEventId    Prointer to the Event Object.

\return      
   IFX_SUCCESS if the initialization was successful, else
   IFX_ERROR in case of error.
*/
IFX_int_t IFXOS_EventInit(
               IFXOS_event_t  *pEventId)
{
   if(pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_FALSE)
      {
         if(NU_Create_Event_Group(&pEventId->object, "event") == NU_SUCCESS)
         {
            pEventId->bValid = IFX_TRUE;
            return IFX_SUCCESS;
         }
      }
   }

   return IFX_ERROR;
}

/**
   Nucleus - Delete the given Event Object.

\par Implementation
   - delete the semaphore object (see "NU_Delete_Event_Group").

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
         NU_Delete_Event_Group(&pEventId->object);
         pEventId->bValid = IFX_FALSE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   Nucleus - Wakeup a Event Object to signal the occurance of the "event" to 
   the waiting processes.

\par Implementation
   - set the event with the mask 1 and the NU_OR mode (see "NU_Set_Events").

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
         NU_Set_Events(&pEventId->object, 0x01, NU_OR);

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   Nucleus - Wait for the occurance of an "event" with timeout.

\par Implementation
   - Retrieve the event 0x01 with timeout [ms] and the mode NU_OR_CONSUME (see "NU_Retrieve_Events").

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
   UNSIGNED events = 0;

   if (pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_TRUE)
      {
         switch(NU_Retrieve_Events(&pEventId->object, 0x01, NU_OR_CONSUME, &events, IFXOS_MSEC_TO_TICK(waitTime_ms)))
         {
            case NU_SUCCESS:
               if(pRetCode)
               {
                  *pRetCode = 0;
               }
               return IFX_SUCCESS;
         
            case NU_TIMEOUT:
               if(pRetCode)
               {
                  *pRetCode = 1;
               }
               break;

            default:
               if(pRetCode)
               {
                  *pRetCode = 0;
               }
               break;
         }
      }
   }

   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) ) */

/** @} */

#endif      /* #ifdef NUCLEUS_PLUS */

