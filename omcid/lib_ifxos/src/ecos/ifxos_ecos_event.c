/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains the IFXOS Layer implementation for eCos
   Event Handling.
*/

/* ============================================================================
   IFX eCos adaptation - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_time.h"
#include "ifxos_event.h"
#include "ifxos_common.h"

/* ============================================================================
   IFX eCos adaptation - EVENT handling
   ========================================================================= */
/** \addtogroup IFXOS_EVENT_ECOS
@{ */


#if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) )

/**
   eCos - Initialize a Event Object for synchronisation.

\par Implementation
   - the event is intialized through cyg_flag_init() call

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
         cyg_flag_init(&pEventId->object);
         pEventId->bValid = IFX_TRUE;

         return IFX_SUCCESS;
      }
   }
   
   return IFX_ERROR;
}

/**
   eCos - Delete the given Event Object.

\par Implementation
   - Clear the event through cyg_flag_maskbits() call and destroy through 
     the cyg_flag_destroy() call.

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
         cyg_flag_maskbits(&pEventId->object, 1);
         cyg_flag_destroy(&pEventId->object);
         pEventId->bValid = IFX_FALSE;

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   eCos - Wakeup a Event Object to signal the occurance of the "event" to 
   the waiting processes.

\par Implementation
   - The cyg_flag_setbits() function is used to signal a event.

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
         cyg_flag_setbits(&pEventId->object, 1);

         return IFX_SUCCESS;
      }
   }

   return IFX_ERROR;
}

/**
   eCos - Wait for the occurance of an "event" with timeout.

\par Implementation
   - The cyg_flag_timed_wait() function is called with CYG_FLAG_WAITMODE_AND 
     and CYG_FLAG_WAITMODE_CLR set.

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
   cyg_flag_value_t ret = 1;

   if (pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_TRUE)
      {
         ret = cyg_flag_timed_wait(&pEventId->object, 1, CYG_FLAG_WAITMODE_AND | CYG_FLAG_WAITMODE_CLR, 
                  (cyg_current_time() + IFXOS_MSEC_TO_TICK(waitTime_ms)) );
   
         if( ret != 0 )
         {
            if(pRetCode)
               *pRetCode = 0;

            return IFX_SUCCESS;
         }
      }
   }

   if (pRetCode)
   {
      *pRetCode = (ret == 0 ) ? 1 : 0;
   }
  
   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) ) */

/** @} */

#endif      /* #ifdef ECOS */

