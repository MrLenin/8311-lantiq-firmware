/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(WIN32) && !defined(NUCLEUS_PLUS)

/** \file
   This file contains the IFXOS Layer implementation for Win32 - 
   Event Handling.
*/
/* ============================================================================
   IFX Win32 adaptation - Global Includes
   ========================================================================= */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_print.h"
#include "ifxos_time.h"
#include "ifxos_event.h"

/* ============================================================================
   IFX Win32 adaptation - User Space, XXX
   ========================================================================= */
/** \addtogroup IFXOS_EVENT_WIN32
@{ */
#if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) )

/**
   Win32 - Initialize a Event Object for synchronisation.

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
         pEventId->object = CreateSemaphore( 
                                    NULL,    /* no security attributes */
                                    0,       /* initial count - not signaled */
                                    1,       /* maximum count */
                                    NULL /* pName */);  /* named semaphore */
   
         if(pEventId->object != NULL)
         {
            pEventId->bValid = IFX_TRUE;

            return IFX_SUCCESS;
         }
      }
      else
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - EventInit, init already done!" IFXOS_CRLF));
      }
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - EventInit, missing obj-pointer!" IFXOS_CRLF));
   }

   return IFX_ERROR;
}

/**
   Win32 - Delete the given Event Object.

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
         pEventId->bValid = IFX_FALSE;
         if (!(CloseHandle((HANDLE)pEventId->object)))
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - EventDelete, close handle!" IFXOS_CRLF));
         }
         else
         {
            return IFX_SUCCESS;
         }
      }
      else
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - EventDelete, delete already done!" IFXOS_CRLF));
      }
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - EventDelete, missing obj-pointer!" IFXOS_CRLF));
   }

   return IFX_ERROR;
}

/**
   Win32 - Wakeup a Event Object to signal the occurance of the "event" to 
   the waiting processes.

\par Implementation
   - Give the semaphore to signal the event (see "ReleaseSemaphore").

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
         ReleaseSemaphore(
               pEventId->object, /* handle to semaphore */
               1,                /* increase count by one */
               NULL);

         return IFX_SUCCESS;
      }
      else
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - EventWakeUp, object not valid!" IFXOS_CRLF));
      }
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - EventWakeUp, missing obj-pointer!" IFXOS_CRLF));
   }

   return IFX_ERROR;
}

/**
   Win32 - Wait for the occurance of an "event" with timeout.

\par Implementation
   - Take the semaphore with timeout [ms] for wait for the event (see "WaitForSingleObject").

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
IFX_int32_t IFXOS_EventWait(
               IFXOS_event_t  *pEventId,
               IFX_uint32_t   waitTime_ms,
               IFX_int32_t    *pRetCode)
{
   if (pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_TRUE)
      {
         if (pRetCode)
         {
            *pRetCode = 0;
         }

         switch(waitTime_ms)
         {
            case 0xFFFFFFFF:
               /* Blocking call */
               if(WaitForSingleObject(pEventId->object, INFINITE) == WAIT_OBJECT_0)
               {
                  return IFX_SUCCESS;
               }
               break;

            case 0:
               /* Non Blocking */
               if(WaitForSingleObject(pEventId->object, 0L) == WAIT_OBJECT_0)
               {
                  return IFX_SUCCESS;
               }
               break;

            default:
               {
                  /* Blocking call */
                  DWORD retVal;
                  retVal = WaitForSingleObject(pEventId->object, waitTime_ms);
                  switch (retVal ) 
                  { 
                     case WAIT_OBJECT_0: 
                        return IFX_SUCCESS;

                     case WAIT_TIMEOUT: 
                        if (pRetCode)
                        {
                           *pRetCode = 1;
                        }
                        break;

                     default:
                        IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
                           ("IFXOS ERROR - EventWait - unexpected ret-code 0x%X" IFXOS_CRLF,
                           (IFX_uint32_t)retVal));
                        break;
                  }
               }
               break;
         }
      }
      else
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - EventWait, object not valid!" IFXOS_CRLF));
      }
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - EventWait, missing obj-pointer!" IFXOS_CRLF));
   }

   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) ) */

/** @} */

#endif      /* #ifdef WIN32 */
