/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#if defined(LINUX) && !defined(__KERNEL__)

/** \file
   This file contains the IFXOS Layer implementation for LINUX User Space
   Event Handling.
*/

/* ============================================================================
   IFX LINUX User Space adaptation - Global Includes
   ========================================================================= */
#define _GNU_SOURCE     1
#include <features.h>

#if !defined(USE_PHTREAD_SEM) || (USE_PHTREAD_SEM == 0)
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <unistd.h>
#include <signal.h>
#endif

#include <time.h>

#include "ifx_types.h"
#include "ifxos_common.h"
#include "ifxos_debug.h"
#include "ifxos_time.h"
#include "ifxos_event.h"

#include "ifxos_sys_show.h"

/* ============================================================================
   IIFX LINUX User Space adaptation - EVENT handling
   ========================================================================= */
/** \addtogroup IFXOS_EVENT_LINUX_USER
@{ */


#if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) )

/**
   Linux Appl - Initialize a Event Object for synchronisation.

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

#if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)

   if(pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_FALSE)
      {
         /* for event handling - take the semaphore immediately */
         if(sem_init(&pEventId->object, 0, 0) == 0)
         {
            pEventId->bValid = IFX_TRUE;

            pEventId->pSysObject = (IFX_void_t*)IFXOS_SYS_OBJECT_GET(IFXOS_SYS_OBJECT_EVENT);
            IFXOS_SYS_EVENT_INIT_COUNT_INC(pEventId->pSysObject);

            return IFX_SUCCESS;
         }
      }
   }
#else
   IFX_int32_t    nsemkey = IPC_PRIVATE;
   union semun    arg;

   if(pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_FALSE)
      {
         if ((pEventId->object = semget(nsemkey, 1, 0666|IPC_CREAT|IPC_EXCL)) < 0)
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
               ("IFXOS ERROR - create event object - semget(0x%X,0), errno=%d" IFXOS_CRLF,
                 nsemkey, errno));

            return IFX_ERROR;
         }

         /* set the value of semaphore to 0 blocked until event wakeup */
         arg.val = 0;
         if (semctl(pEventId->object, 0, SETVAL, arg) < 0 )
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
               ("IFXOS ERROR - create event object - semctl(0x%X,0,SETVAL,1), errno=%d" IFXOS_CRLF,
                 (IFX_uint32_t)pEventId->object, errno));

            return IFX_ERROR;
         }

         IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_LOW, 
            ("IFXOS - create event object - nsemkey=0x%X, semid=0x%X" IFXOS_CRLF,
              nsemkey, (IFX_uint32_t)pEventId->object));

         pEventId->pSysObject = (IFX_void_t*)IFXOS_SYS_OBJECT_GET(IFXOS_SYS_OBJECT_EVENT);
         IFXOS_SYS_EVENT_INIT_COUNT_INC(pEventId->pSysObject);

         pEventId->bValid = IFX_TRUE;
      
         return IFX_SUCCESS;
      }
   }
#endif

   return IFX_ERROR;
}

/**
   Linux Appl - Delete the given Event Object.

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
#if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)
   if(pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_TRUE)
      {
         if (sem_destroy(&pEventId->object) == 0)
         {
            pEventId->bValid = IFX_FALSE;

            IFXOS_SYS_OBJECT_RELEASE(pEventId->pSysObject);

            return IFX_SUCCESS;
         }
      }
   }
#else
   int dummy=0;

   if(pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_TRUE)
      {
         if (semctl(pEventId->object, 0, IPC_RMID, &dummy) != -1)
         {
            pEventId->bValid = IFX_FALSE;
            IFXOS_SYS_OBJECT_RELEASE(pEventId->pSysObject);

            return IFX_SUCCESS;
         }
      }
   }
#endif

   return IFX_ERROR;
}

/**
   Linux Appl - Wakeup a Event Object to signal the occurance of the "event" to 
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

#if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)
   if(pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_TRUE)
      {
         if (sem_post(&pEventId->object) == 0)
         {
            return IFX_SUCCESS;
         }
      }
   }
#else
   struct sembuf sb;

   sb.sem_num = 0;
   /* specifies the operation ie to set the semaphore */
   sb.sem_op = 1;
   /* DO NOT USE FLAG 'SEM_UNDO' HERE! */
   sb.sem_flg = 0;

   if(pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_TRUE)
      {
         if (semop(pEventId->object, &sb, 1) == 0)
         {
            return IFX_SUCCESS;
         }
      }
   }

   IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
      ("IFXOS ERROR - release event object failed - semop(0x%X,0,..,..), errno=%d" IFXOS_CRLF,
         pEventId ? pEventId->object : 0, errno));
#endif

   return IFX_ERROR;
}

/**
   Linux Appl - Wait for the occurance of an "event" with timeout.

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

#if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)
   struct timespec t;
   int ret;
   IFX_uint32_t start=0;

   if(pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_TRUE)
      {
         switch(waitTime_ms)
         {
            case 0xFFFFFFFF:
               /* wait forever */
               ret = sem_wait(&pEventId->object);
               if(ret != 0)
               {
                  if (pRetCode) 
                  {
                     *pRetCode = 0;
                  }

                  return IFX_ERROR;
               }

               break;

            case 0:
               /* just try to get the semaphore without waiting, 
                  if not available return to calling thread */
               ret = sem_trywait(&pEventId->object);
               if(ret != 0)
               {
                  if (pRetCode) 
                  {
                     *pRetCode = 0;
                  }

                  return IFX_ERROR;
               }

               break;

            default:
               start = IFXOS_ElapsedTimeMSecGet(0);
               clock_gettime(CLOCK_REALTIME, &t);
               t.tv_sec +=  (waitTime_ms / 1000);
               t.tv_nsec += (waitTime_ms % 1000) * 1000 * 1000;

               if (t.tv_nsec >= 1000000000) {
                  t.tv_nsec -= 1000000000;
                  t.tv_sec += 1;
               }

               ret = sem_timedwait(&pEventId->object, &t);
         }

         if(ret == 0)
         {
            if (pRetCode) *pRetCode = 0;
            return IFX_SUCCESS;
         }

         switch(errno)
         {

            case ETIMEDOUT:
               if (pRetCode) *pRetCode = 1;
               break;

            default:
               if (pRetCode) *pRetCode = 0;
         }
      }
   }

   return IFX_ERROR;

#else

   struct sigaction  sa;
   struct sembuf     sb;
   struct timespec   timeout;

   sb.sem_num = 0;
   /* specifies the operation ie to get the semaphore */
   sb.sem_op = -1;
   /* DO NOT USE FLAG 'SEM_UNDO' HERE! */
   sb.sem_flg = 0;

   if(pEventId)
   {
      if (IFXOS_EVENT_INIT_VALID(pEventId) == IFX_TRUE)
      {
         switch(waitTime_ms)
         {
            case 0xFFFFFFFF:
            /* Blocking call */
            break;

            case 0:
            /* Non Blocking */
            sb.sem_flg |= IPC_NOWAIT;
            break;

            default:
            /* Blocking call */
            /* Initialize timer expiration value */
            timeout.tv_sec        = (waitTime_ms/1000);
            timeout.tv_nsec       = (waitTime_ms%1000) * 1000 * 1000;

            memset(&sa, 0x00, sizeof(sa));
            sa.sa_handler = IFXOSL_SemAlarm;
      
            sigaction(SIGALRM, &sa, NULL);
            alarm(timeout.tv_sec + 1);

            break;
         }

         /* Acquire semaphore */
         if (semop(pEventId->object, &sb, 1) == 0)
         {
            if((waitTime_ms > 0) && (waitTime_ms < 0xFFFFFFFF))
            {
               alarm(0);
            }

            return IFX_SUCCESS;
         }
         else
         {
            if((waitTime_ms > 0) && (waitTime_ms < 0xFFFFFFFF))
            {
               alarm(0);
            }

            if(errno == EINTR)
            {
               if (pRetCode)
               {
                  *pRetCode = 1 /* DSL_ERR_TIMEOUT */;
               }

               return IFX_ERROR;
            }
            else
            {
               if((waitTime_ms == 0) && (errno == EAGAIN))
               {
                  if (pRetCode)
                  {
                     *pRetCode = 1 /* DSL_ERR_TIMEOUT */;
                  }

                  return IFX_ERROR;
               }

               return IFX_ERROR;
            }
         }
      }
   }
#endif

   return IFX_ERROR;
}

#endif      /* #if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) ) */

/** @} */

#endif      /* #if defined(LINUX) && !defined(__KERNEL__) */

