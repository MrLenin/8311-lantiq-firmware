/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation - thread handling (Application Space)
   Remark: ...
   ========================================================================= */

#ifdef LINUX

/** \file
   This file contains the IFXOS Layer implementation for LINUX Application
   Thread handling.
*/


/* ============================================================================
   IFX Linux adaptation - Global Includes - Application
   ========================================================================= */

#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_debug.h"
#include "ifxos_time.h"
#include "ifxos_thread.h"

#include "ifxos_sys_show.h"


#if (!defined(IFXOS_HAVE_TIME_SLEEP_MS) || (defined(IFXOS_HAVE_TIME_SLEEP_MS) && (IFXOS_HAVE_TIME_SLEEP_MS == 0)))
#  error "IFXOS Thread Layer - time sleep [ms] required"
#endif

/* ============================================================================
   Local macros and definition
   ========================================================================= */
#ifdef IFXOS_STATIC
#undef IFXOS_STATIC
#endif

#ifdef IFXOS_DEBUG
#define IFXOS_STATIC
#else
#define IFXOS_STATIC   static
#endif

/** \addtogroup IFXOS_THREAD_LINUX_APPL
@{ */

#if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) )


IFXOS_STATIC IFX_int32_t IFXOS_UserThreadStartup(
                              IFXOS_ThreadCtrl_t *pThrCntrl);


/* ============================================================================
   IFX Linux adaptation - Application Thread handling
   ========================================================================= */

/**
   LINUX Application - Thread stub function. The stub function will be called
   before calling the user defined thread routine. This gives
   us the possibility to add checks etc.

\par Implementation
   Before the stub function enters the user thread routin the following setup will
   be done:
   - make the kernel thread to a daemon
   - asign the parent to the init process (avoid termination if the parent thread dies).
   - setup thread name, and signal handling (if required).
   After this the user thread routine will be entered.

\param
   pThrCntrl   Thread information data

\return
   - IFX_SUCCESS on success
   - IFX_ERROR on error
*/
IFXOS_STATIC IFX_int32_t IFXOS_UserThreadStartup(
                              IFXOS_ThreadCtrl_t *pThrCntrl)
{
   IFX_int32_t retVal     = IFX_ERROR;

   if(pThrCntrl)
   {
      if (!pThrCntrl->pThrFct)
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - User Thread startup <%s>, missing THR function" IFXOS_CRLF,
              pThrCntrl->thrParams.pName));

         return IFX_ERROR;
      }

      IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_NORMAL,
         ("IFXOS - User Thread Startup <%s>, TID %d (PID %d) - ENTER" IFXOS_CRLF,
           pThrCntrl->thrParams.pName, (IFX_int_t)pthread_self(), (IFX_int_t)getpid()));

      pThrCntrl->thrParams.bRunning = IFX_TRUE;
      retVal = pThrCntrl->pThrFct(&pThrCntrl->thrParams);
      pThrCntrl->thrParams.bRunning = IFX_FALSE;

      IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_NORMAL,
         ("IFXOS - User Thread Startup <%s>, TID %d (PID %d) - EXIT" IFXOS_CRLF,
           pThrCntrl->thrParams.pName, (IFX_int_t)pthread_self(), (IFX_int_t)getpid()));
   }
   else
   {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - User Thread startup <%s>, missing control object" IFXOS_CRLF,
              pThrCntrl->thrParams.pName));
   }

   return retVal;
}

/**
   LINUX Application - Creates a new thread / task.

\par Implementation
   - Allocate and setup the internal thread control structure.
   - setup the LINUX specific thread parameter (see "init_completion").
   - start the LINUX Kernel thread with the internal stub function (see "kernel_thread")

\param
   pThrCntrl         Pointer to thread control structure. This structure has to
                     be allocated outside and will be initialized.
\param
   pName             specifies the 8-char thread / task name.
\param
   pThreadFunction   specifies the user entry function of the thread / task.
\param
   nStackSize        specifies the size of the thread stack - not used.
\param
   nPriority         specifies the thread priority, 0 will be ignored
\param
   nArg1             first argument passed to thread / task entry function.
\param
   nArg2             second argument passed to thread / task entry function.

\return
   - IFX_SUCCESS thread was successful started.
   - IFX_ERROR thread was not started
*/
IFX_int32_t IFXOS_ThreadInit(
               IFXOS_ThreadCtrl_t *pThrCntrl,
               IFX_char_t     *pName,
               IFXOS_ThreadFunction_t pThreadFunction,
               IFX_uint32_t   nStackSize,
               IFX_uint32_t   nPriority,
               IFX_ulong_t    nArg1,
               IFX_ulong_t    nArg2)
{
   IFX_int32_t          retVal=0;
   pthread_t            tid;
   pthread_attr_t       attr;

   if(pThreadFunction == IFX_NULL) return IFX_ERROR;
   if(pName == IFX_NULL) return IFX_ERROR;

   if(pThrCntrl)
   {
      if (IFXOS_THREAD_INIT_VALID(pThrCntrl) == IFX_FALSE)
      {
         pthread_attr_init(&attr);
         /*pthread_attr_setstacksize (&attr, nStackSize);*/

         memset(pThrCntrl, 0x00, sizeof(IFXOS_ThreadCtrl_t));

         /* set thread function arguments */
         strncpy(pThrCntrl->thrParams.pName, pName, IFXOS_THREAD_NAME_LEN);
         pThrCntrl->thrParams.pName[IFXOS_THREAD_NAME_LEN-1] = 0;
         pThrCntrl->nPriority = nPriority;
         pThrCntrl->thrParams.nArg1 = nArg1;
         pThrCntrl->thrParams.nArg2 = nArg2;
         pThrCntrl->thrParams.bShutDown = IFX_FALSE;

         /* set thread control settings */
         pThrCntrl->pThrFct = pThreadFunction;

         pThrCntrl->thrParams.pSysObject = (IFX_void_t*)IFXOS_SYS_OBJECT_GET(IFXOS_SYS_OBJECT_THREAD);
         IFXOS_SYS_THREAD_PARAMS_SET(pThrCntrl->thrParams.pSysObject, pThrCntrl);
         IFXOS_SYS_THREAD_INIT_COUNT_INC(pThrCntrl->thrParams.pSysObject);

         /*
            create thread with configured attributes
            we call first our own routine for further checks and setup etc.
         */
         retVal = pthread_create (
                     &tid, &attr,
                     (IFXOS_USER_THREAD_StartRoutine)IFXOS_UserThreadStartup,
                     (IFX_void_t*)pThrCntrl);
         if (retVal)
         {
            pthread_attr_destroy(&attr);
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - User Thread create <%s> - pthread_create = %d" IFXOS_CRLF,
                 (pName ? (pName) : "noname"), errno ));

            return IFX_ERROR;
         }

         pThrCntrl->tid = tid;
         pThrCntrl->bValid = IFX_TRUE;

         return IFX_SUCCESS;
      }
      else
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - ThreadInit, object already valid" IFXOS_CRLF));
      }
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - ThreadInit, missing object" IFXOS_CRLF));
   }

   return IFX_ERROR;
}


/**
   LINUX Application - Shutdown and terminate a given thread.
   Therefore the thread delete functions triggers the user thread function
   to shutdown. In case of not responce (timeout) the thread will be canceled.

\par Implementation
   - force a shutdown via the shutdown flag.
   - wait for completion (see "wait_for_completion").
   - free previous allocated internal data.

\param
   pThrCntrl   Thread control struct.
\param
   waitTime_ms Time [ms] to wait for "self-shutdown" of the user thread.

\return
   - IFX_SUCCESS thread was successful deleted - thread control struct is freed.
   - IFX_ERROR thread was not deleted
*/
IFX_int32_t IFXOS_ThreadDelete(
               IFXOS_ThreadCtrl_t *pThrCntrl,
               IFX_uint32_t       waitTime_ms)
{
   IFX_uint32_t   waitCnt = 1;

   if(pThrCntrl)
   {
      if (IFXOS_THREAD_INIT_VALID(pThrCntrl) == IFX_TRUE)
      {
         if (pThrCntrl->thrParams.bRunning == 1)
         {
            /* trigger user thread routine to shutdown */
            pThrCntrl->thrParams.bShutDown = IFX_TRUE;

            if (waitTime_ms != IFXOS_THREAD_DELETE_WAIT_FOREVER)
            {
               waitCnt = waitTime_ms / IFXOS_THREAD_DOWN_WAIT_POLL_MS;
            }

            while (waitCnt && (pThrCntrl->thrParams.bRunning == 1) )
            {
               IFXOS_MSecSleep(IFXOS_THREAD_DOWN_WAIT_POLL_MS);

               if (waitTime_ms != IFXOS_THREAD_DELETE_WAIT_FOREVER)
                  waitCnt--;
            }
         }
         else
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
               ("IFXOS WRN - User Thread Delete <%s> - not running" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName));
         }

         if (pThrCntrl->thrParams.bRunning == 1)
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
               ("IFXOS WRN - User Thread Delete <%s> TID %d - kill, no shutdown responce" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName, pThrCntrl->tid));

            /** still running --> kill */
            switch(pthread_cancel(pThrCntrl->tid))
            {
               case 0:
                  pThrCntrl->thrParams.bRunning = IFX_FALSE;
                  break;

               case ESRCH:
                  /* just information that task already exited by itself */
                  IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
                     ("IFXOS WRN - User Thread Delete <%s> TID %d - not found (already exited)" IFXOS_CRLF,
                       pThrCntrl->thrParams.pName, pThrCntrl->tid));
                  pThrCntrl->thrParams.bRunning = IFX_FALSE;
                  break;

               default:
                  IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
                     ("IFXOS ERROR - User Thread Delete <%s> TID %d - unknown (mem loss)" IFXOS_CRLF,
                       pThrCntrl->thrParams.pName, pThrCntrl->tid));

                  pThrCntrl->bValid = IFX_FALSE;
                  IFXOS_SYS_OBJECT_RELEASE(pThrCntrl->thrParams.pSysObject);

                  return IFX_ERROR;
            }
         }

         pThrCntrl->bValid = IFX_FALSE;
         IFXOS_SYS_OBJECT_RELEASE(pThrCntrl->thrParams.pSysObject);

         return IFX_SUCCESS;
      }
      else
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - ThreadDelete, invalid object" IFXOS_CRLF));
      }
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - ThreadDelete, missing object" IFXOS_CRLF));
   }

   return IFX_ERROR;

}


/**
   LINUX Application - Shutdown a given thread.
   Therefore the thread delete functions triggers the user thread function
   to shutdown.

\par Implementation
   - force a shutdown via the shutdown flag.
   - wait for completion (see "wait_for_completion").
   - free previous allocated internal data.

\param
   pThrCntrl   Thread control struct.
\param
   waitTime_ms Time [ms] to wait for "self-shutdown" of the user thread.

\return
   - IFX_SUCCESS successful shutdown - thread control struct is freed.
   - IFX_ERROR  no success, thread struct still exists.
*/
IFX_int32_t IFXOS_ThreadShutdown(
               IFXOS_ThreadCtrl_t *pThrCntrl,
               IFX_uint32_t       waitTime_ms)
{
   IFX_uint32_t   waitCnt = 1;

   if(pThrCntrl)
   {
      if (IFXOS_THREAD_INIT_VALID(pThrCntrl) == IFX_TRUE)
      {
         if (pThrCntrl->thrParams.bRunning == 1)
         {
            /* trigger user thread routine to shutdown */
            pThrCntrl->thrParams.bShutDown = IFX_TRUE;

            if (waitTime_ms != IFXOS_THREAD_DELETE_WAIT_FOREVER)
            {
               waitCnt = waitTime_ms / IFXOS_THREAD_DOWN_WAIT_POLL_MS;
            }

            while (waitCnt && (pThrCntrl->thrParams.bRunning == 1) )
            {
               IFXOS_MSecSleep(IFXOS_THREAD_DOWN_WAIT_POLL_MS);

               if (waitTime_ms != IFXOS_THREAD_DELETE_WAIT_FOREVER)
                  waitCnt--;
            }
         }
         else
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
               ("IFXOS WRN - User Thread Shutdown <%s> - not running" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName));
         }

         if (pThrCntrl->thrParams.bRunning != 0)
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - User Thread Shutdown <%s> - no responce" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName));

            pThrCntrl->bValid = IFX_FALSE;
            IFXOS_SYS_OBJECT_RELEASE(pThrCntrl->thrParams.pSysObject);

            return IFX_ERROR;
         }

         pThrCntrl->bValid = IFX_FALSE;
         IFXOS_SYS_OBJECT_RELEASE(pThrCntrl->thrParams.pSysObject);

         return IFX_SUCCESS;
      }
      else
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - Thread Shutdown, invalid object" IFXOS_CRLF));
      }
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Thread Shutdown, missing object" IFXOS_CRLF));
   }

   return IFX_ERROR;
}

/**
   LINUX Application - Modify own thread priority.

\todo
   Under discussion how to handle the priority!

\param
   newPriority - new thread priority.
                 Possible Values are:
                 - IFXOS_THREAD_PRIO_IDLE
                 - IFXOS_THREAD_PRIO_LOWEST
                 - IFXOS_THREAD_PRIO_LOW
                 - IFXOS_THREAD_PRIO_NORMAL
                 - IFXOS_THREAD_PRIO_HIGH
                 - IFXOS_THREAD_PRIO_HIGHEST
                 - IFXOS_THREAD_PRIO_TIME_CRITICAL
\attention
   The intention for the priority "TIME_CRITICAL" is for use within
   driver space.

\return
   - IFX_SUCCESS priority changed.
   - IFX_ERROR priority not changed.
*/
IFX_int32_t IFXOS_ThreadPriorityModify(
               IFX_uint32_t       newPriority)
{
   struct sched_param param;
   int ret=0, policy=0;

   memset(&param, 0x00, sizeof(param));

   ret = pthread_getschedparam (pthread_self(), &policy, &param);
   if(ret == 0)
   {
      param.sched_priority = +newPriority;

      /* fix the scheduler to FIFO to be able to increase the priority */
      policy = SCHED_FIFO;

      switch(policy)
      {
         case SCHED_OTHER:
            IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_NORMAL,
               ("IFXOS - Thread, using SCHED_OTHER (regular, non-realtime scheduling)" IFXOS_CRLF));
            break;

         case SCHED_RR:
            IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_NORMAL,
               ("IFXOS - Thread, using SCHED_RR (realtime, round-robin)" IFXOS_CRLF));
            break;

         case SCHED_FIFO:
            IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_NORMAL,
               ("IFXOS - Thread, using SCHED_FIFO (realtime, first-in first-out)" IFXOS_CRLF));
            break;

         default:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
               ("IFXOS - Thread, priority not defined %d" IFXOS_CRLF, policy));
            break;
      }

      /* setting the new priority */
      ret = pthread_setschedparam (pthread_self(), policy, &param);
      if(ret == 0)
      {
         IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_NORMAL,
            ("IFXOS - Thread, Set new priority %d, policy %d" IFXOS_CRLF,
              param.sched_priority, policy));

         return IFX_SUCCESS;
      }
      else
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - Thread, Set of new priority %d failed (pid %d / thread %d)" IFXOS_CRLF,
              param.sched_priority, (int)getpid(), (int)pthread_self()));
      }
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Thread, Get of priority failed (pid %d / thread %d)" IFXOS_CRLF,
           (int)getpid(), (int)pthread_self()));
   }

   switch(ret)
   {
      case ENOSYS:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
            ("IFXOS - Thread, The option _POSIX_THREAD_PRIORITY_SCHEDULING is not defined and the "
             "implementation does not support the function." IFXOS_CRLF));
         break;

      case ESRCH:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
            ("IFXOS - Thread, The value specified by thread does not refer to a existing thread." IFXOS_CRLF));
      break;

      case EINVAL:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
            ("IFXOS - Thread, The value specified by policy or one of the scheduling parameters "
             "associated with the scheduling policy policy is invalid." IFXOS_CRLF));
         break;

      case ENOTSUP:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
            ("IFXOS - Thread, An attempt was made to set the policy or scheduling parameters "
             "to an unsupported value." IFXOS_CRLF));
         break;

      case EPERM:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
            ("IFXOS - Thread, The caller does not have the appropriate permission to set either "
             "the scheduling parameters or the scheduling policy of the specified thread." IFXOS_CRLF));
         break;
   }

   return IFX_ERROR;
}


/**
   Return the own thread / task ID

\return
   Thread ID of the current thread.
*/
IFXOS_thread_t IFXOS_ThreadIdGet(void)
{
   return pthread_self();
}


/**
   Return the own process ID

\return
   Process ID of the current thread.
*/
IFXOS_process_t IFXOS_ProcessIdGet(void)
{
   return getpid();
}


#endif      /* #if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) ) */

/** @} */

#endif      /* #ifdef LINUX */

