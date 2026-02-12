/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains the IFXOS Layer implementation for XAPI
   Task handling.
*/

#ifdef XAPI

/* ============================================================================
   IFX XAPI adaptation - Global Includes
   ========================================================================= */

#include <xapi.h>

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_debug.h"
#include "ifxos_time.h"
#include "ifxos_thread.h"

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

/* ============================================================================
   IFX XAPI adaptation - Task handling
   ========================================================================= */

/** \addtogroup IFXOS_THREAD_XAPI
@{ */

#if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) )

/**
   XAPI - Thread stub function. The stub function will be called
   before calling the user defined thread routine. This gives
   us the possibility to add checks etc.

\par Implementation
   Before the stub function enters the user task routine task control flags
   are set and after this the user thread routine will be entered.

\param
   pThrCntrl Thread information data

\return
   - IFX_SUCCESS on success
   - IFX_ERROR on error
*/
IFXOS_STATIC IFX_int32_t IFXOS_ThreadStartup(
                              IFX_ulong_t task_args1,
                              IFX_ulong_t task_args2,
                              IFX_ulong_t task_args3,
                              IFX_ulong_t task_args4)
{
   IFX_int32_t retVal = IFX_ERROR;
   IFXOS_ThreadCtrl_t *pThrCntrl;

   if(task_args1 == 0)
   {
      return retVal;
   }

   pThrCntrl = (IFXOS_ThreadCtrl_t *)task_args1;

   if(pThrCntrl == IFX_NULL)
   {
      return retVal;
   }

   pThrCntrl->thrParams.bRunning = IFX_TRUE;
   retVal = pThrCntrl->pThrFct(&pThrCntrl->thrParams);
   pThrCntrl->thrParams.bRunning = IFX_FALSE;

   return retVal;
}

/**
   XAPI - Creates a new task.

\par Implementation
   - Allocate and setup the internal thread control structure.
   - setup the XAPI specific thread parameter.
   - start the XAPI task with the internal stub function (see "taskSpawn")
   - the IFXOS default prio and stack size is used

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
   - IFX_ERROR thread was not deleted
*/
IFX_int32_t IFXOS_ThreadInit(
               IFXOS_ThreadCtrl_t *pThrCntrl,
               IFX_char_t *pName,
               IFXOS_ThreadFunction_t pThreadFunction,
               IFX_uint32_t nStackSize,
               IFX_uint32_t nPriority,
               IFX_ulong_t nArg1,
               IFX_ulong_t nArg2)
{
   IFX_ulong_t task_args[4] = {0};
   IFX_uint32_t i;

   if(pThreadFunction == IFX_NULL) return IFX_ERROR;
   if(pName == IFX_NULL) return IFX_ERROR;

   if(pThrCntrl)
   {
      if (IFXOS_THREAD_INIT_VALID(pThrCntrl) == IFX_FALSE)
      {
         /* set task function arguments */
         for (i = 0; pName[i] && i < IFXOS_THREAD_NAME_LEN - 1; i++)
            pThrCntrl->thrParams.pName[i] = pName[i];

         pThrCntrl->thrParams.pName[IFXOS_THREAD_NAME_LEN-1] = 0;
         pThrCntrl->nPriority = nPriority;
         pThrCntrl->thrParams.nArg1 = nArg1;
         pThrCntrl->thrParams.nArg2 = nArg2;
         pThrCntrl->thrParams.bShutDown = IFX_FALSE;

         pThrCntrl->pThrFct = pThreadFunction;

         /* \param sup_stack IN Tasdk's stack size in bytes.
          Must be at least 640.*/
         if (nStackSize < 640)
         {
            nStackSize = 640;
         }

         if (nPriority == 0)
         {
            nPriority = IFXOS_DEFAULT_PRIO;
         }

         if (xt_create(pThrCntrl->thrParams.pName, nPriority,
                       nStackSize, 0, 0, &(pThrCntrl->tid)) )
         {
            return IFX_ERROR;
         }

         task_args[0] = (IFX_ulong_t)pThrCntrl;

         if (xt_start(pThrCntrl->tid, IFXOS_DEFAULT_TASK_MODE,
               (void (*)(void))IFXOS_ThreadStartup, task_args))
         {
            return IFX_ERROR;
         }

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
   XAPI - Shutdown and terminate a given thread.
   Therefore the thread delete functions triggers the user thread function
   to shutdown. In case of not responce (timeout) the thread will be canceled.

\par Implementation
   - force a shutdown via the shutdown flag and wait for task end with timeout.
   - kill in case of no shutdown responce.
   - free previous allocated internal data.

\param
   pThrCntrl - Thread control struct.
\param
   waitTime_ms - Time [ms] to wait for "self-shutdown" of the user thread.

\return
   - IFX_SUCCESS thread was successful deleted - thread control struct is freed.
   - IFX_ERROR thread was not deleted
*/
IFX_int32_t IFXOS_ThreadDelete(
               IFXOS_ThreadCtrl_t *pThrCntrl,
               IFX_uint32_t       waitTime_ms)
{
	IFX_uint32_t waitCnt = 1;

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
               ("IFXOS WRN - Thread Delete <%s> - not running" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName));
         }

         /* terminate the task if it does not terminate within given time */
         if (pThrCntrl->thrParams.bRunning == 1)
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
               ("IFXOS WRN - Thread Delete <%s> TID %d - kill, no shutdown responce" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName, pThrCntrl->tid));

            if (xt_delete(pThrCntrl->tid))
            {
               IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
                  ("IFXOS ERROR - Thread Delete <%s> TID %d - kill failed (mem loss ?)" IFXOS_CRLF,
                    pThrCntrl->thrParams.pName, pThrCntrl->tid));

               pThrCntrl->bValid = IFX_FALSE;

               return IFX_ERROR;
            }
            pThrCntrl->thrParams.bRunning = IFX_FALSE;
         }

         pThrCntrl->bValid = IFX_FALSE;

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
   XAPI - Shutdown a given thread.
   Therefore the thread delete functions triggers the user thread function
   to shutdown and wait for end.

\par Implementation
   - force a shutdown via the shutdown flag and wait for task end with timeout.
   - free previous allocated internal data.

\param
   pThrCntrl - Thread control struct.
\param
   waitTime_ms - Time [ms] to wait for "self-shutdown" of the user thread.

\return
   - IFX_SUCCESS thread was successful deleted - thread control struct is freed.
   - IFX_ERROR thread was not deleted
*/
IFX_int32_t IFXOS_ThreadShutdown(
               IFXOS_ThreadCtrl_t *pThrCntrl,
               IFX_uint32_t       waitTime_ms)
{
   IFX_uint32_t waitCnt = 1;

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
               ("IFXOS WRN - Thread Shutdown <%s> - not running" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName));
         }

         if (pThrCntrl->thrParams.bRunning != 0)
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Thread Shutdown <%s> - no responce" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName));

            pThrCntrl->bValid = IFX_FALSE;

            return IFX_ERROR;
         }

         pThrCntrl->bValid = IFX_FALSE;

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
   XAPI - Modify own thread priority.

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

   return IFX_SUCCESS;
}


/**
   Return the own thread / task ID

\return
   Thread ID of the current thread.
*/
IFXOS_thread_t IFXOS_ThreadIdGet(void)
{
   IFX_ulong_t taskId = 0;

   if (xt_ident(0, 0L, &taskId) == ERR_NO_ERROR)
      return taskId;

   return 0;
}

/**
   Return the own process ID

\return
   Thread ID of the current thread.
*/
IFXOS_process_t IFXOS_ProcessIdGet(void)
{
   IFX_ulong_t taskId = 0;

   if (xt_ident(0, 0L, &taskId) == ERR_NO_ERROR)
      return taskId;

   return 0;
}

#endif      /* #if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) ) */

/** @} */
#endif      /* #ifdef XAPI */




