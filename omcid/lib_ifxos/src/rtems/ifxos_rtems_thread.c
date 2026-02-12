/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains the IFXOS Layer implementation for RTEMS
   Task handling.
*/

#ifdef RTEMS

/* ============================================================================
   RTEMS adaptation - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_debug.h"
#include "ifxos_time.h"
#include "ifxos_thread.h"

#include "xapi.h"
#include "print.h"
#include "alloc.h"

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

//static unsigned long task_id;   // SchS

/* ============================================================================
   RTEMS adaptation - Task handling
   ========================================================================= */

/** \addtogroup IFXOS_THREAD_RTEMS
@{ */

#if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) )

//weirong define the debug level
IFXOS_PRN_USR_MODULE_CREATE(IFXOS,IFXOS_PRN_LEVEL_LOW);

/**
   RTEMS - Thread stub function. The stub function will be called
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
                              IFXOS_ThreadCtrl_t *pThrCntrl)
{
   IFX_int32_t retVal = IFX_ERROR;

   if(pThrCntrl)
   {
      pThrCntrl->thrParams.bRunning = 1;
      retVal = pThrCntrl->pThrFct(&pThrCntrl->thrParams);
      pThrCntrl->thrParams.bRunning = 0;
   }

   return retVal;
}

/**
   RTEMS - Creates a new task.

\par Implementation
   - Allocate and setup the internal thread control structure.
   - setup the RTEMS specific thread parameter.
   - start the RTEMS task with the internal stub function (see "taskSpawn")
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
               IFX_char_t     *pName,
               IFXOS_ThreadFunction_t pThreadFunction,
               IFX_uint32_t   nStackSize,
               IFX_uint32_t   nPriority,
               IFX_ulong_t    nArg1,
               IFX_ulong_t    nArg2)
{
   if(pThreadFunction == IFX_NULL) return IFX_ERROR;
   if(pName == IFX_NULL) return IFX_ERROR;

   if(pThrCntrl)
   {
      if (IFXOS_THREAD_INIT_VALID(pThrCntrl) == IFX_FALSE)
      {
         strncpy(pThrCntrl->thrParams.pName, pName, IFXOS_THREAD_NAME_LEN);
         pThrCntrl->thrParams.pName[IFXOS_THREAD_NAME_LEN-1] = 0;
         pThrCntrl->nPriority = nPriority;
         pThrCntrl->thrParams.nArg1 = nArg1;
         pThrCntrl->thrParams.nArg2 = nArg2;
         pThrCntrl->thrParams.bShutDown = 0;

         pThrCntrl->pThrFct = pThreadFunction;

         IFX_uint32_t error;
         IFX_uint32_t args[4];

         printf("Thread %s starting\n", pName);
         if( (error = xt_create(pName, nPriority, nStackSize,0L,0L, &pThrCntrl->tid)) != ERR_NO_ERROR)
         {
            printf("Task start error: %d\n", error);
            return IFX_ERROR;
         }
         args[0]= (IFXOS_ThreadParams_t*)(&pThrCntrl->thrParams);
         args[1]=0;
         args[2]=0;
         args[3]=0;

         if( (error = xt_start(pThrCntrl->tid, (T_PREEMPT | T_TSLICE), (void*)pThreadFunction, (unsigned long) (args))) != ERR_NO_ERROR)
         {
            printf("Task start error: %d\n", error);
            return IFX_ERROR;
         }
         pThrCntrl->bValid = IFX_TRUE;
         printf("IFXOS_ThreadInit %x started\n", pThreadFunction);
         return IFX_SUCCESS;

        }
      }

   return IFX_ERROR;
}

/**
   RTEMS - Shutdown and terminate a given thread.
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
            pThrCntrl->thrParams.bShutDown = 1;

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

         pThrCntrl->thrParams.bRunning = 1;

         /* terminate the task if it does not terminate within given time */
         if (pThrCntrl->thrParams.bRunning == 1)
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
               ("IFXOS WRN - Thread Delete <%s> TID %d - kill, no shutdown responce" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName, pThrCntrl->tid));

            if (xt_delete(pThrCntrl->tid)!= IFX_SUCCESS)    /* <-- delete thread */
            {
               IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
                  ("IFXOS ERROR - Thread Delete <%s> TID %d - kill failed (mem loss ?)" IFXOS_CRLF,
                    pThrCntrl->thrParams.pName, pThrCntrl->tid));

               pThrCntrl->bValid = IFX_FALSE;

               return IFX_ERROR;
            }
            pThrCntrl->thrParams.bRunning = 0;
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
   RTEMS - Shutdown a given thread.
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

   if (pThrCntrl == IFX_NULL)
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Thread Shutdown - setup" IFXOS_CRLF));

      return IFX_ERROR;
   }

   if(pThrCntrl)
   {
      if (IFXOS_THREAD_INIT_VALID(pThrCntrl) == IFX_TRUE)
      {
         if (pThrCntrl->thrParams.bRunning == 1)
         {
            /* trigger user thread routine to shutdown */
            pThrCntrl->thrParams.bShutDown = 1;

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
   RTEMS - Modify own thread priority.

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

   /*
      Customer-ToDo:
      Fill with your customer OS implementation to modify the priority
   */
   return IFX_SUCCESS;
}


/**
   Return the own thread / task ID

\return
   Thread ID of the current thread.
*/
IFXOS_thread_t IFXOS_ThreadIdGet(void)
{
   unsigned long tid;

   xt_ident((char *) 0, 0, &tid);

   return tid;
}

#endif      /* #if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) ) */

/** @} */

#endif      /* #ifdef RTEMS */




