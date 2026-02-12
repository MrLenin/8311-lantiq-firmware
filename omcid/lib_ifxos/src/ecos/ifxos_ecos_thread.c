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
   Task handling.
*/

/* ============================================================================
   IFX eCos adaptation - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_debug.h"
#include "ifxos_memory_alloc.h"  /* stack alloc */
#include "ifxos_time.h"
#include "ifxos_thread.h"
#include "ifxos_print.h"

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


/* ============================================================================
   IFX eCos adaptation - Task handling
   ========================================================================= */

/** \addtogroup IFXOS_THREAD_ECOS
@{ */

#if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) )

/**
   eCos - Thread stub function. The stub function will be called
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
IFXOS_STATIC void IFXOS_ThreadStartup(cyg_addrword_t data)
{
   IFX_int32_t retVal = IFX_ERROR;
   IFXOS_ThreadCtrl_t *pThrCntrl = (IFXOS_ThreadCtrl_t *)data;

   if(!pThrCntrl)
   {
      return;
   }

   IFXOS_ThreadPriorityModify(pThrCntrl->nPriority);

   pThrCntrl->thrParams.bRunning = IFX_TRUE;
   retVal = pThrCntrl->pThrFct(&pThrCntrl->thrParams);
   pThrCntrl->thrParams.bRunning = IFX_FALSE;

   cyg_thread_exit();

   return;
}

/**
   eCos - Creates a new task.

\par Implementation
   - Allocate and setup the internal thread control structure.
   - setup the eCos specific thread parameter.
   - start the eCos task with the internal stub function (see "cyg_thread_create")
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
         /* set task function arguments */
         strncpy(pThrCntrl->thrParams.pName, pName, IFXOS_THREAD_NAME_LEN);
         pThrCntrl->thrParams.pName[IFXOS_THREAD_NAME_LEN-1] = 0;
         pThrCntrl->nPriority = nPriority;
         pThrCntrl->thrParams.nArg1 = nArg1;
         pThrCntrl->thrParams.nArg2 = nArg2;
         pThrCntrl->thrParams.bShutDown = IFX_FALSE;

         pThrCntrl->pThrFct = pThreadFunction;

         pThrCntrl->thrParams.pSysObject = (IFX_void_t*)IFXOS_SYS_OBJECT_GET(IFXOS_SYS_OBJECT_THREAD);
         IFXOS_SYS_THREAD_PARAMS_SET(pThrCntrl->thrParams.pSysObject, pThrCntrl);
         IFXOS_SYS_THREAD_INIT_COUNT_INC(pThrCntrl->thrParams.pSysObject);

         if(nStackSize == 0)
         {
            nStackSize = 4096;
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Thread Init - set default stack size to 4096" IFXOS_CRLF));
         }

         pThrCntrl->stack_pointer = IFXOS_MemAlloc(nStackSize);

         if(pThrCntrl->stack_pointer == IFX_NULL)
         {
            goto IFXOS_THREADCREATE_ERROR;
         }

         memset(pThrCntrl->stack_pointer, 0x00, nStackSize);

         cyg_thread_create(
            IFXOS_DEFAULT_PRIO,
            IFXOS_ThreadStartup,
            (cyg_addrword_t)pThrCntrl,
            pThrCntrl->thrParams.pName,
            pThrCntrl->stack_pointer,
            nStackSize,
            &pThrCntrl->tid,
            &pThrCntrl->threadObject);

         cyg_thread_resume(pThrCntrl->tid);

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

IFXOS_THREADCREATE_ERROR:

   if(pThrCntrl)
   {
      if(pThrCntrl->stack_pointer != IFX_NULL)
      {
         IFXOS_MemFree(pThrCntrl->stack_pointer);
         pThrCntrl->stack_pointer = IFX_NULL;
      }
   }

   return IFX_ERROR;
}

/**
   eCos - Shutdown and terminate a given thread.
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
         }

         if (cyg_thread_delete(pThrCntrl->tid) != IFX_TRUE)
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Thread Delete <%s> TID %d - kill failed (stack mem loss ?)" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName, pThrCntrl->tid));

            pThrCntrl->stack_pointer = IFX_NULL;
            IFXOS_SYS_OBJECT_RELEASE(pThrCntrl->thrParams.pSysObject);
            pThrCntrl->bValid = IFX_FALSE;

            return IFX_ERROR;
         }

         pThrCntrl->thrParams.bRunning = IFX_FALSE;
         if(pThrCntrl->stack_pointer != IFX_NULL)
         {
            IFXOS_MemFree(pThrCntrl->stack_pointer);
            pThrCntrl->stack_pointer = IFX_NULL;
         }

         IFXOS_SYS_OBJECT_RELEASE(pThrCntrl->thrParams.pSysObject);
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
   eCos - Shutdown a given thread.
   Therefore the thread delete functions triggers the user thread function
   to shutdown and wait for end.

\par Implementation
   - force a shutdown via the shutdown flag and wait for task end with timeout.
   - remove the thread from the eCos scheduler
   - free previous allocated internal data.

\attention
   Under eCos: if a thread ends by itself this will correspond to the
   cyg_thread_exit() api call. But independant of this the thread is still
   registered within the eCos scheduler.
   So it is part of the user to keep the thread object valid.
   To remove the thread also from the scheduler you have to call the
   cyg_thread_delete() function.
   The IFXOS shutdown and delete function will behave on this way (a thread is
   also removed from the scheduler to get the same behaviour like other OS.


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
               ("IFXOS WRN - Thread Shutdown <%s> - not running" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName));
         }

         if (pThrCntrl->thrParams.bRunning != 0)
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Thread Shutdown <%s> - no responce" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName));

            return IFX_ERROR;
         }

         /* the thread function has been left by itself, but the thread is
            still registered within the eCos scheduler:
            --> delete the thread to remove it from the eCos scheduler */
         if (cyg_thread_delete(pThrCntrl->tid) != IFX_TRUE)
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("IFXOS ERROR - Thread Shutdown <%s> TID %d - delete failed (stack mem loss ?)" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName, pThrCntrl->tid));

            pThrCntrl->tid           = 0;
            pThrCntrl->stack_pointer = IFX_NULL;
            IFXOS_SYS_OBJECT_RELEASE(pThrCntrl->thrParams.pSysObject);
            pThrCntrl->bValid = IFX_FALSE;

            return IFX_ERROR;
         }

         pThrCntrl->tid = 0;

         if(pThrCntrl->stack_pointer != IFX_NULL)
         {
            IFXOS_MemFree(pThrCntrl->stack_pointer);
            pThrCntrl->stack_pointer = IFX_NULL;
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
   eCos - Modify own thread priority.

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
   if(newPriority)
   {
      cyg_thread_set_priority(cyg_thread_self(), newPriority);
   }

   return IFX_SUCCESS;
}


/**
   Return the own thread / task ID

\return
   Thread ID of the current thread.
*/
IFXOS_thread_t IFXOS_ThreadIdGet(void)
{
   return cyg_thread_self();
}

/**
   Return the own process ID

\return
   Process ID of the current thread.

\Note
   On non multiprocess systems the thread/task ID is returned.
*/
IFXOS_process_t IFXOS_ProcessIdGet(void)
{
   return cyg_thread_self();
}

#endif      /* #if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) ) */

/** @} */

#endif      /* #ifdef ECOS */




