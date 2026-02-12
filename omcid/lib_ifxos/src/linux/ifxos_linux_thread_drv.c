/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation - thread handling (Kernel Space)
   Remark: ...
   ========================================================================= */

#ifdef LINUX
#ifdef __KERNEL__

/** \file
   This file contains the IFXOS Layer implementation for LINUX Kernel
   Thread handling.
*/


/* ============================================================================
   IFX Linux adaptation - Global Includes - Kernel
   ========================================================================= */

#include <linux/kernel.h>
#ifdef MODULE
   #include <linux/module.h>
#endif
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/completion.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33))
#include <linux/smp_lock.h>
#endif
#include <linux/signal.h>


#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_linux_drv.h"
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

/** \addtogroup IFXOS_THREAD_LINUX_DRV
@{ */

#if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) )


IFXOS_STATIC IFX_int32_t IFXOS_KernelThreadStartup(
                              IFXOS_ThreadCtrl_t *pThrCntrl);


/* ============================================================================
   IFX Linux adaptation - Kernel Thread handling
   ========================================================================= */

/**
   LINUX Kernel - Thread stub function. The stub function will be called
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
IFXOS_STATIC IFX_int32_t IFXOS_KernelThreadStartup(
                              IFXOS_ThreadCtrl_t *pThrCntrl)
{
   IFX_int32_t retVal          = IFX_ERROR;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
   struct task_struct *kthread = current;
#endif

   if(!pThrCntrl)
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Kernel ThreadStartup, missing object" IFXOS_CRLF));

      return retVal;
   }

   /* terminate the name if necessary */
   pThrCntrl->thrParams.pName[16 -1] = 0;

   IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_NORMAL,
      ("ENTER - Kernel Thread Startup <%s>" IFXOS_CRLF,
        pThrCntrl->thrParams.pName));

   /* do LINUX specific setup */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
   daemonize();
   reparent_to_init();

   /* lock the kernel. A new kernel thread starts without
      the big kernel lock, regardless of the lock state
      of the creator (the lock level is *not* inheritated)
   */
   lock_kernel();

   /* set signal mask to what we want to respond */
   siginitsetinv(&current->blocked, sigmask(SIGKILL)|sigmask(SIGINT)|sigmask(SIGTERM));

   /* set name of this process */
   strcpy(kthread->comm, pThrCntrl->thrParams.pName);

   /* let others run */
   unlock_kernel();
#else
   daemonize(pThrCntrl->thrParams.pName);

   /* Enable signals in Kernel >= 2.6 */
   allow_signal(SIGKILL);
   allow_signal(SIGINT);
   allow_signal(SIGTERM);
#endif

   if (pThrCntrl->nPriority)
      IFXOS_ThreadPriorityModify(pThrCntrl->nPriority);

   pThrCntrl->thrParams.bRunning = IFX_TRUE;
   retVal = pThrCntrl->pThrFct(&pThrCntrl->thrParams);
   pThrCntrl->thrParams.bRunning = IFX_FALSE;

   complete_and_exit(&pThrCntrl->thrCompletion, (long)retVal);

   IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_NORMAL,
      ("EXIT - Kernel Thread Startup <%s>" IFXOS_CRLF,
        pThrCntrl->thrParams.pName));

   return retVal;
}

/**
   LINUX Kernel - Creates a new thread / task.

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
   if(pThreadFunction == IFX_NULL) return IFX_ERROR;
   if(pName == IFX_NULL) return IFX_ERROR;

   if(pThrCntrl)
   {
      if (IFXOS_THREAD_INIT_VALID(pThrCntrl) == IFX_FALSE)
      {
         /* set thread function arguments */
         strcpy(pThrCntrl->thrParams.pName, pName);
         pThrCntrl->nPriority = nPriority;
         pThrCntrl->thrParams.nArg1 = nArg1;
         pThrCntrl->thrParams.nArg2 = nArg2;
         pThrCntrl->thrParams.bShutDown = IFX_FALSE;

         /* set thread control settings */
         pThrCntrl->pThrFct = pThreadFunction;
         init_completion(&pThrCntrl->thrCompletion);

         /* start kernel thread via the wrapper function */
         pThrCntrl->tid = kernel_thread( (IFXOS_KERNEL_THREAD_StartRoutine)IFXOS_KernelThreadStartup,
                        (void *)pThrCntrl,
                        IFXOS_DRV_THREAD_OPTIONS);

         pThrCntrl->bValid = IFX_TRUE;

         return IFX_SUCCESS;
      }
      else
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - Kernel ThreadInit, object already valid" IFXOS_CRLF));
      }
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Kernel ThreadInit, missing object" IFXOS_CRLF));
   }

   return IFX_ERROR;
}

/**
   LINUX Kernel - Shutdown and terminate a given thread.
   Therefore the thread delete functions triggers the user thread function
   to shutdown. In case of not responce (timeout) the thread will be canceled.

\par Implementation
   - force a shutdown via the shutdown flag and wait.
   - wait for completion (see "wait_for_completion").
   - free previous allocated internal data.

\param
   pThrCntrl   Thread control struct.
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

            /* wait for thread end */
            wait_for_completion (&pThrCntrl->thrCompletion);
         }
         else
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
               ("IFXOS WRN - Kernel Thread Delete <%s> - not running" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName));
         }

         pThrCntrl->bValid = IFX_FALSE;

         if (pThrCntrl->thrParams.bRunning != 0)
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("ERROR - Kernel Thread Delete <%s> not stopped" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName));

            return IFX_ERROR;
         }

         return IFX_SUCCESS;
      }
      else
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - Kernel ThreadDelete, invalid object" IFXOS_CRLF));
      }
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Kernel ThreadDelete, missing object" IFXOS_CRLF));
   }

   return IFX_ERROR;
}

/**
   LINUX Kernel - Shutdown a given thread.
   Therefore the thread delete functions triggers the user thread function
   to shutdown.

\par Implementation
   - force a shutdown via the shutdown flag.
   - wait for completion only if the thread down (see "wait_for_completion").
   - free previous allocated internal data.

\param
   pThrCntrl   Thread control struct.
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

            if (pThrCntrl->thrParams.bRunning == 0)
            {
               wait_for_completion (&pThrCntrl->thrCompletion);
            }
         }
         else
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_WRN,
               ("IFXOS WRN - Kernel Thread Shutdown <%s> - not running" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName));
         }

         pThrCntrl->bValid = IFX_FALSE;

         if (pThrCntrl->thrParams.bRunning == 1)
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
               ("ERROR - Kernel Thread Shutdown <%s> not stopped" IFXOS_CRLF,
                 pThrCntrl->thrParams.pName));
         }
         return IFX_SUCCESS;
      }
      else
      {
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
            ("IFXOS ERROR - Kernel Thread Shutdown, invalid object" IFXOS_CRLF));
      }
   }
   else
   {
      IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR,
         ("IFXOS ERROR - Kernel Thread Shutdown, missing object" IFXOS_CRLF));
   }

   return IFX_ERROR;
}


/**
   LINUX Kernel - Modify own thread priority.

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
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
   return (current->pid);
#else
   return 0;
#endif
}


/**
   Return the own process ID

\return
   Process ID of the current thread.
*/
IFXOS_process_t IFXOS_ProcessIdGet(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
   return (current->pid);
#else
   return 0;
#endif
}


#endif      /* #if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) ) */

/** @} */

#ifdef MODULE
EXPORT_SYMBOL(IFXOS_ThreadInit);
EXPORT_SYMBOL(IFXOS_ThreadDelete);
EXPORT_SYMBOL(IFXOS_ThreadShutdown);
EXPORT_SYMBOL(IFXOS_ThreadPriorityModify);
#endif

#endif      /* #ifdef __KERNEL__ */
#endif      /* #ifdef LINUX */

