/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef RTEMS

/** \file
   This file contains the IFXOS Layer implementation for RTEMS
   Syncronistation Poll / Select.
*/


/* ============================================================================
   IFX RTEMS adaptation - Global Includes - Kernel
   ========================================================================= */

/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_time.h"
#include "ifxos_select.h"


/* ============================================================================
   IFX RTEMS adaptation - Kernel Driver SELECT handling
   ========================================================================= */

/** \addtogroup IFXOS_SELECT_RTEMS_DRV
@{ */

#if ( defined(IFXOS_HAVE_DRV_SELECT) && (IFXOS_HAVE_DRV_SELECT == 1) )
static unsigned int numQueueName = 0;
/**
   RTEMS - Initialize a Select Queue Object for synchronisation between
   user and driver space via the select / poll mechanism.

\par Implementation
   - init a select wakeup list (see "selWakeupListInit").

\param
   pDrvSelectQueue   Points to a Driver Select Queue object.

\return
   IFX_SUCCESS if the initialization was successful, else
   IFX_ERROR in case of error.
*/
IFX_int32_t IFXOS_DrvSelectQueueInit(
               IFXOS_drvSelectQueue_t  *pDrvSelectQueue)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      selWakeupListInit(pDrvSelectQueue);
   */
   //unsigned long queue;
   //char name[4]="qqqq";
   //IFXOS_RETURN_IF_POINTER_NULL(pDrvSelectQueue, IFX_ERROR);
  // queue = *pDrvSelectQueue;
  // xq_create(name,10, Q_FIFO, &queue);

 //  return IFX_SUCCESS;

   char name[4];
   unsigned long queue_id;
   IFXOS_RETURN_IF_POINTER_NULL(pDrvSelectQueue, IFX_ERROR);
   xt_entercritical();
   numQueueName++;
   xt_exitcritical();
   sprintf(name, "%x", numQueueName);
   if(xq_create(name,10L, Q_FIFO, &queue_id))
   {
        return IFX_ERROR;
   }

   *pDrvSelectQueue = queue_id;
    return IFX_SUCCESS;
}

/**
   RTEMS - Wakeup all the task added from the Select Queue.
   This function is used from driver space to signal the occurance of an event
   from driver space to one or several waiting user (poll / select mechanism).

\par Implementation
   - signal a wakeup for all waiting tasks (see "selWakeupAll").
   - the select type is "Read" and "Write"

\param
   pDrvSelectQueue   Points to used Select Queue object.
\param
   drvSelType        OS specific parameter.

\return
   None
*/
IFX_void_t IFXOS_DrvSelectQueueWakeUp(
               IFXOS_drvSelectQueue_t  *pDrvSelectQueue,
               IFX_uint32_t            drvSelType)
{
   IFX_uint32_t msg_buf[4]={0,0,0,0};
   IFX_uint32_t qid;
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      selWakeupAll(pDrvSelectQueue, (SELECT_TYPE)drvSelType);
   */
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pDrvSelectQueue, IFX_ERROR);
   qid = (IFX_uint32_t) *pDrvSelectQueue;
   //xq_receive (qid,Q_WAIT,0,msg_buf);  // 0=Wait forever
   xq_send(qid, msg_buf);
   return;
//   if(xq_send(qid, msg_buf))
//       return IFX_ERROR;
//   return IFX_SUCCESS;
}

/**
   RTEMS - Add an user task to a Select Queue.
   This function is used from user space to add a thread / task to a corresponding
   Select Queue. The task will be waked up if the event occures or if
   the time expires.

\par Implementation
   - add the user tasks for select wait (see "selNodeAdd").

\note
   The add function is called by the corresponding OS system call.

\param
   pDrvSelectOsArg   OS specific parameter.
\param
   pDrvSelectQueue   Points to used Select Queue object.
\param
   pDrvSelectTable   OS specific parameter.

\return
   IFX_SUCCESS if the thread / task has been added, else
   IFX_ERROR.
*/
IFX_int32_t IFXOS_DrvSelectQueueAddTask(
               IFXOS_drvSelectOSArg_t  *pDrvSelectOsArg,
               IFXOS_drvSelectQueue_t  *pDrvSelectQueue,
               IFXOS_drvSelectTable_t  *pDrvSelectTable)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      selNodeAdd(pDrvSelectQueue, (SEL_WAKEUP_NODE*)pDrvSelectOsArg);
   */

   IFXOS_RETURN_IF_POINTER_NULL(pDrvSelectQueue, IFX_ERROR);
   /*
      --> depending on your OS the arguments are required
      IFXOS_RETURN_IF_POINTER_NULL(pDrvSelectOsArg, IFX_ERROR);
      IFXOS_RETURN_IF_POINTER_NULL(pDrvSelectTable, IFX_ERROR);
   */


   return IFX_SUCCESS;
}

/**
   RTEMS - Wait for the occurance of an "event" with timeout.

\par Implementation
   - Take the semaphore with timeout [ms] for wait for the event.

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
IFX_int_t IFXOS_Select(
               IFX_uint32_t  eventWaitQueue,
               IFX_uint32_t   waitTime_ms)
{
   unsigned long msg_buf[4];
   IFX_uint32_t qid;

   IFXOS_RETURN_IF_POINTER_NULL(pDrvSelectQueue, IFX_ERROR);

   qid = (IFX_uint32_t) eventWaitQueue;

   // Note: If waitTime_ms = 0 and Q_WAIT , then no timeout (wait forever).
   if(waitTime_ms==0)
   {
       if(xq_receive (qid,Q_NOWAIT,waitTime_ms,msg_buf))
       {
            return IFX_ERROR;
       }
   }
   else
   {
       if(xq_receive (qid,Q_WAIT,waitTime_ms,msg_buf))
       {
            return IFX_ERROR;
       }
   }


   /*
      - in case of timeout, signal the timeout via the *pRetCode
        (if the variable is given).
   */

   return IFX_SUCCESS;
}


#endif      /* #if ( defined(IFXOS_HAVE_DRV_SELECT) && (IFXOS_HAVE_DRV_SELECT == 1) ) */

/** @} */

#endif      /* #ifdef RTEMS */


