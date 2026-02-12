/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation - driver select handling (Kernel Space)
   Remark: ...
   ========================================================================= */

#ifdef LINUX
#ifdef __KERNEL__

/** \file
   This file contains the IFXOS Layer implementation for LINUX Kernel 
   Syncronistation Poll / Select.
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes - Kernel
   ========================================================================= */

#include <linux/kernel.h>
#ifdef MODULE
   #include <linux/module.h>
#endif
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/sched.h>

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_time.h"
#include "ifxos_select.h"


/* ============================================================================
   IFX Linux adaptation - Kernel Driver SELECT handling
   ========================================================================= */
/** \addtogroup IFXOS_DRV_SELECT_LINUX_KERNEL
@{ */

#if ( defined(IFXOS_HAVE_DRV_SELECT) && (IFXOS_HAVE_DRV_SELECT == 1) )

/**
   LINUX Kernel - Initialize a Select Queue Object for synchronisation between user 
   and driver space via the select / poll mechanism.

\par Implementation
   - setup a LINUX wait queue (see "init_waitqueue_head").

\param
   pDrvSelectQueue   Points to a Driver Select Queue object.

\return      
   IFX_SUCCESS if the initialization was successful, else
   IFX_ERROR in case of error.
*/
IFX_int32_t IFXOS_DrvSelectQueueInit(
               IFXOS_drvSelectQueue_t  *pDrvSelectQueue)
{
   IFXOS_RETURN_IF_POINTER_NULL(pDrvSelectQueue, IFX_ERROR);

   init_waitqueue_head(pDrvSelectQueue);
   return IFX_SUCCESS;
}

/**
   LINUX Kernel - Wakeup from the Select Queue all added task. 
   This function is used from driver space to signal the occurance of an event 
   from driver space to one or several waiting user (poll / select mechanism).

\par Implementation
   - signal a wakeup for the given wait queue (see "wake_up_interruptible").

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
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pDrvSelectQueue, IFX_ERROR);

   wake_up_interruptible(pDrvSelectQueue);
   return;
}

/**
   LINUX Kernel - Add an user thread / task to a Select Queue
   This function is used from user space to add a thread / task to a corresponding
   Select Queue. The thread / task will be waked up if the event occures or if
   the time expires.

\par Implementation
   - add the user tasks for poll wait (see "poll_wait").

\param
   pDrvSelectOsArg   LINUX file struct, comes from the IO call.
\param
   pDrvSelectQueue   Points to used Select Queue object (Linux wait queue), which can 
                     change the poll status.
\param
   pDrvSelectTable   LINUX poll table, comes from the IO call.

\return
   IFX_SUCCESS if the thread / task has been added, else
   IFX_ERROR.
*/
IFX_int32_t IFXOS_DrvSelectQueueAddTask(
               IFXOS_drvSelectOSArg_t  *pDrvSelectOsArg,
               IFXOS_drvSelectQueue_t  *pDrvSelectQueue,
               IFXOS_drvSelectTable_t  *pDrvSelectTable)
{
   IFXOS_RETURN_IF_POINTER_NULL(pDrvSelectQueue, IFX_ERROR);
   /*
      --> depending on your OS the arguments are required
      IFXOS_RETURN_IF_POINTER_NULL(pDrvSelectOsArg, IFX_ERROR);
      IFXOS_RETURN_IF_POINTER_NULL(pDrvSelectTable, IFX_ERROR);
   */

   poll_wait( (struct file *)pDrvSelectOsArg, 
              pDrvSelectQueue, 
              (poll_table *)pDrvSelectTable );
   return IFX_SUCCESS;
}

#endif      /* #if ( defined(IFXOS_HAVE_DRV_SELECT) && (IFXOS_HAVE_DRV_SELECT == 1) ) */

/** @} */

#ifdef MODULE
EXPORT_SYMBOL(IFXOS_DrvSelectQueueInit);
EXPORT_SYMBOL(IFXOS_DrvSelectQueueWakeUp);
EXPORT_SYMBOL(IFXOS_DrvSelectQueueAddTask);
#endif

#endif      /* #ifdef __KERNEL__ */
#endif      /* #ifdef LINUX */

