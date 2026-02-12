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
   Syncronistation Poll / Select.

\Remark
   The intention of this layer is to allow a application / driver simulation
   within the LINUX user space
   The simulation is base on the IFXOS DevIo implementation.
*/


/* ============================================================================
   IFX LINUX User Space adaptation - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_time.h"
#include "ifxos_select.h"


/* ============================================================================
   IFX LINUX User Space adaptation - Driver SELECT handling
   ========================================================================= */

/** \addtogroup IFXOS_DRV_SELECT_LINUX_APPL
@{ */

#if ( defined(IFXOS_HAVE_DRV_SELECT) && (IFXOS_HAVE_DRV_SELECT == 1) )

/**
   Linux Appl - Initialize a Select Queue Object for synchronisation between 
   user and driver space via the select / poll mechanism.

\attention
  Not implemented.

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

   return IFX_SUCCESS;
}

/**
   Linux Appl - Wakeup all the task added from the Select Queue. 
   This function is used from driver space to signal the occurance of an event 
   from driver space to one or several waiting user (poll / select mechanism).

\attention
  Not implemented.

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
   IFXOS_RETURN_VOID_IF_POINTER_NULL(pDrvSelectQueue, IFX_ERROR);

   return;
}

/**
   Linux Appl - Add an user task to a Select Queue.
   This function is used from user space to add a thread / task to a corresponding
   Select Queue. The task will be waked up if the event occures or if
   the time expires.

\attention
  Not implemented.

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
   IFXOS_RETURN_IF_POINTER_NULL(pDrvSelectQueue, IFX_ERROR);
   /*
      --> depending on your OS the arguments are required
      IFXOS_RETURN_IF_POINTER_NULL(pDrvSelectOsArg, IFX_ERROR);
      IFXOS_RETURN_IF_POINTER_NULL(pDrvSelectTable, IFX_ERROR);
   */

   return IFX_SUCCESS;
}

#endif      /* #if ( defined(IFXOS_HAVE_DRV_SELECT) && (IFXOS_HAVE_DRV_SELECT == 1) ) */

/** @} */

#endif      /* #if defined(LINUX) && !defined(__KERNEL__) */

