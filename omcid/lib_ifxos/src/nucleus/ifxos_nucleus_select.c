/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS

/** \file
   This file contains the IFXOS Layer implemantation for Nucleus 
   Syncronistation Poll / Select.
*/


/* ============================================================================
   IFX Nucleus adaptation - Global Includes - Kernel
   ========================================================================= */

#include <nucleus.h>

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_time.h"
#include "ifxos_select.h"


/* ============================================================================
   IFX Nucleus adaptation - Kernel Driver SELECT handling
   ========================================================================= */

/** \addtogroup IFXOS_SELECT_NUCLEUS_DRV
@{ */

#if ( defined(IFXOS_HAVE_DRV_SELECT) && (IFXOS_HAVE_DRV_SELECT == 1) )

/**
   Nucleus - Initialize a Select Queue Object for synchronisation between 
   user and driver space via the select / poll mechanism.

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
   Nucleus - Wakeup all the task added from the Select Queue. 
   This function is used from driver space to signal the occurance of an event 
   from driver space to one or several waiting user (poll / select mechanism).

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
   Nucleus - Add an user task to a Select Queue.
   This function is used from user space to add a thread / task to a corresponding
   Select Queue. The task will be waked up if the event occures or if
   the time expires.

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

#endif      /* #ifdef NUCLEUS_PLUS */

