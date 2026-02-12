#ifndef _IFXOS_VXWORKS_THREAD_H
#define _IFXOS_VXWORKS_THREAD_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS

/** \defgroup IFXOS_THREAD_VXWORKS Task  (VxWorks).

   This Group contains the VxWorks Task definitions and function. 

\ingroup IFXOS_LAYER_VXWORKS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX VxWorks adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

#include <vxWorks.h>
#include <taskLib.h>


/* ============================================================================
   IFX VxWorks adaptation - supported features
   ========================================================================= */

/** IFX VxWorks adaptation - support "Task feature" */
#ifndef IFXOS_HAVE_THREAD
#  define IFXOS_HAVE_THREAD                          1
#endif

/* ============================================================================
   IFX VxWorks adaptation - task defines
   ========================================================================= */
/** \addtogroup IFXOS_THREAD_VXWORKS
@{ */

/** set if a option is not used for this OS adaptation */
#define IFXOS_THREAD_OPTION_NOT_USED_FOR_VXWORKS   0

/** VxWorks Task - priority - IDLE */
#define IFXOS_THREAD_PRIO_IDLE                     255
/** VxWorks Task - priority - LOWEST */
#define IFXOS_THREAD_PRIO_LOWEST                   250
/** VxWorks Task - priority - LOW */
#define IFXOS_THREAD_PRIO_LOW                      200
/** VxWorks Task - priority - NORMAL */
#define IFXOS_THREAD_PRIO_NORMAL                   100
/** VxWorks Task - priority - HIGH */
#define IFXOS_THREAD_PRIO_HIGH                     55
/** VxWorks Task - priority - HIGHEST */
#define IFXOS_THREAD_PRIO_HIGHEST                  10
/** VxWorks Task - priority - TIME_CRITICAL 
\attention
   You should use this priority only for driver threads.
*/
#define IFXOS_THREAD_PRIO_TIME_CRITICAL            0


/** VxWorks Task - internal poll time for check thread end */
#define IFXOS_THREAD_DOWN_WAIT_POLL_MS             10

/** VxWorks Task - thread options */
#define IFXOS_DRV_THREAD_OPTIONS                   IFXOS_THREAD_OPTION_NOT_USED_FOR_VXWORKS
/** VxWorks Task - default prio */
#define IFXOS_DEFAULT_PRIO                         100
/** VxWorks Task - default stack size */
#define IFXOS_DEFAULT_STACK_SIZE                   4096

/** VxWorks Task - lock scheduling */
#define IFXOS_ThreadLock()                         taskLock()
/** VxWorks Task - unlock scheduling */
#define IFXOS_ThreadUnlock()                       taskUnlock()

/* ============================================================================
   IFX VxWorks adaptation - task types
   ========================================================================= */

/**
   VxWorks Task - map the Thread ID.
*/
typedef int    IFXOS_thread_t;

/**
   VxWorks Process - map the Process ID.
*/
typedef int    IFXOS_process_t;


/**
   VxWorks Task - Control struct for task handling.
*/
typedef struct
{
   /** Contains the user and task control parameters */
   IFXOS_ThreadParams_t    thrParams;

   /** Points to the user task start routine */
   IFXOS_ThreadFunction_t  pThrFct;

   /** Vxworks specific for internal - keep the task VxWorks ID */
   IFXOS_thread_t          tid;

   /** requested kernel thread priority */
   IFX_int32_t             nPriority;
   
   /** flag indicates that the structure is initialized */
   IFX_boolean_t           bValid;

} IFXOS_ThreadCtrl_t;

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef VXWORKS */
#endif      /* #ifndef _IFXOS_VXWORKS_THREAD_H */

