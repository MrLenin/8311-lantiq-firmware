#ifndef _IFXOS_GENERIC_OS_THREAD_H
#define _IFXOS_GENERIC_OS_THREAD_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS

/** \defgroup IFXOS_THREAD_GENERIC_OS Task  (Generic OS).

   This Group contains the Generic OS Task definitions and function. 

\ingroup IFXOS_LAYER_GENERIC_OS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Generic OS adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"


/* ============================================================================
   IFX Generic OS adaptation - supported features
   ========================================================================= */

/** IFX Generic OS adaptation - support "Task feature" */
#ifndef IFXOS_HAVE_THREAD
#define IFXOS_HAVE_THREAD                          1
#endif

/* ============================================================================
   IFX Generic OS adaptation - task defines
   ========================================================================= */
/** \addtogroup IFXOS_THREAD_GENERIC_OS
@{ */

/** set if a option is not used for this OS adaptation */
#ifndef IFXOS_THREAD_OPTION_NOT_USED_FOR_GENERIC_OS
#define IFXOS_THREAD_OPTION_NOT_USED_FOR_GENERIC_OS   0
#endif

/** Generic OS Task - priority - IDLE */
#ifndef IFXOS_THREAD_PRIO_IDLE
#define IFXOS_THREAD_PRIO_IDLE                     255
#endif

/** Generic OS Task - priority - LOWEST */
#ifndef IFXOS_THREAD_PRIO_LOWEST
#define IFXOS_THREAD_PRIO_LOWEST                   250
#endif

/** Generic OS Task - priority - LOW */
#ifndef IFXOS_THREAD_PRIO_LOW
#define IFXOS_THREAD_PRIO_LOW                      200
#endif

/** Generic OS Task - priority - NORMAL */
#ifndef IFXOS_THREAD_PRIO_NORMAL
#define IFXOS_THREAD_PRIO_NORMAL                   100
#endif

/** Generic OS Task - priority - HIGH */
#ifndef IFXOS_THREAD_PRIO_HIGH
#define IFXOS_THREAD_PRIO_HIGH                     55
#endif

/** Generic OS Task - priority - HIGHEST */
#ifndef IFXOS_THREAD_PRIO_HIGHEST
#define IFXOS_THREAD_PRIO_HIGHEST                  10
#endif

/** Generic OS Task - priority - TIME_CRITICAL 
\attention
   You should use this priority only for driver threads.
*/
#ifndef IFXOS_THREAD_PRIO_TIME_CRITICAL
#define IFXOS_THREAD_PRIO_TIME_CRITICAL            0
#endif

/** Generic OS Task - internal poll time for check thread end */
#ifndef IFXOS_THREAD_DOWN_WAIT_POLL_MS
#define IFXOS_THREAD_DOWN_WAIT_POLL_MS             10
#endif

/** Generic OS Task - thread options */
#ifndef IFXOS_DRV_THREAD_OPTIONS
#define IFXOS_DRV_THREAD_OPTIONS                   IFXOS_THREAD_OPTION_NOT_USED_FOR_GENERIC_OS
#endif

/** Generic OS Task - default prio */
#ifndef IFXOS_DEFAULT_PRIO
#define IFXOS_DEFAULT_PRIO                         100
#endif

/** Generic OS Task - default stack size */
#ifndef IFXOS_DEFAULT_STACK_SIZE
#define IFXOS_DEFAULT_STACK_SIZE                   4096
#endif

/** Generic OS Task - lock scheduling */
#define IFXOS_ThreadLock()
/** Generic OS Task - unlock scheduling */
#define IFXOS_ThreadUnlock()

/* ============================================================================
   IFX Generic OS adaptation - task types
   ========================================================================= */

/**
   Generic OS Task - map the Thread ID.
*/
typedef int    IFXOS_thread_t;

/**
   Generic OS Process - map the Process ID.
*/
typedef int    IFXOS_process_t;


/**
   Generic OS Task - Control struct for task handling.
*/
typedef struct
{
   /** Contains the user and task control parameters */
   IFXOS_ThreadParams_t    thrParams;

   /** Points to the user task start routine */
   IFXOS_ThreadFunction_t  pThrFct;

   /** Vxworks specific for internal - keep the task Generic OS ID */
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
#endif      /* #ifdef GENERIC_OS */
#endif      /* #ifndef _IFXOS_GENERIC_OS_THREAD_H */

