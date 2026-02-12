#ifndef _IFXOS_NUCLEUS_THREAD_H
#define _IFXOS_NUCLEUS_THREAD_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS

/** \defgroup IFXOS_THREAD_NUCLEUS Task  (Nucleus).

   This Group contains the Nucleus Task definitions and function. 

\ingroup IFXOS_LAYER_NUCLEUS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Nucleus adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"
#include <nucleus.h>

/* ============================================================================
   IFX Nucleus adaptation - supported features
   ========================================================================= */

/** IFX Nucleus adaptation - support "Task feature" */
#ifndef IFXOS_HAVE_THREAD
#  define IFXOS_HAVE_THREAD                          1
#endif

/* ============================================================================
   IFX Nucleus adaptation - task defines
   ========================================================================= */
/** \addtogroup IFXOS_THREAD_NUCLEUS
@{ */

/** set if a option is not used for this OS adaptation */
#define IFXOS_THREAD_OPTION_NOT_USED_FOR_NUCLEUS   0

/** Nucleus Task - priority - IDLE */
#define IFXOS_THREAD_PRIO_IDLE                     255
/** Nucleus Task - priority - LOWEST */
#define IFXOS_THREAD_PRIO_LOWEST                   250
/** Nucleus Task - priority - LOW */
#define IFXOS_THREAD_PRIO_LOW                      200
/** Nucleus Task - priority - NORMAL */
#define IFXOS_THREAD_PRIO_NORMAL                   100
/** Nucleus Task - priority - HIGH */
#define IFXOS_THREAD_PRIO_HIGH                     55
/** Nucleus Task - priority - HIGHEST */
#define IFXOS_THREAD_PRIO_HIGHEST                  10
/** Nucleus Task - priority - TIME_CRITICAL 
\attention
   You should use this priority only for driver threads.
*/
#define IFXOS_THREAD_PRIO_TIME_CRITICAL            0


/** Nucleus Task - internal poll time for check thread end */
#define IFXOS_THREAD_DOWN_WAIT_POLL_MS             10

/** Nucleus Task - thread options */
#define IFXOS_DRV_THREAD_OPTIONS                   IFXOS_THREAD_OPTION_NOT_USED_FOR_NUCLEUS
/** Nucleus Task - default prio */
#define IFXOS_DEFAULT_PRIO                         100
/** Nucleus Task - default stack size */
#define IFXOS_DEFAULT_STACK_SIZE                   4096

/* ============================================================================
   IFX Nucleus adaptation - task types
   ========================================================================= */

/**
   Nucleus Task - map the Thread ID.
*/
typedef NU_TASK*    IFXOS_thread_t;

/**
   Nucleus Process - map the Process ID.
*/
typedef NU_TASK*    IFXOS_process_t;


/**
   Nucleus Task - Control struct for task handling.
*/
typedef struct
{
   /** Contains the user and task control parameters */
   IFXOS_ThreadParams_t    thrParams;

   /** Points to the user task start routine */
   IFXOS_ThreadFunction_t  pThrFct;

   /** Nucleus specific for internal - keep the task Nucleus ID */
   NU_TASK                 tid;

   /** stack */
   IFX_uint8_t             *stack_pointer;

   /** requested kernel thread priority */
   IFX_int32_t             nPriority;
   
   /** flag indicates that the structure is initialized */
   IFX_boolean_t           bValid;

} IFXOS_ThreadCtrl_t;

/** Nucleus Task - lock scheduling */
#define IFXOS_ThreadLock()      NU_Change_Preemption(NU_NO_PREEMPT)                           
/** Nucleus Task - unlock scheduling */
#define IFXOS_ThreadUnlock()    NU_Change_Preemption(NU_PREEMPT)

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef NUCLEUS_PLUS */
#endif      /* #ifndef _IFXOS_NUCLEUS_THREAD_H */

