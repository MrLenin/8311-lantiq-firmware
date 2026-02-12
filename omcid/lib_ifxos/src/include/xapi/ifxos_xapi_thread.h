#ifndef _IFXOS_XAPI_THREAD_H
#define _IFXOS_XAPI_THREAD_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef XAPI

/** \defgroup IFXOS_THREAD_XAPI Task  (XAPI).

   This Group contains the XAPI Task definitions and function.

\ingroup IFXOS_LAYER_XAPI
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX XAPI adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"

#include <xapi.h>

/* ============================================================================
   IFX XAPI adaptation - supported features
   ========================================================================= */

/** IFX XAPI adaptation - support "Task feature" */
#ifndef IFXOS_HAVE_THREAD
#  define IFXOS_HAVE_THREAD                          1
#endif

/* ============================================================================
   IFX XAPI adaptation - task defines
   ========================================================================= */
/** \addtogroup IFXOS_THREAD_XAPI
@{ */

/** set if a option is not used for this OS adaptation */
#define IFXOS_THREAD_OPTION_NOT_USED_FOR_XAPI   0

#ifdef IFXOS_THREAD_NAME_LEN
#  undef IFXOS_THREAD_NAME_LEN
/** 4 bytes + null termination */
#  define IFXOS_THREAD_NAME_LEN                    5
#endif

/** VxWorks Task - priority - IDLE */
#define IFXOS_THREAD_PRIO_IDLE                     1
/** VxWorks Task - priority - LOWEST */
#define IFXOS_THREAD_PRIO_LOWEST                   20
/** VxWorks Task - priority - LOW */
#define IFXOS_THREAD_PRIO_LOW                      50
/** VxWorks Task - priority - NORMAL */
#define IFXOS_THREAD_PRIO_NORMAL                   100
/** VxWorks Task - priority - HIGH */
#define IFXOS_THREAD_PRIO_HIGH                     150
/** VxWorks Task - priority - HIGHEST */
#define IFXOS_THREAD_PRIO_HIGHEST                  255
/** VxWorks Task - priority - TIME_CRITICAL
\attention
   You should use this priority only for driver threads.
 */
#define IFXOS_THREAD_PRIO_TIME_CRITICAL            200


/** XAPI Task - internal poll time for check thread end */
#define IFXOS_THREAD_DOWN_WAIT_POLL_MS             10

/** XAPI Task - thread options */
#define IFXOS_DRV_THREAD_OPTIONS                   IFXOS_THREAD_OPTION_NOT_USED_FOR_XAPI
/** XAPI Task - default prio */
#define IFXOS_DEFAULT_PRIO                         IFXOS_THREAD_PRIO_NORMAL
/** XAPI Task - default stack size */
#define IFXOS_DEFAULT_STACK_SIZE                   4096

/** Task mode
 *     Bit mask :
 *  preemption   bit 0: 0 = enabled, 1 = disabled
 *  roundrobin   bit 1: 0 = disabled, 1 = enabled
 *  reserved     bit 2: must be 1
 *    All other bits must be 0.
 */
#define IFXOS_DEFAULT_TASK_MODE 0x7

/** XAPI Task - lock scheduling */
#define IFXOS_ThreadLock()                         xt_entercritical()
/** XAPI Task - unlock scheduling */
#define IFXOS_ThreadUnlock()                       xt_exitcritical()

/* ============================================================================
   IFX XAPI adaptation - task types
   ========================================================================= */

/**
   XAPI Task - map the Thread ID.
*/
typedef unsigned long    IFXOS_thread_t;

/**
   XAPI Task - map the Process ID.
*/
typedef unsigned long    IFXOS_process_t;

/**
   XAPI Task - Control struct for task handling.
*/
typedef struct
{
   /** Contains the user and task control parameters */
   IFXOS_ThreadParams_t    thrParams;

   /** Points to the user task start routine */
   IFXOS_ThreadFunction_t  pThrFct;

   /** XAPI specific for internal - keep the task XAPI ID */
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
#endif      /* #ifdef XAPI */
#endif      /* #ifndef _IFXOS_XAPI_THREAD_H */

