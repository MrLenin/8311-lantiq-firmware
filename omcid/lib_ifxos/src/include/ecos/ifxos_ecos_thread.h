#ifndef _IFXOS_ECOS_THREAD_H
#define _IFXOS_ECOS_THREAD_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \defgroup IFXOS_THREAD_ECOS Task  (eCos).

   This Group contains the eCos Task definitions and function. 

\ingroup IFXOS_LAYER_ECOS
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX eCos adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"
#include <cyg/kernel/kapi.h>  /* All the kernel specific stuff like cyg_flag_t, ... */

/* ============================================================================
   IFX eCos adaptation - supported features
   ========================================================================= */

/** IFX eCos adaptation - support "Task feature" */
#ifndef IFXOS_HAVE_THREAD
#  define IFXOS_HAVE_THREAD                          1
#endif
/* ============================================================================
   IFX eCos adaptation - task defines
   ========================================================================= */
/** \addtogroup IFXOS_THREAD_ECOS
@{ */

/** set if a option is not used for this OS adaptation */
#define IFXOS_THREAD_OPTION_NOT_USED_FOR_ECOS   0

/** eCos Task - priority - IDLE */
#define IFXOS_THREAD_PRIO_IDLE                     30
/** eCos Task - priority - LOWEST */
#define IFXOS_THREAD_PRIO_LOWEST                   25
/** eCos Task - priority - LOW */
#define IFXOS_THREAD_PRIO_LOW                      20
/** eCos Task - priority - NORMAL */
#define IFXOS_THREAD_PRIO_NORMAL                   15
/** eCos Task - priority - HIGH */
#define IFXOS_THREAD_PRIO_HIGH                     10
/** eCos Task - priority - HIGHEST */
#define IFXOS_THREAD_PRIO_HIGHEST                  5
/** eCos Task - priority - TIME_CRITICAL 
\attention
   You should use this priority only for driver threads.
*/
#define IFXOS_THREAD_PRIO_TIME_CRITICAL            4


/** eCos Task - internal poll time for check thread end */
#define IFXOS_THREAD_DOWN_WAIT_POLL_MS             10

/** eCos Task - thread options */
#define IFXOS_DRV_THREAD_OPTIONS                   IFXOS_THREAD_OPTION_NOT_USED_FOR_ECOS
/** eCos Task - default prio */
#define IFXOS_DEFAULT_PRIO                         10
/** eCos Task - default stack size */
#define IFXOS_DEFAULT_STACK_SIZE                   4096

/* ============================================================================
   IFX eCos adaptation - task types
   ========================================================================= */

/**
   eCos Task - map the Thread ID.
*/
typedef cyg_handle_t IFXOS_thread_t;

/**
   eCos Process - map the Process ID.
*/
typedef cyg_handle_t IFXOS_process_t;


/**
   eCos Task - Control struct for task handling.
*/
typedef struct
{
   /** Contains the user and task control parameters */
   IFXOS_ThreadParams_t    thrParams;

   /** Points to the user task start routine */
   IFXOS_ThreadFunction_t  pThrFct;

   /** eCos specific for internal - keep the task eCos ID */
   IFXOS_thread_t          tid;

   /** thread object */  
   cyg_thread              threadObject;

   /** stack */
   IFX_uint8_t             *stack_pointer;

   /** requested kernel thread priority */
   IFX_int32_t             nPriority;
   
   /** flag indicates that the structure is initialized */
   IFX_boolean_t           bValid;

} IFXOS_ThreadCtrl_t;

/** eCos Task - lock scheduling */
#define IFXOS_ThreadLock()
/** eCos Task - unlock scheduling */
#define IFXOS_ThreadUnlock()

/** @} */

#ifdef __cplusplus
}
#endif
#endif      /* #ifdef ECOS */
#endif      /* #ifndef _IFXOS_ECOS_THREAD_H */

