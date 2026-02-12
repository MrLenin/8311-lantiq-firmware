#ifndef _IFXOS_LINUX_THREAD_H
#define _IFXOS_LINUX_THREAD_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX

/** \file
   This file contains LINUX definitions for Thread handling.
*/

/** \defgroup IFXOS_THREAD_LINUX Thread  (Linux).

   This Group contains the LINUX Thread definitions and function. 

   Here we have to differ between:\n
   - user threads on user space (application code).
   - kernel thread on kernel space (driver code).

\ingroup IFXOS_LAYER_LINUX
*/

/** \defgroup IFXOS_THREAD_LINUX_APPL Thread (Linux User Space).

   This group contains the LINUX Application Thread Definitions and Function. 

\ingroup IFXOS_THREAD_LINUX
*/


/** \defgroup IFXOS_THREAD_LINUX_DRV Thread (Linux Kernel).

   This Group contains the LINUX Kernel Thread definitions and function. 

\ingroup IFXOS_THREAD_LINUX
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX LINUX adaptation - Includes
   ========================================================================= */
#include "ifx_types.h"
#include "ifxos_common.h"

#ifdef __KERNEL__
#include <linux/completion.h>
#else

#endif

/* ============================================================================
   IFX LINUX adaptation - supported features
   ========================================================================= */
#ifdef __KERNEL__

   /** IFX LINUX adaptation - Kernel Space, support "Thread/Task feature" */
#  ifndef IFXOS_HAVE_THREAD
#     define IFXOS_HAVE_THREAD                       1
#  endif

#else

   /** IFX LINUX adaptation - User Space, support "Thread/Task feature" */
#  ifndef IFXOS_HAVE_THREAD
#     define IFXOS_HAVE_THREAD                       1
#  endif

#endif      /* #ifdef __KERNEL__ */


#ifdef __KERNEL__

/* ============================================================================
   IFX LINUX adaptation - Kernel Threads defines
   ========================================================================= */
/** \addtogroup IFXOS_THREAD_LINUX_DRV
@{ */


/** set if a option is not used for this OS adaptation */
#define IFXOS_THREAD_OPTION_NOT_USED_FOR_LINUX     0

/** LINUX Kernel Thread - priority - IDLE */
#define IFXOS_THREAD_PRIO_IDLE                     1
/** LINUX Kernel Thread - priority - LOWEST */
#define IFXOS_THREAD_PRIO_LOWEST                   5
/** LINUX Kernel Thread - priority - LOW */
#define IFXOS_THREAD_PRIO_LOW                      20
/** LINUX Kernel Thread - priority - NORMAL */
#define IFXOS_THREAD_PRIO_NORMAL                   40
/** LINUX Kernel Thread - priority - HIGH */
#define IFXOS_THREAD_PRIO_HIGH                     60
/** LINUX Kernel Thread - priority - HIGHEST */
#define IFXOS_THREAD_PRIO_HIGHEST                  80
/** LINUX Kernel Thread - priority - TIME_CRITICAL 
\attention
   You should use this priority only for driver threads.
*/
#define IFXOS_THREAD_PRIO_TIME_CRITICAL            90

/** LINUX Kernel Thread - default prio (use OS default)  */
#define IFXOS_DEFAULT_PRIO                         IFXOS_THREAD_OPTION_NOT_USED_FOR_LINUX

/** LINUX Kernel Thread - internal poll time for check thread end */
#define IFXOS_THREAD_DOWN_WAIT_POLL_MS             10

/** LINUX Kernel Thread - thread options */
#define IFXOS_DRV_THREAD_OPTIONS                   (CLONE_FS | CLONE_FILES)
/** LINUX Kernel Thread - default stack size (use OS default)  */
#define IFXOS_DEFAULT_STACK_SIZE                   IFXOS_THREAD_OPTION_NOT_USED_FOR_LINUX

/** Linux Task - lock scheduling */
#define IFXOS_ThreadLock()
/** Linux Task - unlock scheduling */
#define IFXOS_ThreadUnlock()

/**
   LINUX Kernel Thread - map the Thread ID.
*/
typedef int    IFXOS_thread_t;

/**
   LINUX Kernel Process - map the Process ID.
*/
typedef int    IFXOS_process_t;

/**
   LINUX Kernel Thread - function type LINUX Kernel Thread Start Routine.
*/
typedef int (*IFXOS_KERNEL_THREAD_StartRoutine)(void *);

/**
   LINUX Kernel Thread - Control struct for thread handling.
*/
typedef struct
{
   /** Contains the user and thread control parameters */
   IFXOS_ThreadParams_t    thrParams;

   /** Points to the thread start routine */
   IFXOS_ThreadFunction_t  pThrFct;

   /** Kernel thread process ID */
   IFX_int32_t             tid;

   /** requested kernel thread priority */
   IFX_int32_t             nPriority;
   
   /** LINUX specific internal data - completion handling */
   struct completion       thrCompletion;

   /** flag indicates that the structure is initialized */
   IFX_boolean_t           bValid;

} IFXOS_ThreadCtrl_t;

/** @} */

#else       /* #ifdef __KERNEL__ ... #else ... */

/* ============================================================================
   IFX LINUX adaptation - User Threads
   ========================================================================= */
/** \addtogroup IFXOS_THREAD_LINUX_APPL
@{ */

/** set if a option is not used for this OS adaptation */
#define IFXOS_THREAD_OPTION_NOT_USED_FOR_LINUX     0

#if 0
/** LINUX Kernel Thread - priority - IDLE */
#define IFXOS_THREAD_PRIO_IDLE                     1
/** LINUX User Thread - priority - LOWEST */
#define IFXOS_THREAD_PRIO_LOWEST                   5
/** LINUX User Thread - priority - LOW */
#define IFXOS_THREAD_PRIO_LOW                      20
/** LINUX User Thread - priority - NORMAL */
#define IFXOS_THREAD_PRIO_NORMAL                   40
/** LINUX User Thread - priority - HIGH */
#define IFXOS_THREAD_PRIO_HIGH                     60
/** LINUX User Thread - priority - HIGHEST */
#define IFXOS_THREAD_PRIO_HIGHEST                  80
#endif

/** LINUX User Thread - internal poll time for check thread end */
#define IFXOS_THREAD_DOWN_WAIT_POLL_MS             10
/** LINUX Kernel Thread - default stack size (use OS default)  */
#define IFXOS_DEFAULT_STACK_SIZE                   IFXOS_THREAD_OPTION_NOT_USED_FOR_LINUX

/** Linux Task - lock scheduling */
#define IFXOS_ThreadLock()
/** Linux Task - unlock scheduling */
#define IFXOS_ThreadUnlock()

/**
   LINUX User Thread - map the Thread ID.
*/
typedef int    IFXOS_thread_t;

/**
   LINUX Kernel Process - map the Process ID.
*/
typedef int    IFXOS_process_t;

/**
   LINUX User Thread - function type LINUX User Thread Start Routine.
*/
typedef void *(*IFXOS_USER_THREAD_StartRoutine)(void*);

/**
   LINUX User Thread - Control struct for thread handling.
*/
typedef struct
{
   /* Contains the user and thread control parameters */
   IFXOS_ThreadParams_t    thrParams;

   /* Points to the thread start routine */
   IFXOS_ThreadFunction_t  pThrFct;

   /** LINUX User specific for internal - keep the task thread ID */
   IFXOS_thread_t          tid;

   /** requested kernel thread priority */
   IFX_int32_t             nPriority;
   
   /** flag indicates that the structure is initialized */
   IFX_boolean_t           bValid;

} IFXOS_ThreadCtrl_t;

/** @} */

#endif      /* #ifdef __KERNEL__ ... #else ... #endif */

#ifdef __cplusplus
   }
#endif
#endif      /* #ifdef LINUX */
#endif      /* #ifndef _IFXOS_LINUX_THREAD_H */



