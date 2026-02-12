#ifndef _IFXOS_WIN32_THREAD_H
#define _IFXOS_WIN32_THREAD_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef WIN32

/** \file
   This file contains Win32 definitions for Thread handling.
*/

/** \defgroup IFXOS_THREAD_WIN32 Thread  (Win32).

   This Group contains the Win32 Task definitions and function. 

\ingroup IFXOS_LAYER_WIN32
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX Win32 adaptation - Includes
   ========================================================================= */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "ifx_types.h"

/* ============================================================================
   IFX Win32 adaptation - supported features
   ========================================================================= */

/** IFX Win32 adaptation - support "Thread feature" */
#ifndef IFXOS_HAVE_THREAD
#  define IFXOS_HAVE_THREAD                          1
#endif

/* ============================================================================
   IFX Win32 adaptation - Thread defines
   ========================================================================= */
/** \addtogroup IFXOS_THREAD_WIN32
@{ */

/** set if a option is not used for this OS adaptation */
#define IFXOS_THREAD_OPTION_NOT_USED_FOR_WIN32     0

/** Win32 Thread - priority - LOWEST */
#define IFXOS_THREAD_PRIO_LOWEST                   THREAD_PRIORITY_LOWEST
/** Win32 Thread - priority - LOW */
#define IFXOS_THREAD_PRIO_LOW                      THREAD_PRIORITY_BELOW_NORMAL
/** Win32 Thread - priority - NORMAL */
#define IFXOS_THREAD_PRIO_NORMAL                   THREAD_PRIORITY_NORMAL
/** Win32 Thread - priority - HIGH */
#define IFXOS_THREAD_PRIO_HIGH                     THREAD_PRIORITY_ABOVE_NORMAL
/** Win32 Thread - priority - HIGHEST */
#define IFXOS_THREAD_PRIO_HIGHEST                  THREAD_PRIORITY_HIGHEST
/** Win32 Thread - priority - TIME_CRITICAL 
\attention
   You should use this priority only for driver threads.
*/
#define IFXOS_THREAD_PRIO_TIME_CRITICAL            THREAD_PRIORITY_TIME_CRITICAL

/** Win32 Thread - internal poll time for check thread end */
#define IFXOS_THREAD_DOWN_WAIT_POLL_MS             10

/** Win32 Thread - thread options */
#define IFXOS_DRV_THREAD_OPTIONS                   IFXOS_THREAD_OPTION_NOT_USED_FOR_WIN32
/** Win32 Thread - default prio */
#define IFXOS_DEFAULT_PRIO                         IFXOS_THREAD_OPTION_NOT_USED_FOR_WIN32
/** Win32 Thread - default stack size */
#define IFXOS_DEFAULT_STACK_SIZE                   IFXOS_THREAD_OPTION_NOT_USED_FOR_WIN32

/** Win32 Task - lock scheduling */
#define IFXOS_ThreadLock()
/** Win32 Task - unlock scheduling */
#define IFXOS_ThreadUnlock()

/* ============================================================================
   IFX Win32 adaptation - Thread types
   ========================================================================= */

/**
   Win32 Thread - map the Thread ID.
*/
typedef HANDLE    IFXOS_thread_t;

/**
   Win32 Process - map the Process ID.
*/
typedef DWORD     IFXOS_process_t;


/**
   Win32 Thread - Control struct for task handling.
*/
typedef struct
{
   /** Contains the user and Thread control parameters */
   IFXOS_ThreadParams_t    thrParams;

   /** Points to the user Thread start routine */
   IFXOS_ThreadFunction_t  pThrFct;

   /** Win32 specific for internal - keep the Thread Win32 ID */
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
#endif      /* #ifdef WIN32 */
#endif      /* #ifndef _IFXOS_WIN32_THREAD_H */

