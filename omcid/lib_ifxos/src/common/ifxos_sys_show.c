/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains additional debug and trace features.
*/

/* ============================================================================
   inlcudes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_common.h"
#include "ifxos_print.h"

#include "ifxos_sys_show_interface.h"
#include "ifxos_sys_show.h"

#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)

/* ============================================================================
   Defines
   ========================================================================= */

#ifdef IFXOS_STATIC
#undef IFXOS_STATIC
#endif

#ifdef IFXOS_DEBUG
#define IFXOS_STATIC
#else
#define IFXOS_STATIC   static
#endif

#define IFXOS_SYS_PREFIX         "IFXOS_SYS >>"
#define IFXOS_SYS_OBJ_DEBUG      1


/* = Start ====================================================================
   IFXOS Sys Objects - OS independant definitons
   ========================================================================= */

/* ============================================================================
   IFXOS Sys Objects - internal types
   ========================================================================= */

/**
   The IFXOS SYS Objects requires IFXOS independant definitions for 
   synchronisation
*/
#ifdef LINUX
#  ifdef __KERNEL__
      typedef struct semaphore IFXOS_SYS_LOCK_t;
#  else
#  if !defined(USE_PHTREAD_SEM)
#     define USE_PHTREAD_SEM 1
#  endif

#  if (USE_PHTREAD_SEM == 1)
#     define _GNU_SOURCE     1
#     include <features.h>

#     include <string.h>
#     include <semaphore.h>

      typedef sem_t IFXOS_SYS_LOCK_t;

#  else
#     include <errno.h>
#     include <string.h>
#     include <sys/types.h>
#     include <sys/ipc.h>
#     include <sys/sem.h>
#     include <unistd.h>
#     include <signal.h>

      typedef int IFXOS_SYS_LOCK_t;
#  endif
#  endif

#elif defined(VXWORKS)
#  include <string.h>

/* add VXWORKS implementation */
typedef SEM_ID       IFXOS_SYS_LOCK_t;

#elif defined(ECOS)
#  include <cyg/kernel/kapi.h>
#  include <string.h>

/* add ECOS implementation */
typedef cyg_sem_t    IFXOS_SYS_LOCK_t;

#elif defined(NUCLEUS_PLUS)
#  include <string.h>

/* add NUCLEUS_PLUS implementation */
typedef int IFXOS_SYS_LOCK_t;

#elif defined(WIN32)
#  include <string.h>

/* add WIN32 implementation */
typedef CRITICAL_SECTION IFXOS_SYS_LOCK_t;

#elif defined(GENERIC_OS)

/* add GENERIC_OS implementation */
typedef int IFXOS_SYS_LOCK_t;

#else
#  error "System Objects - Please define your OS"
#endif

/* ============================================================================
   IFXOS Sys Objects - internal functions declarations
   ========================================================================= */
IFXOS_STATIC IFX_int_t IFXOS_SysObject_LockInit(
                              IFXOS_SYS_LOCK_t *pLockId);

IFXOS_STATIC IFX_int_t IFXOS_SysObject_LockDelete(
                              IFXOS_SYS_LOCK_t *pLockId);

IFXOS_STATIC IFX_int_t IFXOS_SysObject_LockGet(
                              IFXOS_SYS_LOCK_t *pLockId);

IFXOS_STATIC IFX_int_t IFXOS_SysObject_LockRelease(
                              IFXOS_SYS_LOCK_t *pLockId);

/* ============================================================================
   IFXOS Sys Objects - internal variables
   ========================================================================= */

/** IFXOS SYS Object global sync object */
IFXOS_STATIC IFXOS_SYS_LOCK_t IFXOS_SYS_Lock;

/* ============================================================================
   IFXOS Sys Objects - internal functions definitions
   ========================================================================= */

/**
   Init the IFXOS SYS Object Lock
*/
IFXOS_STATIC IFX_int_t IFXOS_SysObject_LockInit(
                              IFXOS_SYS_LOCK_t *pLockId)
{
#if defined(LINUX)
#  ifdef __KERNEL__

   sema_init(pLockId, 1);

   return IFX_SUCCESS;

#  else     /* __KERNEL__ */
#  if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)

   if(sem_init(pLockId, 0, 1) == 0)
   {
      return IFX_SUCCESS;
   }
   return IFX_ERROR;

#  else     /* USE_PHTREAD_SEM */

   IFX_int32_t    nsemkey = IPC_PRIVATE;
   union semun    arg;

   if ((*pLockId = semget(nsemkey, 1, 0666|IPC_CREAT|IPC_EXCL)) < 0)
   {
      return IFX_ERROR;
   }

   /* set the value of semaphore to 1 ie released or free to use */
   arg.val = 1;
   if (semctl(*pLockId, 0, SETVAL, arg) < 0 )
   {
      return IFX_ERROR;
   }

   return IFX_SUCCESS;

#  endif    /* USE_PHTREAD_SEM */
#  endif    /* __KERNEL__ */

#elif defined(VXWORKS)
   /* add VXWORKS implementation */
   *pLockId = semBCreate(SEM_Q_PRIORITY, SEM_FULL);

   return IFX_SUCCESS;

#elif defined(ECOS)
   /* add ECOS implementation */
   cyg_semaphore_init(pLockId, 1);

   return IFX_SUCCESS;

#elif defined(NUCLEUS_PLUS)
   /* add NUCLEUS_PLUS implementation */
   return IFX_SUCCESS;

#elif defined(WIN32)
   /* add WIN32 implementation */

   InitializeCriticalSection(pLockId);

   return IFX_SUCCESS;

#elif defined(GENERIC_OS)
   /* add GENERIC_OS implementation */
   return IFX_SUCCESS;

#else
#  error "System Objects - Please define your OS"
#endif
}


/**
   Delete the IFXOS SYS Object Lock
*/
IFXOS_STATIC IFX_int_t IFXOS_SysObject_LockDelete(
                              IFXOS_SYS_LOCK_t *pLockId)
{
#ifdef LINUX
#  ifdef __KERNEL__
      return IFX_SUCCESS;
#  else     /* __KERNEL__ */
#  if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)
   if (sem_destroy(pLockId) == 0)
   {
      return IFX_SUCCESS;
   }
   return IFX_ERROR;

#  else     /* USE_PHTREAD_SEM */

   int dummy=0;

   if (semctl(*pLockId, 0, IPC_RMID, &dummy) != -1)
   {
      return IFX_SUCCESS;
   }

   return IFX_ERROR;

#  endif    /* USE_PHTREAD_SEM */
#  endif    /* __KERNEL__ */

#elif defined(VXWORKS)
   /* add VXWORKS implementation */
   semDelete(*pLockId);

   return IFX_SUCCESS;

#elif defined(ECOS)
   /* add ECOS implementation */
   cyg_semaphore_destroy(pLockId);

   return IFX_SUCCESS;

#elif defined(NUCLEUS_PLUS)
   /* add NUCLEUS_PLUS implementation */
   return IFX_SUCCESS;

#elif defined(WIN32)
   /* add WIN32 implementation */
   DeleteCriticalSection(pLockId);

   return IFX_SUCCESS;

#elif defined(GENERIC_OS)
   /* add GENERIC_OS implementation */
   return IFX_SUCCESS;

#else
#  error "System Objects - Please define your OS"
#endif
}


/**
   Get the IFXOS SYS Object Lock
*/
IFXOS_STATIC IFX_int_t IFXOS_SysObject_LockGet(
                              IFXOS_SYS_LOCK_t *pLockId)
{
#ifdef LINUX
#  ifdef __KERNEL__

   down(pLockId);

   return IFX_SUCCESS;

#  else     /* __KERNEL__ */
#  if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)
   if (sem_wait(pLockId) == 0)
   {
      return IFX_SUCCESS;
   }
   return IFX_ERROR;

#  else     /* USE_PHTREAD_SEM */

   struct sembuf     sb;

   /*
      !!! Always a Blocking Call !!!
   */
   
   sb.sem_num = 0;
   /* specifies the operation ie to get the semaphore */
   sb.sem_op = -1;
   /* DO NOT USE FLAG 'SEM_UNDO' HERE! */
   sb.sem_flg = 0;

   if (semop(*pLockId, &sb, 1) == 0)
   {
      return IFX_SUCCESS;
   }

   return IFX_SUCCESS;

#  endif    /* USE_PHTREAD_SEM */
#  endif    /* __KERNEL__ */

#elif defined(VXWORKS)
   /* add VXWORKS implementation */
   if (semTake(*pLockId, WAIT_FOREVER) == OK)
   {
      return IFX_SUCCESS;
   }

   return IFX_ERROR;

#elif defined(ECOS)
   /* add ECOS implementation */
   if (cyg_semaphore_wait(pLockId))
   {
      return IFX_SUCCESS;
   }

   return IFX_ERROR;

#elif defined(NUCLEUS_PLUS)
   /* add NUCLEUS_PLUS implementation */
   return IFX_SUCCESS;

#elif defined(WIN32)
   /* add WIN32 implementation */
   EnterCriticalSection(pLockId); 

   return IFX_SUCCESS;

#elif defined(GENERIC_OS)
   /* add GENERIC_OS implementation */
   return IFX_SUCCESS;

#else
#  error "System Objects - Please define your OS"
#endif
}

/**
   Release the IFXOS SYS Object Lock
*/
IFXOS_STATIC IFX_int_t IFXOS_SysObject_LockRelease(
                              IFXOS_SYS_LOCK_t *pLockId)
{
#ifdef LINUX
#  ifdef __KERNEL__

      up(pLockId);

      return IFX_SUCCESS;

#  else     /* __KERNEL__ */
#  if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)

   if (sem_post(pLockId) == 0)
   {
      return IFX_SUCCESS;
   }
   return IFX_ERROR;

#  else     /* USE_PHTREAD_SEM */

   struct sembuf sb;

   sb.sem_num = 0;
   /* specifies the operation ie to set the semaphore */
   sb.sem_op = 1;
   /* DO NOT USE FLAG 'SEM_UNDO' HERE! */
   sb.sem_flg = 0;

   if (semop(*pLockId, &sb, 1) == 0)
   {
      return IFX_SUCCESS;
   }

   return IFX_ERROR;

#  endif    /* USE_PHTREAD_SEM */
#  endif    /* __KERNEL__ */

#elif defined(VXWORKS)
   /* add VXWORKS implementation */
   if (semGive(*pLockId) == OK)
   {
      return IFX_SUCCESS;
   }

   return IFX_ERROR;

#elif defined(ECOS)
   /* add ECOS implementation */
   cyg_semaphore_post(pLockId);

   return IFX_SUCCESS;

#elif defined(NUCLEUS_PLUS)
   /* add NUCLEUS_PLUS implementation */
   return IFX_SUCCESS;

#elif defined(WIN32)
   /* add WIN32 implementation */

   LeaveCriticalSection(pLockId);

   return IFX_SUCCESS;

#elif defined(GENERIC_OS)
   /* add GENERIC_OS implementation */
   return IFX_SUCCESS;

#else
#  error "System Objects - Please define your OS"
#endif
}

/* = END ======================================================================
   IFXOS Sys Objects - OS independant definitons
   ========================================================================= */

/* ============================================================================
   Types
   ========================================================================= */


/* ============================================================================
   Variables
   ========================================================================= */

/**
   Debug Object Buffer:
   - the first object struct will be assigned to the debug object feature itself
     (currently not used)
   - the second object struct will be assigned to the memory handling.

*/

/** global debug object control */
IFXOS_sys_object_cntrl_t IFXOS_sysObjectControl = {IFX_FALSE};

/** global debug object buffer */
IFXOS_sys_object_t IFXOS_sysObjectBuffer[IFXOS_SYS_MAX_OBJECT] = {{0}};

/** points to the first SYS Obj - used for own purposals */
IFXOS_sys_object_t *pIFXOS_sysObjectThis   = IFX_NULL;
/** points to the second SYS Obj - used for memory purposals */
IFXOS_sys_object_t *pIFXOS_sysObjectMemory = IFX_NULL;

/** dummy system object */
IFXOS_sys_object_t IFXOS_dummySysObjectBuffer = {0};

/* ============================================================================
   Local Functions - Declarations
   ========================================================================= */
IFXOS_STATIC IFX_int_t IFXOS_SysObject_SetCreatorThrInfo(
                  IFXOS_sys_object_t *pSysObject);

#if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) )
IFXOS_STATIC IFX_void_t IFXOS_SysObjectShow_MemAlloc(
                  IFX_uint_t                 objIndex, 
                  IFXOS_sys_object_mem_t     *pSysObjMemory);
#endif

#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) )
IFXOS_STATIC IFX_void_t IFXOS_SysObjectShow_Lock(
                  IFX_uint_t                 objIndex, 
                  IFXOS_sys_object_lock_t    *pSysObjLock);
#endif

#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) )
IFXOS_STATIC IFX_void_t IFXOS_SysObjectShow_Mutex(
                  IFX_uint_t                 objIndex, 
                  IFXOS_sys_object_mutex_t   *pSysObjMutex);
#endif

#if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) )
IFXOS_STATIC IFX_void_t IFXOS_SysObjectShow_Event(
                  IFX_uint_t                 objIndex, 
                  IFXOS_sys_object_event_t   *pSysObjEvent);
#endif

#if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) )
IFXOS_STATIC IFX_void_t IFXOS_SysObjectShow_Thread(
                  IFX_uint_t                 objIndex, 
                  IFXOS_sys_object_thread_t  *pSysObjThread);
#endif

IFXOS_STATIC IFX_void_t IFXOS_SysObjectShow_Fifo(
                  IFX_uint_t                 objIndex, 
                  IFXOS_sys_object_fifo_t    *pSysObjFifo);


/* ============================================================================
   Local Functions - Definitions
   ========================================================================= */

IFXOS_STATIC IFX_int_t IFXOS_SysObject_SetCreatorThrInfo(
                  IFXOS_sys_object_t *pSysObject)
{
   if (pSysObject != IFX_NULL)
   {
      pSysObject->reqCount++;

#if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) )
      pSysObject->creatorThr.pId   = (IFX_int_t)IFXOS_ProcessIdGet();
      pSysObject->creatorThr.thrId = (IFX_int_t)IFXOS_ThreadIdGet();
#else
      pSysObject->creatorThr.pId   = -1;
      pSysObject->creatorThr.thrId = -1;
#endif

      return IFX_SUCCESS;
   }

   return IFX_ERROR;
}

#if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) )
IFXOS_STATIC IFX_void_t IFXOS_SysObjectShow_MemAlloc(
                  IFX_uint_t              objIndex, 
                  IFXOS_sys_object_mem_t  *pSysObjMemory)
{
   if (pSysObjMemory != IFX_NULL)
   {
      IFXOS_DBG_PRINT_USR( 
            "SysObj[%03d] Mem - calls: %d / %d (alloc / free)" IFXOS_CRLF, 
            objIndex, pSysObjMemory->numOfMemAlloc, pSysObjMemory->numOfMemFree);

   }
   return;
}
#endif

#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) )
IFXOS_STATIC IFX_void_t IFXOS_SysObjectShow_Lock(
                  IFX_uint_t              objIndex, 
                  IFXOS_sys_object_lock_t *pSysObjLock)
{
   if (pSysObjLock != IFX_NULL)
   {
      IFXOS_DBG_PRINT_USR( 
            "SysObj[%03d] LOCK - calls: init %d,  get %d, release %d" IFXOS_CRLF, 
            objIndex, pSysObjLock->numOfInit, pSysObjLock->numOfGet, pSysObjLock->numOfRelease);

      IFXOS_DBG_PRINT_USR( 
            "SysObj[%03d] LOCK - timeouts %d,  get failed %d, recursive calles %d" IFXOS_CRLF, 
            objIndex, pSysObjLock->numOfGetTimeout, 
            pSysObjLock->numOfGetFails, pSysObjLock->numOfRecursiveCalls);

      IFXOS_DBG_PRINT_USR( 
            "SysObj[%03d] LOCK - last wait thread %d" IFXOS_CRLF, 
            objIndex, pSysObjLock->reqThreadId);
#if ( defined(HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT) && (HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT == 1))
      IFXOS_DBG_PRINT_USR( 
            "SysObj[%03d] LOCK - ext Trace \"%s\"" IFXOS_CRLF, 
            objIndex, (strlen(pSysObjLock->extTraceInfo) > 0) ? pSysObjLock->extTraceInfo : "none" );

#endif
   }

   return;
}
#endif

#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) )
IFXOS_STATIC IFX_void_t IFXOS_SysObjectShow_Mutex(
                  IFX_uint_t                 objIndex, 
                  IFXOS_sys_object_mutex_t   *pSysObjMutex)
{
   if (pSysObjMutex != IFX_NULL)
   {
      IFXOS_DBG_PRINT_USR( 
            "SysObj[%03d] MUTEX - calls: init %d,  get %d, release %d" IFXOS_CRLF, 
            objIndex, pSysObjMutex->numOfInit, pSysObjMutex->numOfGet, pSysObjMutex->numOfRelease);

      IFXOS_DBG_PRINT_USR( IFXOS_SYS_PREFIX
            "SysObj[%03d] MUTEX - get failed %d" IFXOS_CRLF, 
            objIndex, pSysObjMutex->numOfGetFails);
   }

   return;
}
#endif

#if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) )
IFXOS_STATIC IFX_void_t IFXOS_SysObjectShow_Event(
                  IFX_uint_t                 objIndex, 
                  IFXOS_sys_object_event_t   *pSysObjEvent)
{
   if (pSysObjEvent != IFX_NULL)
   {
      IFXOS_DBG_PRINT_USR( 
            "SysObj[%03d] EVENT - calls: init %d" IFXOS_CRLF, 
            objIndex, pSysObjEvent->numOfInit);
   }

   return;
}
#endif


#if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) )
IFXOS_STATIC IFX_void_t IFXOS_SysObjectShow_Thread(
                  IFX_uint_t                 objIndex, 
                  IFXOS_sys_object_thread_t  *pSysObjThread)
{
   if (pSysObjThread != IFX_NULL)
   {
      IFXOS_DBG_PRINT_USR( 
            "SysObj[%03d] THREAD - calls: init %d" IFXOS_CRLF, 
            objIndex, pSysObjThread->numOfInit);

      if (pSysObjThread->pThis && pSysObjThread->pThis->bValid)
      {
         IFXOS_DBG_PRINT_USR( 
               "SysObj[%03d] THREAD <%s> tid = %d, prio = %d, bRun =%d" IFXOS_CRLF, 
               objIndex, pSysObjThread->pThis->thrParams.pName,
               pSysObjThread->pThis->tid,
               pSysObjThread->pThis->nPriority,
               pSysObjThread->pThis->thrParams.bRunning);

#if ( defined(HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT) && (HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT == 1))
               IFXOS_DBG_PRINT_USR( 
                     "SysObj[%03d] THREAD - run Count = %d, Info \"%s\"" IFXOS_CRLF, 
                     objIndex, pSysObjThread->runCount,
                     (strlen(pSysObjThread->extTraceInfo) > 0) ? pSysObjThread->extTraceInfo : "none" );
#endif

      }
      else
      {
         IFXOS_DBG_PRINT_USR( 
               "SysObj[%03d] THREAD <invalid> - thread object not valid" IFXOS_CRLF, 
               objIndex);
      }
   }

   return;
}
#endif

IFXOS_STATIC IFX_void_t IFXOS_SysObjectShow_Fifo(
                  IFX_uint_t              objIndex, 
                  IFXOS_sys_object_fifo_t *pSysObjFifo)
{
   if (pSysObjFifo != IFX_NULL)
   {
      IFXOS_DBG_PRINT_USR( 
            "SysObj[%03d] FIFO - FIFO: pStart 0x%08X (0x%08X), pStart 0x%08X (0x%08X) --> Size 0x%X (%d)" IFXOS_CRLF, 
            objIndex, 
            pSysObjFifo->pThis->pStart, pSysObjFifo->pStart,
            pSysObjFifo->pThis->pEnd,   pSysObjFifo->pEnd,
            (pSysObjFifo->pEnd - pSysObjFifo->pStart),
            (pSysObjFifo->pEnd - pSysObjFifo->pStart) );

      IFXOS_DBG_PRINT_USR( 
            "SysObj[%03d] FIFO - FIFO: pRd 0x%08X, pWr 0x%08X, Count %d, Max ElSize %d" IFXOS_CRLF, 
            objIndex, 
            pSysObjFifo->pThis->pRead, pSysObjFifo->pThis->pWrite, 
            pSysObjFifo->pThis->count, pSysObjFifo->pThis->size );

      IFXOS_DBG_PRINT_USR( 
            "SysObj[%03d] FIFO - Elements: reqWr %d, written %d, read %d" IFXOS_CRLF, 
            objIndex, 
            pSysObjFifo->rqNumOfElem, pSysObjFifo->wrNumOfElem, pSysObjFifo->rdNumOfElem );

   }

   return;
}


/* ============================================================================
   SYS Objects Functions - Definitions
   ========================================================================= */

/**
   Search for the next free debug object and return it.

\param
   maxNumOfObjects   max. number of expected objects
                     (fixed size currently used)
*/
IFXOS_sys_object_t* IFXOS_SysObject_Get(
                              IFX_int_t objectType)
{
   IFX_uint_t   idx;
   IFXOS_sys_object_t *pSysObj = IFX_NULL;

   if (IFXOS_sysObjectControl.initDone != IFX_TRUE)
   {
      return pSysObj;
   }

   if (IFXOS_SysObject_LockGet(&IFXOS_SYS_Lock) == IFX_SUCCESS)
   {

      for (idx = 2; idx < IFXOS_sysObjectControl.numOfObject; idx++)
      {
         if (IFXOS_sysObjectControl.pObjectBuffer[idx].objType == 0)
         {
            /* mark object for use */
            IFXOS_sysObjectControl.pObjectBuffer[idx].objType  = objectType;
            break;
         }
      }
      IFXOS_sysObjectControl.objCount++;

      IFXOS_SysObject_LockRelease(&IFXOS_SYS_Lock);
   }
   else
   {
      IFXOS_DBG_PRINT_USR( IFXOS_SYS_PREFIX
            "ERROR Get: cannot get internal lock" IFXOS_CRLF);

      return pSysObj;
   }

   if (idx < IFXOS_sysObjectControl.numOfObject)
   {
      pSysObj = &IFXOS_sysObjectControl.pObjectBuffer[idx];
      memset(&pSysObj->uSysObject, 0x00, sizeof(IFXOS_sys_object_u));
      pSysObj->objIndex = idx;
   }
   else
   {
      IFXOS_DBG_PRINT_USR( IFXOS_SYS_PREFIX
            "ERROR Get: Object[%03d] to less objects (max %d), use dummy obj!!" IFXOS_CRLF,
            IFXOS_sysObjectControl.objCount, IFXOS_sysObjectControl.numOfObject);

      pSysObj = &IFXOS_dummySysObjectBuffer;
   }

   IFXOS_SysObject_SetCreatorThrInfo(pSysObj);

   return pSysObj;
}


/**
   Release the debug object.

\param
   maxNumOfObjects   max. number of expected objects
                     (fixed size currently used)
*/
IFX_void_t IFXOS_SysObject_Release(
                              IFXOS_sys_object_t *pSysObject)
{
   if (IFXOS_sysObjectControl.initDone != IFX_TRUE)
   {
      return;
   }

   if (pSysObject == IFX_NULL)
   {
      IFXOS_DBG_PRINT_USR( IFXOS_SYS_PREFIX
            "ERROR Release: called with NULL ptr !!" IFXOS_CRLF);

      return;
   }

   if (pSysObject->objType != 0)
   {
      pSysObject->reqCount--;      
   }

   if (pSysObject->reqCount > 0)
   {
      IFXOS_DBG_PRINT_USR( IFXOS_SYS_PREFIX
            "ERROR Release: Object[%d] multiple use (count = %d, type = 0x=%08X)!!" IFXOS_CRLF, 
            pSysObject->objIndex, pSysObject->reqCount, pSysObject->objType);

      return;
   }

   if (IFXOS_SysObject_LockGet(&IFXOS_SYS_Lock) == IFX_SUCCESS)
   {
      pSysObject->objType      = 0;
      pSysObject->userDescr[0] = '\0';
      IFXOS_sysObjectControl.objCount--;

      IFXOS_SysObject_LockRelease(&IFXOS_SYS_Lock);
   }
   else
   {
      IFXOS_DBG_PRINT_USR( IFXOS_SYS_PREFIX
            "ERROR Release: cannot get internal lock" IFXOS_CRLF);

      return;
   }

   return;
}


IFX_void_t IFXOS_SysObject_SetOwnerThrInfo(
                  IFXOS_sys_object_t *pSysObject)
{
   if (pSysObject != IFX_NULL)
   {
#if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) )
      pSysObject->ownerThr.pId     = (IFX_int_t)IFXOS_ProcessIdGet();
      pSysObject->ownerThr.thrId   = (IFX_int_t)IFXOS_ThreadIdGet();
#else
      pSysObject->ownerThr.pId   = -1;
      pSysObject->ownerThr.thrId = -1;
#endif
      return;
   }

   return;
}


IFX_void_t IFXOS_SysObject_ClearOwnerThrInfo(
                  IFXOS_sys_object_t *pSysObject)
{
   if (pSysObject != IFX_NULL)
   {
      pSysObject->ownerThr.pId   = -1;
      pSysObject->ownerThr.thrId = -1;

      return;
   }

   return;
}


#endif      /* #if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1) */

/* ============================================================================
   SYS Objects Interface Functions - Definitions
   ========================================================================= */

/**
   Setup and init the IFXOS Debug Object feature.

\param
   maxNumOfObjects   max. number of expected objects
                     (fixed size currently used)
*/
IFX_void_t IFXOS_SysObject_Setup(
                              IFX_int_t maxNumOfObjects)
{
#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
   IFX_int_t idx, numOfObj = IFXOS_SYS_MAX_OBJECT;

   if (IFXOS_sysObjectControl.initDone == IFX_TRUE)
   {
      IFXOS_DBG_PRINT_USR( IFXOS_SYS_PREFIX
            "SysObj[---] Warning: Init IFXOS Sys Objects already done" IFXOS_CRLF, 
            numOfObj);

      return;
   }

#if (IFXOS_SYS_OBJ_DEBUG == 1)
   IFXOS_DBG_PRINT_USR( IFXOS_SYS_PREFIX
         "SysObj[---] Setup start, num of elements %d" IFXOS_CRLF, 
         numOfObj);
#endif

   if (IFXOS_SysObject_LockInit(&IFXOS_SYS_Lock) != IFX_SUCCESS)
   {

      IFXOS_DBG_PRINT_USR( IFXOS_SYS_PREFIX
            "SysObj[---] ERROR Setup: init internal lock failed" IFXOS_CRLF);

      return;
   }

   if (IFXOS_SysObject_LockGet(&IFXOS_SYS_Lock) == IFX_SUCCESS)
   {

      memset(&IFXOS_sysObjectControl, 0x00, sizeof(IFXOS_sysObjectControl));
      IFXOS_sysObjectControl.numOfObject   = numOfObj;
      IFXOS_sysObjectControl.pObjectBuffer = IFXOS_sysObjectBuffer;

      memset(IFXOS_sysObjectBuffer,  0x00, sizeof(IFXOS_sysObjectBuffer));
      for (idx = 0; idx < numOfObj; idx++)
      {
         IFXOS_sysObjectBuffer[idx].objIndex = idx;
      }


      /* init "own" */
      pIFXOS_sysObjectThis           = &IFXOS_sysObjectBuffer[IFXOS_SYS_OBJECT_IDX_THIS];
      pIFXOS_sysObjectThis->objType  = IFXOS_SYS_OBJECT_OWN;
      IFXOS_SysObject_SetCreatorThrInfo(pIFXOS_sysObjectThis);
      IFXOS_SysObject_SetOwnerThrInfo(pIFXOS_sysObjectThis);
      IFXOS_sysObjectControl.objCount = 1;

      /* init "memory" */
      pIFXOS_sysObjectMemory           = &IFXOS_sysObjectBuffer[IFXOS_SYS_OBJECT_IDX_MEMORY];
      pIFXOS_sysObjectMemory->objType  = IFXOS_SYS_OBJECT_MEM_ALLOC;
      IFXOS_SysObject_SetCreatorThrInfo(pIFXOS_sysObjectMemory);
      IFXOS_SysObject_SetOwnerThrInfo(pIFXOS_sysObjectMemory);
      IFXOS_sysObjectControl.objCount++;

      IFXOS_sysObjectControl.initDone = IFX_TRUE;

      IFXOS_SysObject_LockRelease(&IFXOS_SYS_Lock);

#if (IFXOS_SYS_OBJ_DEBUG == 1)
      IFXOS_DBG_PRINT_USR( IFXOS_SYS_PREFIX
            "SysObj[---] Setup done, num of elements %d" IFXOS_CRLF, 
            IFXOS_sysObjectControl.numOfObject);
#endif
   }
   else
   {
      IFXOS_DBG_PRINT_USR( IFXOS_SYS_PREFIX
            "SysObj[---] ERROR Setup: cannot get internal lock" IFXOS_CRLF);
   }
#else
      IFXOS_DBG_PRINT_USR(
            "WARNING Setup: IFXOS SYS Objects not enabled" IFXOS_CRLF);
#endif      /* #if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1) */
   return;
}

/**
   Setup and init the IFXOS Debug Object feature.

\param
   maxNumOfObjects   max. number of expected objects
                     (fixed size currently used)
*/
IFX_void_t IFXOS_SysObject_Cleanup(void)
{
#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
   if (IFXOS_sysObjectControl.initDone == IFX_TRUE)
   {
      IFXOS_sysObjectControl.initDone = IFX_FALSE;

      IFXOS_SysObject_LockDelete(&IFXOS_SYS_Lock);
   }
#else
      IFXOS_DBG_PRINT_USR(
            "WARNING Cleanup: IFXOS SYS Objects not enabled" IFXOS_CRLF);
#endif

   return;
}

/**
   Setup a user description.

\param
   pSysObject  - points to the system object
\param
   pDesrc      - points to the user description.
\param
   descrIdx    - user index of the object

*/
IFX_void_t IFXOS_SysObject_UserDesrcSet(
                              IFXOS_sys_object_t   *pSysObject,
                              const IFX_char_t     *pDescr,
                              const IFX_int_t      descrIdx)
{
#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
   IFX_char_t  buf[IFXOS_SYS_OBJECT_USER_DESC_LEN];

   if (pSysObject)
   {
      if (pDescr)
      {
         if (descrIdx != -1)
         {
            strncpy(buf, pDescr, IFXOS_SYS_OBJECT_USER_DESC_LEN - 5);
            buf[IFXOS_SYS_OBJECT_USER_DESC_LEN - 5] = '\0';
            sprintf(pSysObject->userDescr, "%s %d", buf, descrIdx );
         }
         else
         {
            strncpy(buf, pDescr, IFXOS_SYS_OBJECT_USER_DESC_LEN - 1);
            buf[IFXOS_SYS_OBJECT_USER_DESC_LEN - 1] = '\0';
            sprintf(pSysObject->userDescr, "%s", buf);
         }
      }

      pSysObject->userDescr[IFXOS_SYS_OBJECT_USER_DESC_LEN - 1] = '\0';
   }
#else
      IFXOS_DBG_PRINT_USR(
            "WARNING UserDesrcSet: IFXOS SYS Objects not enabled" IFXOS_CRLF);
#endif

   return;
}

/**
   Show a single IFXOS System Object.
*/
IFX_void_t IFXOS_SysObject_ShowObject(
                              IFXOS_sys_object_t *pSysObject)
{
#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
   if (pSysObject)
   {
      IFXOS_DBG_PRINT_USR("--------" IFXOS_CRLF
            "SysObj[%03d] - user: %d, type: 0x%08X, Desrc: %s" IFXOS_CRLF, 
            pSysObject->objIndex, pSysObject->reqCount, pSysObject->objType,
            (strlen(pSysObject->userDescr) > 0) ? pSysObject->userDescr : "<none>");

      if (pSysObject->objType == IFXOS_SYS_OBJECT_NOT_USED)
      {
         IFXOS_DBG_PRINT_USR(
               "SysObj[%03d] - not used" IFXOS_CRLF, 
               pSysObject->objIndex);
      }
      else
      {
         IFXOS_DBG_PRINT_USR(
               "SysObj[%03d] - creator: %d / %d current owner %d / %d (pId / thrId)" IFXOS_CRLF, 
               pSysObject->objIndex, 
               pSysObject->creatorThr.pId, pSysObject->creatorThr.thrId,
               pSysObject->ownerThr.pId,   pSysObject->ownerThr.thrId);


         switch(pSysObject->objType)
         {
            case IFXOS_SYS_OBJECT_OWN:
               break;

#if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) )
            case IFXOS_SYS_OBJECT_MEM_ALLOC:
               IFXOS_SysObjectShow_MemAlloc(
                           pSysObject->objIndex, &pSysObject->uSysObject.sysObjMemory);
               break;
#endif

#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) )
            case IFXOS_SYS_OBJECT_LOCK:
               IFXOS_SysObjectShow_Lock(
                           pSysObject->objIndex, &pSysObject->uSysObject.sysObjLock);
               break;
#endif

#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) )
            case IFXOS_SYS_OBJECT_MUTEX:
               IFXOS_SysObjectShow_Mutex(
                           pSysObject->objIndex, &pSysObject->uSysObject.sysObjMutex);
               break;
#endif

#if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) )
            case IFXOS_SYS_OBJECT_EVENT:
               IFXOS_SysObjectShow_Event(
                           pSysObject->objIndex, &pSysObject->uSysObject.sysObjEvent);
               break;
#endif

#if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) )
            case IFXOS_SYS_OBJECT_THREAD:
               IFXOS_SysObjectShow_Thread(
                           pSysObject->objIndex, &pSysObject->uSysObject.sysObjThread);
               break;
#endif

            case IFXOS_SYS_OBJECT_FIFO:
               IFXOS_SysObjectShow_Fifo(
                           pSysObject->objIndex, &pSysObject->uSysObject.sysObjFifo);
               break;

            case IFXOS_SYS_OBJECT_FILE_ACCESS:
               break;

            case IFXOS_SYS_OBJECT_SOCKET:
               break;

            case IFXOS_SYS_OBJECT_PIPE:
               break;

            default:
               break;
         }
      }

   }

#else
      IFXOS_DBG_PRINT_USR(
            "WARNING UserDesrcSet: IFXOS SYS Objects not enabled" IFXOS_CRLF);
#endif

   return;
}


/**
   Show the IFXOS internal system objects

\param
   objType  - specify the objects to show
              0, -1 selects all else
              only the objects of the given types are displayed.
*/
IFX_void_t IFXOS_SysObject_ShowAll(
                              IFX_uint_t objType)
{
#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
   IFX_uint_t idx, objCount = 0;


   IFXOS_DBG_PRINT_USR( IFXOS_SYS_PREFIX
         "SysObj[--] Cntrl - init %d,  curr count %d, available %d" IFXOS_CRLF, 
         IFXOS_sysObjectControl.initDone, 
         IFXOS_sysObjectControl.objCount, 
         IFXOS_sysObjectControl.numOfObject);


   for (idx = 0; idx < IFXOS_sysObjectControl.numOfObject; idx++)
   {
      if ( (objType == (IFX_uint_t)-1) || (objType == 0) )
      {
         if (IFXOS_sysObjectControl.pObjectBuffer[idx].objType != IFXOS_SYS_OBJECT_NOT_USED)
         {
            IFXOS_SysObject_ShowObject(&IFXOS_sysObjectControl.pObjectBuffer[idx]);
            objCount++;
         }
      }
      else
      {
         if (IFXOS_sysObjectControl.pObjectBuffer[idx].objType == objType)
         {
            IFXOS_SysObject_ShowObject(&IFXOS_sysObjectControl.pObjectBuffer[idx]);
            objCount++;
         }
      }
   }

   IFXOS_DBG_PRINT_USR( IFXOS_SYS_PREFIX
         "SysObj[--] found %d objects from type 0x%08X" IFXOS_CRLF IFXOS_CRLF, 
         objCount, objType);
#else
      IFXOS_DBG_PRINT_USR(
            "WARNING ShowAll: IFXOS SYS Objects not enabled" IFXOS_CRLF);
#endif

   return;
}


/**
   Set exteded text trace informations.

\param
   pSysObject  - points to the system object
\param
   pTraceInfo  - points to the extended trace informations.

*/
IFX_void_t IFXOS_SysObject_StringTraceInfoSet(
                              IFXOS_sys_object_t   *pSysObject,
                              const IFX_char_t     *pTraceInfo)
{
#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
#if ( defined(HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT) && (HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT == 1))

   if (pSysObject)
   {
      switch(pSysObject->objType)
      {
         case IFXOS_SYS_OBJECT_LOCK:
            strncpy( pSysObject->uSysObject.sysObjLock.extTraceInfo,
                     (pTraceInfo) ? pTraceInfo : "null",
                     IFXOS_SYS_OBJECT_EXT_TRACE_INFO_LEN);

            pSysObject->uSysObject.sysObjLock.extTraceInfo[IFXOS_SYS_OBJECT_EXT_TRACE_INFO_LEN - 1] = '\0';
            break;

         case IFXOS_SYS_OBJECT_THREAD:
            strncpy( pSysObject->uSysObject.sysObjThread.extTraceInfo,
                     (pTraceInfo) ? pTraceInfo : "null",
                     IFXOS_SYS_OBJECT_EXT_TRACE_INFO_LEN);

            pSysObject->uSysObject.sysObjThread.extTraceInfo[IFXOS_SYS_OBJECT_EXT_TRACE_INFO_LEN - 1] = '\0';
            break;

         default:
            break;
      }
   }

#endif

#else
      IFXOS_DBG_PRINT_USR(
            "WARNING ExtTraceInfoSet: IFXOS SYS Objects not enabled" IFXOS_CRLF);
#endif

   return;
}


/**
   Set exteded text trace informations.

\param
   pSysObject  - points to the system object
\param
   bIncrement  - if set increment the object specific trace info.
\param
   digitValue  - if increment not set, set the given value.

*/
IFX_void_t IFXOS_SysObject_DigitTraceInfoSet(
                              IFXOS_sys_object_t   *pSysObject,
                              IFX_boolean_t        bIncrement,
                              IFX_uint_t           digitValue)
{
#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
#if ( defined(HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT) && (HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT == 1))

   if (pSysObject)
   {
      switch(pSysObject->objType)
      {
         case IFXOS_SYS_OBJECT_THREAD:
            if (bIncrement == IFX_TRUE)
            {
               pSysObject->uSysObject.sysObjThread.runCount++;
            }
            else
            {
               pSysObject->uSysObject.sysObjThread.runCount = digitValue;
            }
            break;

         default:
            break;
      }
   }

#endif

#else
      IFXOS_DBG_PRINT_USR(
            "WARNING DigitTraceInfoSet: IFXOS SYS Objects not enabled" IFXOS_CRLF);
#endif

   return;
}

