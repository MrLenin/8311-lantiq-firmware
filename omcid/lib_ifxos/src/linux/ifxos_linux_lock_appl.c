/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation - lock handling (Application Space)
   ========================================================================= */

#ifdef LINUX

/** \file
   This file contains the IFXOS Layer implementation for LINUX Application Space 
   Lock and Protection.
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes - Application
   ========================================================================= */
#define _GNU_SOURCE     1
#include <features.h>

#if !defined(USE_PHTREAD_SEM) || (USE_PHTREAD_SEM == 0)
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <unistd.h>
#include <signal.h>
#endif

#include <time.h>

#include "ifx_types.h"
#include "ifxos_debug.h"
#include "ifxos_time.h"
#include "ifxos_lock.h"
#include "ifxos_thread.h"

#include "ifxos_sys_show.h"


#ifdef IFXOS_STATIC
#undef IFXOS_STATIC
#endif

#ifdef IFXOS_DEBUG
#define IFXOS_STATIC
#else
#define IFXOS_STATIC   static
#endif


/* ============================================================================
   IFX Linux adaptation - Kernel LOCK handling, local
   ============================================================================ */
#if !defined(USE_PHTREAD_SEM) || (USE_PHTREAD_SEM == 0)

#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) )

#if defined(__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
   /* union semun is defined by including <sys/sem.h> */
#else
   /* according to X/OPEN we have to define it ourselves */
   union semun {
       int val;                  /* value for SETVAL */
      struct semid_ds *buf;     /* buffer for IPC_STAT, IPC_SET */
      unsigned short *array;    /* array for GETALL, SETALL */
                           /* Linux specific part: */
      struct seminfo *__buf;    /* buffer for IPC_INFO */
   };
#endif

/* declare sig-alarm user function */
IFXOS_STATIC void IFXOSL_SemAlarm(int val);

#if (IFXOS_USE_ERROR_PRINT == 1)
   /* declare debug function and wrapper */
   IFXOS_STATIC void IFXOS_PrintLockError(int err);
#  define IFXOS_PRINT_LOCK_ERROR(errCode) IFXOS_PrintLockError(errCode)
#else
#  define IFXOS_PRINT_LOCK_ERROR(errCode)
#endif

/** signal handler, will abort blocking semop() call */
IFXOS_STATIC void IFXOSL_SemAlarm(int val)
{
}

#if (IFXOS_USE_ERROR_PRINT == 1)
/** 
   IFXOS Lock - Local debug print
*/
IFXOS_STATIC void IFXOS_PrintLockError(int err)
{
   switch(err)
   {
      case E2BIG:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
            ("IFXOS ERROR - LOCK: The value of nsops is greater than the system-"
             "imposed maximum." IFXOS_CRLF));
         break;

      case EACCES:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
            ("IFXOS ERROR - LOCK: Operation permission is denied to the calling "
             "process, see IPC." IFXOS_CRLF));
         break;

      case EAGAIN:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
            ("IFXOS ERROR - LOCK: The operation would result in suspension of the "
             "calling process but (sem_flg&IPC_NOWAIT) is non-zero." IFXOS_CRLF));
         break;

      case EFBIG:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
            ("IFXOS ERROR - LOCK: The value of sem_num is less than 0 or greater "
             "than or equal to the number of semaphores in the set associated "
             "with semid." IFXOS_CRLF));
         break;

      case EIDRM:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
            ("IFXOS ERROR - LOCK: The semaphore identifier semid is removed from "
             "the system." IFXOS_CRLF));
         break;

      case EINTR:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
            ("IFXOS ERROR - LOCK: The semop() function was interrupted by a signal." IFXOS_CRLF));
         break;

      case EINVAL:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
            ("IFXOS ERROR - LOCK: The value of semid is not a valid semaphore "
             "identifier, or the number of individual semaphores for which the "
             "calling process requests a SEM_UNDO would exceed the system-"
             "imposed limit." IFXOS_CRLF));
         break;

      case ENOSPC:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
            ("IFXOS ERROR - LOCK: The limit on the number of individual processes "
             "requesting a SEM_UNDO would be exceeded." IFXOS_CRLF));
         break;

      case ERANGE:
         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
            ("IFXOS ERROR - LOCK: An operation would cause a semval to overflow "
             "the system-imposed limit, or an operation would cause a semadj "
             "value to overflow the system-imposed limit." IFXOS_CRLF));
         break;

      default:
         break;
   }
}
#endif /* #if (IFXOS_USE_ERROR_PRINT == 1) */
#endif /* #if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) ) */

#endif /* USE_PHTREAD_SEM */


/* ============================================================================
   IFX Linux adaptation - Kernel LOCK handling
   ========================================================================= */

/** \addtogroup IFXOS_LOCK_LINUX_APPL
@{ */
#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) )

/**
   LINUX Application - Initialize a Lock Object for protection and lock.
   The lock is based on binary semaphores, recursive calls are not allowded.

\par Implementation
   - Init the LINUX kernel semaphore as "UNLOCKED" (see "sema_init").

\param
   lockId   Provides the pointer to the Lock Object.

\return      
   IFX_SUCCESS if initialization was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int32_t IFXOS_LockInit(
               IFXOS_lock_t *lockId)
{
#if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)

   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_FALSE)
      {
         if(sem_init(&lockId->object, 0, 1) == 0)
         {
            lockId->bValid = IFX_TRUE;

            lockId->pSysObject = (IFX_void_t*)IFXOS_SYS_OBJECT_GET(IFXOS_SYS_OBJECT_LOCK);
            IFXOS_SYS_LOCK_INIT_COUNT_INC(lockId->pSysObject);

            return IFX_SUCCESS;
         }
      }
   }
#else
   IFX_int32_t    nsemkey = IPC_PRIVATE;
   union semun    arg;

   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_FALSE)
      {
         if ((lockId->object = semget(nsemkey, 1, 0666|IPC_CREAT|IPC_EXCL)) < 0)
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
               ("IFXOS ERROR - create lock object - semget(0x%X,0), errno=%d" IFXOS_CRLF,
                 nsemkey, errno));
            IFXOS_PRINT_LOCK_ERROR(errno);
            return IFX_ERROR;
         }

         /* set the value of semaphore to 1 ie released or free to use */
         arg.val = 1;
         if (semctl(lockId->object, 0, SETVAL, arg) < 0 )
         {
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
               ("IFXOS ERROR - create lock object - semctl(0x%X,0,SETVAL,1), errno=%d" IFXOS_CRLF,
                 (IFX_uint32_t)lockId->object, errno));
            IFXOS_PRINT_LOCK_ERROR(errno);
            return IFX_ERROR;
         }

         IFXOS_PRN_USR_DBG_NL( IFXOS, IFXOS_PRN_LEVEL_LOW, 
            ("IFXOS - create lock object - nsemkey=0x%X, semid=0x%X" IFXOS_CRLF,
              nsemkey, (IFX_uint32_t)lockId->object));

         lockId->bValid = IFX_TRUE;
      
         return IFX_SUCCESS;
      }
   }
#endif
   
   return IFX_ERROR;
}

/**
   LINUX Application - Delete the given Lock Object.

\par Implementation

\param
   lockId   Provides the pointer to the Lock Object.

\return
   IFX_SUCCESS if delete was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int32_t IFXOS_LockDelete(
               IFXOS_lock_t *lockId)
{
   /* delete semaphore */
#if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         if (sem_destroy(&lockId->object) == 0)
         {
            lockId->bValid = IFX_FALSE;

            IFXOS_SYS_OBJECT_RELEASE(lockId->pSysObject);

            return IFX_SUCCESS;
         }
      }
   }
#else
   int dummy=0;

   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         if (semctl(lockId->object, 0, IPC_RMID, &dummy) != -1)
         {
            lockId->bValid = IFX_FALSE;
            IFXOS_SYS_OBJECT_RELEASE(lockId->pSysObject);

            return IFX_SUCCESS;
         }
      }
   }
#endif
 
   return IFX_ERROR;
}


/**
   LINUX Application - Get the Lock (not interuptable).

\par Implementation
   Decrement the Kernel semaphore counter to "0" --> LOCKED (see "down").

\param
   lockId   Provides the pointer to the Lock Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error.
*/
IFX_int32_t IFXOS_LockGet(
               IFXOS_lock_t *lockId)
{
#if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         IFXOS_SYS_LOCK_RECURSIVE_CALL_COUNT_INC(lockId->pSysObject);
         IFXOS_SYS_LOCK_REQ_THREAD_ID_SET(lockId->pSysObject);

         if (sem_wait(&lockId->object) == 0)
         {
            IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
            IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

            return IFX_SUCCESS;
         }

         IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
      }
   }
#else
   struct sembuf     sb;

   /*
      !!! Always a Blocking Call !!!
   */
   
   sb.sem_num = 0;
   /* specifies the operation ie to get the semaphore */
   sb.sem_op = -1;
   /* DO NOT USE FLAG 'SEM_UNDO' HERE! */
   sb.sem_flg = 0;

   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         IFXOS_SYS_LOCK_RECURSIVE_CALL_COUNT_INC(lockId->pSysObject);
         IFXOS_SYS_LOCK_REQ_THREAD_ID_SET(lockId->pSysObject);

         if (semop(lockId->object, &sb, 1) == 0)
         {
            IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
            IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

            return IFX_SUCCESS;
         }

         IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
      }
   }

   IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
      ("IFXOS ERROR - get lock object - semop(0x%X,0,..,..), errno=%d" IFXOS_CRLF,
         lockId ? lockId->object : 0, errno));
   IFXOS_PRINT_LOCK_ERROR(errno);
#endif

   return IFX_ERROR;
}

/**
   LINUX Application - Release the Lock.

\par Implementation
   Increment the Kernel semaphore counter to "1" --> UNLOCKED (see "up").

\param
   lockId   Provides the pointer to the Lock Object.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error or timeout.
*/
IFX_int32_t IFXOS_LockRelease(
               IFXOS_lock_t *lockId)
{
#if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)
   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         if (sem_post(&lockId->object) == 0)
         {
            IFXOS_SYS_LOCK_RELEASE_COUNT_INC(lockId->pSysObject);
            IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(lockId->pSysObject);

            return IFX_SUCCESS;
         }
      }
   }
#else
   struct sembuf sb;

   sb.sem_num = 0;
   /* specifies the operation ie to set the semaphore */
   sb.sem_op = 1;
   /* DO NOT USE FLAG 'SEM_UNDO' HERE! */
   sb.sem_flg = 0;

   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         if (semop(lockId->object, &sb, 1) == 0)
         {
            IFXOS_SYS_LOCK_RELEASE_COUNT_INC(lockId->pSysObject);
            IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(lockId->pSysObject);

            return IFX_SUCCESS;
         }
      }
   }

   IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
      ("IFXOS ERROR - release lock object failed - semop(0x%X,0,..,..), errno=%d" IFXOS_CRLF,
         lockId ? lockId->object : 0, errno));
   IFXOS_PRINT_LOCK_ERROR(errno);
#endif

   return IFX_ERROR;
}

#if ( defined(IFXOS_HAVE_NAMED_LOCK) && (IFXOS_HAVE_NAMED_LOCK == 1) )
/**
   LINUX Application - Initialize a Named Lock Object for protection and lock.
   The lock is based on binary semaphores, recursive calls are not allowded.

\remark
   The name will be set within the internal lock object. 
   Currently used for debugging.

\param
   lockId      Provides the pointer to the Lock Object.
\param
   pLockName   Points to the LOCK name
\param
   lockIdx     additional index which is used to generate the lock name

\return      
   IFX_SUCCESS if initialization was successful, else
   IFX_ERROR if something was wrong
*/
IFX_int32_t IFXOS_NamedLockInit(
               IFXOS_lock_t      *lockId,
               const IFX_char_t  *pLockName,
               const IFX_int_t   lockIdx)
{
   IFX_int32_t retVal = IFX_SUCCESS;

   retVal = IFXOS_LockInit(lockId);

#if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)
   IFXOS_SYS_OBJECT_USER_DESRC_SET( lockId->pSysObject, 
                                    (pLockName) ? pLockName : "plock", 
                                    lockIdx);
#else
   IFXOS_SYS_OBJECT_USER_DESRC_SET( lockId->pSysObject, 
                                    (pLockName) ? pLockName : "lock", 
                                    lockIdx);
#endif

   return retVal;
}
#endif

#endif      /* #if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) ) */


#if ( defined(IFXOS_HAVE_LOCK_TIMEOUT) && (IFXOS_HAVE_LOCK_TIMEOUT == 1) )
/**
   LINUX Application - Get the Lock with timeout.

\par Implementation

\param
   lockId   Provides the pointer to the Lock Object.

\param
   timeout_ms  Timeout value [ms]
               - 0: no wait
               - -1: wait forever
               - any other value: waiting for specified amount of milliseconds
\param
   pRetCode    Points to the return code variable. [O]
               - If the pointer is NULL the return code will be ignored, else
                 the corresponding return code will be set
               - For timeout the return code is set to 1.

\return
   IFX_SUCCESS on success.
   IFX_ERROR   on error or timeout.

\note
   To detect timeouts provide the return code varibale, in case of timeout
   the return code is set to 1.
*/
IFX_int32_t IFXOS_LockTimedGet(
               IFXOS_lock_t *lockId,
               IFX_uint32_t timeout_ms,
               IFX_int32_t  *pRetCode)
{
#if defined(USE_PHTREAD_SEM) && (USE_PHTREAD_SEM == 1)
   struct timespec t;
   int ret;
   IFX_uint32_t start=0;

   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         if(timeout_ms == 0xFFFFFFFF)
         {
            return IFXOS_LockGet(lockId);
         }

         IFXOS_SYS_LOCK_RECURSIVE_CALL_COUNT_INC(lockId->pSysObject);
         IFXOS_SYS_LOCK_REQ_THREAD_ID_SET(lockId->pSysObject);

         if(timeout_ms == 0)
         {
               /* just try to get the semaphore without waiting, if not available return to calling thread */
            ret = sem_trywait(&lockId->object);
            if(ret != 0)
            {
               if (pRetCode) 
               {
                  *pRetCode = 0;
               }

               return IFX_ERROR;
            }
         }
         else
         {
            start = IFXOS_ElapsedTimeMSecGet(0);

            clock_gettime(CLOCK_REALTIME, &t);
      
            t.tv_sec +=  (timeout_ms / 1000);
            t.tv_nsec += (timeout_ms % 1000) * 1000 * 1000;

            ret = sem_timedwait(&lockId->object, &t);
         }

         if(ret == 0)
         {
            IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
            IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

            if (pRetCode) *pRetCode = 0;
            return IFX_SUCCESS;
         }

         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
            ("IFXOS ERROR - IFXOS_LockTimedGet failed - ret = %d" IFXOS_CRLF, ret));

         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
           ("   Caller: PID %d, thrId %d (curr lock owner: PID %d, thrID %d)" IFXOS_CRLF, 
            (int)IFXOS_ProcessIdGet(), (int)IFXOS_ThreadIdGet(), 
            IFXOS_SYS_OBJECT_OWNER_THREAD_ID_GET(lockId->pSysObject), 
            IFXOS_SYS_OBJECT_OWNER_PROCESS_ID_GET(lockId->pSysObject) ));

         IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
           ("   timeout_ms %d, current time %ld, t.tv_sec %d t.tv_nsec %d" IFXOS_CRLF, 
            timeout_ms, IFXOS_ElapsedTimeMSecGet(0), (IFX_int_t)t.tv_sec, (IFX_int_t)t.tv_nsec));      

         switch(errno)
         {
            case EINTR:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
               ("IFXOS ERROR - IFXOS_LockTimedGet failed - EINTR, wait time %d, measured time %ld" IFXOS_CRLF, 
                  start, IFXOS_ElapsedTimeMSecGet(start)));      
            if (pRetCode)
            {
                *pRetCode = 0;
            }
            IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
            break;

            case EDEADLK:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
               ("IFXOS ERROR - IFXOS_LockTimedGet failed - EDEADLK, wait time %d, measured time %ld" IFXOS_CRLF, 
                  start, IFXOS_ElapsedTimeMSecGet(start)));      
            if (pRetCode) *pRetCode = 0;
            IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
            break;

            case EINVAL:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
               ("IFXOS ERROR - IFXOS_LockTimedGet failed - EINVAL, wait time %d, measured time %ld" IFXOS_CRLF, 
                  start, IFXOS_ElapsedTimeMSecGet(start)));      
            if (pRetCode) *pRetCode = 0;
            IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
            break;

            case ETIMEDOUT:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
               ("IFXOS ERROR - IFXOS_LockTimedGet failed - ETIMEDOUT, wait time %d, measured time %ld" IFXOS_CRLF, 
                  start, IFXOS_ElapsedTimeMSecGet(start)));      
            if (pRetCode) *pRetCode = 1;
            IFXOS_SYS_LOCK_GET_TOUT_COUNT_INC(lockId->pSysObject);
            break;
      
            default:
            IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
               ("IFXOS ERROR - IFXOS_LockTimedGet failed - ETIMEDOUT, wait time %d, measured time %ld" IFXOS_CRLF, 
                  start, IFXOS_ElapsedTimeMSecGet(start)));          
            if (pRetCode) *pRetCode = 0;
            IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);
            break;
         }
      }
   }
#else
   struct sigaction  sa;
   struct sembuf     sb;
   struct timespec   timeout;

   sb.sem_num = 0;
   /* specifies the operation ie to get the semaphore */
   sb.sem_op = -1;
   /* DO NOT USE FLAG 'SEM_UNDO' HERE! */
   sb.sem_flg = 0;

   if(lockId)
   {
      if (IFXOS_LOCK_INIT_VALID(lockId) == IFX_TRUE)
      {
         IFXOS_SYS_LOCK_RECURSIVE_CALL_COUNT_INC(lockId->pSysObject);
         IFXOS_SYS_LOCK_REQ_THREAD_ID_SET(lockId->pSysObject);

         switch(timeout_ms)
         {
            case 0xFFFFFFFF:
            /* Blocking call */
            break;

            case 0:
            /* Non Blocking */
            sb.sem_flg |= IPC_NOWAIT;
            break;

            default:
            /* Blocking call */
            /* Initialize timer expiration value */
            timeout.tv_sec        = (timeout_ms/1000);
            timeout.tv_nsec       = (timeout_ms%1000) * 1000 * 1000;

            memset(&sa, 0x00, sizeof(sa));
            sa.sa_handler = IFXOSL_SemAlarm;
      
            sigaction(SIGALRM, &sa, NULL);
            alarm(timeout.tv_sec + 1);

            break;
         }

         /* Acquire semaphore */
         if (semop(lockId->object, &sb, 1) == 0)
         {
            if((timeout_ms > 0) && (timeout_ms < 0xFFFFFFFF))
            {
               alarm(0);
            }

            IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(lockId->pSysObject);
            IFXOS_SYS_LOCK_GET_COUNT_INC(lockId->pSysObject);

            return IFX_SUCCESS;
         }
         else
         {
            if((timeout_ms > 0) && (timeout_ms < 0xFFFFFFFF))
            {
               alarm(0);
            }
            if(errno == EINTR)
            {
               IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
                  ("IFXOS - get lock object timeout." IFXOS_CRLF ));

               if (pRetCode)
               {
                  *pRetCode = 1 /* DSL_ERR_TIMEOUT */;
               }

               IFXOS_SYS_LOCK_GET_TOUT_COUNT_INC(lockId->pSysObject);

               return IFX_ERROR;
            }
            else
            {
               if((timeout_ms == 0) && (errno == EAGAIN))
               {
                  if (pRetCode)
                  {
                     *pRetCode = 1 /* DSL_ERR_TIMEOUT */;
                  }

                  IFXOS_SYS_LOCK_GET_TOUT_COUNT_INC(lockId->pSysObject);

                  return IFX_ERROR;
               }

               IFXOS_PRN_USR_ERR_NL( IFXOS, IFXOS_PRN_LEVEL_ERR, 
                  ("IFXOS ERROR - get lock object failed - semop(0x%X,0,..,..), errno=%d" IFXOS_CRLF,
                    lockId ? lockId->object : 0, errno));
               IFXOS_PRINT_LOCK_ERROR(errno);

               IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(lockId->pSysObject);

               return IFX_ERROR;
            }
         }
      }
   }
#endif
   return IFX_ERROR;   
}
#endif      /* #if ( defined(IFXOS_HAVE_LOCK_TIMEOUT) && (IFXOS_HAVE_LOCK_TIMEOUT == 1) ) */

/** @} */

#endif      /* #ifdef LINUX */


