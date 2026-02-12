#ifndef _IFXOS_SYS_SHOW_H
#define _IFXOS_SYS_SHOW_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains additional system debug and trace features.
*/

#ifdef __cplusplus
   extern "C" {
#endif
/* ============================================================================
   inlcudes
   ========================================================================= */
#include "ifx_types.h"
#include "ifxos_sys_show_interface.h"

#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
#  include "ifxos_lock.h"
#  include "ifxos_mutex.h"
#  include "ifxos_event.h"
#  include "ifxos_thread.h"
#  include "ifxos_memory_alloc.h"
#endif

#include "ifx_fifo.h"

/* ============================================================================
   IFX OS SYS debug / trace defines
   ========================================================================= */
#define IFXOS_SYS_OBJECT_IDX_THIS               0
#define IFXOS_SYS_OBJECT_IDX_MEMORY             1
#define IFXOS_SYS_OBJECT_USER_DESC_LEN          16
#define IFXOS_SYS_OBJECT_EXT_TRACE_INFO_LEN     80

#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
#  define IFXOS_SYS_OBJECT_OWNER_THREAD_ID_GET(pIFXOS_SysObject)\
               ((pIFXOS_SysObject != IFX_NULL) ? (((IFXOS_sys_object_t *)(pIFXOS_SysObject))->ownerThr.thrId) : (0))

#  define IFXOS_SYS_OBJECT_OWNER_PROCESS_ID_GET(pIFXOS_SysObject)\
               ((pIFXOS_SysObject != IFX_NULL) ? (((IFXOS_sys_object_t *)(pIFXOS_SysObject))->ownerThr.pId) : (0))
#else
#  define IFXOS_SYS_OBJECT_OWNER_THREAD_ID_GET(pIFXOS_SysObject)      (-1)
#  define IFXOS_SYS_OBJECT_OWNER_PROCESS_ID_GET(pIFXOS_SysObject)     (-1)
#endif

/* ============================================================================
   IFX OS SYS debug / trace LOCK handling
   ========================================================================= */
/**
   Struct to debug/trace the IFXOS LOCK feature.
*/
typedef struct 
{
#if defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1)
   /** points the LOCK object */
   IFXOS_lock_t *pThis;
#endif

   /** thread ID of the waiting thread */
   IFX_int_t    reqThreadId;
   /*
      statistics 
   */
   /** number of Inits / Init Attempts */
   IFX_uint_t  numOfInit;
   /** number of get lock (success) */
   IFX_uint_t  numOfGet;
   /** number of get lock (not successful - timeout) */
   IFX_uint_t  numOfGetTimeout;
   /** number of get lock (not successful - error) */
   IFX_uint_t  numOfGetFails;
   /** number of release lock (success) */
   IFX_uint_t  numOfRelease;
   /** number of recursive call attempts - error */
   IFX_uint_t  numOfRecursiveCalls;

#if ( defined(HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT) && (HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT == 1))
   /** keep extended trace info within the object */
   IFX_char_t  extTraceInfo[IFXOS_SYS_OBJECT_EXT_TRACE_INFO_LEN];
#endif

} IFXOS_sys_object_lock_t;

#if ( defined(IFXOS_HAVE_LOCK) && (IFXOS_HAVE_LOCK == 1) && defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1) )

#  define IFXOS_SYS_LOCK_INIT_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjLock.numOfInit++; } \
               } while (0)

#  define IFXOS_SYS_LOCK_GET_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjLock.numOfGet++; } \
               } while (0)


#  define IFXOS_SYS_LOCK_RELEASE_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjLock.numOfRelease++; } \
               } while (0)

#  define IFXOS_SYS_LOCK_GET_TOUT_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjLock.numOfGetTimeout++; } \
               } while (0)

#  define IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjLock.numOfGetFails++; } \
               } while (0)


#  if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1))
#     define IFXOS_SYS_LOCK_REQ_THREAD_ID_SET(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjLock.reqThreadId = (IFX_int_t)IFXOS_ThreadIdGet(); } \
               } while (0)

#  else
#     define IFXOS_SYS_LOCK_REQ_THREAD_ID_SET(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjLock.reqThreadId = -1; } \
               } while (0)

#  endif

#  if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1))
#     define IFXOS_SYS_LOCK_RECURSIVE_CALL_COUNT_INC(pIFXOS_SysObject) \
               /*lint -e{19} */ \
               do { \
                  if (pIFXOS_SysObject != IFX_NULL) { \
                     if (IFXOS_SYS_OBJECT_OWNER_THREAD_ID_GET(pIFXOS_SysObject) == (IFX_int_t)IFXOS_ThreadIdGet()) { \
                       ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjLock.numOfRecursiveCalls++; } } \
               } while (0)

#  else
#     define IFXOS_SYS_LOCK_RECURSIVE_CALL_COUNT_INC(pIFXOS_SysObject) /*lint -e{19} */
#  endif

#else
#  define IFXOS_SYS_LOCK_INIT_COUNT_INC(pIFXOS_SysObject)                        /*lint -e{19} */
#  define IFXOS_SYS_LOCK_NUM_OF_INIT_INC(pIFXOS_SysObject)                       /*lint -e{19} */
#  define IFXOS_SYS_LOCK_GET_COUNT_INC(pIFXOS_SysObject)                         /*lint -e{19} */
#  define IFXOS_SYS_LOCK_RELEASE_COUNT_INC(pIFXOS_SysObject)                     /*lint -e{19} */
#  define IFXOS_SYS_LOCK_GET_TOUT_COUNT_INC(pIFXOS_SysObject)                    /*lint -e{19} */
#  define IFXOS_SYS_LOCK_GET_FAILED_COUNT_INC(pIFXOS_SysObject)                  /*lint -e{19} */
#  define IFXOS_SYS_LOCK_REQ_THREAD_ID_SET(pIFXOS_SysObject)                     /*lint -e{19} */
#  define IFXOS_SYS_LOCK_RECURSIVE_CALL_COUNT_INC(pIFXOS_SysObject)              /*lint -e{19} */
#endif


/* ============================================================================
   IFX OS SYS debug / trace MUTEX handling
   ========================================================================= */

/**
   Struct to debug/trace the IFXOS MUTEX feature.
*/
typedef struct 
{
#if defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1)
   /** points the MUTEX object */
   IFXOS_mutex_t *pThis;
#endif

   /*
      statistics 
   */
   /** number of Inits / Init Attempts */
   IFX_uint_t  numOfInit;
   /** number of get MUTEX (success) */
   IFX_uint_t  numOfGet;
   /** number of get MUTEX (not successful - error) */
   IFX_uint_t  numOfGetFails;
   /** number of release MUTEX (success) */
   IFX_uint_t  numOfRelease;

} IFXOS_sys_object_mutex_t;

#if ( defined(IFXOS_HAVE_MUTEX) && (IFXOS_HAVE_MUTEX == 1) && defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1) )

#  define IFXOS_SYS_MUTEX_INIT_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjMutex.numOfInit++; } \
               } while (0)

#  define IFXOS_SYS_MUTEX_GET_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjMutex.numOfGet++; } \
               } while (0)

#  define IFXOS_SYS_MUTEX_GET_TOUT_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjMutex.numOfGetTimeout++; } \
               } while (0)

#  define IFXOS_SYS_MUTEX_GET_FAILED_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjMutex.numOfGetFails++; } \
               } while (0)

#else

#  define IFXOS_SYS_MUTEX_NUM_OF_INIT_INC(pIFXOS_SysObject)          /*lint -e{19} */
#  define IFXOS_SYS_MUTEX_GET_COUNT_INC(pIFXOS_SysObject)            /*lint -e{19} */
#  define IFXOS_SYS_MUTEX_GET_TOUT_COUNT_INC(pIFXOS_SysObject)       /*lint -e{19} */
#  define IFXOS_SYS_MUTEX_GET_FAILED_COUNT_INC(pIFXOS_SysObject)     /*lint -e{19} */
#endif


/* ============================================================================
   IFX OS SYS debug / trace EVENT handling
   ========================================================================= */

/**
   Struct to debug/trace the IFXOS EVENT feature.
*/
typedef struct 
{
#if defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1)
   /** points the LOCK object */
   IFXOS_event_t *pThis;
#endif

   /*
      statistics 
   */
   /** number of Inits / Init Attempts */
   IFX_uint_t  numOfInit;

} IFXOS_sys_object_event_t;

#if ( defined(IFXOS_HAVE_EVENT) && (IFXOS_HAVE_EVENT == 1) && defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1) )

#  define IFXOS_SYS_EVENT_INIT_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjEvent.numOfInit++; } \
               } while (0)

#else

#  define IFXOS_SYS_EVENT_INIT_COUNT_INC(pIFXOS_SysObject)          /*lint -e{19} */
#endif



/* ============================================================================
   IFX OS SYS debug / trace Thread handling
   ========================================================================= */

/**
   Struct to debug/trace the IFXOS Thread feature.
*/
typedef struct 
{
#if defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1)
   /** points the THREAD object */
   IFXOS_ThreadCtrl_t *pThis;
#endif

   /*
      statistics 
   */
   /** number of Inits / Init Attempts */
   IFX_uint_t           numOfInit;

#if ( defined(HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT) && (HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT == 1))
   /** running count */
   volatile IFX_uint_t  runCount;

   /** keep extended trace info within the object */
   IFX_char_t  extTraceInfo[IFXOS_SYS_OBJECT_EXT_TRACE_INFO_LEN];
#endif

} IFXOS_sys_object_thread_t;

#if ( defined(IFXOS_HAVE_THREAD) && (IFXOS_HAVE_THREAD == 1) && defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1) )

#  define IFXOS_SYS_THREAD_PARAMS_SET(pIFXOS_SysObject, pParams)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjThread.pThis = pParams; } \
               } while (0)

#  define IFXOS_SYS_THREAD_INIT_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjThread.numOfInit++; } \
               } while (0)

#else

#  define IFXOS_SYS_THREAD_PARAMS_SET(pIFXOS_SysObject, pParams)     /*lint -e{19} */
#  define IFXOS_SYS_THREAD_INIT_COUNT_INC(pIFXOS_SysObject)          /*lint -e{19} */
#endif


/* ============================================================================
   IFX OS SYS debug / trace Memory handling
   ========================================================================= */

/**
   Struct to debug/trace the IFXOS MEM ALLOC handling.
*/
typedef struct 
{
   /** points to the FIFO object */
   IFX_void_t *pThis;

   /*
      statistics 
   */
   /** number of mem allocation calles */
   IFX_uint_t  numOfMemAlloc;
   /** number of mem free calls */
   IFX_uint_t  numOfMemFree;

   /**  current size of allocated memory */
   IFX_uint_t  currMemSize;
   /**  max size of allocated memory */
   IFX_uint_t  maxMemSize;

   /**  max block size of allocated memory */
   IFX_uint_t  maxMemBlockSize;
   /**  max block size of allocated memory */
   IFX_uint_t  minMemBlockSize;

} IFXOS_sys_object_mem_t;

#if ( defined(IFXOS_HAVE_MEM_ALLOC) && (IFXOS_HAVE_MEM_ALLOC == 1) && defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1) )

#  define IFXOS_SYS_MEM_ALLOC_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{717} */ \
               do { \
                  if (IFXOS_sysObjectControl.initDone == IFX_TRUE) \
                     { IFXOS_sysObjectBuffer[IFXOS_SYS_OBJECT_IDX_MEMORY].uSysObject.sysObjMemory.numOfMemAlloc++; } \
               } while (0)

#  define IFXOS_SYS_MEM_FREE_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{717} */ \
               do { \
                  if (IFXOS_sysObjectControl.initDone == IFX_TRUE) \
                     { IFXOS_sysObjectBuffer[IFXOS_SYS_OBJECT_IDX_MEMORY].uSysObject.sysObjMemory.numOfMemFree++; } \
               } while (0)

#  define IFXOS_SYS_MEM_MAX_BLOCK_SET(pIFXOS_SysObject, blockSize) \
               /*lint -e{717} */ \
               do { \
                 if (IFXOS_sysObjectBuffer[IFXOS_SYS_OBJECT_IDX_MEMORY].uSysObject.sysObjMemory.maxMemBlockSize < blockSize) \
                    { IFXOS_sysObjectBuffer[IFXOS_SYS_OBJECT_IDX_MEMORY].uSysObject.sysObjMemory.maxMemBlockSize = (blockSize); } \
               } while (0)


#  define IFXOS_SYS_MEM_MIN_BLOCK_SET(pIFXOS_SysObject)\
               /*lint -e{717} */ \
               do {\
                  if (IFXOS_sysObjectBuffer[IFXOS_SYS_OBJECT_IDX_MEMORY].uSysObject.sysObjMemory.minMemBlockSize > blockSize) \
                     { IFXOS_sysObjectBuffer[IFXOS_SYS_OBJECT_IDX_MEMORY].uSysObject.sysObjMemory.minMemBlockSize = (blockSize); } \
               } while (0)

#else

#  define IFXOS_SYS_MEM_ALLOC_COUNT_INC(pIFXOS_SysObject)            /*lint -e{19} */
#  define IFXOS_SYS_MEM_FREE_COUNT_INC(pIFXOS_SysObject)             /*lint -e{19} */
#  define IFXOS_SYS_MEM_MAX_BLOCK_SET(pIFXOS_SysObject, blockSize)   /*lint -e{19} */
#  define IFXOS_SYS_MEM_MAX_BLOCK_SET(pIFXOS_SysObject, blockSize)   /*lint -e{19} */
#endif

/* ============================================================================
   IFX OS SYS debug / trace FIFO handling
   ========================================================================= */

/**
   Struct to debug/trace the IFXOS FIFO handling.
*/
typedef struct 
{

   /** points to the FIFO object */
   IFX_FIFO *pThis;

   /** start pointer of IFX_FIFO buffer */
   IFX_ulong_t* pStart;
   /** end pointer of IFX_FIFO buffer */
   IFX_ulong_t* pEnd;

   /*
      statistics 
   */
   /** number of Inits / Init Attempts */
   IFX_uint_t  numOfInit;

   /** requested number of elements */
   IFX_uint_t  rqNumOfElem;
   /** written number of elements */
   IFX_uint_t  wrNumOfElem;
   /** read number of elements */
   IFX_uint_t  rdNumOfElem;

   /** current fill-level */
   IFX_uint_t  currFillLevel;
   /** max fill-level */
   IFX_uint_t  maxFillLevel;
   /** max element size */
   IFX_uint_t  maxElementSize;
} IFXOS_sys_object_fifo_t;

#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) &&  (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)

#  define IFXOS_SYS_FIFO_PARAMS_SET(pIFXOS_SysObject, pParams)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { \
                        ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjFifo.pThis = pParams; \
                        if ((IFX_VFIFO*)(pParams) != IFX_NULL) \
                        { \
                           ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjFifo.pStart = ((IFX_VFIFO*)(pParams))->pStart; \
                           ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjFifo.pEnd   = ((IFX_VFIFO*)(pParams))->pEnd; \
                        } \
                      } \
               } while (0)


#  define IFXOS_SYS_FIFO_INIT_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjFifo.numOfInit++; } \
               } while (0)


#  define IFXOS_SYS_FIFO_REQ_ELEM_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjFifo.rqNumOfElem++; } \
               } while (0)

#  define IFXOS_SYS_FIFO_WR_ELEM_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjFifo.wrNumOfElem++; } \
               } while (0)


#  define IFXOS_SYS_FIFO_RD_ELEM_COUNT_INC(pIFXOS_SysObject)\
               /*lint -e{19} */ \
               do {\
                  if (pIFXOS_SysObject != IFX_NULL) \
                     { ((IFXOS_sys_object_t *)(pIFXOS_SysObject))->uSysObject.sysObjFifo.rdNumOfElem++; } \
               } while (0)


#else
#  define IFXOS_SYS_FIFO_PARAMS_SET(pIFXOS_SysObject, pParams)     /*lint -e{19} */
#  define IFXOS_SYS_FIFO_INIT_COUNT_INC(pIFXOS_SysObject)          /*lint -e{19} */
#  define IFXOS_SYS_FIFO_REQ_ELEM_COUNT_INC(pIFXOS_SysObject)      /*lint -e{19} */
#  define IFXOS_SYS_FIFO_WR_ELEM_COUNT_INC(pIFXOS_SysObject)       /*lint -e{19} */
#  define IFXOS_SYS_FIFO_RD_ELEM_COUNT_INC(pIFXOS_SysObject)       /*lint -e{19} */
#endif


/* ============================================================================
   Types
   ========================================================================= */

/**
   Debug and trace - this struct contains the PID and Thread ID.
*/
typedef struct 
{
   IFX_int_t      pId;
   IFX_int_t      thrId;
} IFXOS_sys_obj_thread_info_t;

/**
   Struct to debug/trace IFXOS objects.
*/
typedef union
{
   /** IFXOS LOCK debug object */
   IFXOS_sys_object_lock_t     sysObjLock;

   /** IFXOS MUTEX debug object */
   IFXOS_sys_object_mutex_t    sysObjMutex;

   /** IFXOS EVENT debug object */
   IFXOS_sys_object_event_t    sysObjEvent;

   /** IFXOS THREAD debug object */
   IFXOS_sys_object_thread_t   sysObjThread;

   /** IFXOS FIFO debug object */
   IFXOS_sys_object_fifo_t     sysObjFifo;

   /** IFXOS MEM debug object */
   IFXOS_sys_object_mem_t      sysObjMemory;

} IFXOS_sys_object_u;

/**
   Struct to debug/trace IFXOS objects.
*/
struct IFXOS_sys_object_s
{
   /** index within the array */
   IFX_uint_t              objIndex;
   /** number of request attempts */
   IFX_uint_t              reqCount;

   /** object type to identify this object */
   IFX_uint_t              objType;
   /** user description */
   IFX_char_t              userDescr[IFXOS_SYS_OBJECT_USER_DESC_LEN];

   /** the thread which has created / init the object */
   IFXOS_sys_obj_thread_info_t creatorThr;

   /** the thread which currently owns the object */
   IFXOS_sys_obj_thread_info_t ownerThr;

   /** contains the object specific infos */
   IFXOS_sys_object_u      uSysObject;
};


/**
   Debug and trace - this struct contains the PID and Thread ID.
*/
typedef struct 
{
   /** init / setup done */
   IFX_boolean_t  initDone;

   /** current object count */
   IFX_uint_t     objCount;
   /** max object count while operation */
   IFX_uint_t     objMaxCount;

   /** available objects */
   IFX_uint_t         numOfObject;
   /** points to the object buffer */
   IFXOS_sys_object_t *pObjectBuffer;

} IFXOS_sys_object_cntrl_t;


/* ============================================================================
   Internal Exports
   ========================================================================= */

extern IFXOS_sys_object_t        IFXOS_sysObjectBuffer[IFXOS_SYS_MAX_OBJECT];
extern IFXOS_sys_object_cntrl_t  IFXOS_sysObjectControl;

extern IFXOS_sys_object_t* IFXOS_SysObject_Get(
                              IFX_int_t objectType);

extern IFX_void_t IFXOS_SysObject_Release(
                              IFXOS_sys_object_t *pSysObject);

extern IFX_void_t IFXOS_SysObject_SetOwnerThrInfo(
                              IFXOS_sys_object_t *pSysObject);

extern IFX_void_t IFXOS_SysObject_ClearOwnerThrInfo(
                              IFXOS_sys_object_t *pSysObject);


#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)

#  define IFXOS_SYS_OBJECT_GET(objectType)\
               IFXOS_SysObject_Get(objectType)

#  define IFXOS_SYS_OBJECT_RELEASE(pSysObject)\
               /*lint -e{717} */ \
               do { \
                  IFXOS_SysObject_Release((IFXOS_sys_object_t *)pSysObject); \
                  if (pSysObject) {pSysObject = (IFXOS_sys_object_t *)IFX_NULL;} \
               } while(0)


#  define IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(pSysObject)\
               IFXOS_SysObject_SetOwnerThrInfo((IFXOS_sys_object_t *)pSysObject)

#  define IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(pSysObject)\
               IFXOS_SysObject_ClearOwnerThrInfo((IFXOS_sys_object_t *)pSysObject)

#else

#  define IFXOS_SYS_OBJECT_GET(objectType)                  IFX_NULL
#  define IFXOS_SYS_OBJECT_RELEASE(pSysObject)              pSysObject = (IFXOS_sys_object_t *)IFX_NULL
#  define IFXOS_SYSOBJECT_SET_OWNER_THR_INFO(pSysObject)    /*lint -e{19} */
#  define IFXOS_SYSOBJECT_CLEAR_OWNER_THR_INFO(pSysObject)  /*lint -e{19} */

#endif

#ifdef __cplusplus
   }
#endif

#endif      /* #ifndef _IFXOS_SYS_SHOW_H */

