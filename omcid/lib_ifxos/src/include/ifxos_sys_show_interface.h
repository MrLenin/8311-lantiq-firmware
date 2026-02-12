#ifndef _IFXOS_SYS_SHOW_INTERFACE_H
#define _IFXOS_SYS_SHOW_INTERFACE_H
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

#ifdef __cplusplus
   extern "C" {
#endif
/* ============================================================================
   inlcudes
   ========================================================================= */
#include "ifx_types.h"

/* ============================================================================
   IFX OS ADDON - debug / trace setup
   ========================================================================= */
/* enable the IFXOS Debug/Trace feature */
#ifndef HAVE_IFXOS_SYSOBJ_SUPPORT
#  define HAVE_IFXOS_SYSOBJ_SUPPORT                0
#endif

/* max number of IFXOS objects */
#ifndef IFXOS_SYS_MAX_OBJECT
#  define IFXOS_SYS_MAX_OBJECT                     300
#endif

/* enable the IFXOS Extended Debug/Trace feature */
#ifndef HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT
#  define HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT      1
#endif


/* ============================================================================
   IFX OS ADDON - debug / trace defines
   ========================================================================= */

#define IFXOS_SYS_OBJECT_NOT_USED               0x00000000
#define IFXOS_SYS_OBJECT_OWN                    0x00000001
#define IFXOS_SYS_OBJECT_MEM_ALLOC              0x00000002

#define IFXOS_SYS_OBJECT_LOCK                   0x00000100
#define IFXOS_SYS_OBJECT_MUTEX                  0x00000101
#define IFXOS_SYS_OBJECT_EVENT                  0x00000102
#define IFXOS_SYS_OBJECT_THREAD                 0x00000103

#define IFXOS_SYS_OBJECT_FIFO                   0x00000200
#define IFXOS_SYS_OBJECT_FILE_ACCESS            0x00000201
#define IFXOS_SYS_OBJECT_SOCKET                 0x00000202
#define IFXOS_SYS_OBJECT_PIPE                   0x00000203


/* ============================================================================
   Types
   ========================================================================= */

/** forward declaration */
typedef struct IFXOS_sys_object_s   IFXOS_sys_object_t;

/* ============================================================================
   Macros to get the system object form the corresponding IFXOS opject
   ========================================================================= */

#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
#  define IFXOS_SYS_OBJECT_FROM_LOCK_GET(p_lock)     (p_lock)->pSysObject
#  define IFXOS_SYS_OBJECT_FROM_THREAD_GET(p_thread) (p_thread)->pSysObject
#  define IFXOS_SYS_OBJECT_FROM_FIFO_GET(p_fifo)     (p_fifo)->pSysObject
#else
#  define IFXOS_SYS_OBJECT_FROM_LOCK_GET(p_lock)     /*lint -e{19} */
#  define IFXOS_SYS_OBJECT_FROM_THREAD_GET(p_thread) /*lint -e{19} */
#  define IFXOS_SYS_OBJECT_FROM_FIFO_GET(p_fifo)     /*lint -e{19} */
#endif


/* ============================================================================
   Exports
   ========================================================================= */

extern IFX_void_t IFXOS_SysObject_Setup(
                              IFX_int_t maxNumOfObjects);

extern IFX_void_t IFXOS_SysObject_Cleanup(void);

extern IFX_void_t IFXOS_SysObject_UserDesrcSet(
                              IFXOS_sys_object_t   *pSysObject,
                              const IFX_char_t     *pDescr,
                              const IFX_int_t      descrIdx);

extern IFX_void_t IFXOS_SysObject_ShowObject(
                              IFXOS_sys_object_t *pSysObject);

extern IFX_void_t IFXOS_SysObject_ShowAll(
                              IFX_uint_t objType);


extern IFX_void_t IFXOS_SysObject_StringTraceInfoSet(
                              IFXOS_sys_object_t   *pSysObject,
                              const IFX_char_t     *pTraceInfo);

extern IFX_void_t IFXOS_SysObject_DigitTraceInfoSet(
                              IFXOS_sys_object_t   *pSysObject,
                              IFX_boolean_t        bIncrement,
                              IFX_uint_t           digitValue);


#if defined(HAVE_IFXOS_SYSOBJ_SUPPORT) && (HAVE_IFXOS_SYSOBJ_SUPPORT == 1)
#  define IFXOS_SYS_OBJECT_SETUP(maxNumOfObjects)\
               IFXOS_SysObject_Setup(maxNumOfObjects)

#  define IFXOS_SYS_OBJECT_CLEANUP(no_args)\
               IFXOS_SysObject_Cleanup()

#  define IFXOS_SYS_OBJECT_USER_DESRC_SET(p_sys_object, p_descr, descr_idx)\
               IFXOS_SysObject_UserDesrcSet((IFXOS_sys_object_t *)p_sys_object, p_descr, descr_idx)

#  define IFXOS_SYS_OBJECT_SHOW(p_sys_object)\
               IFXOS_SysObject_ShowObject((IFXOS_sys_object_t *)p_sys_object)

#  define IFXOS_SYS_OBJECT_SHOW_ALL(objType)\
               IFXOS_SysObject_ShowAll(objType)

#  if ( defined(HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT) && (HAVE_IFXOS_SYSOBJ_EXT_TRACE_SUPPORT == 1))
#     define IFXOS_SYS_OBJECT_STR_TRACE_INFO_SET(p_sys_object, p_trace_info)\
               IFXOS_SysObject_StringTraceInfoSet((IFXOS_sys_object_t *)p_sys_object, p_trace_info)

#     define IFXOS_SYS_OBJECT_DIG_TRACE_INFO_SET(p_sys_object, digit_info)\
               IFXOS_SysObject_DigitTraceInfoSet((IFXOS_sys_object_t *)p_sys_object, IFX_FALSE, digit_info)

#     define IFXOS_SYS_OBJECT_DIG_TRACE_INFO_INC(p_sys_object)\
               IFXOS_SysObject_DigitTraceInfoSet((IFXOS_sys_object_t *)p_sys_object, IFX_TRUE, 0)

#  else
#     define IFXOS_SYS_OBJECT_STR_TRACE_INFO_SET(p_sys_object, p_trace_info)     /*lint -e{19} */
#     define IFXOS_SYS_OBJECT_DIG_TRACE_INFO_SET(p_sys_object, digit_info)       /*lint -e{19} */
#     define IFXOS_SYS_OBJECT_DIG_TRACE_INFO_INC(p_sys_object)                   /*lint -e{19} */
#  endif

#else
#  define IFXOS_SYS_OBJECT_SETUP(maxNumOfObjects) \
               IFXOS_SysObject_Setup(maxNumOfObjects)
#  define IFXOS_SYS_OBJECT_CLEANUP(no_args) \
               IFXOS_SysObject_Cleanup()

#  define IFXOS_SYS_OBJECT_USER_DESRC_SET(p_sys_object, p_descr, descr_idx)   /*lint -e{19} */
#  define IFXOS_SYS_OBJECT_SHOW(pSysObject)                                   /*lint -e{19} */
#  define IFXOS_SYS_OBJECT_SHOW_ALL(objType)                                  /*lint -e{19} */

#  define IFXOS_SYS_OBJECT_STR_TRACE_INFO_SET(p_sys_object, p_trace_info)     /*lint -e{19} */
#  define IFXOS_SYS_OBJECT_DIG_TRACE_INFO_SET(p_sys_object, digit_info)       /*lint -e{19} */
#  define IFXOS_SYS_OBJECT_DIG_TRACE_INFO_INC(p_sys_object)                   /*lint -e{19} */
#endif


#ifdef __cplusplus
   }
#endif

#endif      /* #ifndef _IFXOS_SYS_SHOW_INTERFACE_H */

