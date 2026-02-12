/******************************************************************************
 * Copyright (c) 2017 Intel Corporation
 * Copyright (c) 2011 - 2016 Lantiq Beteiligungs-GmbH & Co. KG
 *
 * For licensing information, see the file 'LICENSE' in the root folder of
 * this software module.
 ******************************************************************************/
#ifndef _LIB_CLI_OSMAP_H
#define _LIB_CLI_OSMAP_H

/* ==========================================================================
	Description : IFX OS mapping of the used IVE drvier OS functions.
	========================================================================== */

/** \file
   Mapping of the OS functions used by the IVE Network Management.
*/

#ifdef __cplusplus
extern "C"
{
#endif

/* ==========================================================================
   includes - not mapped functions
   ========================================================================== */

#include "ifxos_common.h"

#if defined(IFXOS_HAVE_VERSION_CHECK)
#	if (!IFXOS_VERSION_CHECK_EG_THAN(1,1,2))
#		error "IFXOS_VERSION_CHECK: requiere at least IFX OS version 1.1.2"
#	endif
#else
#	error "IFXOS_VERSION_CHECK: requiere at least IFX OS version 1.1.2"
#endif

#if defined(LINUX) && defined(__KERNEL__)
#	include <linux/kernel.h>
#	include <linux/ctype.h>
#else
#	include "ifxos_std_defs.h"
#endif

#include "lib_cli_config.h"

/* ==========================================================================
   OS default defines
   ========================================================================== */


/* ==========================================================================
   Function map - Standard Functions.
   ========================================================================== */

/** Not Mapped Functions
   For this function there is no special mapped IFXOS function. They are only
   mapped to the corresponding standard function. */

#define clios_strlen	strlen
#define clios_strcpy	strcpy
#define clios_strstr	strstr
#define clios_strcmp	strcmp
#define clios_strncmp	strncmp
#ifdef WIN32
#	define clios_strtok_r	strtok_s
#else
#	define clios_strtok_r	strtok_r
#endif

#define clios_memset	memset
#define clios_memcpy	memcpy
#define clios_memcmp	memcmp

#define clios_printf	printf
#define clios_sprintf	sprintf
#define clios_sscanf	sscanf

#ifdef LINUX
#	include <sys/ioctl.h>
#	include <unistd.h>
#endif
#define clios_ioctl	ioctl

/* ==========================================================================
   includes - IFXOS mapped functions
   ========================================================================== */
#include "ifx_types.h"
#include "ifxos_common.h"
#include "ifxos_print.h"
#include "ifxos_memory_alloc.h"
#include "ifxos_lock.h"
#include "ifxos_time.h"
#include "ifxos_event.h"
#if (CLI_SUPPORT_FILE_OUT == 1) || (CLI_SUPPORT_CONSOLE == 1) || (CLI_SUPPORT_PIPE == 1)
#	include "ifxos_print_io.h"
#	include "ifxos_file_access.h"
#endif

#if (CLI_SUPPORT_PIPE == 1)
#	include "ifxos_thread.h"
#	include "ifxos_pipe.h"
#	include "ifx_fifo.h"
#endif

#if (CLI_SUPPORT_AUTO_COMPLETION == 1)
#	include "ifxos_termios.h"
#endif

/* ==========================================================================
   IFXOS mapped functions
   ========================================================================== */

/* Function map - IFXOS Printout and debug. */
#define CLI_CRLF	IFXOS_CRLF
#define CLIOS_PRINT_USR_DBG	IFXOS_PRINT_USR_RAW
#define CLIOS_PRINT_USR_ERR	IFXOS_PRINT_USR_RAW


/* Function map - "ifxos_print_io.h" */
#if defined(LINUX) && defined(__KERNEL__)
#	define clios_fprintf	fprintf_not_available
#	define clios_snprintf	snprintf
#  define clios_vsnprintf   vsnprintf
#  define clios_vfprintf fprintf_not_available
#else
#	define clios_fprintf	IFXOS_FPrintf
#	define clios_snprintf	IFXOS_SNPrintf
#  define clios_vsnprintf  IFXOS_VSNPrintf
#  define clios_vfprintf   vfprintf
#endif

/* Function map - Memory Functions. */
#define clios_memalloc	IFXOS_MemAlloc
#define clios_memfree	IFXOS_MemFree

/* Function map - File Access Functions. */
#if (CLI_SUPPORT_FILE_OUT == 1)
	/** map IFXOS define */
#	define clios_file_t	IFXOS_File_t
#endif

#define clios_feof	IFXOS_FEof
#define clios_fread	IFXOS_FRead
#define clios_fflush	IFXOS_FFlush

#define clios_getchar	IFXOS_GetChar
#define clios_putchar	IFXOS_PutChar

/* Function map - Event Objects Functions. */
#define clios_event_wakeup	IFXOS_EventWakeUp
#define clios_event_wait	IFXOS_EventWait
#define clios_event_init	IFXOS_EventInit
#define clios_event_delete	IFXOS_EventDelete

/* Function map - Time and Wait Functions and Defines. */
#define clios_sleep_msec	IFXOS_MSecSleep


/* Function map - Lock handling. */
#if ( defined(IFXOS_HAVE_NAMED_LOCK) && (IFXOS_HAVE_NAMED_LOCK == 1) )
#  define clios_lockinit(lock_id, name, idx)	IFXOS_NamedLockInit(lock_id, name, idx)
#else
#  define clios_lockinit(lock_id, name, idx)	IFXOS_LockInit(lock_id)
#endif
#define clios_lockget		IFXOS_LockGet
#define clios_lockget_timout	IFXOS_LockTimedGet
#define clios_lockrelease	IFXOS_LockRelease
#define clios_lockdelete	IFXOS_LockDelete

/* Function map - Thread/Task Handling */
#ifndef IFXOS_DEFAULT_PRIO
#	define IFXOS_DEFAULT_PRIO 0
#endif

#define CLIOS_DEFAULT_PRIO		IFXOS_DEFAULT_PRIO
#define CLIOS_DEFAULT_STACK_SIZE	IFXOS_DEFAULT_STACK_SIZE

#define clios_thread_t		IFXOS_thread_t
#define clios_thr_params_t	IFXOS_ThreadParams_t
#define clios_thr_function_t	IFXOS_ThreadFunction_t
#define clios_thr_ctrl_t	IFXOS_ThreadCtrl_t

#define clios_thr_init		IFXOS_ThreadInit
#define clios_thr_delete	IFXOS_ThreadDelete
#define clios_thr_shutdown	IFXOS_ThreadShutdown
#define clios_thr_prioritymodify	IFXOS_ThreadPriorityModify

/* Function map - Variable FIFO Handling */
#define clios_vfifo		IFX_VFIFO
#define clios_vfifo_init	IFX_Var_Fifo_Init
#define clios_vfifo_clear	IFX_Var_Fifo_Clear
#define clios_vfifo_get_count	IFX_Var_Fifo_getCount
#define clios_vfifo_is_empty	IFX_Var_Fifo_isEmpty
#define clios_vfifo_is_full	IFX_Var_Fifo_isFull
#define clios_vfifo_read_element	IFX_Var_Fifo_readElement
#define clios_vfifo_peek_element	IFX_Var_Fifo_peekElement
#define clios_vfifo_write_element	IFX_Var_Fifo_writeElement


/* Function map - Pipe Handling Handling */
#define clios_pipe_t		IFXOS_Pipe_t
#define clios_pipe_create	IFXOS_PipeCreate
#define clios_pipe_close	IFXOS_PipeClose
#define clios_pipe_open		IFXOS_PipeOpen
#define clios_pipe_read		IFXOS_PipeRead

/* Function map - terminal IO */
#define clios_echo_off		IFXOS_EchoOff
#define clios_echo_on		IFXOS_EchoOn
#define clios_keypress_set	IFXOS_KeypressSet
#define clios_keypress_reset	IFXOS_KeypressReset

#if (CLI_CONSOLE_NON_BLOCKING == 1)
/*
   OS defines for support the console non-blocking mode
*/

#if defined(VXWORKS)

#include <selectLib.h>

typedef fd_set	CLIOS_ioFd_set_t;
typedef int CLIOS_ioFd_t;

#define clios_fileno	fileno

#elif defined(LINUX) && !defined(__KERNEL__)

#include <sys/types.h>
#include <sys/select.h>

typedef fd_set CLIOS_ioFd_set_t;
typedef int CLIOS_ioFd_t;

#define clios_fileno	fileno

#elif defined (WIN32)

#include <winsock2.h>

typedef fd_set	CLIOS_ioFd_set_t;
typedef int CLIOS_ioFd_t;

#define clios_fileno	_fileno

#endif

#endif	/* #if (CLI_CONSOLE_NON_BLOCKING == 1) */


#ifdef __cplusplus
/* extern "C" */
}
#endif

#endif   /* #define _LIB_CLI_OSMAP_H */

