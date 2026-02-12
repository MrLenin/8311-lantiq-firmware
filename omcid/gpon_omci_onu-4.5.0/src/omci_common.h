/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_common_h
#define _omci_common_h

#define OMCI_PRIVATE

#if defined(WIN32) && !defined(inline)
#    define inline __inline
#endif

#ifdef HAVE_CONFIG_H
#  include "omci_config.h"
#endif

#include "omci_interface_types.h"
#include "omci_list.h"

#ifndef SWIG
#  include "ifxos_common.h"
#endif
#include "ifx_types.h"

#ifndef _lint
#  include <assert.h> /* assert */
#else
#  include <stddef.h>
#endif

#ifndef SWIG
#  include "ifxos_version.h"
#  ifndef _lint
#     include "ifxos_std_defs.h"
#  endif
#endif

#include "omci_api.h"

#ifdef INCLUDE_OMCI_ONU_DMALLOC
#	define DMALLOC
#	define DMALLOC_FUNC_CHECK

#	include <dmalloc.h>

#	define IFXOS_MemAlloc(SIZE) malloc((SIZE))
#	define IFXOS_MemFree(PTR) free((PTR))

static inline void heap_check_init(void)
{
	dmalloc_logpath = "/tmp/omci_dmalloc";

/*
	DEBUG_LOG_STATS		BIT_FLAG(0)	generally log statistics 
	DEBUG_LOG_NONFREE	BIT_FLAG(1)	report non-freed pointers
	DEBUG_LOG_KNOWN		BIT_FLAG(2)	report only known nonfreed
	DEBUG_LOG_TRANS		BIT_FLAG(3)	log memory transactions
	DEBUG_LOG_ADMIN		BIT_FLAG(5)	log background admin info
	DEBUG_LOG_BAD_SPACE	BIT_FLAG(8)	dump space from bad pnt
	DEBUG_LOG_NONFREE_SPACE	BIT_FLAG(9)	dump space from non-freed
	DEBUG_LOG_ELAPSED_TIME	BIT_FLAG(18)	log pnt elapsed time info
	DEBUG_LOG_CURRENT_TIME	BIT_FLAG(19)	log pnt current time info
	DEBUG_CHECK_FENCE	BIT_FLAG(10)	check fence-post errors
	DEBUG_CHECK_HEAP	BIT_FLAG(11)	examine heap adm structs
	DEBUG_CHECK_BLANK	BIT_FLAG(13)	check blank sections
	DEBUG_CHECK_FUNCS	BIT_FLAG(14)	check functions
	DEBUG_CHECK_SHUTDOWN	BIT_FLAG(15)	check pointers on shutdown
	DEBUG_CATCH_SIGNALS	BIT_FLAG(17)	catch HUP, INT, and TERM
	DEBUG_REALLOC_COPY	BIT_FLAG(20)	copy all reallocations
	DEBUG_FREE_BLANK	BIT_FLAG(21)	write over free'd memory
	DEBUG_ERROR_ABORT	BIT_FLAG(22)	abort on error else exit
	DEBUG_ALLOC_BLANK	BIT_FLAG(23)	write over to-be-alloced
	DEBUG_PRINT_MESSAGES	BIT_FLAG(25)	write messages to STDERR
	DEBUG_CATCH_NULL	BIT_FLAG(26)	quit before return null
	DEBUG_NEVER_REUSE	BIT_FLAG(27)	never reuse memory
	DEBUG_ERROR_FREE_NULL	BIT_FLAG(28)	catch free(0)
	DEBUG_ERROR_DUMP	BIT_FLAG(30)	dump core on error
*/
	if (!dmalloc_debug_current())
		dmalloc_debug(0xFFFFFFFF ^ ((1 << 28) | (1 << 25)));
}
#else
static inline void heap_check_init(void) { }
#endif

#ifdef LINUX
#	include <stdlib.h>
#else
static inline int system(const char *command)
{
	(void*)command;
	return 0;
}
#endif

#if !defined(OMCI_DEBUG_DISABLE) && defined(OMCI_DBG_MODULE)
static enum omci_dbg_module dbg_module = OMCI_DBG_MODULE;
#endif

#if 0
#ifdef LINUX
#  define OMCI_TIME_MEASURE
#  include <sys/time.h>
#endif
#endif

/* check the IFXOS version */
#if !defined(IFXOS_HAVE_VERSION_CHECK) || !IFXOS_VERSION_CHECK_EG_THAN(1,5,10)
#  error Please update your IFX OS, require at least version 1.5.10!
#endif

#ifndef NULL
#  define NULL ((void *) 0)
#endif

/** \addtogroup OMCI_CORE

   @{
*/

/** \defgroup OMCI_COMMON Optical Network Unit - Common Functionality

   @{
*/

/** ONU reboot timeout (in milliseconds) */
#define REBOOT_TIMEOUT			(10 * 1000)

/** G.988 */
#define INCLUDE_G984_4_AMENDMENT_2	1

#ifdef LINUX
/* from IFXOS, where it's under ifdefs */

/** LINUX Kernel Thread - priority - IDLE */
#  define IFXOS_THREAD_PRIO_IDLE                                       1
/** LINUX User Thread - priority - LOWEST */
#  define IFXOS_THREAD_PRIO_LOWEST                                     5
/** LINUX User Thread - priority - LOW */
#  define IFXOS_THREAD_PRIO_LOW                                        20
/** LINUX User Thread - priority - NORMAL */
#  define IFXOS_THREAD_PRIO_NORMAL                                     40
/** LINUX User Thread - priority - HIGH */
#  define IFXOS_THREAD_PRIO_HIGH                                       60
/** LINUX User Thread - priority - HIGHEST */
#  define IFXOS_THREAD_PRIO_HIGHEST                                    80
#endif

#if defined (__GNUC__) || defined (__GNUG__)
#  if __STDC_VERSION__ < 199901L
#    define __func__ __FUNCTION__
#  endif
#else				/* Other compiler */
#  if defined(WIN32)		/* Hope this is MSVC (add additional checks
				   if needed) */
#    define __func__ __FUNCTION__
#  else				/* Unknown compiler */
/** C99 function name macro (depends on compiler) */
#    define __func__ "<" __FILE__ ":" _MKSTR(__LINE__) ">"
#  endif
#endif

#ifndef IFXOS_BYTE_ORDER
#  error "Unknown byte order!"
#endif

#ifdef INCLUDE_DRIVER_SIMULATION
/** When driver simulation enabled, don't do any swapping */
#define REMOTE_ENDIAN IFXOS_BYTE_ORDER
#else
/** Currently, we assume that target board is always big endian */
#define REMOTE_ENDIAN IFXOS_BIG_ENDIAN
#endif

#if (REMOTE_ENDIAN == IFXOS_BIG_ENDIAN) && \
		    (IFXOS_BYTE_ORDER == IFXOS_LITTLE_ENDIAN)
#  define OMCI_SWAP
#endif

#if defined(OMCI_SWAP)

/** Network to host byte order for 16bit variable */
static inline uint16_t ntoh16(uint16_t val)
{
	return ( ((val & 0xff00) >> 8) | ((val & 0x00ff) << 8) );
}

/** Host to network byte order for 16bit variable */
static inline uint16_t hton16(uint16_t val)
{
	return ntoh16(val);
}

/** Network to host byte order for 32bit variable */
static inline uint32_t ntoh32(uint32_t val)
{
	return ( ((val & 0xff000000) >> 24) |
		 ((val & 0x00ff0000) >> 8)  |
		 ((val & 0x0000ff00) << 8)  |
		 ((val & 0x000000ff) << 24) );
}

/** Host to network byte order for 32bit variable */
static inline uint32_t hton32(uint32_t val)
{
	return ntoh32(val);
}

#else

/** Network to host byte order for 16bit variable */
static inline uint16_t ntoh16(uint16_t val)
{
	return val;
}

/** Host to network byte order for 16bit variable */
static inline uint16_t hton16(uint16_t val)
{
	return val;
}

/** Network to host byte order for 32bit variable */
static inline uint32_t ntoh32(uint32_t val)
{
	return val;
}

/** Host to network byte order for 32bit variable */
static inline uint32_t hton32(uint32_t val)
{
	return val;
}

#endif

#if defined (__GNUC__) || defined (__GNUG__)
/** Define unsigned long long constant */
#define ULL_CONST(NUM) (uint64_t)NUM##ULL
#else
/** Define unsigned long long constant */
#define ULL_CONST(NUM) (uint64_t)NUM
#endif

/** Get high 32-bits of 64-bit integer */
static inline uint32_t uint64_hi(uint64_t val)
{
	return (uint32_t)((val & ULL_CONST(0xffffffff00000000)) >> 32);
}

/** Get low 32-bits of 64-bit integer */
static inline uint32_t uint64_lo(uint64_t val)
{
	return (uint32_t)(val & ULL_CONST(0x00000000ffffffff));

}

/** Return with \ref omci_error::OMCI_ERROR_INVALID_PTR
    if PTR == NULL */
#define RETURN_IF_PTR_NULL(PTR) \
	do { \
		if ((PTR) == NULL) { \
			dbg_err("ERROR(%d) Pointer '" #PTR \
				"' is null in %s", \
			     OMCI_ERROR_INVALID_PTR, \
			     __func__); \
			dbg_out_ret(__func__, OMCI_ERROR_INVALID_PTR); \
			return OMCI_ERROR_INVALID_PTR; \
		} \
	} while (0)

/** Return with \ref omci_error::OMCI_ERROR_MEMORY if PTR == NULL */
#define RETURN_IF_MALLOC_ERROR(PTR) \
	do { \
		if ((PTR) == NULL) { \
			dbg_err("ERROR(%d) Memory allocation error for '" #PTR \
			     "' in %s", \
			     OMCI_ERROR_MEMORY, \
			     __func__); \
			dbg_out_ret(__func__, OMCI_ERROR_MEMORY); \
			return OMCI_ERROR_MEMORY; \
		} \
	} while (0)

/** Return with ERROR if ERROR != OMCI_SUCCESS */
#define RETURN_IF_ERROR(ERROR) \
	do { \
		if ((ERROR)) { \
			dbg_out_ret(__func__, ERROR); \
			return (ERROR); \
		} \
	} while (0)

/** Return with \ref omci_error::OMCI_ERROR_BOUNDS
    if DATA_SIZE < REQ_SIZE */
#define RETURN_IF_BOUNDS_ERROR(DATA_SIZE, REQ_SIZE) \
	do { \
		if ((DATA_SIZE) < (REQ_SIZE)) { \
			dbg_err("ERROR(%d) " \
				"Bounds error (" #DATA_SIZE \
				" > " #REQ_SIZE ")" \
				" in %s", \
				OMCI_ERROR_BOUNDS, \
				__func__); \
			dbg_out_ret(__func__, OMCI_ERROR_BOUNDS); \
			return OMCI_ERROR_BOUNDS; \
		} \
	} while (0)

#ifndef offsetof
/** Receive structure member offset (POSIX 1-2001) */
#define offsetof(STRUCT, MEMBER) \
	/*lint -save -e(413) -e(507) -e(831) */ \
	((size_t) &((STRUCT *) 0)->MEMBER ) \
	/*lint -restore */
#endif

#ifndef assert
#if defined(NDEBUG) || defined(_lint)
/** Assertion macro */
#define assert(EXP) do { } while (0)
#else
/** Assertion macro */
#define assert(EXP) \
	do { \
		if (!(EXP)) { \
			printf("assertion (" #EXP ") failed in file %s, " \
			       "in function %s, on line %d\n", \
			       __FILE__, __func__, __LINE__); \
			abort(); \
		} \
	} while (0)
#endif
#endif

#ifndef ARRAY_SIZE
#   define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
#endif  

/** @} */

/** @} */

#endif
