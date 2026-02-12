/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_onu_debug_h
#define _drv_onu_debug_h

/** \addtogroup ONU_MAPI_REFERENCE_INTERNAL
   @{
*/

/** \defgroup ONU_DEBUG_INTERNAL Debug Interface

   This chapter describes the internal debug interface.

   @{
*/
#ifdef EVENT_LOGGER_DEBUG
#define IFXOS_LIBRARY_USED
#include <el_log_macros.h>
#endif /* EVENT_LOGGER_DEBUG */

#if defined(WIN32)
#  define ONU_CRLF  "\r\n"
#else
#  define ONU_CRLF  "\n"
#endif

#undef IFXOS_CRLF
#define IFXOS_CRLF ONU_CRLF

#if defined(_DEBUG)
/** enable debug printouts */
#  define INCLUDE_DEBUG_SUPPORT
#endif

/** ONU Debug Levels */
enum onu_debug_level {
	/** Message */
	ONU_DBG_MSG,
	/** Warning */
	ONU_DBG_WRN,
	/** Error */
	ONU_DBG_ERR,
	/** Off */
	ONU_DBG_OFF
};

/** Debug message prefix */
#  define DEBUG_PREFIX        "[onu]"

#ifdef INCLUDE_DEBUG_SUPPORT
extern enum onu_debug_level onu_debug_lvl;

#  if defined(__GNUC__)
int onu_debug_print(const enum onu_debug_level level, const char *format, ...);
#  else
#    ifndef SWIG
int onu_debug_print_err(const char *format, ...);
int onu_debug_print_wrn(const char *format, ...);
int onu_debug_print_msg(const char *format, ...);
#    endif
#  endif

#  define DEBUG_ENABLE_ERR
#  define DEBUG_ENABLE_WRN
#  define DEBUG_ENABLE_MSG

#  ifdef __GNUC__
#     define ONU_DEBUG_ERR(fmt, args...) \
				onu_debug_print(ONU_DBG_ERR, fmt, ##args)
#     define ONU_DEBUG_WRN(fmt, args...) \
				onu_debug_print(ONU_DBG_WRN, fmt, ##args)
#     define ONU_DEBUG_MSG(fmt, args...) \
				onu_debug_print(ONU_DBG_MSG, fmt, ##args)
#  else				/* __GNUC__ */
#     ifdef DEBUG_ENABLE_ERR
#        define ONU_DEBUG_ERR   onu_debug_print_err
#     endif			/* DEBUG_ENABLE_ERR */
#     ifdef DEBUG_ENABLE_WRN
#        define ONU_DEBUG_WRN   onu_debug_print_wrn
#     endif			/* DEBUG_ENABLE_WRN */
#     ifdef DEBUG_ENABLE_MSG
#        define ONU_DEBUG_MSG   onu_debug_print_msg
#     endif			/* DEBUG_ENABLE_MSG */
#  endif			/* __GNUC__ */

#endif				/* INCLUDE_DEBUG_SUPPORT */

#ifndef STATIC
#if 1
#define STATIC static
#else
#define STATIC /**/
#endif
#endif

#ifndef ONU_DEBUG_ERR
#  if defined(__GNUC__)
#     define ONU_DEBUG_ERR(fmt, args...)   while(0){}
#  else
#     define ONU_DEBUG_ERR   {}
#  endif
#endif

#ifndef ONU_DEBUG_WRN
#  if defined(__GNUC__)
#     define ONU_DEBUG_WRN(fmt, args...)   while(0){}
#  else
#     define ONU_DEBUG_WRN   {}
#  endif
#endif

#ifndef ONU_DEBUG_MSG
#  if defined(__GNUC__)
#     define ONU_DEBUG_MSG(fmt, args...)   while(0){}
#  else
#     define ONU_DEBUG_MSG   {}
#  endif
#endif

/*! @} */
/*! @} */

#endif
