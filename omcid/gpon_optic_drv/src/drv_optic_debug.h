/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_optic_debug_h
#define _drv_optic_debug_h

/** \addtogroup MAPI_REFERENCE_GOI Optical Interface API Reference
   @{
*/

/** \defgroup OPTIC_DEBUG Debug Interface
   @{
*/
#ifdef EVENT_LOGGER_DEBUG
#define IFXOS_LIBRARY_USED
#include <el_log_macros.h>
#endif /* EVENT_LOGGER_DEBUG */

#if defined(WIN32)
#  define OPTIC_CRLF  "\r\n"
#else
#  define OPTIC_CRLF  "\n"
#endif

#undef IFXOS_CRLF
#define IFXOS_CRLF OPTIC_CRLF

#if defined(_DEBUG) && !defined(WIN32)
/** enable debug printouts */
#  define INCLUDE_DEBUG_SUPPORT
#endif


/** OPTIC Debug Levels */
enum optic_debug_levels {
   /** Message */
   OPTIC_DBG_MSG,
   /** Warning */
   OPTIC_DBG_WRN,
   /** Error */
   OPTIC_DBG_ERR,
   /** Off */
   OPTIC_DBG_OFF
};

/** Debug message prefix */
#define DEBUG_PREFIX        "[optic]"

#ifdef INCLUDE_DEBUG_SUPPORT
extern enum optic_debug_levels optic_debug_level;

#  if defined(__GNUC__)
int optic_debug_print ( const enum optic_debug_levels level,
                        const char *format, ... );
#  else
int optic_debug_print_err ( const char *format, ... );
int optic_debug_print_wrn ( const char *format, ... );
int optic_debug_print_msg ( const char *format, ... );
#  endif

#  define DEBUG_ENABLE_ERR
#  define DEBUG_ENABLE_WRN
#  define DEBUG_ENABLE_MSG

#  define STATIC
#  define INLINE

#  ifdef __GNUC__
#     define OPTIC_DEBUG_ERR(fmt, args...)  optic_debug_print(OPTIC_DBG_ERR, fmt, ##args)
#     define OPTIC_DEBUG_WRN(fmt, args...)  optic_debug_print(OPTIC_DBG_WRN, fmt, ##args)
#     define OPTIC_DEBUG_MSG(fmt, args...)  optic_debug_print(OPTIC_DBG_MSG, fmt, ##args)
#  else                         /* __GNUC__ */
#     ifdef DEBUG_ENABLE_ERR
#        define OPTIC_DEBUG_ERR   optic_debug_print_err
#     endif                     /* DEBUG_ENABLE_ERR */
#     ifdef DEBUG_ENABLE_WRN
#        define OPTIC_DEBUG_WRN   optic_debug_print_wrn
#     endif                     /* DEBUG_ENABLE_WRN */
#     ifdef DEBUG_ENABLE_MSG
#        define OPTIC_DEBUG_MSG   optic_debug_print_msg
#     endif                     /* DEBUG_ENABLE_MSG */
#  endif                        /* __GNUC__ */

#endif /* INCLUDE_DEBUG_SUPPORT */

#ifndef INLINE
#  ifdef WIN32
#     define INLINE __inline
#  else
#     define INLINE inline
#  endif
#endif

#ifndef STATIC
#  define STATIC static
#endif

#ifndef OPTIC_DEBUG_ERR
#  if defined(__GNUC__)
#     define OPTIC_DEBUG_ERR(fmt, args...)   do{}while(0)
#  else
#     define OPTIC_DEBUG_ERR   {}
#  endif
#endif

#ifndef OPTIC_DEBUG_WRN
#  if defined(__GNUC__)
#     define OPTIC_DEBUG_WRN(fmt, args...)   do{}while(0)
#  else
#     define OPTIC_DEBUG_WRN   {}
#  endif
#endif

#ifndef OPTIC_DEBUG_MSG
#  if defined(__GNUC__)
#     define OPTIC_DEBUG_MSG(fmt, args...)   do{}while(0)
#  else
#     define OPTIC_DEBUG_MSG   {}
#  endif
#endif

/*! @} */
/*! @} */

#endif
