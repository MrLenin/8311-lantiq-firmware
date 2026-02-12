#ifndef _IFXOS_DEBUG_OS_H
#define _IFXOS_DEBUG_OS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains common definitions for debug purposal. It defines debug
   levels and also macros to setup debug groups and the corresponding 
   debug printout macros.

\remarks
   This is only a addon module to the IFX OS adaptation. This file provides 
   definitions for debug purposal used within the implementation of the IFX OS layer.
*/


/** \defgroup IFXOS_IF_PRINTOUT_DEBUG Printout and Debug

   This group collects defines for printout and debug handling.

\par Printout
   The printout handling depends on the underlaying OS concerning the 
   available printout functions and the level where the printout has to be done
   (interrupt or user level).
   see "ifxos_print.h"

\par Debug
   The basic debug handling in a OS independant way is provided by the usage
   of the previous menitoned printout handling.
   see "ifxos_debug.h"

\ingroup IFXOS_INTERFACE
*/


/** \defgroup IFXOS_IF_DEBUG_OS Debug Defines

   Here we setup macros and defines for debugging. The debug concept allows \n
   - split between error and debug printout
   - add a printout to a debug group
   - assign a debug level to a printout (the debug level can be changed per group)
.
   For setup a and handling the corresponding macros are defined

\ingroup IFXOS_IF_PRINTOUT_DEBUG
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS driver debug module - Includes
   ========================================================================= */
#include "ifx_types.h"
#include "ifxos_common.h"
#include "ifxos_print.h"

/* ============================================================================
   IFX OS driver debug module - common defines
   ========================================================================= */

#if ( defined(IFXOS_HAVE_PRINT) && (IFXOS_HAVE_PRINT == 1) )
   /* set debug print for user level */
#  if (IFXOS_DEBUG_USR_PRINT == 1)
#     define IFXOS_USE_DEBUG_USR_PRINT             1
#  else
#     define IFXOS_USE_DEBUG_USR_PRINT             0
#  endif
   /* set debug print for interrupt level */
#  if (IFXOS_DEBUG_INT_PRINT == 1)
#     define IFXOS_USE_DEBUG_INT_PRINT             1
#  else
#     define IFXOS_USE_DEBUG_INT_PRINT             0
#  endif

   /* set error print for user level */
#  if (IFXOS_ERROR_USR_PRINT == 1)
#     define IFXOS_USE_ERROR_USR_PRINT             1
#  else
#     define IFXOS_USE_ERROR_USR_PRINT             0
#  endif
   /* set error print for interrupt */
#  if (IFXOS_ERROR_INT_PRINT == 1)
#     define IFXOS_USE_ERROR_INT_PRINT             1
#  else
#     define IFXOS_USE_ERROR_INT_PRINT             0
#  endif
#else
#  define IFXOS_USE_DEBUG_USR_PRINT                0
#  define IFXOS_USE_DEBUG_INT_PRINT                0
#  define IFXOS_USE_ERROR_USR_PRINT                0
#  define IFXOS_USE_ERROR_INT_PRINT                0
#endif

/* ============================================================================
   IFX OS driver debug module - common defines
   ========================================================================= */

/** \addtogroup IFXOS_IF_DEBUG_OS
@{ */

/** Level for debug printout, level OFF */
#define IFXOS_PRN_LEVEL_OFF                        4
/** Level for debug printout, level HIGH */
#define IFXOS_PRN_LEVEL_HIGH                       3
/** Level for debug printout, level NORMAL */
#define IFXOS_PRN_LEVEL_NORMAL                     2
/** Level for debug printout, level LOW */
#define IFXOS_PRN_LEVEL_LOW                        1

/** Level for error printout, level ERROR */
#define IFXOS_PRN_LEVEL_ERR                        IFXOS_PRN_LEVEL_HIGH
/** Level for error printout, level WARNING */
#define IFXOS_PRN_LEVEL_WRN                        IFXOS_PRN_LEVEL_NORMAL


/** get the base name of the internal debug module (user prints) */
#define IFXOS_PRN_USR_MODULE_NAME(module_name) \
               IFXOS_PrnUsrModule_##module_name

/** get the base name of the internal debug module (interrupt prints) */
#define IFXOS_PRN_INT_MODULE_NAME(module_name) \
               IFXOS_PrnIntModule_##module_name

/* ============================================================================
   IFX OS driver debug module - module handling
   ========================================================================= */

#if ( (IFXOS_USE_DEBUG_USR_PRINT == 1) || (IFXOS_USE_ERROR_USR_PRINT == 1) )

   /** Declare a print level variable (user print) for a given module. */
#  define IFXOS_PRN_USR_MODULE_DECL(module_name) \
               extern IFX_uint32_t IFXOS_PrnUsrModule_##module_name

   /** Create a debug level variable (user print) for a given module. */
#  define IFXOS_PRN_USR_MODULE_CREATE(module_name, init_level) \
               IFX_uint32_t IFXOS_PrnUsrModule_##module_name = (init_level)

   /** Set the debug level (user print) for a given module. */
#  define IFXOS_PRN_USR_LEVEL_SET(module_name, new_level) \
            { IFXOS_PrnUsrModule_##module_name = \
               (new_level>IFXOS_PRN_LEVEL_OFF) ?  IFXOS_PRN_LEVEL_OFF : \
               ((new_level<IFXOS_PRN_LEVEL_LOW) ? IFXOS_PRN_LEVEL_OFF :  (new_level)); }

   /** Get the debug level (user print) for a given module. */
#  define IFXOS_PRN_USR_LEVEL_GET(module_name)\
            IFXOS_PrnUsrModule_##module_name

#else
   /** Declare a print level variable (user print) for a given module. */
#  define IFXOS_PRN_USR_MODULE_DECL(module_name)
   /** Create a debug level variable (user print) for a given module. */
#  define IFXOS_PRN_USR_MODULE_CREATE(module_name, init_level)
   /** Set the debug level (user print) for a given module. */
#  define IFXOS_PRN_USR_LEVEL_SET(module_name, new_level)
   /** Get the debug level (user print) for a given module. */
#  define IFXOS_PRN_USR_LEVEL_GET(module_name)    IFXOS_PRN_LEVEL_OFF

#endif      /* #if ( (IFXOS_USE_DEBUG_USR_PRINT == 1) || (IFXOS_USE_ERROR_USR_PRINT == 1) ) */


#if ( (IFXOS_USE_DEBUG_INT_PRINT == 1) || (IFXOS_USE_ERROR_INT_PRINT == 1) )

   /** Declare a debug level variable (interrupt print) for a given module. */
#  define IFXOS_PRN_INT_MODULE_DECL(module_name) \
               extern IFX_uint32_t IFXOS_PrnIntModule_##module_name

   /** Create a debug level variable (interrupt print) for a given module. */
#  define IFXOS_PRN_INT_MODULE_CREATE(module_name, init_level) \
               IFX_uint32_t IFXOS_PrnIntModule_##module_name = (init_level)

   /** Set the debug level (interrupt print) for a given module. */
#  define IFXOS_PRN_INT_LEVEL_SET(module_name, new_level) \
            { IFXOS_PrnIntModule_##module_name = \
               (new_level>IFXOS_PRN_LEVEL_OFF) ?  IFXOS_PRN_LEVEL_OFF : \
               ((new_level<IFXOS_PRN_LEVEL_LOW) ? IFXOS_PRN_LEVEL_OFF :  (new_level)); }

/** Get the debug level (interrupt print) for a given module. */
#  define IFXOS_PRN_INT_LEVEL_GET(module_name) \
            IFXOS_PrnIntModule_##module_name

#else
   /** Declare a debug level variable (interrupt print) for a given module. */
#  define IFXOS_PRN_INT_MODULE_DECL(module_name)
   /** Create a debug level variable (interrupt print) for a given module. */
#  define IFXOS_PRN_INT_MODULE_CREATE(module_name, init_level)
   /** Set the debug level (interrupt print) for a given module. */
#  define IFXOS_PRN_INT_LEVEL_SET(module_name, new_level)
   /** Get the debug level (interrupt print) for a given module. */
#  define IFXOS_PRN_INT_LEVEL_GET(module_name)    IFXOS_PRN_LEVEL_OFF

#endif      /* #if ( (IFXOS_USE_DEBUG_INT_PRINT == 1) || (IFXOS_USE_ERROR_INT_PRINT == 1) ) */


/* ============================================================================
   IFX OS driver debug module - Macros for debug printouts
   ========================================================================= */

#if (IFXOS_USE_DEBUG_USR_PRINT == 1)
/** Debug printout macro, printout on user level. */
#define IFXOS_PRN_USR_DBG_NL(module_name, dbg_level, print_message) \
            do { \
               if ((dbg_level) >= IFXOS_PrnUsrModule_##module_name) \
                  { (void) IFXOS_DBG_PRINT_USR print_message ; }\
            } while(0)
#else
/** Debug printout macro, printout on user level. */
#define IFXOS_PRN_USR_DBG_NL(module_name, dbg_level, print_message)
#endif

#if (IFXOS_USE_DEBUG_INT_PRINT == 1)
/** Debug printout macro, printout on interrupt level */
#define IFXOS_PRN_INT_DBG_NL(module_name, dbg_level, print_message) \
            do { \
               if ((dbg_level) >= IFXOS_PrnIntModule_##module_name) \
                  { (void) IFXOS_DBG_PRINT_INT print_message ; }\
            } while(0)
#else 
/** Debug printout macro, printout on interrupt level */
#define IFXOS_PRN_INT_DBG_NL(module_name, dbg_level, print_message) 
#endif

/* ============================================================================
   IFX OS driver debug module - Macros for error printouts
   ========================================================================= */

#if (IFXOS_USE_ERROR_USR_PRINT == 1)
/** Error printout Macro, printout on user level */
#define IFXOS_PRN_USR_ERR_NL(module_name, dbg_level, print_message) \
            do { \
               if ((dbg_level) >= IFXOS_PrnUsrModule_##module_name) \
                  { (void) IFXOS_ERR_PRINT_USR print_message ; }\
            } while(0)
#else
/** Error printout Macro, printout on user level */
#define IFXOS_PRN_USR_ERR_NL(module_name, dbg_level, print_message)
#endif

#if (IFXOS_USE_ERROR_INT_PRINT == 1)
/** Error printout Macro, printout on interrupt level */
#define IFXOS_PRN_INT_ERR_NL(module_name, dbg_level, print_message) \
            do { \
               if ((dbg_level) >= IFXOS_PrnIntModule_##module_name) \
                  { (void) IFXOS_ERR_PRINT_INT print_message ; }\
            } while(0)
#else
/** Error printout Macro, printout on interrupt level */
#define IFXOS_PRN_INT_ERR_NL(module_name, dbg_level, print_message) 
#endif

/** @} */

/* ============================================================================
   IFX OS driver debug module - Exports
   ========================================================================= */

/** declare debug group (user level) */
IFXOS_PRN_USR_MODULE_DECL(IFXOS);

/** declare debug group (int level) */
IFXOS_PRN_INT_MODULE_DECL(IFXOS);

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_DEBUG_OS_H */

