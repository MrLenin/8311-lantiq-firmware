#ifndef _IFXOS_COMMON_H
#define _IFXOS_COMMON_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains common OS independent definitions for the IFX OS.
*/

/** \defgroup IFXOS_INTERFACE IFXOS Interface Layer

   This Group contains the definitions and functions of the Infineon / Lantiq OS Layer.

   Therefore the IFX OS defines and provides wrapper functions to hide the
   OS specifc implementations.

   Currently supported:
   - eCos
   - Linux
   - VxWorks
*/

/** \defgroup IFXOS_LAYER_LINUX IFXOS Implementation (Linux)

   This Group contains the mapping and implementation layer for the Linux OS.

   Therefore the Linux Layer is splitted in 2 parts:
   - Linux Kernel Layer
   - Linux User Layer
*/

/** \defgroup IFXOS_LAYER_VXWORKS IFXOS Implementation (VxWorks)

   This Group contains the mapping and implementation layer for the VxWorks OS.

   The VxWorks OS doesen't enforce a clear split between driver and
   application code, but for a clear structure and compatibility to Linux the
   IFX OS Layer keeps this border between driver and application code.

\note
   Concerning to this split, there are functions which are related to driver code
*/

/** \defgroup IFXOS_COMMON IFXOS Common Defines

   This Group contains the common OS independant definition.
*/

#ifdef __cplusplus
   extern "C" {
#endif


/* ==========================================================================
   IFXOS Version
   ========================================================================== */

/* get the IFXOS version definitons */
#include "ifxos_version.h"

/* ============================================================================
   IFX OS adaptation - Debug and Error Printout
   ========================================================================= */
/** \addtogroup IFXOS_COMMON
@{ */

#ifndef IFXOS_DEBUG_USR_PRINT
   /** defines the Debug Printout (User Level) */
#  define IFXOS_DEBUG_USR_PRINT                    1
#endif

#ifndef IFXOS_DEBUG_INT_PRINT
   /** defines the Debug Printout (Interrupt Level) */
#  define IFXOS_DEBUG_INT_PRINT                    1
#endif

#ifndef IFXOS_ERROR_USR_PRINT
   /** defines the Error Printout (User Level) */
#  define IFXOS_ERROR_USR_PRINT                    1
#endif

#ifndef IFXOS_ERROR_INT_PRINT
   /** defines the Error Printout (Interrupt Level) */
#  define IFXOS_ERROR_INT_PRINT                    1
#endif


/* ============================================================================
   IFX OS adaptation - Endianess
   ========================================================================= */

#ifndef IFXOS_LITTLE_ENDIAN
   /**
      Definition for the LITTLE endianess handling.
      To be OS independent set an own definition.
   */
#  define IFXOS_LITTLE_ENDIAN                            1234
#endif

#ifndef IFXOS_BIG_ENDIAN
   /**
      Definition for the BIG endianess handling.
      To be OS independent set an own definition.
   */
#  define IFXOS_BIG_ENDIAN                               4321
#endif

/* ============================================================================
   IFX OS adaptation - includes
   ========================================================================= */
#if ( !defined(IFXOS_FLAT_HIRACHY) || (IFXOS_FLAT_HIRACHY == 0) )
#  if defined(LINUX)
#     include "linux/ifxos_linux_common.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_common.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_common.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_common.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_common.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_common.h"
#  elif defined(XAPI)
#     include "xapi/ifxos_xapi_common.h"
#  elif defined(SUN_OS)
#     include "sun_os/ifxos_sun_os_common.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_common.h"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_common.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_common.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_common.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_common.h"
#  elif defined(WIN32)
#     include "ifxos_win32_common.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_common.h"
#  elif defined(XAPI)
#     include "ifxos_xapi_common.h"
#  elif defined(SUN_OS)
#     include "ifxos_sun_os_common.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_common.h"
#  else
#     error "IFX OS common defines - Please define your OS"
#  endif
#endif


/* ============================================================================
   IFX OS adaptation - Misc
   ========================================================================= */

/**
   The function call will wait forever until the event occur.
*/
#define IFXOS_WAIT_FOREVER    0xFFFFFFFF

/**
   Don't wait at all. The function will check the condition and will return 
   immediately.
*/
#define IFXOS_NO_WAIT         0x00000000     
      
/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_COMMON_H */

