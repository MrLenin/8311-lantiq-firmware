#ifndef _IFXOS_PRINT_H
#define _IFXOS_PRINT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for Printout.
*/

/** \defgroup IFXOS_IF_PRINT Printout Defines

   This Group contains the Printout definitions and function.

   Here we have to differ between:\n
   - printout from user code
   - printout form driver code
   - printout on user level
   - printout on interrupt level

\par VXWORKS Printouts
   Under VxWorks the printout on interrupt and user level has to be done via
   different functions. But there is no difference between the printouts from 
   user or driver space

\par Linux Printouts
   Under Linux the printout from driver code (kernel space) is different form 
   printouts on user space (application). But there is no difference between
   printouts on user or interrupt level.

\par Linux Kernel Printouts
   For enable kernel printouts on the console you have to make sure that the 
   printout is enabled on system level. For enable use the following command:
   # echo 8 > /proc/sys/kernel/printk

\ingroup IFXOS_IF_PRINTOUT_DEBUG
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Includes
   ========================================================================= */
#if ( !defined(IFXOS_FLAT_HIRACHY) || (IFXOS_FLAT_HIRACHY == 0) )
#  if defined(LINUX)
#     include "linux/ifxos_linux_print.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_print.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_print.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_print.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_print.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_print.h"
#  elif defined(SUN_OS)
#     include "sun_os/ifxos_sun_os_print.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_print.h"
#  elif defined(XAPI)
#     include "xapi/ifxos_xapi_print.h"
#  else
#     error "Printout Adaptation - Please define your OS"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_print.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_print.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_print.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_print.h"
#  elif defined(WIN32)
#     include "ifxos_win32_print.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_print.h"
#  elif defined(SUN_OS)
#     include "ifxos_sun_os_print.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_print.h"
#  elif defined(XAPI)
#     include "ifxos_xapi_print.h"
#  else
#     error "Printout Adaptation - Please define your OS"
#  endif
#endif

#include "ifx_types.h"

#if ( defined(IFXOS_HAVE_PRINT_STREAM) && (IFXOS_HAVE_PRINT_STREAM == 1) )
#  include "ifxos_file_access.h"
#endif

/* ============================================================================
   IFX OS adaptation - Types and Defines
   ========================================================================= */

/** \addtogroup IFXOS_IF_PRINT
@{ */

/** This defines the function prototype for a external debug printout function */
typedef IFX_int_t (*IFXOS_FCT_DbgPrintf)(const IFX_char_t *, ...)
#if defined(__GNUC__) && defined(IFXOS_CHECK_ARGUMENTS)
   __attribute__ ((format (printf, 1, 2)))
#endif
;

/** This defines the function prototype for a external error printout function */
typedef IFX_int_t (*IFXOS_FCT_ErrPrintf)(const IFX_char_t *, ...)
#if defined(__GNUC__) && defined(IFXOS_CHECK_ARGUMENTS)
   __attribute__ ((format (printf, 1, 2)))
#endif
;

#if ( defined(IFXOS_HAVE_PRINT) && (IFXOS_HAVE_PRINT == 1) )

/** export the debug printout function pointer */
extern IFXOS_FCT_DbgPrintf IFXOS_fctDbgPrintf;
/** export the error printout function pointer */
extern IFXOS_FCT_ErrPrintf IFXOS_fctErrPrintf;

#if ( defined(IFXOS_HAVE_PRINT_STREAM) && (IFXOS_HAVE_PRINT_STREAM == 1) )
/** output stream for debug printouts */
extern IFXOS_File_t *pIFXOS_DbgPrintStream;
/** output stream for error printouts */
extern IFXOS_File_t *pIFXOS_ErrPrintStream;
#endif

#if ( defined(IFXOS_HAVE_PRINT_EXT_DBG_FCT) && (IFXOS_HAVE_PRINT_EXT_DBG_FCT == 1) )
/**
   Set the user specific printout function for debug printouts.

\param
   fctExtDbg   - function pointer to the user debug function

\return      
   NONE
*/
IFX_void_t IFXOS_PrintDbgFctSet(IFXOS_FCT_DbgPrintf fctExtDbg);
#endif

#if ( defined(IFXOS_HAVE_PRINT_EXT_ERR_FCT) && (IFXOS_HAVE_PRINT_EXT_ERR_FCT == 1) )
/**
   Set the user specific printout function for error printouts.

\param
   fctExtErr   - function pointer to the user debug function

\return      
   NONE
*/
IFX_void_t IFXOS_PrintErrFctSet(IFXOS_FCT_ErrPrintf fctExtErr);
#endif

#endif      /* #if ( defined(IFXOS_HAVE_PRINT) && (IFXOS_HAVE_PRINT == 1) ) */
/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_PRINT_H */

