#ifndef _IFXOS_INTERRUPT_H
#define _IFXOS_INTERRUPT_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for interupt handling within driver.
*/

/** \defgroup IFXOS_INTERRUPT Interrupt Sub System.

   This Group contains the interrupt sub system definitions and function. 

   The functions are available for driver code.

\ingroup IFXOS_INTERFACE
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Includes
   ========================================================================= */
#if ( !defined(IFXOS_FLAT_HIRACHY) || (IFXOS_FLAT_HIRACHY == 0) )
#  if defined(LINUX)
#     include "linux/ifxos_linux_interrupt.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_interrupt.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_interrupt.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_interrupt.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_interrupt.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_interrupt.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_interrupt.h"
#  elif defined(XAPI)
#     include "xapi/ifxos_xapi_interrupt.h"
#  else
#     error "INTERRUPT Adaptation - Please define your OS"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_interrupt.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_interrupt.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_interrupt.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_interrupt.h"
#  elif defined(WIN32)
#     include "ifxos_win32_interrupt.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_interrupt.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_interrupt.h"
#  elif defined(XAPI)
#     include "ifxos_xapi_interrupt.h"
#  else
#     error "INTERRUPT Adaptation - Please define your OS"
#  endif
#endif

#include "ifx_types.h"

/* ============================================================================
   IFX OS adaptation - interrupt handling, typedefs
   ========================================================================= */
/** \addtogroup IFXOS_INTERRUPT
@{ */

/* ============================================================================
   IFX OS adaptation - interrupt handling, functions
   ========================================================================= */


/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_INTERRUPT_H */




