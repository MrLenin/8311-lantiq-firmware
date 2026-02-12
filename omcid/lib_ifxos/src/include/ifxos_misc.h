#ifndef _IFXOS_MISC_H
#define _IFXOS_MISC_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for the Miscellaneous functions.
*/

/** \defgroup IFXOS_IF_MISC Miscellaneous functions

   This Group contains the Miscellaneous functions. 

\ingroup IFXOS_INTERFACE
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Global Includes
   ========================================================================= */
#if ( !defined(IFXOS_FLAT_HIRACHY) || (IFXOS_FLAT_HIRACHY == 0) )
#  if defined(LINUX)
#     include "linux/ifxos_linux_misc.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_misc.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_misc.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_misc.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_misc.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_misc.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_misc.h"
#  else
#     error "Terminal IO Adaptation - Please define your OS"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_misc.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_misc.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_misc.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_misc.h"
#  elif defined(WIN32)
#     include "ifxos_win32_misc.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_misc.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_misc.h"
#  else
#     error "Miscellaneous functions - Please define your OS"
#  endif
#endif

#include "ifx_types.h"

/* ============================================================================
   IFX OS adaptation - Miscellaneous functions
   ========================================================================= */

/** \addtogroup IFXOS_MISC
@{ */

#if ( defined(IFXOS_HAVE_MISC) && (IFXOS_HAVE_MISC == 1) )
/**
   Reboot the board
*/   
IFX_void_t IFXOS_Reboot (void);

#endif

/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_MISC_H */

