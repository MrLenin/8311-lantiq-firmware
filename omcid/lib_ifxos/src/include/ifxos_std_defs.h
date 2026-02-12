#ifndef _IFXOS_STD_DEFS_H
#define _IFXOS_STD_DEFS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains standard definitions and includes for the IFX OS.
*/

/** \defgroup IFXOS_STD_DEFS IFXOS Standard Defines

   This Group contains the standard definition and includes.
*/

#ifdef __cplusplus
   extern "C" {
#endif

/* ============================================================================
   IFX OS adaptation - Debug and Error Printout
   ========================================================================= */
/** \addtogroup IFXOS_STD_DEFS
@{ */

/* ============================================================================
   IFX OS adaptation - includes
   ========================================================================= */
#if ( !defined(IFXOS_FLAT_HIRACHY) || (IFXOS_FLAT_HIRACHY == 0) )
#  ifdef _lint
#     include "lint/ifxos_lint_std_defs.h"
#  elif defined(LINUX)
#     include "linux/ifxos_linux_std_defs.h"
#  elif defined(SUN_OS)
#     include "sun_os/ifxos_sun_os_std_defs.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_std_defs.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_std_defs.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_std_defs.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_std_defs.h"
#  elif defined(XAPI)
#     include "xapi/ifxos_xapi_std_defs.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_std_defs.h"
#  endif
#else
#  ifdef _lint
#     include "ifxos_lint_std_defs.h"
#  elif defined(LINUX)
#     include "ifxos_linux_std_defs.h"
#  elif defined(SUN_OS)
#     include "ifxos_sun_os_std_defs.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_std_defs.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_std_defs.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_std_defs.h"
#  elif defined(WIN32)
#     include "ifxos_win32_std_defs.h"
#  elif defined(XAPI)
#     include "ifxos_xapi_std_defs.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_std_defs.h"
#  else
#     error "IFX OS common defines - Please define your OS"
#  endif
#endif

/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_STD_DEFS_H */
