#ifndef _IFXOS_TERMIOS_H
#define _IFXOS_TERMIOS_H
/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   This file contains definitions for the Terminal IO System.
*/

/** \defgroup IFXOS_IF_TERMIOS Terminal IO System

   This Group contains the Terminal IO System definitions and function. 

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
#     include "linux/ifxos_linux_termios.h"
#  elif defined(VXWORKS)
#     include "vxworks/ifxos_vxworks_termios.h"
#  elif defined(ECOS)
#     include "ecos/ifxos_ecos_termios.h"
#  elif defined(NUCLEUS_PLUS)
#     include "nucleus/ifxos_nucleus_termios.h"
#  elif defined(WIN32)
#     include "win32/ifxos_win32_termios.h"
#  elif defined(RTEMS)
#     include "rtems/ifxos_rtems_termios.h"
#  elif defined(GENERIC_OS)
#     include "generic_os/ifxos_generic_os_termios.h"
#  else
#     error "Terminal IO Adaptation - Please define your OS"
#  endif
#else
#  if defined(LINUX)
#     include "ifxos_linux_termios.h"
#  elif defined(VXWORKS)
#     include "ifxos_vxworks_termios.h"
#  elif defined(ECOS)
#     include "ifxos_ecos_termios.h"
#  elif defined(NUCLEUS_PLUS)
#     include "ifxos_nucleus_termios.h"
#  elif defined(WIN32)
#     include "ifxos_win32_termios.h"
#  elif defined(RTEMS)
#     include "ifxos_rtems_termios.h"
#  elif defined(GENERIC_OS)
#     include "ifxos_generic_os_termios.h"
#  else
#     error "Terminal IO Adaptation - Please define your OS"
#  endif
#endif

#include "ifx_types.h"

/* ============================================================================
   IFX OS adaptation - Terminal IO System
   ========================================================================= */

/** \addtogroup IFXOS_IF_TERMIOS
@{ */

#if ( defined(IFXOS_HAVE_TERMIOS) && (IFXOS_HAVE_TERMIOS == 1) )
/**
   Disable the local echo of the console.
*/   
IFX_void_t IFXOS_EchoOff (void);

/**
   Enable the local echo of the console.
*/   
IFX_void_t IFXOS_EchoOn (void);

/**
   Enable the console line mode.
   In this mode the input from the device is available only after receiving NEWLINE . This allows
   to modify the command line until the Enter key is pressed.
*/   
IFX_void_t IFXOS_KeypressSet (void);

/**
   Disable the console line mode. Plesae refer to \ref IFXOS_KeypressSet .
*/   
IFX_void_t IFXOS_KeypressReset (void);

#endif

/** @} */

#ifdef __cplusplus
}
#endif

#endif      /* #ifndef _IFXOS_TERMIOS_H */

