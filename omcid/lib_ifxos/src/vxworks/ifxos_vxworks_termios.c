/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef VXWORKS

/** \file
   This file contains the IFXOS Layer implementation for VxWorks Application 
   "Terminal IO System".
*/

/* ============================================================================
   IFX VxWorks adaptation - Global Includes
   ========================================================================= */
#include <vxWorks.h>
#include <stdio.h>
#include <ioLib.h>
#if 0
--> check
#include <sys/ioctl.h>
#include <tyLib.h>
#endif

#include "ifx_types.h"
#include "ifxos_termios.h"

/* ============================================================================
   IFX VxWorks adaptation - User Space, Terminal IO System
   ========================================================================= */

/** \addtogroup IFXOS_TERMIOS_VXWORKS_APPL
@{ */

#if ( defined(IFXOS_HAVE_TERMIOS) && (IFXOS_HAVE_TERMIOS == 1) )
/**
   Disable the local echo of the console.
*/   
IFX_void_t IFXOS_EchoOff (void)
{
#ifndef _lint
   int options;
   int iofd = fileno(stdout);

   options = ioctl(iofd, FIOGETOPTIONS, 0);
   ioctl(iofd, FIOSETOPTIONS, (int)(options & ~OPT_ECHO));
#endif   
}

/**
   Enable the local echo of the console.
*/   
IFX_void_t IFXOS_EchoOn (void)
{
#ifndef _lint
   int options;
   int iofd = fileno(stdout);

   options = ioctl(iofd, FIOGETOPTIONS, 0);
   ioctl(iofd, FIOSETOPTIONS, (int)(options | OPT_ECHO));
#endif   
}

/**
   Enable the console line mode.
   In this mode the input from the device is available only after receiving NEWLINE . 
   This allows to modify the command line until the Enter key is pressed.
*/   
IFX_void_t IFXOS_KeypressSet (void)
{
#ifndef _lint
   int options;
   int iofd = fileno(stdin);

   options = ioctl(iofd, FIOGETOPTIONS, 0);
   ioctl(iofd, FIOSETOPTIONS, (int)(options & ~OPT_LINE));
#endif   
}

/**
   Disable the console line mode. 
   Plesae refer to \ref IFXOS_KeypressSet .
*/   
IFX_void_t IFXOS_KeypressReset (void)
{
#ifndef _lint
   int options;
   int iofd = fileno(stdin);

   options = ioctl(iofd, FIOGETOPTIONS, 0);
   ioctl(iofd, FIOSETOPTIONS, (int)(options | OPT_LINE));
#endif   
}
#endif      /* #if ( defined(IFXOS_HAVE_TERMIOS) && (IFXOS_HAVE_TERMIOS == 1) ) */

/** @} */

#endif      /* #ifdef VXWORKS */


