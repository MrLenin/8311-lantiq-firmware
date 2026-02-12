/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation - Terminal IO System (Application Space)
   ========================================================================= */

#ifdef LINUX

/** \file
   This file contains the IFXOS Layer implementation for LINUX Application 
   "Terminal IO System".
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes
   ========================================================================= */
#define _GNU_SOURCE     1
#include <features.h>

#include <stdio.h>
#include <termios.h>
#include <unistd.h>

#include "ifx_types.h"
#include "ifxos_termios.h"

#ifdef IFXOS_STATIC
#undef IFXOS_STATIC
#endif

#ifdef IFXOS_DEBUG
#define IFXOS_STATIC
#else
#define IFXOS_STATIC   static
#endif

/* ============================================================================
   IFX Linux adaptation - Application Space, Terminal IO System
   ========================================================================= */

/** \addtogroup IFXOS_TERMIOS_LINUX_APPL
@{ */
#if ( defined(IFXOS_HAVE_TERMIOS) && (IFXOS_HAVE_TERMIOS == 1) )

/**
   Disable the local echo of the console.
*/   
IFX_void_t IFXOS_EchoOff (void)
{
   struct termios settings;

   tcgetattr(fileno(stdin), &settings);
   settings.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
   tcsetattr(fileno(stdin), TCSANOW, &settings);
}

/**
   Enable the local echo of the console.
*/   
IFX_void_t IFXOS_EchoOn (void)
{
   struct termios settings;

   tcgetattr(fileno(stdin), &settings);
   settings.c_lflag |= ECHO | ECHOE | ECHOK | ECHONL;
   tcsetattr(fileno(stdin), TCSANOW, &settings);
}

/**
   Enable the console line mode.
   In this mode the input from the device is available only after receiving NEWLINE . 
   This allows to modify the command line until the Enter key is pressed.
*/   
IFX_void_t IFXOS_KeypressSet (void)
{
   struct termios settings;

   tcgetattr(fileno(stdin), &settings);

   /* Disable canonical mode */
   settings.c_lflag &= ~(ICANON);

   tcsetattr(fileno(stdin),TCSANOW,&settings);
}

/**
   Disable the console line mode. 
   Plesae refer to \ref IFXOS_KeypressSet .
*/   
IFX_void_t IFXOS_KeypressReset (void)
{
   struct termios settings;

   tcgetattr(fileno(stdin), &settings);

   /* Enable canonical mode */
   settings.c_lflag |= ICANON;

   tcsetattr(fileno(stdin),TCSANOW,&settings);
}
#endif   /* #if ( defined(IFXOS_HAVE_TERMIOS) && (IFXOS_HAVE_TERMIOS == 1) ) */

/** @} */

#endif      /* #ifdef LINUX */

