/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef ECOS

/** \file
   This file contains the IFXOS Layer implementation for eCos Application 
   "Terminal IO System".
*/

/* ============================================================================
   IFX eCos adaptation - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_termios.h"

#include <stdio.h>

/* ============================================================================
   IFX eCos adaptation - User Space, Terminal IO System
   ========================================================================= */

/** \addtogroup IFXOS_TERMIOS_ECOS_APPL
@{ */

#if ( defined(IFXOS_HAVE_TERMIOS) && (IFXOS_HAVE_TERMIOS == 1) )

#include <termios.h> /* tcgetattr */

static struct termios stored_stdin_settings,
                      stored_stdout_settings;

/**
   Disable the local echo of the console.
*/   
IFX_void_t IFXOS_EchoOff (void)
{
   struct termios new_settings;
   tcgetattr(fileno(stdout),&stored_stdout_settings);
   new_settings = stored_stdout_settings;
   new_settings.c_lflag &= (~ECHO);
   tcsetattr(fileno(stdout),TCSANOW,&new_settings);
}

/**
   Enable the local echo of the console.
*/   
IFX_void_t IFXOS_EchoOn (void)
{
   tcsetattr(fileno(stdout),TCSANOW,&stored_stdout_settings);
}

/**
   Enable the console line mode.
   In this mode the input from the device is available only after receiving NEWLINE . 
   This allows to modify the command line until the Enter key is pressed.
*/   
IFX_void_t IFXOS_KeypressSet (void)
{
   struct termios new_settings;

   tcgetattr(fileno(stdin),&stored_stdin_settings);

   new_settings = stored_stdin_settings;

   /* Disable canonical mode */
   new_settings.c_lflag &= ~(ICANON);
   /* set buffer size to 0 byte / timeout 100 ms */
   new_settings.c_cc[VTIME] = 10;
   new_settings.c_cc[VMIN] = 0;

   tcsetattr(fileno(stdin),TCSANOW,&new_settings);
}

/**
   Disable the console line mode. 
   Plesae refer to \ref IFXOS_KeypressSet .
*/   
IFX_void_t IFXOS_KeypressReset (void)
{
   tcsetattr(fileno(stdin),TCSANOW,&stored_stdin_settings);
}

#endif      /* #if ( defined(IFXOS_HAVE_TERMIOS) && (IFXOS_HAVE_TERMIOS == 1) ) */

/** @} */

#endif      /* #ifdef ECOS */
