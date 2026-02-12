/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef NUCLEUS_PLUS

/** \file
   This file contains the IFXOS Layer implemantation for Nucleus Application 
   "Terminal IO System".
*/

/* ============================================================================
   IFX Nucleus adaptation - Global Includes
   ========================================================================= */
#include <nucleus.h>
#include <stdio.h>

#include "ifx_types.h"
#include "ifxos_termios.h"

/* ============================================================================
   IFX Nucleus adaptation - User Space, Terminal IO System
   ========================================================================= */

/** \addtogroup IFXOS_TERMIOS_NUCLEUS_APPL
@{ */

#if ( defined(IFXOS_HAVE_TERMIOS) && (IFXOS_HAVE_TERMIOS == 1) )
/**
   Disable the local echo of the console.
*/   
IFX_void_t IFXOS_EchoOff (void)
{
}

/**
   Enable the local echo of the console.
*/   
IFX_void_t IFXOS_EchoOn (void)
{
}

/**
   Enable the console line mode.
   In this mode the input from the device is available only after receiving NEWLINE . 
   This allows to modify the command line until the Enter key is pressed.
*/   
IFX_void_t IFXOS_KeypressSet (void)
{
}

/**
   Disable the console line mode. 
   Please refer to \ref IFXOS_KeypressSet .
*/   
IFX_void_t IFXOS_KeypressReset (void)
{
}
#endif      /* #if ( defined(IFXOS_HAVE_TERMIOS) && (IFXOS_HAVE_TERMIOS == 1) ) */

/** @} */

#endif      /* #ifdef NUCLEUS_PLUS */


