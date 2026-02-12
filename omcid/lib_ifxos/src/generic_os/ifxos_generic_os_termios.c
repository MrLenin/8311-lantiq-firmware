/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef GENERIC_OS

/** \file
   This file contains the IFXOS Layer implementation for GENERIC_OS Application 
   "Terminal IO System".
*/

/* ============================================================================
   IFX GENERIC_OS adaptation - Global Includes
   ========================================================================= */
/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_termios.h"

/* ============================================================================
   IFX GENERIC_OS adaptation - User Space, Terminal IO System
   ========================================================================= */

/** \addtogroup IFXOS_TERMIOS_GENERIC_OS_APPL
@{ */

#if ( defined(IFXOS_HAVE_TERMIOS) && (IFXOS_HAVE_TERMIOS == 1) )
/**
   Disable the local echo of the console.
*/   
IFX_void_t IFXOS_EchoOff (void)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation
   */

   return;
}

/**
   Enable the local echo of the console.
*/   
IFX_void_t IFXOS_EchoOn (void)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation
   */
   return;
}

/**
   Enable the console line mode.
   In this mode the input from the device is available only after receiving NEWLINE . 
   This allows to modify the command line until the Enter key is pressed.
*/   
IFX_void_t IFXOS_KeypressSet (void)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation
   */

   return;
}

/**
   Disable the console line mode. 
   Plesae refer to \ref IFXOS_KeypressSet .
*/   
IFX_void_t IFXOS_KeypressReset (void)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation
   */

   return;
}
#endif      /* #if ( defined(IFXOS_HAVE_TERMIOS) && (IFXOS_HAVE_TERMIOS == 1) ) */

/** @} */

#endif      /* #ifdef GENERIC_OS */


