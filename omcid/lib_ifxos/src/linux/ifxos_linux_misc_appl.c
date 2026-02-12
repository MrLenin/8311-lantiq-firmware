/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX

/** \file
   This file contains the IFXOS Layer implementation for LINUX Application 
   "Miscellaneous functions".
*/

/* ============================================================================
   IFX Linux adaptation - Global Includes
   ========================================================================= */
#include <signal.h>

#include "ifx_types.h"
#include "ifxos_misc.h"

/* ============================================================================
   IFX Linux adaptation - Application Space, Miscellaneous functions
   ========================================================================= */

/** \addtogroup IFXOS_MISC
@{ */

#if ( defined(IFXOS_HAVE_MISC) && (IFXOS_HAVE_MISC == 1) )
/**
   Reboot the board
*/   
IFX_void_t IFXOS_Reboot (void)
{
   kill(1, SIGTERM);
   return;
}
#endif /* #if ( defined(IFXOS_HAVE_MISC) && (IFXOS_HAVE_MISC == 1) ) */

/** @} */

#endif      /* #ifdef LINUX */

