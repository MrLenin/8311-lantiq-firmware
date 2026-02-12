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
   "Miscellaneous functions".
*/

/* ============================================================================
   IFX GENERIC_OS Adaptation Frame - Global Includes
   ========================================================================= */
/*
   Customer-ToDo:
   Include your customer OS header required for the implementation.
*/

#include "ifx_types.h"
#include "ifxos_rt_if_check.h"
#include "ifxos_misc.h"

/* ============================================================================
   IFX GENERIC_OS Adaptation Frame - User Space, Miscellaneous functions
   ========================================================================= */
/** \addtogroup IFXOS_MISC
@{ */

#if ( defined(IFXOS_HAVE_MISC) && (IFXOS_HAVE_MISC == 1) )
/**
   Reboot the board
*/   
IFX_void_t IFXOS_Reboot (void)
{
   /*
      Customer-ToDo:
      Fill with your customer OS implementation like:
      - reboot(BOOT_CLEAR);
   */

   return;
}
#endif /* #if ( defined(IFXOS_HAVE_MISC) && (IFXOS_HAVE_MISC == 1) ) */

/** @} */

#endif      /* #ifdef GENERIC_OS */


