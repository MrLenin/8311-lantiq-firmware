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
   "Miscellaneous functions".
*/

/* ============================================================================
   IFX Nucleus adaptation - Global Includes
   ========================================================================= */

#include "ifx_types.h"
#include "ifxos_misc.h"

/* ============================================================================
   IFX Nucleus adaptation - User Space, Miscellaneous functions
   ========================================================================= */

/** \addtogroup IFXOS_MISC
@{ */

#if ( defined(IFXOS_HAVE_MISC) && (IFXOS_HAVE_MISC == 1) )
/**
   Reboot the board
*/   
IFX_void_t IFXOS_Reboot (void)
{
   return;
}
#endif /* #if ( defined(IFXOS_HAVE_MISC) && (IFXOS_HAVE_MISC == 1) ) */

/** @} */

#endif      /* #ifdef NUCLEUS_PLUS */


