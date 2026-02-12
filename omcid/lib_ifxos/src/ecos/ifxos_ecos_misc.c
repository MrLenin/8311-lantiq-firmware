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
   "Miscellaneous functions".
*/

/* ============================================================================
   IFX eCos adaptation - Global Includes
   ========================================================================= */

#include <cyg/kernel/kapi.h>
/*#include <cyg/hal/quicc/ppc8xx.h>
*/
#include "ifx_types.h"
#include "ifxos_misc.h"

/* ============================================================================
   IFX eCos adaptation - User Space, Miscellaneous functions
   ========================================================================= */

/** \addtogroup IFXOS_MISC
@{ */

#if ( defined(IFXOS_HAVE_MISC) && (IFXOS_HAVE_MISC == 1) )

/**
   Reboot the board
*/   
IFX_void_t IFXOS_Reboot (void)
{
   HAL_PLATFORM_RESET();
   return;
}
#endif /* #if ( defined(IFXOS_HAVE_MISC) && (IFXOS_HAVE_MISC == 1) ) */

/** @} */

#endif      /* #ifdef ECOS */


