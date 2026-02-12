/******************************************************************************

                              Copyright (c) 2009
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* ============================================================================
   Description : IFX Linux adaptation - IFX OS debug module
   ========================================================================= */

/* ============================================================================
   IFX Linux adaptation - Global Includes
   ========================================================================= */
#include "ifxos_debug.h"

/* ============================================================================
   IFX Linux adaptation - debug printout level
   ========================================================================= */

/* Create IFX OS debug module - user part */
IFXOS_PRN_USR_MODULE_CREATE(IFXOS, IFXOS_PRN_LEVEL_HIGH);
/* Create IFX OS debug module - interrupt part */
IFXOS_PRN_INT_MODULE_CREATE(IFXOS, IFXOS_PRN_LEVEL_HIGH);

