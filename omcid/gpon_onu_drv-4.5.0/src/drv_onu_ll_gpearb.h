/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_gpearb_h
#define _drv_onu_gpearb_h

/** \addtogroup ONU_LL_REFERENCE GPON Low-level Functions
   @{
*/

/** \addtogroup ONU_LL_GPEARB GPE Arbiter Low-level Functions

   Low-level functions to access the GPE arbiter module.
   @{
*/

#include "drv_onu_gpe_interface.h"

/**
   Get GPEARB block mode.
*/
enum gpe_arb_mode gpearb_mode_get(void);

/**
   Initialize the GPEARB block.
*/
void gpearb_init(enum gpe_arb_mode arb_mode);

#if defined(INCLUDE_DUMP)

/**
   Dump the GPEARB register block.
*/
void gpearb_dump(struct seq_file *s);

#endif

/*! @} */

/*! @} */

#endif
