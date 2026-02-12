/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_octrlg.h
*/
#ifndef _drv_optic_ll_octrlg_h
#define _drv_optic_ll_octrlg_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"
#include "drv_optic_common.h"



EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_OCTRLG_INTERNAL OCTRLG Interface Module - Internal
   @{
*/

enum optic_errorcode optic_ll_octrlg_ageupdate ( uint8_t *seconds );



/*! @} */

/*! @} */

EXTERN_C_END

#endif
