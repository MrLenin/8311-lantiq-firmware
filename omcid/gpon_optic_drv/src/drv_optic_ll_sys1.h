/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_sys1.h
*/
#ifndef _drv_optic_ll_sys1_h
#define _drv_optic_ll_sys1_h

#include "drv_optic_api.h"
#include "drv_optic_common.h"

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_SYS1_INTERNAL SYS1 Module - Internal
   @{
*/


enum optic_errorcode optic_ll_sys1_ldo_set ( const enum optic_activation mode );
enum optic_errorcode optic_ll_sys1_ldo_get ( enum optic_activation *mode );

/*! @} */

/*! @} */

EXTERN_C_END

#endif
