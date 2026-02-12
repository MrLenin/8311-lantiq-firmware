/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_dcdc_core.h
*/
#ifndef _drv_optic_dcdc_core_h
#define _drv_optic_dcdc_core_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_DCDC_APD_INTERNAL DCDC CORE Module - Internal
   @{
*/

enum optic_errorcode optic_dcdc_core_voltage_set ( struct optic_control *p_ctrl,
						   const uint16_t vcore );
enum optic_errorcode optic_dcdc_core_voltage_get ( struct optic_control *p_ctrl,
						   uint16_t *vcore );

/*! @} */

/*! @} */

EXTERN_C_END

#endif
