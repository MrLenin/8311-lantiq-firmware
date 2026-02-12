/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_dcdc_ddr.h
*/
#ifndef _drv_optic_dcdc_ddr_h
#define _drv_optic_dcdc_ddr_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_DCDC_APD_INTERNAL DCDC DDR Module - Internal
   @{
*/

enum optic_errorcode optic_dcdc_ddr_voltage_set ( struct optic_control *p_ctrl,
						  const uint16_t vddr );
enum optic_errorcode optic_dcdc_ddr_voltage_get ( struct optic_control *p_ctrl,
						  uint16_t *vddr );

/*! @} */

/*! @} */

EXTERN_C_END

#endif
