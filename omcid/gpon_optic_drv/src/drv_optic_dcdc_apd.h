/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_dcdc_apd.h
*/
#ifndef _drv_optic_dcdc_apd_h
#define _drv_optic_dcdc_apd_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_DCDC_APD_INTERNAL DCDC APD Module - Internal
   @{
*/

enum optic_errorcode optic_dcdc_apd_voltage_set ( struct optic_control *p_ctrl,
						  const uint16_t vapd,
						  const uint8_t sat );
void optic_timer_dcdc_apd_adapt (struct optic_control *p_ctrl);
enum optic_errorcode optic_dcdc_apd_voltage_get ( struct optic_control *p_ctrl,
						  uint16_t *vapd,
						  int16_t *regulation_error );
enum optic_errorcode optic_dcdc_apd_update ( struct optic_control *p_ctrl );

/*! @} */

/*! @} */

EXTERN_C_END

#endif
