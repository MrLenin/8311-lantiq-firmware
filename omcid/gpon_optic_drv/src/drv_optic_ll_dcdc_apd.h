/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_dcdc_apd.h
*/
#ifndef _drv_optic_ll_dcdc_apd_h
#define _drv_optic_ll_dcdc_apd_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"
#include "drv_optic_common.h"


EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/


/** \addtogroup OPTIC_DCDC_APD_INTERNAL DC/DC APD Converter Module - Internal
   @{
*/


enum optic_errorcode optic_ll_dcdc_apd_init ( void );
enum optic_errorcode optic_ll_dcdc_apd_exit ( void );
enum optic_errorcode optic_ll_dcdc_apd_set ( const enum optic_activation mode );
enum optic_errorcode optic_ll_dcdc_apd_get ( enum optic_activation *mode );
enum optic_errorcode optic_ll_dcdc_apd_voltage_set ( const int8_t
						     offset_dcdc_apd,
						     const uint8_t
						     gain_dcdc_apd,
						     const uint16_t ext_att,
						     const uint16_t vapd_desired,
						     uint16_t *vapd_actual
						     );
enum optic_errorcode optic_ll_dcdc_apd_voltage_get ( const int8_t
						     offset_dcdc_apd,
						     const uint8_t
						     gain_dcdc_apd,
						     const uint16_t ext_att,
				             uint16_t *vapd_read,
				             int16_t *reg_error );
enum optic_errorcode optic_ll_dcdc_apd_saturation_set ( const uint8_t sat );
enum optic_errorcode optic_ll_dcdc_apd_saturation_get ( uint8_t *sat );

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_DCDC == ACTIVE))
enum optic_errorcode optic_ll_dcdc_apd_dump ( void );
#endif


/*! @} */

/*! @} */

EXTERN_C_END

#endif
