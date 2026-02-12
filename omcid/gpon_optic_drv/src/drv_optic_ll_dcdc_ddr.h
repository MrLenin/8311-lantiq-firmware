/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_dcdc_ddr.h
*/
#ifndef _drv_optic_ll_dcdc_ddr_h
#define _drv_optic_ll_dcdc_ddr_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"
#include "drv_optic_common.h"


EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_DCDC_DDR_INTERNAL DC/DC DDR Converter Module - Internal
   @{
*/

enum optic_errorcode optic_ll_dcdc_ddr_set ( const enum optic_activation
					     mode );
enum optic_errorcode optic_ll_dcdc_ddr_get ( enum optic_activation *mode );
enum optic_errorcode optic_ll_dcdc_ddr_voltage_set ( const int8_t
						     offset_dcdc_ddr,
						     const uint8_t
						     gain_dcdc_ddr,
                                                     const uint16_t vddr );
enum optic_errorcode optic_ll_dcdc_ddr_voltage_get ( const int8_t
						     offset_dcdc_ddr,
						     const uint8_t
						     gain_dcdc_ddr,
				                     uint16_t *vddr );
enum optic_errorcode optic_ll_dcdc_ddr_dutycycle_set ( const uint8_t min,
						       const uint8_t max );
enum optic_errorcode optic_ll_dcdc_ddr_dutycycle_get ( uint8_t *min,
						       uint8_t *max );
enum optic_errorcode optic_ll_dcdc_ddr_deadzone_set ( const uint8_t del_p,
							const uint8_t del_n );

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_DCDC == ACTIVE))
enum optic_errorcode optic_ll_dcdc_ddr_dump ( void );
#endif


/*! @} */

/*! @} */

EXTERN_C_END

#endif
