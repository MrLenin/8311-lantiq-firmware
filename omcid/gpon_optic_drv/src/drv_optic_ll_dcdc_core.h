/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_dcdc_core.h
*/
#ifndef _drv_optic_ll_dcdc_core_h
#define _drv_optic_ll_dcdc_core_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"
#include "drv_optic_common.h"


EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_DCDC_CORE_INTERNAL DC/DC CORE Converter Module - Internal
   @{
*/

enum optic_errorcode optic_ll_dcdc_core_set ( const enum optic_activation
					      mode );
enum optic_errorcode optic_ll_dcdc_core_get ( enum optic_activation *mode );
enum optic_errorcode optic_ll_dcdc_core_voltage_set ( const int8_t
						      offset_dcdc_core,
						      const uint8_t
						      gain_dcdc_core,
                                                      const uint16_t vcore );
enum optic_errorcode optic_ll_dcdc_core_voltage_get ( const int8_t
						      offset_dcdc_core,
						      const uint8_t
						      gain_dcdc_core,
				                      uint16_t *vcore );
enum optic_errorcode optic_ll_dcdc_core_dutycycle_set ( const uint8_t min,
							const uint8_t max );
enum optic_errorcode optic_ll_dcdc_core_dutycycle_get ( uint8_t *min,
							uint8_t *max );
enum optic_errorcode optic_ll_dcdc_core_deadzone_set ( const uint8_t del_p,
							const uint8_t del_n );
enum optic_errorcode optic_ll_dcdc_core_restore_hw_values (void);

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_DCDC == ACTIVE))
enum optic_errorcode optic_ll_dcdc_core_dump ( void );
#endif


/*! @} */

/*! @} */

EXTERN_C_END

#endif
