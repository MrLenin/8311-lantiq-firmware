/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_mm.h
*/
#ifndef _drv_optic_ll_mm_h
#define _drv_optic_ll_mm_h

#ifndef SYSTEM_SIMULATION
#include "drv_optic_api.h"
#include "drv_optic_common.h"
#else
#include "drv_optic_simu.h"
#endif


EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_MM_INTERNAL Measurement Module - Internal
   @{
*/

#define OPTIC_MM_ADC_RESET              0x004C9262
#define OPTIC_MM_M_SET_RESET            0x00000000

#define OPTIC_MM_CFG_MM_DECCFG_INIT              4
#define OPTIC_MM_CFG_MM_CLKCFG_INIT           0xF2
#define OPTIC_M_TIME_CONFIG_MEAS_TIME_INIT   62000

#define OPTIC_MM_CHANNELS   10
/* parallel mode */
/* "channel"-value > 10 means: channel = { 0 ... (value-10) } <- multiple
   measurement via several channels */
#define OPTIC_CHANNEL_MEASURE_GAIN              12
#define OPTIC_CHANNEL_MEASURE_OFFSET            12
#define OPTIC_CHANNEL_MEASURE_VDD_HALF           3
#define OPTIC_CHANNEL_MEASURE_VBE1               4
#define OPTIC_CHANNEL_MEASURE_VBE2               5
#define OPTIC_CHANNEL_MEASURE_VOLTAGE_PN         6
#define OPTIC_CHANNEL_MEASURE_POWER_RSSI_1550    7
#define OPTIC_CHANNEL_MEASURE_POWER_RF_1550      8
#define OPTIC_CHANNEL_MEASURE_POWER_RSSI_1490    9


#define OPTIC_CHANNEL_MEASURE_UPDATE_CYCLE      10
#define OPTIC_CHANNEL_MEASURE_RSSI_UPDATE_CYCLE 4



enum optic_errorcode optic_ll_mm_init ( void );
enum optic_errorcode optic_ll_mm_prepare ( const enum optic_measure_type type,
					   const uint8_t gain_selector,
					   const enum optic_rssi_1490_mode
					   rssi_1490_mode,
					   const enum optic_vref rssi_1550_vref,
					   const enum optic_vref rf_1550_vref,
					   const uint8_t start,
					   const uint8_t end );
enum optic_errorcode optic_ll_mm_measure ( const uint8_t *measure_type,
					   int16_t *read );
enum optic_errorcode optic_ll_mm_thresh_reg_set ( const uint16_t ovl_cw,
					          const uint16_t los_cw );
enum optic_errorcode optic_ll_mm_check_thresh ( const enum optic_irq irq,
						const uint16_t thresh_cw_los,
						const uint16_t thresh_cw_ovl,
						bool *correctness );

/*! @} */

/*! @} */

EXTERN_C_END

#endif
