/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_optic_calc_h
#define _drv_optic_calc_h

#ifndef SYSTEM_SIMULATION
#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_goi_interface.h"
#else
#include "drv_optic_simu.h"
#endif

EXTERN_C_BEGIN


/** \defgroup OPTIC_CALC_INTERNAL Common Driver Calculation Module
   @{
*/

/* granularity of loarithm calculation in post commata binary
   digits (10 ~ 0,002)*/
#define OPTIC_LOG_GRANULARITY 10

enum optic_dcdc_type
{
	OPTIC_DCDC_APD,
	OPTIC_DCDC_CORE,
	OPTIC_DCDC_DDR,
};


int optic_in_range(void* ptr, ulong_t start, ulong_t end);
uint32_t optic_uint_div_rounded ( uint32_t divident, uint32_t divisor );
int32_t optic_int_div_rounded ( int32_t divident, int32_t divisor );
uint16_t optic_shift_temp_back ( const uint16_t temperature );
enum optic_errorcode optic_float2int ( int32_t float_val,
				       uint8_t shift,
                                       uint16_t dec_factor,
                                       int16_t *ib,
                                       uint16_t *fb );
enum optic_errorcode optic_powerlevel2gainbank ( const enum optic_powerlevel
						 powerlevel,
			              		 enum optic_gainbank
			              		 *gainbank );
enum optic_errorcode optic_rangecheck_dcdc ( const struct optic_config_range
					     *range,
					     const enum optic_dcdc_type type,
					     const uint16_t dcdc_voltage );
enum optic_errorcode optic_rangecheck_itemp_nom ( const struct
						  optic_config_range *range,
					          const uint16_t itemp_nom );
enum optic_errorcode optic_rangecheck_itemp_corr ( const struct
						   optic_config_range *range,
					           const uint16_t itemp_corr );
enum optic_errorcode optic_rangecheck_etemp_nom ( const struct
						  optic_config_range *range,
					          const uint16_t etemp_nom,
					          uint16_t *temp_index );
enum optic_errorcode optic_rangecheck_etemp_corr ( const struct
						   optic_config_range *range,
					           const uint16_t extemp_corr,
					           uint16_t *temp_index );
enum optic_errorcode optic_calc_pn_gain_sel ( struct optic_control *p_ctrl );
enum optic_errorcode optic_fill_table_ipol ( struct optic_control *p_ctrl,
                                       	     const enum optic_tabletype type,
                                	     const uint16_t offset,
                                	     const uint8_t size,
                                	     const uint16_t ipol_lb,
                                	     const uint16_t ipol_ub );
enum optic_errorcode optic_fill_table_const ( struct optic_control *p_ctrl,
                                       	      const enum optic_tabletype type,
                                	      uint16_t offset,
                                	      uint8_t size,
                                	      int32_t val );

enum optic_errorcode optic_calc_ibiasimod ( struct optic_control *p_ctrl );
enum optic_errorcode optic_calc_ith_se ( struct optic_control *p_ctrl );
enum optic_errorcode optic_temperature_nom2corr ( const struct
						  optic_config_range *range,
						  const struct
						  optic_table_temperature_nom
						  *table_temperature_nom,
						  const uint16_t temp_nom,
					          uint16_t *temp_corr );
enum optic_errorcode optic_fusecorrect_temp ( struct optic_fuses *fuses,
					      uint16_t temp_nom,
					      uint16_t *temp_corr );
enum optic_errorcode optic_check_age ( struct optic_control *p_ctrl );
#if (OPTIC_FCSI_PREDRIVER_RANGECHECK == ACTIVE)
enum optic_errorcode optic_check_predriver ( uint8_t dd_loadn,
					     uint8_t dd_bias_en,
					     uint8_t dd_loadp,
					     uint8_t dd_cm_load,
					     uint8_t bd_loadn,
					     uint8_t bd_bias_en,
					     uint8_t bd_loadp,
					     uint8_t bd_cm_load );
#endif
enum optic_errorcode optic_check_temperature_alarm ( struct optic_control
						     *p_ctrl );
enum optic_errorcode optic_calc_gain_correct ( struct optic_control *p_ctrl,
					       const bool p0,
					       const int16_t dac_coarse,
					       const int16_t dac_fine,
					       uint16_t *gain_correct );
enum optic_errorcode optic_calc_codeword ( struct optic_control *p_ctrl,
					   const bool p0,
					   const uint16_t temp_ext_corr,
					   const int16_t gain_correct,
				           int32_t *codeword );
enum optic_errorcode optic_calc_bias2reg ( const uint8_t gain_dac_bias,
					   const uint8_t bias_max,
                                           const uint16_t ibias,
					   uint16_t *dbias );
enum optic_errorcode optic_calc_reg2bias ( const uint8_t gain_dac_bias,
					   const uint8_t bias_max,
                                           const uint16_t dbias,
					   uint16_t *bias );
enum optic_errorcode optic_calc_mod2reg ( const uint8_t gain_dac_drive,
					  const uint16_t scalefactor_mod,
					  const uint8_t mod_max,
                                          const uint16_t imod,
					  uint16_t *dmod );
enum optic_errorcode optic_calc_reg2mod ( const uint8_t gain_dac_drive,
					  const uint16_t scalefactor_mod,
					  const uint8_t mod_max,
                                          const uint16_t dmod,
					  uint16_t *mod );
enum optic_errorcode optic_calc_voltage ( const enum optic_measure_type type,
					  const enum optic_vref vref,
					  const struct optic_table_mm_gain
					  *gain,
					  const int16_t reg_value,
					  uint8_t *gain_selector,
					  uint16_t *voltage );
enum optic_errorcode optic_calc_digitword ( const enum optic_vref vref,
					    const struct optic_table_mm_gain
					    *gain,
					    const uint16_t voltage,
					    uint16_t *digitword );
enum optic_errorcode optic_calc_temperature_int ( const uint16_t voltage_vdd,
					          const uint16_t voltage_vbe1,
					          const uint16_t voltage_vbe2,
	                                          uint16_t *t_nom );
enum optic_errorcode optic_calc_temperature_ext ( const uint16_t
						  voltage_offset_pn,
					          const uint16_t tscal_ref,
						  const uint16_t voltage,
						  uint16_t *t_nom );
enum optic_errorcode optic_calc_voltage_digitword ( struct optic_control
						    *p_ctrl,
						    const enum
						    optic_measure_type type,
						    const uint16_t voltage,
						    uint16_t *digitword );
enum optic_errorcode optic_search_apd_saturation ( struct optic_control *p_ctrl,
			                           const uint16_t vapd,
			                           uint8_t *sat );
enum optic_errorcode optic_calc_duty_cycle ( struct optic_control *p_ctrl,
					     const enum optic_dcdc_type type,
			                     const uint16_t voltage,
			                     uint8_t *duty_cycle_min,
			                     uint8_t *duty_cycle_max );
enum optic_errorcode optic_calc_rssi_1490_dark_corr ( const uint16_t
						      meas_voltage_1490_rssi,
                                                      const uint16_t ext_att,
						      const uint16_t
						      vapd_target,
                                                      const uint32_t *r_diff,
                                                      const uint16_t
                                                      rssi_1490_shunt_res,
                                                      uint16_t
                                                      *rssi_1490_dark_corr );
enum optic_errorcode optic_calc_current_offset ( const uint16_t
						 rssi_1490_dark_corr,
						 const uint16_t vapd_target,
						 const uint32_t *r_diff,
						 const uint16_t
						 rssi_1490_shunt_res,
						 uint16_t *current_offset );
enum optic_errorcode optic_calc_current_1490 ( const enum optic_rssi_1490_mode
					       rssi_1490_mode,
                                               const uint16_t voltage_1490,
					       const uint16_t ext_att,
					       const uint16_t
					       rssi_1490_shunt_res,
					       const uint16_t current_offset,
					       struct optic_fuses *fuses,
                                               uint16_t *current_1490,
                                               bool *is_positive );
enum optic_errorcode optic_calc_power ( const enum optic_cfactor factor_index,
					const struct optic_config_range *range,
					const uint16_t temperature_ext,
					struct optic_table_temperature_corr
					*t_corr,
					const uint16_t scal_ref,
					const uint16_t meas_value,
					uint16_t *power,
					const uint16_t parabolic_ref,
					const uint16_t dark_ref);
enum optic_errorcode optic_calc_thresh_current ( const uint16_t
						 rssi_1490_scal_ref,
						 const uint16_t threshold,
						 uint16_t *thresh_current );
enum optic_errorcode optic_calc_thresh_voltage_1490 ( const enum
						      optic_rssi_1490_mode
						      rssi_1490_mode,
						      const uint16_t
						      thresh_current,
					       	      const uint16_t ext_att,
					       	      const uint16_t
						      rssi_1490_shunt_res,
					       	      const uint16_t
					       	      current_offset,
						      struct optic_fuses *fuses,
						      const bool force,
						      uint16_t *thresh_voltage );
enum optic_errorcode optic_calc_offset_and_thresh ( struct optic_control
						    *p_ctrl );

enum optic_errorcode optic_calc_lol_thresh(  const uint32_t base,
					     const uint8_t limit_low,
					     const uint8_t limit_high,
					     int32_t *low_tresh,
					     int32_t *high_tresh);
uint32_t optic_ln2_arithmentic ( void );
uint32_t optic_ld_arithmentic ( uint32_t value );
uint32_t optic_ln_arithmentic ( uint32_t value );
int32_t optic_ln_lookuptable ( uint32_t value );


/*! @} */

EXTERN_C_END

#endif
