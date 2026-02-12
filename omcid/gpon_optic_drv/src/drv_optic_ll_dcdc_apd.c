/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, DCDC APD Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_STATUS_DCDC_APD_INTERNAL DC/DC APD Converter Module - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_register.h"
#include "drv_optic_calc.h"
#include "drv_optic_ll_dcdc_apd.h"

#if (defined(LINUX) && defined(__KERNEL__)) || defined(OPTIC_LIBRARY)
#if defined(OPTIC_LIBRARY)
#include <sysctrl.h>
#include <reg/sys1_reg.h>
#else
#include <falcon/sysctrl.h>
#include <falcon/sys1_reg.h>
#endif
#endif


#include "drv_optic_reg_dcdc.h"

/**
	init APD DCDC module

	- DCDC_PID_HI_B0 = 0
	- DCDC_PID_LO_B0 = 0
	- DCDC_PID_HI_B1 = 0xF6        Kp = 1/Ks
	- DCDC_PID_LO_B1 = 0
	- DCDC_PID_HI_B2 = 0x0A
	- DCDC_PID_LO_B2 = 0x01
	- DCDC_CLK_SET0 = 0x26         1440 MHz VDSL, 1000MHz non-VDSL
	- DCDC_CLK_SET1 = 0x01         bias resistance = 1
	- DCDC_PWM0 = 0xFF             Counter pre-load = 255
	- DCDC_PWM1 = 0                Static Duty Cycle Value = 0
	- DCDC_BIAS_VREG = 0x10        vreg_sel = nominal value 1.05V
	- DCDC_PDI_DIG_REF = 0x7F      v=127, nominal value 1,0V
	- DCDC_GENERAL = 0x8C          OS_EN=1, SET_LSB_DIGREF=1
	- DCDC_ADC0 = 0x62             SET_COMP2ARITH=2, SET_COMP2ARRAY=4,
	                               SET_ROM_SEL=1
	- DCDC_ADC1 = 0x12             SET_OFFSET_CAL_EN=1, SET_COMP_CURR=4
	- DCDC_ADC2 = 0x77             SET_ROM_START=7, SET_START=7
	- DCDC_CONF_TEST_ANA_NOAUTO = 0x78
	- DCDC_CONF_TEST_ANA_NOAUTO = 0
	- DCDC_DUTY_CYCLE = 0
	- DCDC_NON_OV_DELAY = 0x47
	- DCDC_ANALOG_GAIN = 0
	- DCDC_DUTY_CYCLE_MAX_SAT = 0x34
	- DCDC_DUTY_CYCLE_MIN_SAT = 0x07
	- DCDC_DUTY_CYCLE_MAX = 0xFF
	- DCDC_DUTY_CYCLE_MIN = 0
	- DCDC_ERROR_MAX = 0xFF
	- DCDC_DELAY_DEGLITCH = 0x7F   128 DCDC cycle, deglitch 15 DCDC cycles
	- DCDC_LATCH_CONTROL_NOAUTO = 0x01             CAP_CLK_MODE=1
	- DCDC_CAP_CLK_CNT = 0x80
	- DCDC_MDLL_DIVIDER = 0x03      DIVIDER=3, divide by 4
*/
enum optic_errorcode optic_ll_dcdc_apd_init ( void )
{
#if (defined(LINUX) && defined(__KERNEL__)) || defined(OPTIC_LIBRARY)
	/* fbs0/sys1 clock enable for DCDC APD */
	sys1_hw_activate ( CLKS_DCDCAPD_EN );
#endif

	/* reset */
	dcdc_apd_w8( 0x00, pdi_pid_hi_b0);
	dcdc_apd_w8( 0x00, pdi_pid_lo_b0);
	/* Kp = 1/Ks */

	dcdc_apd_w8( 0xF6, pdi_pid_hi_b1);
	dcdc_apd_w8( 0x00, pdi_pid_lo_b1);
/*
	dcdc_apd_w8( 0x91, pdi_pid_hi_b2);
	dcdc_apd_w8( 0x84, pdi_pid_lo_b2);
*/
	dcdc_apd_w8( 0x0A, pdi_pid_hi_b2);
	dcdc_apd_w8( 0x01, pdi_pid_lo_b2);

	/* 1440 MHz VDSL, 1000MHz non-VDSL */
	dcdc_apd_w8( 0x26, pdi_clk_set0);
	/* bias resistance = 1 */
	dcdc_apd_w8( 0x01, pdi_clk_set1);
	/* Counter pre-load = 255 */
	dcdc_apd_w8( 0xFF, pdi_pwm0);
	/* Static Duty Cycle Value = 0 */
	dcdc_apd_w8( 0x00, pdi_pwm1);
	/* vreg_sel = nominal value 1.05V */
	dcdc_apd_w8( 0x10, pdi_bias_vreg);
	/* v=127, nominal value 1,0V */
/*	dcdc_apd_w8( 0xB2, dcdc_pdi_dig_ref); */
	dcdc_apd_w8( 0x53, pdi_dig_ref);
	/* OS_EN=1, SET_LSB_DIGREF=1
	   !! instead of 0x8c: the output needs to be inverted!! */
	dcdc_apd_w8( 0x9C, pdi_general);

	/* SET_COMP2ARITH=2, SET_COMP2ARRAY=4, SET_ROM_SEL=1 */
	dcdc_apd_w8( 0x62, pdi_adc0);
	/* SET_OFFSET_CAL_EN=1, SET_COMP_CURR=4 */
	dcdc_apd_w8( 0x12, pdi_adc1);
	/* SET_ROM_START=7, SET_START=7 */
	dcdc_apd_w8( 0x77, pdi_adc2);

	dcdc_apd_w8( 0x78, pdi_conf_test_ana_noauto);
	dcdc_apd_w8( 0x00, pdi_conf_test_dig_noauto);

	dcdc_apd_w8( 0x00, pdi_duty_cycle);
	dcdc_apd_w8( 0x47, pdi_non_ov_delay);
	dcdc_apd_w8( 0x00, pdi_analog_gain);

/*	dcdc_apd_w8( 0x6C, dcdc_pdi_duty_cycle_max_sat); */
	dcdc_apd_w8( 0x34, pdi_duty_cycle_max_sat);
	dcdc_apd_w8( 0x07, pdi_duty_cycle_min_sat);
	dcdc_apd_w8( 0xFF, pdi_duty_cycle_max);
	dcdc_apd_w8( 0x00, pdi_duty_cycle_min);

	dcdc_apd_w8( 0xFF, pdi_error_max);
	/* 128 DCDC cycle, deglitch 15 DCDC cycles */
	dcdc_apd_w8( 0x07, pdi_delay_deglitch);

	/* CAP_CLK_MODE=1 */
	dcdc_apd_w8( 0x21, pdi_latch_control_noauto);

	dcdc_apd_w8( 0x80, pdi_cap_clk_cnt);
	/* DIVIDER=3, divide by 4 */
	dcdc_apd_w8( 0x03, pdi_mdll_divider);


#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_DCDC == ACTIVE))
	optic_ll_dcdc_apd_dump ();
#endif

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_dcdc_apd_exit ( void )
{
#if defined(LINUX) && defined(__KERNEL__)
	/* fbs0/sys1 clock disable for DCDC APD */
	sys1_hw_deactivate ( CLKS_DCDCAPD_EN );
#endif

	/* reset */
	dcdc_apd_w8( 0x00, pdi_pid_hi_b0);
	dcdc_apd_w8( 0x00, pdi_pid_lo_b0);
	dcdc_apd_w8( 0x00, pdi_pid_hi_b1);
	dcdc_apd_w8( 0x00, pdi_pid_lo_b1);
	dcdc_apd_w8( 0x00, pdi_pid_hi_b2);
	dcdc_apd_w8( 0x00, pdi_pid_lo_b2);


#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP == ACTIVE))
	optic_ll_dcdc_apd_dump ();
#endif

	return OPTIC_STATUS_OK;
}


/**
	Activates/deactivates APD DCDC.
*/
enum optic_errorcode optic_ll_dcdc_apd_set ( const enum optic_activation mode )
{
	uint32_t reg;
	enum optic_activation mode_actual;

	if (mode == OPTIC_ENABLE) {

		/* if already enabled do not enable again
		 * as it influences HW regulation */
		optic_ll_dcdc_apd_get(&mode_actual);
		if (mode_actual == OPTIC_ENABLE)
			return OPTIC_STATUS_OK;

		reg = DCDC_CONF_TEST_ANA_NOAUTO_SOFT_RES_ADC_N |
		      DCDC_CONF_TEST_ANA_NOAUTO_SOFT_RES_MDLL_N |
		      DCDC_CONF_TEST_ANA_NOAUTO_SOFT_RES_DPWM_N;
		dcdc_apd_w8( reg, pdi_conf_test_ana_noauto);

		/* perform 1-0-1 transition for pid bit */
		dcdc_apd_w8( DCDC_CONF_TEST_DIG_NOAUTO_SOFT_RES_PID_N,
				pdi_conf_test_dig_noauto);
		dcdc_apd_w8( 0x00, pdi_conf_test_dig_noauto);
		reg = DCDC_CONF_TEST_DIG_NOAUTO_SOFT_RES_PID_N |
		      DCDC_CONF_TEST_DIG_NOAUTO_SOFT_RES_RAMPUP_N;
		dcdc_apd_w8( reg, pdi_conf_test_dig_noauto);

		dcdc_apd_w8_mask( DCDC_LATCH_CONTROL_NOAUTO_NFORCE_EN,
		                  DCDC_LATCH_CONTROL_NOAUTO_CAP_CLK_MODE,
		                  pdi_latch_control_noauto);

	} else {
		dcdc_apd_w8( DCDC_LATCH_CONTROL_NOAUTO_CAP_CLK_MODE |
			     DCDC_LATCH_CONTROL_NOAUTO_NFORCE_EN,
			     pdi_latch_control_noauto);

		dcdc_apd_w8( 0x78, pdi_conf_test_ana_noauto);
		dcdc_apd_w8( 0x00, pdi_conf_test_dig_noauto);
	}

	return OPTIC_STATUS_OK;
}

/**
	Reads back DCDC APD mode (enable/disable).
*/
enum optic_errorcode optic_ll_dcdc_apd_get ( enum optic_activation *mode )
{
	uint32_t reg_ana, reg_dig;
	uint32_t reg_ana_enable, reg_dig_enable;

	reg_ana_enable = (DCDC_CONF_TEST_ANA_NOAUTO_SOFT_RES_ADC_N |
		          DCDC_CONF_TEST_ANA_NOAUTO_SOFT_RES_MDLL_N |
		          DCDC_CONF_TEST_ANA_NOAUTO_SOFT_RES_DPWM_N);
	reg_dig_enable = (DCDC_CONF_TEST_DIG_NOAUTO_SOFT_RES_PID_N |
		          DCDC_CONF_TEST_DIG_NOAUTO_SOFT_RES_RAMPUP_N);

	if (mode == NULL)
		return OPTIC_STATUS_ERR;

	reg_ana = dcdc_apd_r8( pdi_conf_test_ana_noauto);
	reg_dig = dcdc_apd_r8( pdi_conf_test_dig_noauto);

	if ((reg_ana & reg_ana_enable) != reg_ana_enable) {
		*mode = OPTIC_DISABLE;
		return OPTIC_STATUS_OK;
	}

	if ((reg_dig & reg_dig_enable) != reg_dig_enable) {
		*mode = OPTIC_DISABLE;
		return OPTIC_STATUS_OK;
	}

	*mode = OPTIC_ENABLE;

	return OPTIC_STATUS_OK;
}

/**
	Set the APD Voltage.
	This function controls the APD DC/DC converter.

	If the APD voltage is to be switched on, a voltage ramp is generated.
	If already on, and the voltage difference is < 1V,
	only the voltage values is changed.
	If already on, and the voltage change is greater than 1 V,
	the voltage shall be changed gradually to avoid overshoots
	(>1 ms wait time between the voltage steps, 1 V per step).

*/
enum optic_errorcode optic_ll_dcdc_apd_voltage_set (
							 const int8_t offset_dcdc_apd,
						     const uint8_t gain_dcdc_apd,
						     const uint16_t ext_att,
						     const uint16_t vapd_desired,
						     uint16_t *vapd_actual )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint16_t vapd_read;
	int16_t regulation_error;
	uint16_t vapd_target;
	uint16_t vapd_regulation = (1 << OPTIC_FLOAT2INTSHIFT_VOLTAGE)/4;
	/* dig. representation of 1V at the ADC output, used for voltage ramp */
	uint16_t vapd_step = (1 << OPTIC_FLOAT2INTSHIFT_VOLTAGE);
	uint16_t vapd_min = (20 << OPTIC_FLOAT2INTSHIFT_VOLTAGE); /* same for 20V */
	uint32_t reg_write, reg_read;
	uint32_t temp;


	if (vapd_desired == 0)
		return OPTIC_STATUS_ERR;

	/* &vapd_read = [dig] actual DCDC Voltage at the ADC output.FdS=1V=2^9 */
	/* &regulation_error = reg.error at the ADC output, not used here at the moment */
	ret = optic_ll_dcdc_apd_voltage_get ( offset_dcdc_apd,
					      gain_dcdc_apd,
					      ext_att,
					      &vapd_read,
					      &regulation_error );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_ll_dcdc_apd_voltage_get(): %d", ret);
		return ret;
	}

	/* DCDC APD not ready for next step: regulation error < threshold */
	if (abs(regulation_error) > vapd_regulation) {
		return OPTIC_STATUS_DCDC_APD_RAMP_WAIT;
	}

	/* SW ramp: change of the ramp target of +/- 1V respect to the read value,
	            allowed if the error is more than 1V,
	            determine direction of SW ramp */
	if (vapd_read >= (vapd_desired + vapd_step)) {
		/*if the read value is too big, reduce the target by 1V */
		vapd_target = vapd_read - vapd_step;
	}
	else
	{
		if(vapd_read <= (vapd_desired - vapd_step)) {
			/*if the read value is too low, increase the target by 1V */
			vapd_target = vapd_read + vapd_step;
		}
		else {
			/* desired value vapd_desired is kept as it is */
			vapd_target = vapd_desired;
		}
	}

	if (vapd_target < vapd_min)
		vapd_target = vapd_min;

	/**
		 VAPD * 512
		 ----------  - 3
			extAtt                 fuse_gain * 0.2
	VREF =  ---------------- * ( 0.9 + --------------- ) + fuse_offset
			   4                        64

		 VAPD * 512
		 ---------- - 3
			extAtt         288 + fuse_gain
	VREF =  --------------- * -----------------  + fuse_offset
			   4                320

	VAPD [<<OPTIC_FLOAT2INTSHIFT_VOLTAGE]
	extAtt [<<OPTIC_FLOAT2INTSHIFT_EXTATT]

		 VAPD * 512 << OPTIC_FLOAT2INTSHIFT_EXTATT
		 -----------------------------------------  - (3 <<  OPTIC_FLOAT2INTSHIFT_VOLTAGE)
								  extAtt                                                           288 + fuse_gain
	VREF =  ---------------------------------------------------------------------------------- * -------------------------------------  + fuse_offset
											   4                                             320 <<  OPTIC_FLOAT2INTSHIFT_VOLTAGE

		  VAPD << (OPTIC_FLOAT2INTSHIFT_EXTATT +7)                                                 288 + fuse_gain
	VREF = ( ------------------------------------------ - (3 <<  OPTIC_FLOAT2INTSHIFT_VOLTAGE-2) ) * ------------------------------------  + fuse_offset
						  extAtt                                                                 320 <<  OPTIC_FLOAT2INTSHIFT_VOLTAGE

	*/

	temp = vapd_target << (OPTIC_FLOAT2INTSHIFT_EXTATT + 7);
	temp = optic_uint_div_rounded ( temp, ext_att );

	temp -= (3 << (OPTIC_FLOAT2INTSHIFT_VOLTAGE-2));
	temp *= (288 + gain_dcdc_apd);

	temp = optic_uint_div_rounded ( temp,
					320 <<
					 OPTIC_FLOAT2INTSHIFT_VOLTAGE );

	reg_write = temp + offset_dcdc_apd;

	/* read "last" reference value */
	reg_read = dcdc_apd_r8 ( pdi_dig_ref );
	if(reg_read != reg_write) {
#if (OPTIC_APD_DEBUG == ACTIVE)
		OPTIC_DEBUG_ERR("writing pdi_dig_ref = %d now...", reg_write);
#endif
		/* set reference value */
		dcdc_apd_w8 ( reg_write, pdi_dig_ref );
	}

	if (vapd_target == vapd_desired) {
		/* desired voltage has been reached */
#if (OPTIC_APD_DEBUG == ACTIVE)
		OPTIC_DEBUG_ERR("OPTIC_STATUS_DCDC_APD_CHANGE vapd_desired=%d vapd_target=%d", vapd_desired, vapd_target);
#endif
		ret = OPTIC_STATUS_DCDC_APD_CHANGE;
	} else {
		/* desired voltage has not been reached, we still need to ramp with steps */
#if (OPTIC_APD_DEBUG == ACTIVE)
		OPTIC_DEBUG_ERR("OPTIC_STATUS_DCDC_APD_RAMP vapd_desired=%d vapd_target=%d", vapd_desired, vapd_target);
#endif
		/* return the actual voltage to the top level function */
		*vapd_actual = vapd_target;
		ret = OPTIC_STATUS_DCDC_APD_RAMP;
	}

	return ret;
}
enum optic_errorcode optic_ll_dcdc_apd_voltage_get ( const int8_t
						     offset_dcdc_apd,
						     const uint8_t
						     gain_dcdc_apd,
						     const uint16_t ext_att,
						     uint16_t *vapd_read,
						     int16_t *regulation_error )
{
	uint32_t reg;
	uint32_t temp;
	int32_t tempi;
	int32_t pdi_error;

	if (vapd_read == NULL)
		return OPTIC_STATUS_ERR;

	if (regulation_error == NULL)
		return OPTIC_STATUS_ERR;

	/**
	         VAPD * 512
	         ----------  - 3
	            extAtt                fuse_gain * 0.2
	VREF =  ---------------- * ( 0.9 + --------------- ) + fuse_offset
	               4                        64

		 VAPD * 512
	         ---------- - 3
		    extAtt         288 + fuse_gain
	VREF =  --------------- * -----------------  + fuse_offset
                       4                320

	VAPD * 512
	---------- - 3
	   extAtt           ( VREF - fuse_offset ) * 320
	---------------  =  -----------------------------
	      4                  288 + fuse_gain

	VAPD * 512      ( VREF - fuse_offset ) * 1280
	----------  =  ------------------------------ + 3
	   extAtt             288 + fuse_gain

	           ( VREF - fuse_offset ) * 1280         extAtt
	VAPD  =  (------------------------------ + 3 ) * ------
	                  288 + fuse_gain                 512

	VAPD [<<OPTIC_FLOAT2INTSHIFT_VOLTAGE]
	extAtt [<<OPTIC_FLOAT2INTSHIFT_EXTATT]

	           ( VREF - fuse_offset ) * 1280 <<OPTIC_FLOAT2INTSHIFT_VOLTAGE
	VAPD  =  (------------------------------ -------------------------------  + 3 <<OPTIC_FLOAT2INTSHIFT_VOLTAGE ) * extAtt >> (OPTIC_FLOAT2INTSHIFT_EXTATT + 9)
	                  288 + fuse_gain

	*/

	reg = dcdc_apd_r8 ( pdi_dig_ref );
#if (OPTIC_APD_DEBUG == ACTIVE)
	OPTIC_DEBUG_ERR("optic_ll_dcdc_apd_voltage_get: digref %d", reg);
#endif

	/* the uint temp must not be negative!! */
	tempi = reg-offset_dcdc_apd;
	if (tempi < 0)
		tempi = 0;

	temp = tempi * (1280 << OPTIC_FLOAT2INTSHIFT_VOLTAGE);

	temp = optic_uint_div_rounded ( temp , 288 + gain_dcdc_apd );
	temp += (3 << OPTIC_FLOAT2INTSHIFT_VOLTAGE);

	temp = optic_uint_div_rounded ( temp , 1 << 9 );

	temp *= ext_att;

	*vapd_read = (uint16_t) optic_uint_div_rounded ( temp,
					1 << OPTIC_FLOAT2INTSHIFT_EXTATT );

	/* register value 1 digit = 120mV */
	reg = dcdc_apd_r8 ( pdi_error_read );
	pdi_error = (int8_t) reg;

#if (OPTIC_APD_DEBUG == ACTIVE)
	OPTIC_DEBUG_ERR("optic_ll_dcdc_apd_voltage_get: "
			"pdi_error(bit) = %d, vapd_read = %d",
			pdi_error,
			*vapd_read);
#endif

	pdi_error = pdi_error * (60 << OPTIC_FLOAT2INTSHIFT_VOLTAGE); /* 60 [V] */
	*regulation_error = (int16_t) optic_int_div_rounded ( pdi_error, 1000 ); /* [V] scaling */

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_dcdc_apd_saturation_set ( const uint8_t sat )
{
	uint32_t reg = sat;

	/* set duty cycle saturation */
	dcdc_apd_w8 ( reg, pdi_duty_cycle_max_sat );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_dcdc_apd_saturation_get ( uint8_t *sat )
{
	uint32_t reg;

	if (sat == NULL)
		return OPTIC_STATUS_ERR;

	/* set duty cycle saturation */
	reg = dcdc_apd_r8 ( pdi_duty_cycle_max_sat );
	*sat = reg & 0xFF;

	return OPTIC_STATUS_OK;
}

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_DCDC == ACTIVE))
enum optic_errorcode optic_ll_dcdc_apd_dump ( void )
{
	OPTIC_DEBUG_WRN("DCDC APD #0: 0x%02X",
			dcdc_apd_r8(pdi_pid_hi_b0));
	OPTIC_DEBUG_WRN("DCDC APD #1: 0x%02X",
			dcdc_apd_r8(pdi_pid_lo_b0));
	OPTIC_DEBUG_WRN("DCDC APD #2: 0x%02X",
			dcdc_apd_r8(pdi_pid_hi_b1));
	OPTIC_DEBUG_WRN("DCDC APD #3: 0x%02X",
			dcdc_apd_r8(pdi_pid_lo_b1));
	OPTIC_DEBUG_WRN("DCDC APD #4: 0x%02X",
			dcdc_apd_r8(pdi_pid_hi_b2));
	OPTIC_DEBUG_WRN("DCDC APD #5: 0x%02X",
			dcdc_apd_r8(pdi_pid_lo_b2));

	OPTIC_DEBUG_WRN("DCDC APD #6: 0x%02X",
			dcdc_apd_r8(pdi_clk_set0));
	OPTIC_DEBUG_WRN("DCDC APD #7: 0x%02X",
			dcdc_apd_r8(pdi_clk_set1));

	OPTIC_DEBUG_WRN("DCDC APD #8: 0x%02X",
			dcdc_apd_r8(pdi_pwm0));
	OPTIC_DEBUG_WRN("DCDC APD #9: 0x%02X",
			dcdc_apd_r8(pdi_pwm1));
	OPTIC_DEBUG_WRN("DCDC APD #10: 0x%02X",
			dcdc_apd_r8(pdi_bias_vreg));
	OPTIC_DEBUG_WRN("DCDC APD #11: 0x%02X",
			dcdc_apd_r8(pdi_dig_ref));
	OPTIC_DEBUG_WRN("DCDC APD #12: 0x%02X",
			dcdc_apd_r8(pdi_general));


	OPTIC_DEBUG_WRN("DCDC APD #13: 0x%02X",
			dcdc_apd_r8(pdi_adc0));
	OPTIC_DEBUG_WRN("DCDC APD #14: 0x%02X",
			dcdc_apd_r8(pdi_adc1));
	OPTIC_DEBUG_WRN("DCDC APD #15: 0x%02X",
			dcdc_apd_r8(pdi_adc2));

	OPTIC_DEBUG_WRN("DCDC APD #16: 0x%02X",
			dcdc_apd_r8(pdi_conf_test_ana));
	OPTIC_DEBUG_WRN("DCDC APD #17: 0x%02X",
			dcdc_apd_r8(pdi_conf_test_dig));
	OPTIC_DEBUG_WRN("DCDC APD #18: 0x%02X",
			dcdc_apd_r8(pdi_conf_test_ana_noauto));
	OPTIC_DEBUG_WRN("DCDC APD #19: 0x%02X",
			dcdc_apd_r8(pdi_conf_test_dig_noauto));

	OPTIC_DEBUG_WRN("DCDC APD #20: 0x%02X",
			dcdc_apd_r8(pdi_dcdc_status));
	OPTIC_DEBUG_WRN("DCDC APD #21: 0x%02X",
			dcdc_apd_r8(pdi_pid_status));
	OPTIC_DEBUG_WRN("DCDC APD #22: 0x%02X",
			dcdc_apd_r8(pdi_duty_cycle));
	OPTIC_DEBUG_WRN("DCDC APD #23: 0x%02X",
			dcdc_apd_r8(pdi_non_ov_delay));
	OPTIC_DEBUG_WRN("DCDC APD #24: 0x%02X",
			dcdc_apd_r8(pdi_analog_gain));

	OPTIC_DEBUG_WRN("DCDC APD #25: 0x%02X",
			dcdc_apd_r8(pdi_duty_cycle_max_sat));
	OPTIC_DEBUG_WRN("DCDC APD #26: 0x%02X",
			dcdc_apd_r8(pdi_duty_cycle_min_sat));
	OPTIC_DEBUG_WRN("DCDC APD #27: 0x%02X",
			dcdc_apd_r8(pdi_duty_cycle_max));
	OPTIC_DEBUG_WRN("DCDC APD #28: 0x%02X",
			dcdc_apd_r8(pdi_duty_cycle_min));

	OPTIC_DEBUG_WRN("DCDC APD #29: 0x%02X",
			dcdc_apd_r8(pdi_error_max));
	OPTIC_DEBUG_WRN("DCDC APD #30: 0x%02X",
			dcdc_apd_r8(pdi_error_read));
	OPTIC_DEBUG_WRN("DCDC APD #31: 0x%02X",
			dcdc_apd_r8(pdi_delay_deglitch));
	OPTIC_DEBUG_WRN("DCDC APD #32: 0x%02X",
			dcdc_apd_r8(pdi_latch_control));
	OPTIC_DEBUG_WRN("DCDC APD #33: 0x%02X",
			dcdc_apd_r8(pdi_latch_control_noauto));
	OPTIC_DEBUG_WRN("DCDC APD #34: 0x%02X",
			dcdc_apd_r8(pdi_cap_clk_cnt));
	OPTIC_DEBUG_WRN("DCDC APD #35: 0x%02X",
			dcdc_apd_r8(pdi_mdll_divider));

	return OPTIC_STATUS_OK;
}
#endif

/*! @} */
/*! @} */
