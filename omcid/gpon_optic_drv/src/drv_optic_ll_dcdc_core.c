/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, DCDC CORE Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_STATUS_DCDC_CORE_INTERNAL DC/DC CORE Converter Module - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_register.h"
#include "drv_optic_calc.h"
#include "drv_optic_ll_dcdc_core.h"

#if defined(LINUX) && defined(__KERNEL__)
#include <falcon/sys1_reg.h>
#include <falcon/sysctrl.h>
#endif
#include "drv_optic_reg_dcdc.h"

/**
	Activates/deactivates DCDC CORE.
*/
enum optic_errorcode optic_ll_dcdc_core_set ( const enum optic_activation mode )
{
	uint32_t reg;

	if (mode == OPTIC_ENABLE) {
		reg = DCDC_CONF_TEST_ANA_SOFT_RES_ADC_N |
		      DCDC_CONF_TEST_ANA_SOFT_RES_MDLL_N |
		      DCDC_CONF_TEST_ANA_SOFT_RES_DPWM_N;
		dcdc_core_w8( reg, pdi_conf_test_ana);

		reg = DCDC_CONF_TEST_DIG_SOFT_RES_PID_N |
		      DCDC_CONF_TEST_DIG_SOFT_RES_RAMPUP_N;
		dcdc_core_w8( reg, pdi_conf_test_dig);
	} else {
		reg = DCDC_CONF_TEST_ANA_PD_ADC |
		      DCDC_CONF_TEST_ANA_RESERVED0 |
		      DCDC_CONF_TEST_ANA_PD_PFMCOMP |
		      DCDC_CONF_TEST_ANA_DPWM_BYP;
		dcdc_core_w8( reg, pdi_conf_test_ana );
		dcdc_core_w8( 0x00, pdi_conf_test_dig );
	}

	return OPTIC_STATUS_OK;
}

/**
	Reads back DCDC CORE mode (enable/disable).
*/
enum optic_errorcode optic_ll_dcdc_core_get ( enum optic_activation *mode )
{
	uint32_t reg_ana, reg_dig;
	uint32_t reg_ana_enable, reg_dig_enable;

	reg_ana_enable = (DCDC_CONF_TEST_ANA_SOFT_RES_ADC_N |
		          DCDC_CONF_TEST_ANA_SOFT_RES_MDLL_N |
		          DCDC_CONF_TEST_ANA_SOFT_RES_DPWM_N);
	reg_dig_enable = (DCDC_CONF_TEST_DIG_SOFT_RES_PID_N |
		          DCDC_CONF_TEST_DIG_SOFT_RES_RAMPUP_N);

	if (mode == NULL)
		return OPTIC_STATUS_ERR;

	reg_ana = dcdc_core_r8( pdi_conf_test_ana );
	reg_dig = dcdc_core_r8( pdi_conf_test_dig );

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
	Set the CORE Voltage.
	This function controls the DC/DC CORE converter.
*/
enum optic_errorcode optic_ll_dcdc_core_voltage_set ( const int8_t
						      offset_dcdc_core,
						      const uint8_t
						      gain_dcdc_core,
						      const uint16_t vcore )
{
	uint32_t reg;
	uint32_t temp;

	/**

	          VCORE * 512 - 3           fuse_gain * 0.2
	VREF =  ----------------- * ( 0.9 + --------------- ) + fuse_offset
			4                         64

		 VCORE * 512 - 3     288 + fuse_gain
	VREF =  ----------------- * -----------------  + fuse_offset
			4                320

	VCORE [<<OPTIC_FLOAT2INTSHIFT_VOLTAGE]

		                               288 + fuse_gain
	VREF =  ((VCORE << 9) - 3) * ------------------------------------------  + fuse_offset
			              320 << (OPTIC_FLOAT2INTSHIFT_VOLTAGE + 2)

	*/

	temp = (vcore << 9) - 3;

	temp *= (288 + gain_dcdc_core);

	temp = optic_uint_div_rounded ( temp,
				320 << (OPTIC_FLOAT2INTSHIFT_VOLTAGE + 2) );

	reg = temp + offset_dcdc_core;

	/* set reference value */
	dcdc_core_w8 ( reg, pdi_dig_ref );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_dcdc_core_voltage_get ( const int8_t
						      offset_dcdc_core,
						      const uint8_t
						      gain_dcdc_core,
				                      uint16_t *vcore )
{
	uint32_t reg;
	uint32_t temp;
	uint8_t shift = OPTIC_FLOAT2INTSHIFT_VOLTAGE - 9;

	if (vcore == NULL)
		return OPTIC_STATUS_ERR;

	/**
		  VCORE * 512 - 3            fuse_gain * 0.2
	VREF =  ------------------ * ( 0.9 + --------------- ) + fuse_offset
		        4                          64

		 VCORE * 512 - 3     288 + fuse_gain
	VREF =  ----------------- * -----------------  + fuse_offset
			4                320

	  VCORE * 512 - 3      ( VREF - fuse_offset ) * 320
	------------------  =  -----------------------------
	         4                   288 + fuse_gain

		  ( VREF - fuse_offset ) * 1280
	         ------------------------------- + 3
	                  288 + fuse_gain
	VCORE = ---------------------------------------
				512

	VCORE [<<OPTIC_FLOAT2INTSHIFT_VOLTAGE]

		   ( VREF - fuse_offset ) * 1280
	VCORE =  ( ------------------------------- + 3 ) << (OPTIC_FLOAT2INTSHIFT_VOLTAGE - 9)
	               288 + fuse_gain

	shift = OPTIC_FLOAT2INTSHIFT_VOLTAGE - 9

		 ( VREF - fuse_offset ) * (1280 << shift)
	VCORE =  ---------------------------------------- + (3 << shift)
			288 + fuse_gain
	*/

	reg = dcdc_core_r8 ( pdi_dig_ref );

	temp = (reg - offset_dcdc_core) * (1280 << shift);

	temp = optic_uint_div_rounded ( temp, 288 + gain_dcdc_core );
	temp += (3 << shift);

	*vcore = (uint16_t) temp;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_dcdc_core_dutycycle_set ( const uint8_t min,
							const uint8_t max )
{
	uint32_t reg;

	/* set duty cycle min/max */
	reg = min;
	dcdc_core_w8 ( reg, pdi_duty_cycle_min );

	reg = max;
	dcdc_core_w8 ( reg, pdi_duty_cycle_max );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_dcdc_core_deadzone_set ( const uint8_t del_p,
							const uint8_t del_n )
{
	uint32_t reg;

	reg = ((del_n << DCDC_NON_OV_DELAY_DEL_N_OFFSET)
			& DCDC_NON_OV_DELAY_DEL_N_MASK) |
		  ((del_p << DCDC_NON_OV_DELAY_DEL_P_OFFSET)
		  	& DCDC_NON_OV_DELAY_DEL_P_MASK);

	dcdc_core_w8 ( reg, pdi_non_ov_delay );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_dcdc_core_dutycycle_get ( uint8_t *min,
							uint8_t *max )
{
	uint32_t reg;

	if ((min == NULL) || (max == NULL))
		return OPTIC_STATUS_ERR;

	/* get duty cycle min/max */
	reg = dcdc_core_r8 ( pdi_duty_cycle_min );
	*min = reg & 0xFF;

	reg = dcdc_core_r8 ( pdi_duty_cycle_max );
	*max = reg & 0xFF;

	return OPTIC_STATUS_OK;
}

static void wait_and_print_dcdc_err(uint32_t m_sec, const char *txt)
{
	OPTIC_DEBUG_MSG("%s: error_read %d",
			txt,
			(int8_t)dcdc_core_r8(pdi_error_read));
	if (m_sec) {
		/* wait X ms for stabilisation */
		optic_udelay(m_sec*1000);
		OPTIC_DEBUG_MSG("after %d ms: error_read %d",
				m_sec,
				(int8_t)dcdc_core_r8(pdi_error_read));
	}
}

enum optic_errorcode optic_ll_dcdc_core_restore_hw_values (void)
{
	uint32_t duty_cycle_av, i;
	uint8_t  duty_cycle_curr, duty_cycle_min, duty_cycle_max;
	const uint32_t DUTY_CYCLE_TIMES = 500;
	int8_t error_read;

	/* set voltage to HW reset value */
	dcdc_core_w8(DCDC_DIG_REF_V_NOMINAL, pdi_dig_ref);
	wait_and_print_dcdc_err(1, "switch voltage");
	dcdc_core_w8(0xFF, pdi_pwm0);
	wait_and_print_dcdc_err(1, "switch freq");

	duty_cycle_av = 0;
	duty_cycle_min = 0xFF;
	duty_cycle_max = 0;
	for (i=0; i<DUTY_CYCLE_TIMES; i++) {
		duty_cycle_curr = dcdc_core_r8(pdi_duty_cycle);
		duty_cycle_av += duty_cycle_curr;
		if (duty_cycle_curr < duty_cycle_min)
			duty_cycle_min = duty_cycle_curr;
		if (duty_cycle_curr > duty_cycle_max)
			duty_cycle_max = duty_cycle_curr;
		optic_udelay(10);
	}
	duty_cycle_av = duty_cycle_av / DUTY_CYCLE_TIMES;
	OPTIC_DEBUG_MSG("duty_cycle: average = %d, min = %d, max = %d", 
		duty_cycle_av, duty_cycle_min, duty_cycle_max);

	/* restrict duty cycle range around average */
	dcdc_core_w8(duty_cycle_av+10, pdi_duty_cycle_max_sat);
	dcdc_core_w8(duty_cycle_av-10, pdi_duty_cycle_min_sat);

	/* force static duty cycle value during coefficient programming */
	dcdc_core_w8(duty_cycle_av, pdi_pwm1);
	dcdc_core_w8_mask(0, DCDC_CONF_TEST_DIG_SOFT_PRESET_PID |
			     DCDC_CONF_TEST_DIG_FREEZE_PID, 
			     pdi_conf_test_dig);

	/* write HW default coefficients */
	dcdc_core_w8(DCDC_PID_HI_B0_B_KP_3, pdi_pid_hi_b0);
	dcdc_core_w8(DCDC_PID_LO_B0_B_KP_3, pdi_pid_lo_b0);
	dcdc_core_w8(DCDC_PID_HI_B1_B_KP_3, pdi_pid_hi_b1);
	dcdc_core_w8(DCDC_PID_LO_B1_B_KP_3, pdi_pid_lo_b1);
	dcdc_core_w8(DCDC_PID_HI_B2_B_KP_3, pdi_pid_hi_b2);
	dcdc_core_w8(DCDC_PID_LO_B2_B_KP_3, pdi_pid_lo_b2);

	error_read = (int8_t)dcdc_core_r8(pdi_error_read);
	/* unfreeze PID */
	dcdc_core_w8_mask(DCDC_CONF_TEST_DIG_SOFT_PRESET_PID |
			  DCDC_CONF_TEST_DIG_FREEZE_PID,
			  0, pdi_conf_test_dig);

	OPTIC_DEBUG_MSG("before unfreeze: error_read %d", error_read);
	wait_and_print_dcdc_err(1, "unfreeze");

	return OPTIC_STATUS_OK;
}

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_DCDC == ACTIVE))
enum optic_errorcode optic_ll_dcdc_core_dump ( void )
{
	OPTIC_DEBUG_WRN("DCDC CORE #0: 0x%02X",
			dcdc_core_r8(pdi_pid_hi_b0));
	OPTIC_DEBUG_WRN("DCDC CORE #1: 0x%02X",
			dcdc_core_r8(pdi_pid_lo_b0));
	OPTIC_DEBUG_WRN("DCDC CORE #2: 0x%02X",
			dcdc_core_r8(pdi_pid_hi_b1));
	OPTIC_DEBUG_WRN("DCDC CORE #3: 0x%02X",
			dcdc_core_r8(pdi_pid_lo_b1));
	OPTIC_DEBUG_WRN("DCDC CORE #4: 0x%02X",
			dcdc_core_r8(pdi_pid_hi_b2));
	OPTIC_DEBUG_WRN("DCDC CORE #5: 0x%02X",
			dcdc_core_r8(pdi_pid_lo_b2));

	OPTIC_DEBUG_WRN("DCDC CORE #6: 0x%02X",
			dcdc_core_r8(pdi_clk_set0));
	OPTIC_DEBUG_WRN("DCDC CORE #7: 0x%02X",
			dcdc_core_r8(pdi_clk_set1));

	OPTIC_DEBUG_WRN("DCDC CORE #8: 0x%02X",
			dcdc_core_r8(pdi_pwm0));
	OPTIC_DEBUG_WRN("DCDC CORE #9: 0x%02X",
			dcdc_core_r8(pdi_pwm1));
	OPTIC_DEBUG_WRN("DCDC CORE #10: 0x%02X",
			dcdc_core_r8(pdi_bias_vreg));
	OPTIC_DEBUG_WRN("DCDC CORE #11: 0x%02X",
			dcdc_core_r8(pdi_dig_ref));
	OPTIC_DEBUG_WRN("DCDC CORE #12: 0x%02X",
			dcdc_core_r8(pdi_general));


	OPTIC_DEBUG_WRN("DCDC CORE #13: 0x%02X",
			dcdc_core_r8(pdi_adc0));
	OPTIC_DEBUG_WRN("DCDC CORE #14: 0x%02X",
			dcdc_core_r8(pdi_adc1));
	OPTIC_DEBUG_WRN("DCDC CORE #15: 0x%02X",
			dcdc_core_r8(pdi_adc2));

	OPTIC_DEBUG_WRN("DCDC CORE #16: 0x%02X",
			dcdc_core_r8(pdi_conf_test_ana));
	OPTIC_DEBUG_WRN("DCDC CORE #17: 0x%02X",
			dcdc_core_r8(pdi_conf_test_dig));
	OPTIC_DEBUG_WRN("DCDC CORE #18: 0x%02X",
			dcdc_core_r8(pdi_conf_test_ana_noauto));
	OPTIC_DEBUG_WRN("DCDC CORE #19: 0x%02X",
			dcdc_core_r8(pdi_conf_test_dig_noauto));

	OPTIC_DEBUG_WRN("DCDC CORE #20: 0x%02X",
			dcdc_core_r8(pdi_dcdc_status));
	OPTIC_DEBUG_WRN("DCDC CORE #21: 0x%02X",
			dcdc_core_r8(pdi_pid_status));
	OPTIC_DEBUG_WRN("DCDC CORE #22: 0x%02X",
			dcdc_core_r8(pdi_duty_cycle));
	OPTIC_DEBUG_WRN("DCDC CORE #23: 0x%02X",
			dcdc_core_r8(pdi_non_ov_delay));
	OPTIC_DEBUG_WRN("DCDC CORE #24: 0x%02X",
			dcdc_core_r8(pdi_analog_gain));

	OPTIC_DEBUG_WRN("DCDC CORE #25: 0x%02X",
			dcdc_core_r8(pdi_duty_cycle_max_sat));
	OPTIC_DEBUG_WRN("DCDC CORE #26: 0x%02X",
			dcdc_core_r8(pdi_duty_cycle_min_sat));
	OPTIC_DEBUG_WRN("DCDC CORE #27: 0x%02X",
			dcdc_core_r8(pdi_duty_cycle_max));
	OPTIC_DEBUG_WRN("DCDC CORE #28: 0x%02X",
			dcdc_core_r8(pdi_duty_cycle_min));

	OPTIC_DEBUG_WRN("DCDC CORE #29: 0x%02X",
			dcdc_core_r8(pdi_error_max));
	OPTIC_DEBUG_WRN("DCDC CORE #30: 0x%02X",
			dcdc_core_r8(pdi_error_read));
	OPTIC_DEBUG_WRN("DCDC CORE #31: 0x%02X",
			dcdc_core_r8(pdi_delay_deglitch));
	OPTIC_DEBUG_WRN("DCDC CORE #32: 0x%02X",
			dcdc_core_r8(pdi_latch_control));
	OPTIC_DEBUG_WRN("DCDC CORE #33: 0x%02X",
			dcdc_core_r8(pdi_latch_control_noauto));
	OPTIC_DEBUG_WRN("DCDC CORE #34: 0x%02X",
			dcdc_core_r8(pdi_cap_clk_cnt));
	OPTIC_DEBUG_WRN("DCDC CORE #35: 0x%02X",
			dcdc_core_r8(pdi_mdll_divider));

	return OPTIC_STATUS_OK;
}
#endif

/*! @} */
/*! @} */
