/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, DCDC DDR Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_STATUS_DCDC_DDR_INTERNAL DC/DC DDR Converter Module - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_register.h"
#include "drv_optic_calc.h"
#include "drv_optic_ll_dcdc_ddr.h"

#if defined(LINUX) && defined(__KERNEL__)
#include <falcon/sys1_reg.h>
#include <falcon/sysctrl.h>
#endif
#include "drv_optic_reg_dcdc.h"

/**
	Activates/deactivates DCDC DDR.
*/
enum optic_errorcode optic_ll_dcdc_ddr_set ( const enum optic_activation mode )
{
	uint32_t reg;

	if (mode == OPTIC_ENABLE) {
		reg = DCDC_CONF_TEST_ANA_NOAUTO_SOFT_RES_ADC_N |
		      DCDC_CONF_TEST_ANA_NOAUTO_SOFT_RES_MDLL_N |
		      DCDC_CONF_TEST_ANA_NOAUTO_SOFT_RES_DPWM_N;
		dcdc_ddr_w8( reg, pdi_conf_test_ana_noauto);

		reg = DCDC_CONF_TEST_DIG_NOAUTO_SOFT_RES_PID_N |
		      DCDC_CONF_TEST_DIG_NOAUTO_SOFT_RES_RAMPUP_N;
		dcdc_ddr_w8( reg, pdi_conf_test_dig_noauto);
	} else {
		reg = DCDC_CONF_TEST_ANA_NOAUTO_PD_ADC |
		      DCDC_CONF_TEST_ANA_NOAUTO_RESERVED0 |
		      DCDC_CONF_TEST_ANA_NOAUTO_PD_PFMCOMP |
		      DCDC_CONF_TEST_ANA_NOAUTO_DPWM_BYP;
		dcdc_ddr_w8( reg, pdi_conf_test_ana_noauto);
		dcdc_ddr_w8( 0x00, pdi_conf_test_dig_noauto);
	}

	return OPTIC_STATUS_OK;
}

/**
	Reads back DCDC DDR mode (enable/disable).
*/
enum optic_errorcode optic_ll_dcdc_ddr_get ( enum optic_activation *mode )
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

	reg_ana = dcdc_ddr_r8( pdi_conf_test_ana_noauto);
	reg_dig = dcdc_ddr_r8( pdi_conf_test_dig_noauto);

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
	Set the DDR Voltage.
	This function controls the DC/DC DDR converter.
*/
enum optic_errorcode optic_ll_dcdc_ddr_voltage_set ( const int8_t
						     offset_dcdc_ddr,
						     const uint8_t
						     gain_dcdc_ddr,
						     const uint16_t vddr )
{
	uint32_t reg;
	uint32_t temp;

	/**

		(VDDR/2 + 0,5) * 512 - 3            fuse_gain * 0.2
	VREF =  ------------------------- * ( 0.9 + --------------- ) + fuse_offset
			     4                            64



		VDDR * 256 + 253     288 + fuse_gain
	VREF =  ----------------- * -----------------  + fuse_offset
			4                320

	VDDR [<<OPTIC_FLOAT2INTSHIFT_VOLTAGE]

		                               288 + fuse_gain
	VREF =  ((VDDR << 8) + 253) * ------------------------------------------  + fuse_offset
			               320 << (OPTIC_FLOAT2INTSHIFT_VOLTAGE + 2)

	*/

	temp = (vddr << 8) + 253;

	temp *= (288 + gain_dcdc_ddr);

	temp = optic_uint_div_rounded ( temp,
				320 << (OPTIC_FLOAT2INTSHIFT_VOLTAGE + 2) );


	reg = temp + offset_dcdc_ddr;

	/* set reference value */
	dcdc_ddr_w8 ( reg, pdi_dig_ref );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_dcdc_ddr_voltage_get ( const int8_t
						     offset_dcdc_ddr,
						     const uint8_t
						     gain_dcdc_ddr,
				                     uint16_t *vddr )
{
	uint32_t reg;
	uint32_t temp;
	uint8_t shift = OPTIC_FLOAT2INTSHIFT_VOLTAGE - 8;

	if (vddr == NULL)
		return OPTIC_STATUS_ERR;

	/**
		(VDDR/2 + 0,5) * 512 - 3            fuse_gain * 0.2
	VREF =  ------------------------- * ( 0.9 + --------------- ) + fuse_offset
			     4                            64

		VDDR * 256 + 253     288 + fuse_gain
	VREF =  ----------------- * -----------------  + fuse_offset
			4                320

	 VDDR * 256 + 253      ( VREF - fuse_offset ) * 320
	------------------  =  -----------------------------
	         4                   288 + fuse_gain

		 ( VREF - fuse_offset ) * 1280
	        ------------------------------- - 253
	              288 + fuse_gain
	VDDR = ---------------------------------------
				256

	VDDR [<<OPTIC_FLOAT2INTSHIFT_VOLTAGE]

		  ( VREF - fuse_offset ) * 1280
	VDDR =  ( ------------------------------- - 253 ) << (OPTIC_FLOAT2INTSHIFT_VOLTAGE - 8)
	              288 + fuse_gain

	shift = OPTIC_FLOAT2INTSHIFT_VOLTAGE - 8

		( VREF - fuse_offset ) * (1280 << shift)
	VDDR =  ---------------------------------------- - (253 << shift)
			288 + fuse_gain
	*/

	reg = dcdc_ddr_r8 ( pdi_dig_ref );

	temp = (reg - offset_dcdc_ddr) * (1280 << shift);

	temp = optic_uint_div_rounded ( temp, 288 + gain_dcdc_ddr );

	temp -= (253 << shift);

	*vddr = (uint16_t) temp;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_dcdc_ddr_dutycycle_set ( const uint8_t min,
						       const uint8_t max )
{
	uint32_t reg;

	/* set duty cycle min/max */
	reg = min;
	dcdc_ddr_w8 ( reg, pdi_duty_cycle_min );

	reg = max;
	dcdc_ddr_w8 ( reg, pdi_duty_cycle_max );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_dcdc_ddr_deadzone_set ( const uint8_t del_p,
							const uint8_t del_n )
{
	uint32_t reg;

	reg = ((del_n << DCDC_NON_OV_DELAY_DEL_N_OFFSET)
			& DCDC_NON_OV_DELAY_DEL_N_MASK) |
		  ((del_p << DCDC_NON_OV_DELAY_DEL_P_OFFSET)
		  	& DCDC_NON_OV_DELAY_DEL_P_MASK);

	dcdc_ddr_w8 ( reg, pdi_non_ov_delay );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_dcdc_ddr_dutycycle_get ( uint8_t *min,
						       uint8_t *max )
{
	uint32_t reg;

	if ((min == NULL) || (max == NULL))
		return OPTIC_STATUS_ERR;

	/* get duty cycle min/max */
	reg = dcdc_ddr_r8 ( pdi_duty_cycle_min );
	*min = reg & 0xFF;

	reg = dcdc_ddr_r8 ( pdi_duty_cycle_max );
	*max = reg & 0xFF;

	return OPTIC_STATUS_OK;
}

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_DCDC == ACTIVE))
enum optic_errorcode optic_ll_dcdc_ddr_dump ( void )
{
	OPTIC_DEBUG_WRN("DCDC DDR #0: 0x%02X",
			dcdc_ddr_r8(pdi_pid_hi_b0));
	OPTIC_DEBUG_WRN("DCDC DDR #1: 0x%02X",
			dcdc_ddr_r8(pdi_pid_lo_b0));
	OPTIC_DEBUG_WRN("DCDC DDR #2: 0x%02X",
			dcdc_ddr_r8(pdi_pid_hi_b1));
	OPTIC_DEBUG_WRN("DCDC DDR #3: 0x%02X",
			dcdc_ddr_r8(pdi_pid_lo_b1));
	OPTIC_DEBUG_WRN("DCDC DDR #4: 0x%02X",
			dcdc_ddr_r8(pdi_pid_hi_b2));
	OPTIC_DEBUG_WRN("DCDC DDR #5: 0x%02X",
			dcdc_ddr_r8(pdi_pid_lo_b2));

	OPTIC_DEBUG_WRN("DCDC DDR #6: 0x%02X",
			dcdc_ddr_r8(pdi_clk_set0));
	OPTIC_DEBUG_WRN("DCDC DDR #7: 0x%02X",
			dcdc_ddr_r8(pdi_clk_set1));

	OPTIC_DEBUG_WRN("DCDC DDR #8: 0x%02X",
			dcdc_ddr_r8(pdi_pwm0));
	OPTIC_DEBUG_WRN("DCDC DDR #9: 0x%02X",
			dcdc_ddr_r8(pdi_pwm1));
	OPTIC_DEBUG_WRN("DCDC DDR #10: 0x%02X",
			dcdc_ddr_r8(pdi_bias_vreg));
	OPTIC_DEBUG_WRN("DCDC DDR #11: 0x%02X",
			dcdc_ddr_r8(pdi_dig_ref));
	OPTIC_DEBUG_WRN("DCDC DDR #12: 0x%02X",
			dcdc_ddr_r8(pdi_general));


	OPTIC_DEBUG_WRN("DCDC DDR #13: 0x%02X",
			dcdc_ddr_r8(pdi_adc0));
	OPTIC_DEBUG_WRN("DCDC DDR #14: 0x%02X",
			dcdc_ddr_r8(pdi_adc1));
	OPTIC_DEBUG_WRN("DCDC DDR #15: 0x%02X",
			dcdc_ddr_r8(pdi_adc2));

	OPTIC_DEBUG_WRN("DCDC DDR #16: 0x%02X",
			dcdc_ddr_r8(pdi_conf_test_ana));
	OPTIC_DEBUG_WRN("DCDC DDR #17: 0x%02X",
			dcdc_ddr_r8(pdi_conf_test_dig));
	OPTIC_DEBUG_WRN("DCDC DDR #18: 0x%02X",
			dcdc_ddr_r8(pdi_conf_test_ana_noauto));
	OPTIC_DEBUG_WRN("DCDC DDR #19: 0x%02X",
			dcdc_ddr_r8(pdi_conf_test_dig_noauto));

	OPTIC_DEBUG_WRN("DCDC DDR #20: 0x%02X",
			dcdc_ddr_r8(pdi_dcdc_status));
	OPTIC_DEBUG_WRN("DCDC DDR #21: 0x%02X",
			dcdc_ddr_r8(pdi_pid_status));
	OPTIC_DEBUG_WRN("DCDC DDR #22: 0x%02X",
			dcdc_ddr_r8(pdi_duty_cycle));
	OPTIC_DEBUG_WRN("DCDC DDR #23: 0x%02X",
			dcdc_ddr_r8(pdi_non_ov_delay));
	OPTIC_DEBUG_WRN("DCDC DDR #24: 0x%02X",
			dcdc_ddr_r8(pdi_analog_gain));

	OPTIC_DEBUG_WRN("DCDC DDR #25: 0x%02X",
			dcdc_ddr_r8(pdi_duty_cycle_max_sat));
	OPTIC_DEBUG_WRN("DCDC DDR #26: 0x%02X",
			dcdc_ddr_r8(pdi_duty_cycle_min_sat));
	OPTIC_DEBUG_WRN("DCDC DDR #27: 0x%02X",
			dcdc_ddr_r8(pdi_duty_cycle_max));
	OPTIC_DEBUG_WRN("DCDC DDR #28: 0x%02X",
			dcdc_ddr_r8(pdi_duty_cycle_min));

	OPTIC_DEBUG_WRN("DCDC DDR #29: 0x%02X",
			dcdc_ddr_r8(pdi_error_max));
	OPTIC_DEBUG_WRN("DCDC DDR #30: 0x%02X",
			dcdc_ddr_r8(pdi_error_read));
	OPTIC_DEBUG_WRN("DCDC DDR #31: 0x%02X",
			dcdc_ddr_r8(pdi_delay_deglitch));
	OPTIC_DEBUG_WRN("DCDC DDR #32: 0x%02X",
			dcdc_ddr_r8(pdi_latch_control));
	OPTIC_DEBUG_WRN("DCDC DDR #33: 0x%02X",
			dcdc_ddr_r8(pdi_latch_control_noauto));
	OPTIC_DEBUG_WRN("DCDC DDR #34: 0x%02X",
			dcdc_ddr_r8(pdi_cap_clk_cnt));
	OPTIC_DEBUG_WRN("DCDC DDR #35: 0x%02X",
			dcdc_ddr_r8(pdi_mdll_divider));

	return OPTIC_STATUS_OK;
}
#endif

/*! @} */
/*! @} */
