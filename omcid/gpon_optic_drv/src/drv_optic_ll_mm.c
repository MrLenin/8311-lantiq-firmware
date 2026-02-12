/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, PMA MM Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_MM_INTERNAL Measurement Module - Internal
   @{
*/

/* activate SYSTEM_SIMULATION for using io_write and fcsi_w */

#include "drv_optic_ll_mm.h"
#include "drv_optic_api.h"
#include "drv_optic_register.h"
#include "drv_optic_calc.h"
#include "drv_optic_ll_fcsi.h"
#include "drv_optic_reg_pma.h"

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_MMTIME == ACTIVE))
static uint32_t jiff[1000];
static uint8_t jiff_index = 0;
#endif


#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_MMTIME == ACTIVE))
static void print_measure_jiffies ( int16_t measure_history[OPTIC_MEASURE_MAX]
						[OPTIC_MM_INIT_AVERAGE_DEPTH] )
{
	uint16_t type, j, t;

	for (type=0; type<OPTIC_MEASURE_MAX; type++)
		for (j=0; j<OPTIC_MM_INIT_AVERAGE_DEPTH; j++) {
			if (j % 10 == 0) {
				t = type*((OPTIC_MM_INIT_AVERAGE_DEPTH-1)/10+2);
				OPTIC_DEBUG_ERR("measure(%d, %d): <%u>",
						type, j/10, jiff[t + j/10 + 1]);
			}
			OPTIC_DEBUG_ERR("measure(%d): hist %d",
					type, measure_history[type][j]);
		}
	return;
}

#endif


enum optic_errorcode optic_ll_mm_prepare ( const enum optic_measure_type type,
					   const uint8_t gain_selector,
					   const enum optic_rssi_1490_mode
					   rssi_1490_mode,
					   const enum optic_vref rssi_1550_vref,
					   const enum optic_vref rf_1550_vref,
					   const uint8_t start,
					   const uint8_t end )
{
	uint32_t reg = OPTIC_MM_M_SET_RESET;
	uint32_t fcsi;
	uint8_t i;

	switch (type) {
	case OPTIC_MEASURE_GAIN_GS0:
	case OPTIC_MEASURE_GAIN_GS1:
	case OPTIC_MEASURE_GAIN_GS2:
	case OPTIC_MEASURE_GAIN_GS3:
	case OPTIC_MEASURE_GAIN_GS4:
	case OPTIC_MEASURE_GAIN_GS5:
		reg |= PMA_M_SET_ROP1490N |
		       PMA_M_SET_IREF;

		if (gain_selector >= 5)
			reg |= PMA_M_SET_IREFVAL;                    /* 20 uA */

		if (is_falcon_chip_a1x())
			break;

		/* additional 300 uA via FCSI */
		optic_ll_fcsi_read (FCSI_CBIAS_CTRL1, &fcsi );
		if (gain_selector < 3) {
			fcsi |= CBIAS_CTRL1_MCAL;
		} else {
			fcsi &= ~CBIAS_CTRL1_MCAL;
		}
		optic_ll_fcsi_write (FCSI_CBIAS_CTRL1, fcsi );
		break;
	case OPTIC_MEASURE_OFFSET_GS0:
	case OPTIC_MEASURE_OFFSET_GS1:
	case OPTIC_MEASURE_OFFSET_GS2:
	case OPTIC_MEASURE_OFFSET_GS3:
	case OPTIC_MEASURE_OFFSET_GS4:
	case OPTIC_MEASURE_OFFSET_GS5:
		reg |= PMA_M_SET_PN_SHORT;
		break;
	case OPTIC_MEASURE_VDD_HALF:
		reg |= ((1<<PMA_M_SET_TS_OFFSET) &
			    PMA_M_SET_TS_MASK) |                       /* vdd */
		       ((1<<PMA_M_SET_VREF_VAL_OFFSET) &
			    PMA_M_SET_VREF_VAL_MASK);
		break;
	case OPTIC_MEASURE_VBE1:
		reg |= ((2<<PMA_M_SET_TS_OFFSET) &
			    PMA_M_SET_TS_MASK) |                      /* vbe1 */
		       ((1<<PMA_M_SET_VREF_VAL_OFFSET) &
			    PMA_M_SET_VREF_VAL_MASK);
		break;
	case OPTIC_MEASURE_VBE2:
		reg |= ((3<<PMA_M_SET_TS_OFFSET) &
			    PMA_M_SET_TS_MASK) |                      /* vbe2 */
		       ((1<<PMA_M_SET_VREF_VAL_OFFSET) &
			    PMA_M_SET_VREF_VAL_MASK);
		break;
	case OPTIC_MEASURE_VOLTAGE_PN:
#if 1
		reg |= PMA_M_SET_TSTRN |
		       PMA_M_SET_TSPN |
		       PMA_M_SET_VREF;

#else
		reg |= PMA_M_SET_TSTRN1 |
		       PMA_M_SET_TSTRN |
		       PMA_M_SET_TSPN |
		       PMA_M_SET_IREF;

		if (pn_iref == OPTIC_IREF_20UA)
			reg |= PMA_M_SET_IREFVAL;

		if (is_falcon_chip_a1x())
			break;

		/* additional 300 uA via FCSI */
		optic_ll_fcsi_read (FCSI_CBIAS_CTRL1, &fcsi );
		if (pn_iref == OPTIC_IREF_400UA)
			fcsi |= CBIAS_CTRL1_MCAL;
		else
			fcsi &= ~CBIAS_CTRL1_MCAL;
		optic_ll_fcsi_write (FCSI_CBIAS_CTRL1, fcsi );
#endif
		break;
	case OPTIC_MEASURE_POWER_RSSI_1490:
		switch (rssi_1490_mode) {
		case OPTIC_RSSI_1490_DIFFERENTIAL:
			reg |= PMA_M_SET_DCDCAPD|
			       PMA_M_SET_ROP1490P;
			break;

		case OPTIC_RSSI_1490_SINGLE_ENDED:
			reg |= PMA_M_SET_ROP1490N |
			       PMA_M_SET_ROP1490P;
			break;
		default:
			return OPTIC_STATUS_POOR;
		}
		break;
	case OPTIC_MEASURE_POWER_RF_1550:
		reg |= ((rf_1550_vref << PMA_M_SET_VREF_VAL_OFFSET) &
			                 PMA_M_SET_VREF_VAL_MASK) |
			PMA_M_SET_RF1550;
		break;
	case OPTIC_MEASURE_POWER_RSSI_1550:
		reg |= ((rssi_1550_vref << PMA_M_SET_VREF_VAL_OFFSET) &
					   PMA_M_SET_VREF_VAL_MASK) |
			PMA_M_SET_ROP1550;
		break;
	default:
		OPTIC_DEBUG_ERR("optic_ll_mm_prepare: invalid type %d", type);
		return OPTIC_STATUS_POOR;
	}

	/* prepare M_SET */
	reg |= (gain_selector << PMA_M_SET_GAIN_OFFSET) & PMA_M_SET_GAIN_MASK;

	for (i=start; i<=end; i++) {
		/* write M_SET */
		pma_w32_table(reg, gpon_mm_slice_pdi_m_set, i);

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP == ACTIVE))
		OPTIC_DEBUG_ERR("optic_ll_mm_prepare: type %d, gain %d, ch %d: 0x%08X",
				type, gain_selector, i, reg);
#endif
	}


	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mm_measure ( const uint8_t *measure_type,
					   int16_t *read )
{
	uint32_t reg;
	/* uint32_t reg2; */
	uint8_t i;

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_MMTIME == ACTIVE))
#if defined(LINUX) && !defined(OPTIC_SIMULATION)
	if (p_ctrl->state.current_state < OPTIC_STATE_RUN)
		jiff[jiff_index++] = jiffies;
#endif
#endif

	for (i=0; i<OPTIC_MM_CHANNELS; i++) {
		if (measure_type[i] == OPTIC_MEASURE_NONE)
			continue;

		reg = pma_r32_table(gpon_mm_slice_pdi_m_result, i);
/*
		reg2 = pma_r32_table(gpon_mm_slice_pdi_m_set, i);
		OPTIC_DEBUG_ERR("set: 0x%08x, result: %d", reg2, reg);
*/
		read[i] = (int16_t) (reg & 0xFFFF);
	}

	return OPTIC_STATUS_OK;
}


/**
   Initialize the Measurement Module (MM).

   	- Set ADC control to default values
      	  GPON_MM_SLICE_PDI.ADC = 0x004C 9262
   	- Disable all measurement channels and open all hardware switches
          GPON_MM_SLICE_PDI.M_SET_0...9 = 0x0000 0000
	- Set the measurement time interval to 1 ms
 	  (this is different from the hardware default value!)
	  GPON_MM_SLICE_PDI.M_TIME_CONFIG = 0x0000 7918
	- Reset the ADC clock divider
	  GPON_MM_SLICE_PDI.MMADC_CLK = 0x0000 0001
	  GPON_MM_SLICE_PDI.MMADC_CLK = 0x0000 0000
	- Initialize the LOS interrupt threshold
	  GPON_MM_SLICE_PDI.ALARM_CFG.LOS_CFG = 0x0000
	- Initialize the overload interrupt threshold
	  GPON_MM_SLICE_PDI.ALARM_CFG.OVERLOAD_CFG = 0xFFFF
	- Initialize MM filter paramaeters
	  GPON_MM_SLICE_PDI.MM_CFG.MM_CLKCFG = 0x0C
	  GPON_MM_SLICE_PDI.MM_CFG.MM_DECCFG = 0x0
	- prepare M_SET for channel 1,2,3 (VDD/2, VBE1, VBE2)
	- estimate gain selector for pn junction measurement (channel 4)
	- prepare M_SET for channel 4
	- Perform the measurement path calibration. optic_ll_mm_calibrate()

   \return
   - OPTIC_STATUS_OK - MM successfully initialized,
   - OPTIC_STATUS_INIT_FAIL - MM not initialized
*/
enum optic_errorcode optic_ll_mm_init ( void )
{
	uint8_t i;
	uint32_t reg;

	/* reset ADC */
	reg = OPTIC_MM_ADC_RESET;
	pma_w32(reg, gpon_mm_slice_pdi_adc);

	/* disable all MM channels */
	reg = OPTIC_MM_M_SET_RESET;
	for (i=0; i<OPTIC_MM_CHANNELS; i++) {
		pma_w32_table(reg, gpon_mm_slice_pdi_m_set, i);
	}

	/* set measurement time interval to 1 ms = 31000  (in 31 MHz cycles) */
	reg = (OPTIC_M_TIME_CONFIG_MEAS_TIME_INIT <<
	       PMA_M_TIME_CONFIG_MEAS_TIME_OFFSET) &
	       PMA_M_TIME_CONFIG_MEAS_TIME_MASK;
	pma_w32(reg, gpon_mm_slice_pdi_m_time_config);

	/* reset ADC clock divider */
	reg = PMA_MMADC_CLK_DIV_RESET;
	pma_w32(reg, gpon_mm_slice_pdi_mmadc_clk);
	reg = 0;
	pma_w32(reg, gpon_mm_slice_pdi_mmadc_clk);

	/* init mm filter */
	reg = ((OPTIC_MM_CFG_MM_DECCFG_INIT << PMA_MM_CFG_MM_DECCFG_OFFSET) &
		                               PMA_MM_CFG_MM_DECCFG_MASK) |
	       ((OPTIC_MM_CFG_MM_CLKCFG_INIT << PMA_MM_CFG_MM_CLKCFG_OFFSET) &
			                        PMA_MM_CFG_MM_CLKCFG_MASK);
	pma_w32(reg, gpon_mm_slice_pdi_mm_cfg);

	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_ll_mm_thresh_reg_set ( const uint16_t ovl_cw,
					          const uint16_t los_cw )
{
	uint32_t reg;

	reg = ((ovl_cw << PMA_ALARM_CFG_OVERLOAD_CFG_OFFSET) &
			  PMA_ALARM_CFG_OVERLOAD_CFG_MASK) |
	      ((los_cw << PMA_ALARM_CFG_LOS_CFG_OFFSET) &
			  PMA_ALARM_CFG_LOS_CFG_MASK);

	pma_w32 ( reg, gpon_mm_slice_pdi_alarm_cfg );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mm_check_thresh ( const enum optic_irq irq,
						const uint16_t thresh_cw_los,
						const uint16_t thresh_cw_ovl,
						bool *correctness )
{
	uint16_t reg;

	if (correctness == NULL)
		return OPTIC_STATUS_ERR;

	*correctness = false;

	reg =  abs ((int16_t) (pma_r32_table(gpon_mm_slice_pdi_m_result, 9)));

	switch (irq) {
	case OPTIC_IRQ_SD:
		if (reg > thresh_cw_los)
			*correctness = true;
		break;
	case OPTIC_IRQ_LOS:
		if (reg < thresh_cw_los)
			*correctness = true;
		break;
	case OPTIC_IRQ_OVL:
		if (reg > thresh_cw_ovl)
			*correctness = true;
		break;
	default:
		*correctness = true;
		break;
	}

	return OPTIC_STATUS_OK;
}



/*! @} */
/*! @} */
