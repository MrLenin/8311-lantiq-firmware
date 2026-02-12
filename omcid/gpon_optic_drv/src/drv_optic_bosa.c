/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, BOSA Interface - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_BOSA_INTERNAL BOSA Interface - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_bosa_interface.h"
#include "drv_optic_bosa.h"

#include "drv_optic_calc.h"
#include "drv_optic_fcsi.h"
#include "drv_optic_rx.h"
#include "drv_optic_tx.h"
#include "drv_optic_dcdc_apd.h"
#include "drv_optic_mpd.h"
#include "drv_optic_ll_fcsi.h"
#include "drv_optic_ll_mm.h"
#include "drv_optic_ll_mpd.h"
#include "drv_optic_ll_pll.h"
#include "drv_optic_ll_rx.h"
#include "drv_optic_ll_tx.h"
#include "drv_optic_ll_gpio.h"
#include "drv_optic_ll_int.h"
#include "drv_optic_ll_dcdc_apd.h"

/**
	Set the BOSA receiver configuration
*/
enum optic_errorcode bosa_rx_cfg_set ( struct optic_device *p_dev,
                                       const struct optic_bosa_rx_config
                                       *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_bosa *bosa = &(p_ctrl->config.bosa);
	enum optic_errorcode ret = OPTIC_STATUS_OK;

	if (param->threshold_lol_set > 100)
		return OPTIC_STATUS_POOR;
	if (param->threshold_lol_clear > 100)
		return OPTIC_STATUS_POOR;

	bosa->dead_zone_elimination = param->dead_zone_elimination;
	bosa->threshold_lol_set     = param->threshold_lol_set;
	bosa->threshold_lol_clear   = param->threshold_lol_clear;
	bosa->threshold_los         = param->threshold_los;
	bosa->threshold_rx_overload = param->threshold_rx_overload;

	/* ready to read tables & read configs */
	p_ctrl->state.config_read[OPTIC_CONFIGTYPE_BOSA_RX] = true;
	optic_state_set ( p_ctrl, OPTIC_STATE_CONFIG );

	return ret;
}

/**
	Read back the BOSA receiver configuration
*/
enum optic_errorcode bosa_rx_cfg_get ( struct optic_device *p_dev,
                                       struct optic_bosa_rx_config *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_bosa *bosa = &(p_ctrl->config.bosa);

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_bosa_rx_config) );

	param->dead_zone_elimination = bosa->dead_zone_elimination;
	param->threshold_lol_set     = bosa->threshold_lol_set;
	param->threshold_lol_clear   = bosa->threshold_lol_clear;
	param->threshold_los         = bosa->threshold_los;
	param->threshold_rx_overload = bosa->threshold_rx_overload;

	return OPTIC_STATUS_OK;
}

/**
	Set the BOSA transmitter configuration
*/
enum optic_errorcode bosa_tx_cfg_set ( struct optic_device *p_dev,
                                       const struct optic_bosa_tx_config
                                       *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_bosa *bosa = &(p_ctrl->config.bosa);
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint8_t i;

	bosa->loop_mode = param->loop_mode;

	for (i=OPTIC_BIAS; i<=OPTIC_MOD; i++) {
		bosa->intcoeff_init[i]        = param->intcoeff_init[i];
		bosa->updatethreshold[i]      = param->updatethreshold[i];
		bosa->learnthreshold[i]       = param->learnthreshold[i];
		bosa->stablethreshold[i]      = param->stablethreshold[i];
		bosa->resetthreshold[i]       = param->resetthreshold[i];
	}
	bosa->pi_control                    = param->pi_control;

	for (i=0; i<3; i++) {
		bosa->p0[i]                 = param->p0[i];
		bosa->p1[i]                 = param->p1[i];
	}

	bosa->pth                           = param->pth;

	/* ready to read tables & read configs */
	p_ctrl->state.config_read[OPTIC_CONFIGTYPE_BOSA_TX] = true;
	optic_state_set ( p_ctrl, OPTIC_STATE_CONFIG );

	return ret;
}

/**
	Read back the BOSA transmitter configuration
*/
enum optic_errorcode bosa_tx_cfg_get ( struct optic_device *p_dev,
                                       struct optic_bosa_tx_config
                                       *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_bosa *bosa = &(p_ctrl->config.bosa);
	uint8_t i;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_bosa_tx_config) );

	param->loop_mode = bosa->loop_mode;

	for (i=OPTIC_BIAS; i<=OPTIC_MOD; i++) {
		param->intcoeff_init[i]        = bosa->intcoeff_init[i];
		param->updatethreshold[i]      = bosa->updatethreshold[i];
		param->learnthreshold[i]       = bosa->learnthreshold[i];
		param->stablethreshold[i]      = bosa->stablethreshold[i];
		param->resetthreshold[i]       = bosa->resetthreshold[i];
	}

	param->pi_control                    = bosa->pi_control;

	for (i=0; i<3; i++) {
		param->p0[i]                 = bosa->p0[i];
		param->p1[i]                 = bosa->p1[i];
	}

	param->pth                           = bosa->pth;

	return OPTIC_STATUS_OK;
}

/**
	Set the power level
*/
enum optic_errorcode bosa_powerlevel_set ( struct optic_device *p_dev,
                                           const struct optic_bosa_powerlevel
                                           *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	/* GPONSW-998: automatic smooth power scaling
	 * save the old powerlevel, this powerlevel will be
	 * returned to PLOAM state machine during powerlevel_get call
	 * if autolevel is switched on
	 */
	if(p_ctrl->config.measurement.RSSI_autolevel == true)
		p_ctrl->calibrate.auto_powerlevel = param->powerlevel ;

	return optic_bosa_powerlevel_set ( p_ctrl, param->powerlevel );
}

/**
	Read the power level
*/
enum optic_errorcode bosa_powerlevel_get ( struct optic_device *p_dev,
                                           struct optic_bosa_powerlevel
                                           *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	memset ( param, 0, sizeof(struct optic_bosa_powerlevel) );

	/* in case of automatic smooth power scaling return 
	   the true power level  */
	param->powerlevel = p_ctrl->calibrate.powerlevel;

	return OPTIC_STATUS_OK;
}

/**
	Configure the bosa loop mode
*/
enum optic_errorcode bosa_loopmode_set ( struct optic_device *p_dev,
                                         const struct optic_bosa_loopmode
                                         *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_config_bosa *bosa = &(p_ctrl->config.bosa);

	if (bosa->loop_mode == param->loop_mode)
		return ret;

	bosa->loop_mode = param->loop_mode;
	if (p_ctrl->config.monitor.rogue_interburst ||
	    p_ctrl->config.monitor.rogue_intraburst)
		optic_ll_mpd_rogue_int_set (0, 0);

	ret = optic_mpd_loopmode ( p_ctrl );

	return ret;
}

/**
	Reads back loop mode
*/
enum optic_errorcode bosa_loopmode_get ( struct optic_device *p_dev,
					 struct optic_bosa_loopmode *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	memset ( param, 0, sizeof(struct optic_bosa_loopmode) );

	param->loop_mode = p_ctrl->config.bosa.loop_mode;

	return OPTIC_STATUS_OK;
}


/**
	Enable the BOSA laser receiver input
*/
enum optic_errorcode bosa_rx_enable ( struct optic_device *p_dev )
{
	enum optic_errorcode ret;
	(void) p_dev;

	ret = optic_ll_rx_dsm_switch(OPTIC_ENABLE);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_rx_cdr_bpd(OPTIC_ENABLE);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret =  optic_ll_rx_afectrl_set ( OPTIC_ENABLE, false );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return OPTIC_STATUS_OK;
}


/**
	Disable the BOSA laser receiver input
*/
enum optic_errorcode bosa_rx_disable ( struct optic_device *p_dev )
{
	enum optic_errorcode ret;
	(void) p_dev;

	/* Switching on/off of RX slice via RSTN of PLL is not allowed 
	 * Switching off RX slice is realized via
	 * switching off data path from GTC to PMA
	 * 
	 * To enable the feature:
	 * "Disable CDR if RX not there but TX eye-measurement wanted"
	 * 
	 * Disabling of bipolar phase detection must be disabled and
	 * LOAD bit in TX slice in register PI_CTRL needs to be set, 
	 * in order to keep frequency and phase constant for TX and 
	 * not having any RX CDR.
	 * (LOAD bit is always set, therefore no function call here)
	 * */
	ret = optic_ll_rx_afectrl_set ( OPTIC_DISABLE, false );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_rx_cdr_bpd(OPTIC_DISABLE);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_rx_dsm_switch(OPTIC_DISABLE);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return OPTIC_STATUS_OK;
}

/**
	Enable the BOSA laser transmitter output
*/
enum optic_errorcode bosa_tx_enable ( struct optic_device *p_dev )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	/* enable rougue ont interrupt */
	if ((p_ctrl->config.monitor.rogue_interburst) ||
	    (p_ctrl->config.monitor.rogue_intraburst))
		optic_ll_mpd_rogue_int_set (
			p_ctrl->config.monitor.rogue_interburst,
			p_ctrl->config.monitor.rogue_intraburst);

	optic_ll_int_reset (&(p_ctrl->state.interrupts));

	/* GPONSW-909
	 * Switching on the TX part via PLL reset bit is not allowed!
	 * For "software rogue" feature, TX shall be switched on by simple
	 * enabling laser light to fiber via switching on pre driver in PMD.
	 *
	 * The enable of pre driver at this position is allowed since
	 * the pre driver was configured properly already before !!!
	 * */
	return optic_ll_fcsi_predriver_switch ( OPTIC_ENABLE);
}

/**
	Disable the BOSA laser transmitter output
*/
enum optic_errorcode bosa_tx_disable ( struct optic_device *p_dev )
{
	(void) p_dev;

	/* GPONSW-909
	 * Switching off the TX part via PLL reset bit is not allowed!
	 * For "software rogue" feature, TX shall be switched off by simple
	 * "cutting" laser light to fiber via switching off pre driver in PMD
	 * */
	return optic_ll_fcsi_predriver_switch ( OPTIC_DISABLE);
}

/**
	Read the BOSA's receiver status
*/
enum optic_errorcode bosa_rx_status_get ( struct optic_device *p_dev,
                                          struct optic_bosa_rx_status
                                          *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_interrupts *irq = &(p_ctrl->state.interrupts);
 	enum optic_activation mode;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
 	enum optic_errorcode ret = OPTIC_STATUS_OK;

	memset ( param, 0, sizeof(struct optic_bosa_rx_status) );

	/* read bosa rx state */
	ret = optic_ll_pll_module_get ( OPTIC_PLL_RX, &mode );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	param->rx_enable = (mode == OPTIC_ENABLE) ? true : false;

	param->meas_power_1490_rssi   = cal->meas_power_1490_rssi;
	param->meas_voltage_1490_rssi = cal->meas_voltage_1490_rssi;
	param->meas_current_1490_rssi = cal->meas_current_1490_rssi;
	param->meas_current_1490_rssi_is_positive =
				cal->meas_current_1490_rssi_is_positive;
	param->meas_voltage_1550_rssi = cal->meas_voltage_1550_rssi;
	param->meas_voltage_1550_rf   = cal->meas_voltage_1550_rf;

	param->loss_of_signal = irq->signal_lost;
	param->loss_of_lock = irq->rx_lock_lost;

	return ret;
}



/**
	Read the BOSA's transmitter status
*/
enum optic_errorcode bosa_tx_status_get ( struct optic_device *p_dev,
                                          struct optic_bosa_tx_status
                                          *param )
{
 	struct optic_control *p_ctrl = p_dev->p_ctrl;
 	struct optic_table_temperature_corr *table =
						p_ctrl->table_temperature_corr;
	uint16_t tbosa = optic_shift_temp_back (p_ctrl->calibrate.
						temperature_ext);
	uint16_t temp_index;
	enum optic_activation mode, predrv_mode;
	enum optic_errorcode ret = OPTIC_STATUS_OK;

	memset ( param, 0, sizeof(struct optic_bosa_tx_status) );

	/* read bosa tx state */
	ret = optic_ll_pll_module_get ( OPTIC_PLL_TX, &mode );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	/* read bosa predriver tx state */
	ret = optic_ll_fcsi_predriver_switch_get (&predrv_mode);
	if (ret == OPTIC_STATUS_OK && predrv_mode == OPTIC_DISABLE)
		mode = OPTIC_DISABLE;

	param->tx_enable = (mode == OPTIC_ENABLE) ? true : false;

	/** abias/amod */
	/* read (actual) bias current */
	ret = optic_mpd_bias_get ( p_ctrl, false,
					 &(param->bias_current) );
	if (ret != OPTIC_STATUS_OK)
			return ret;

	/* read (actual) modulation current */
	ret = optic_mpd_mod_get ( p_ctrl, false,
					&(param->modulation_current) );
	if (ret != OPTIC_STATUS_OK)
			return ret;

	if (tbosa < p_ctrl->config.range.tabletemp_extcorr_min ||
	    tbosa > p_ctrl->config.range.tabletemp_extcorr_max) {
		param->laser_threshold = 0xFFFF;
		param->slope_efficiency = 0xFFFF;
	} else {
		temp_index = tbosa - p_ctrl->config.range.tabletemp_extcorr_min;

		param->laser_threshold = table[temp_index].laserref.ith;
		param->slope_efficiency = table[temp_index].laserref.se;
	}

	return ret;
}

/**
	Read the BOSA's alarm status
*/
enum optic_errorcode bosa_alarm_status_get ( struct optic_device *p_dev,
                                             struct optic_bosa_alarm
                                             *param )
{
  	struct optic_control *p_ctrl = p_dev->p_ctrl;

	memset ( param, 0, sizeof(struct optic_bosa_alarm) );

	param->loss_of_signal = p_ctrl->state.interrupts.signal_lost;
	param->loss_of_lock = p_ctrl->state.interrupts.rx_lock_lost;
	param->rx_overload = p_ctrl->state.interrupts.signal_overload;

	param->laser_overload = p_ctrl->state.interrupts.tx_overcurrent;
	param->bias_overload = p_ctrl->state.interrupts.tx_bias_limit;
	param->modulation_overload = p_ctrl->state.interrupts.tx_mod_limit;
	param->rogue_p0 = p_ctrl->state.interrupts.tx_p0_interburst_alarm;
	param->rogue_p1 = p_ctrl->state.interrupts.tx_p1_interburst_alarm;

	return OPTIC_STATUS_OK;
}

/**
	Clear the BOSA's alarm status
*/
enum optic_errorcode bosa_alarm_status_clear ( struct optic_device *p_dev )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	return optic_ll_int_reset ( &(p_ctrl->state.interrupts) );
}

/**
	Read the integration coefficients
*/
enum optic_errorcode bosa_int_coeff_get ( struct optic_device *p_dev,
					  struct optic_int_coeff *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint8_t i;

	memset ( param, 0, sizeof(struct optic_int_coeff) );

	for (i=OPTIC_BIAS; i<=OPTIC_MOD; i++) {
		param->intcoeff[i] = p_ctrl->calibrate.intcoeff[i];
	}

	return OPTIC_STATUS_OK;
}

/**
	Read the stable check for bias and modulation.
*/
enum optic_errorcode bosa_stable_get ( struct optic_device *p_dev,
				       struct optic_stable *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint8_t i;

	memset ( param, 0, sizeof(struct optic_stable) );

	for (i=OPTIC_BIAS; i<=OPTIC_MOD; i++) {
		param->stable[i] = p_ctrl->calibrate.stable[i];
	}

	return OPTIC_STATUS_OK;
}

/* ----------------------------- NON IOCTL ---------------------------------- */

/**
	The bosa_init function is used to initialize the on-chip hardware for
	the receive and transmit path of the Bidirectional Optical Subassembly
	(BOSA).

	1. configure TX FIFO
	2. init CDR (RX) <- dead_zone_elimination
	3. set LOL thresholds
	4. set LOS threshold
	5. set RX overload threshold
	6. set LSB-MSB flip for RX: data lo & hi, falling & rising edge, monitor
	7. set LSB-MSB flip for TX: data path & bias path
	8. disable receive data signals to GTC
	9. disable receive DAC offset correction
        10. configure PI Ctrl (TX)
	11. MPD Calibration: optic_ll_mpd_calibrate()
	12. Ibias/Imod init + activation dualloop

*/
enum optic_errorcode optic_bosa_init ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint16_t temp_index = p_ctrl->config.temp_ref -
			      p_ctrl->config.range.tabletemp_extnom_min;
	enum optic_powerlevel pl = p_ctrl->calibrate.powerlevel;
	uint16_t ibias, imod;
	bool ignore_error;
	static const bool calibrate[2] = { OPTIC_MPD_CALIBRATE_P0, 
		OPTIC_MPD_CALIBRATE_P1 };
	int16_t dac_coarse[2], dac_fine[2];

	ignore_error = (p_ctrl->config.run_mode &
	                (1<<OPTIC_RUNMODE_ERROR_IGNORE)) ? true : false;

	ret = optic_ll_pll_laser_set ( OPTIC_DISABLE );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/optic_ll_pll_laser_set: %d",
	 			ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_fcsi_predriver_update ( pl, &(p_ctrl->config.fcsi) );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/optic_ll_fcsi_predriver_update: %d",
	 			ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
		return ret;
	}

	/* init APD DCDC */
	ret = optic_ll_dcdc_apd_init ();
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/optic_ll_apd_init: %d", ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_dcdc_apd_update ( p_ctrl );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/optic_dcdc_apd_update: %d",
	 			ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	/* activate APD DCDC */
	ret = optic_ll_dcdc_apd_set ( OPTIC_ENABLE );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/optic_ll_apd_start: %d", ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_calc_thresh_current (
				p_ctrl->config.measurement.rssi_1490_scal_ref,
				p_ctrl->config.bosa.threshold_los,
				&(p_ctrl->calibrate.thresh_current_los) );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/calc_thresh_current: %d",
	 			ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_calc_thresh_current (
				p_ctrl->config.measurement.rssi_1490_scal_ref,
				p_ctrl->config.bosa.threshold_rx_overload,
				&(p_ctrl->calibrate.thresh_current_ovl) );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/calc_thresh_current_1490: %d",
	 			ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	/* \note: vapd_target has to be set (optic_dcdc_apd_voltage_set)
	          thresh_current_los, thresh_current_ovl have to be
	          calculated (optic_calc_thresh_current) */
	ret = optic_calc_offset_and_thresh ( p_ctrl );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/optic_calc_current_thresh: %d",
	 			ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_tx_init (OPTIC_BOSA, p_ctrl->config.bosa.pi_control,
				    p_ctrl->config.delay_tx_enable,
				    p_ctrl->config.delay_tx_disable,
				    p_ctrl->config.size_tx_fifo,
				    p_ctrl->config.bias_polarity_regular,
				    p_ctrl->config.mod_polarity_regular);
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/optic_ll_tx_init: %d",
	 			ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_rx_init ( OPTIC_BOSA,
				    p_ctrl->config.bosa.dead_zone_elimination,
				    p_ctrl->config.bosa.threshold_lol_clear,
				    p_ctrl->config.bosa.threshold_lol_set,
				    p_ctrl->config.rx_polarity_regular,
				    &(p_ctrl->calibrate.rx_offset) );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/optic_ll_rx_init: %d",
	 			ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	p_ctrl->calibrate.ratio_p0 = p_ctrl->config.monitor.ratio_coarse_fine;
	p_ctrl->calibrate.ratio_p1 = p_ctrl->config.monitor.ratio_coarse_fine;

	ret = optic_mpd_init ( p_ctrl );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/optic_ll_mpd_init: %d", ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	/* init mpd and set  dual loop / open loop */
	ret = optic_mpd_loopmode ( p_ctrl );

	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/bosa_dualloop_enable/disable: %d",
				ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	/* A1.1 workaround repeat BOSA fcsi init */
	ret = optic_ll_fcsi_init_bosa_2nd ( );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_ll_fcsi_init: %d", ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_powersave_set ( p_ctrl );
	if (ret !=  OPTIC_STATUS_OK)
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;

/* BEGIN: do offset and gain correction like in dualloop(): */
	/* standard flow: MPD calibration for P0 and P1 */
	/* gain correction with offset cancelation */
	ret = optic_mpd_calibrate_level ( p_ctrl,
			OPTIC_MPD_CALIBRATE_OFFSET, calibrate,
			dac_coarse, dac_fine);

	if (ret != OPTIC_STATUS_OK)
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;

	ret = optic_mpd_codeword_calc ( p_ctrl, calibrate,
					OPTIC_MPD_CALIBRATE_OFFSET,
					dac_coarse, dac_fine );
	if (ret != OPTIC_STATUS_OK)
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
/* END: do offset and gain correction like in dualloop(): */

#if (OPTIC_MPD_COARSE_FINE_RATIO_CALC == ACTIVE)
	ret = optic_ll_mpd_ratio_measure ( p_ctrl );
	if (ret != OPTIC_STATUS_OK)
		return ret;
#endif

	ibias = p_ctrl->table_temperature_corr[temp_index].ibiasimod.ibias[pl];
	imod = p_ctrl->table_temperature_corr[temp_index].ibiasimod.imod[pl];

	if (ibias != 0) {
		ret = optic_mpd_bias_set ( p_ctrl, ibias );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_bosa_init/optic_ll_mpd_ibias_write: %d",
					ret);
			if (!ignore_error)
				return OPTIC_STATUS_INIT_FAIL;
		}
		if (is_falcon_chip_a2x()){
			/*configure the bias low saturation, let choose 90% of the actual resetthreshold*/
			ibias = optic_int_div_rounded (ibias * (p_ctrl->config.bosa.resetthreshold[OPTIC_BIAS]), 100);
			ibias = optic_int_div_rounded (ibias * 90, 100);

			ret = optic_mpd_biaslowsat_set ( p_ctrl, ibias );
			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR("optic_bosa_init/optic_ll_mpd_ibias_write: %d",
						ret);
				if (!ignore_error)
					return OPTIC_STATUS_INIT_FAIL;
			}
		}
	}

	if (imod != 0) {
		ret = optic_mpd_mod_set ( p_ctrl, imod );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_bosa_init/optic_mpd_imod_set: %d",
					ret);
			if (!ignore_error)
				return OPTIC_STATUS_INIT_FAIL;
		}
	}

	/* GPONSW-1035 activate predriver via FCSI at the end of init routine */
	ret = optic_ll_fcsi_predriver_switch (OPTIC_ENABLE);
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/bosa_tx_enable: %d",
				ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

#if (OPTIC_BOSA_IRQ == ACTIVE)
	/* enable interrupts */
	ret = optic_ll_int_all_set ( OPTIC_ENABLE );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/optic_ll_int_set: %d",
				ret);
		return ret;
	}
#else
	/* disable interrupts */
	ret = optic_ll_int_all_set ( OPTIC_DISABLE );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_bosa_init/optic_ll_int_set: %d",
				ret);
		return ret;
	}
#endif
	return ret;
}

enum optic_errorcode optic_powerlevel_set ( const uint8_t powerlevel )
{
	enum optic_powerlevel pl;
	struct optic_control *p_ctrl = &(optic_ctrl[0]);

	pl = (enum optic_powerlevel) powerlevel;

	/* GPONSW-998: automatic smooth power scaling
	 * save the old powerlevel, this powerlevel will be
	 * returned to PLOAM state machine during powerlevel_get call
	 * if autolevel is switched on
	 */
	if(p_ctrl->config.measurement.RSSI_autolevel == true)
		p_ctrl->calibrate.auto_powerlevel = powerlevel ;

	return optic_bosa_powerlevel_set ( p_ctrl, pl );
}

enum optic_errorcode optic_powerlevel_get ( uint8_t *powerlevel )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	enum optic_powerlevel pl;
	struct optic_control *p_ctrl = &(optic_ctrl[0]);

	if (powerlevel != NULL)
		return OPTIC_STATUS_INVAL;

	ret = optic_bosa_powerlevel_get ( p_ctrl, &pl );
	*powerlevel = (uint8_t) pl;

	/* GPONSW-998: automatic smooth power scaling
	 * save the old powerlevel, this powerlevel will be
	 * returned to PLOAM state machine during powerlevel_get call
	 * if autolevel is switched on
	 */
	if(p_ctrl->config.measurement.RSSI_autolevel == true)
		*powerlevel = p_ctrl->calibrate.auto_powerlevel;


	return ret;
}

enum optic_errorcode optic_bosa_powerlevel_set ( struct optic_control *p_ctrl,
                                                 const enum optic_powerlevel
                                                 powerlevel )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	struct optic_config_fcsi *fcsi = &(p_ctrl->config.fcsi);
	int16_t dac_coarse[2], dac_fine[2];
	static const bool calibrate[2] = { OPTIC_MPD_CALIBRATE_P0, 
		OPTIC_MPD_CALIBRATE_P1 };
	enum optic_gainbank gainbank;

	switch (powerlevel) {
	case OPTIC_POWERLEVEL_0:
	case OPTIC_POWERLEVEL_1:
	case OPTIC_POWERLEVEL_2:
		if (cal->powerlevel != powerlevel) {
			cal->powerlevel = powerlevel;

			if (p_ctrl->config.debug_mode == true)
				return OPTIC_STATUS_OK;

			ret = optic_powerlevel2gainbank ( powerlevel,
							  &gainbank );
			if (ret != OPTIC_STATUS_OK)
				return ret;
			ret = optic_fcsi_predriver_update ( powerlevel, fcsi );
			if (ret != OPTIC_STATUS_OK)
				return ret;

			if (IFXOS_MutexGet(&p_ctrl->access.dac_lock) !=
			    IFX_SUCCESS)
				return ret;

			ret = optic_mpd_gainctrl_set ( p_ctrl,
				                       gainbank,
				                       OPTIC_CAL_OFF );
			if (ret == OPTIC_STATUS_OK)
				ret = optic_mpd_tia_offset_set ( p_ctrl,
							         gainbank );
			IFXOS_MutexRelease(&p_ctrl->access.dac_lock);
			if (ret != OPTIC_STATUS_OK)
				return ret;
			/* MPD calibration: with offset cancellation,
			   for P0 and P1, with ibias/ imod update */
			ret = optic_mpd_calibrate_level ( p_ctrl,
							  false,
							  calibrate,
							  dac_coarse,
							  dac_fine );
			if (ret != OPTIC_STATUS_OK)
				return ret;
			ret = optic_mpd_codeword_calc ( p_ctrl,
				calibrate, OPTIC_MPD_CALIBRATE_OFFSET,
				dac_coarse, dac_fine);
			/* update can throw
			   OPTIC_STATUS_MPD_UPDATE_THRES_NOT_REACHED */
			if (ret == OPTIC_STATUS_OK)
				ret = optic_mpd_biasmod_update ( p_ctrl,
							         OPTIC_BIAS );
			if (ret >= OPTIC_STATUS_OK)
				ret = optic_mpd_biasmod_update ( p_ctrl,
							         OPTIC_MOD );
		}
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return ret;
}

/**
	Read the power level
*/
enum optic_errorcode optic_bosa_powerlevel_get ( struct optic_control *p_ctrl,
                                                 enum optic_powerlevel
                                                 *powerlevel )
{
	if (powerlevel != NULL)
		*powerlevel = p_ctrl->calibrate.powerlevel;

	return OPTIC_STATUS_OK;
}


/* ------------------------------------------------------------------------- */

const struct optic_entry bosa_function_table[OPTIC_BOSA_MAX] =
{
/*  0 */  TE1in  (FIO_BOSA_RX_CFG_SET,          sizeof(struct optic_bosa_rx_config),
						bosa_rx_cfg_set),
/*  1 */  TE1out (FIO_BOSA_RX_CFG_GET,          sizeof(struct optic_bosa_rx_config),
						bosa_rx_cfg_get),
/*  2 */  TE1in  (FIO_BOSA_TX_CFG_SET,          sizeof(struct optic_bosa_tx_config),
						bosa_tx_cfg_set),
/*  3 */  TE1out (FIO_BOSA_TX_CFG_GET,          sizeof(struct optic_bosa_tx_config),
                  				bosa_tx_cfg_get),
/*  4 */  TE0    (FIO_BOSA_RX_ENABLE,           bosa_rx_enable),
/*  5 */  TE0    (FIO_BOSA_RX_DISABLE,          bosa_rx_disable),
/*  6 */  TE0    (FIO_BOSA_TX_ENABLE,           bosa_tx_enable),
/*  7 */  TE0    (FIO_BOSA_TX_DISABLE,          bosa_tx_disable),
/*  8 */  TE1in  (FIO_BOSA_POWERLEVEL_SET,      sizeof(struct optic_bosa_powerlevel),
						bosa_powerlevel_set),
/*  9 */  TE1out (FIO_BOSA_POWERLEVEL_GET,      sizeof(struct optic_bosa_powerlevel),
						bosa_powerlevel_get),
/* 10 */  TE1in  (FIO_BOSA_LOOPMODE_SET,        sizeof(struct optic_bosa_loopmode),
                                                bosa_loopmode_set),
/* 11 */  TE1out (FIO_BOSA_LOOPMODE_GET,        sizeof(struct optic_bosa_loopmode),
                                                bosa_loopmode_get),
/* 12 */  TE1out (FIO_BOSA_RX_STATUS_GET,       sizeof(struct optic_bosa_rx_status),
						bosa_rx_status_get),
/* 13 */  TE1out (FIO_BOSA_TX_STATUS_GET,       sizeof(struct optic_bosa_tx_status),
						bosa_tx_status_get),
/* 14 */  TE1out (FIO_BOSA_ALARM_STATUS_GET,    sizeof(struct optic_bosa_alarm),
						bosa_alarm_status_get),
/* 15 */  TE0    (FIO_BOSA_ALARM_STATUS_CLEAR,  bosa_alarm_status_clear),
/* 16 */  TE1out (FIO_BOSA_INT_COEFF_GET,       sizeof(struct optic_int_coeff),
						bosa_int_coeff_get),
/* 17 */  TE1out (FIO_BOSA_STABLE_GET,          sizeof(struct optic_stable),
						bosa_stable_get),


};

/*! @} */

/*! @} */
