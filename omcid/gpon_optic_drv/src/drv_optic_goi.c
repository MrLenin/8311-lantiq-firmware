/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/**
   \file drv_optic_goi.c
   \remarks This is the GPON Optical Interface program file, used for Lantiq's
            GPON Modem driver.
*/

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_goi_interface.h"

#include "drv_optic_calc.h"
#include "drv_optic_mpd.h"
#include "drv_optic_mm.h"
#include "drv_optic_bosa.h"
#include "drv_optic_timer.h"
#include "drv_optic_ll_sys_gpon.h"
#include "drv_optic_ll_status.h"
#include "drv_optic_ll_pll.h"
#include "drv_optic_ll_fcsi.h"
#include "drv_optic_ll_mm.h"
#include "drv_optic_ll_rx.h"
#include "drv_optic_ll_tx.h"
#include "drv_optic_ll_pll.h"
#include "drv_optic_ll_mpd.h"
#include "drv_optic_ll_bert.h"
#include "drv_optic_ll_gpio.h"
#include "drv_optic_ll_int.h"
#include "drv_optic_ll_gtc.h"


/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_GOI_INTERNAL Common GOI Interface - Internal

    This chapter describes the software interface to access and configure the
    GPON Optical Interface (PMA/PMD).
   @{
*/

/**
   Read general configuration data into the context.
*/
enum optic_errorcode goi_cfg_set ( struct optic_device *p_dev,
                                   const struct optic_goi_config *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config *config = &(p_ctrl->config);

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	/* read config parameters */
	config->temperature_check_time =    param->temperature_check_time;
	config->temperature_thres_mpdcorr = param->temperature_thres_mpdcorr;

	config->update_laser_age =          param->update_laser_age;
	p_ctrl->calibrate.timestamp =       param->laser_age;

	config->delay_tx_enable =           param->delay_tx_enable;

 	/* GPONSW-924 -
 	 * LDD Power Save truncates end of burst in extended burst
 	 * length mode against ALU OLT
 	 * */
 	if(is_falcon_chip_a2x()) {
		config->size_tx_fifo = 2048; /* bits -> 512 nibbles */
 		config->delay_tx_disable = 0;
 	}
 	else { /* A12 */
		config->size_tx_fifo = 436; /* bits -> 109 nibbles */
		config->delay_tx_disable = 40;
 	}
	config->temp_ref =                  param->temp_ref;

	config->rx_polarity_regular =       param->rx_polarity_regular;
	config->bias_polarity_regular =     param->bias_polarity_regular;
	config->mod_polarity_regular =      param->mod_polarity_regular;

	config->temp_alarm_red_set =        param->temp_alarm_red_set;
	config->temp_alarm_red_clear =      param->temp_alarm_red_clear;
	config->temp_alarm_yellow_set =     param->temp_alarm_yellow_set;
	config->temp_alarm_yellow_clear =   param->temp_alarm_yellow_clear;

	/* ready to read tables & read configs */
	p_ctrl->state.config_read[OPTIC_CONFIGTYPE_GOI] = true;
	optic_state_set ( p_ctrl, OPTIC_STATE_CONFIG );

	/* range check */
	if (is_falcon_chip_a1x()) {
		if (config->delay_tx_disable < 28) {
			config->delay_tx_disable = 28;
			return OPTIC_STATUS_POOR;
		}
	}

	return OPTIC_STATUS_OK;
}

/**
   Returns general configuration.
*/
enum optic_errorcode goi_cfg_get ( struct optic_device *p_dev,
				   struct optic_goi_config *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config *config = &(p_ctrl->config);

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_goi_config) );

	param->temperature_check_time =    config->temperature_check_time;
	param->temperature_thres_mpdcorr = config->temperature_thres_mpdcorr;

	param->update_laser_age =          config->update_laser_age;
	param->laser_age =                 p_ctrl->calibrate.timestamp;

	param->delay_tx_enable =           config->delay_tx_enable;
	param->delay_tx_disable =          config->delay_tx_disable;
	param->size_tx_fifo =              config->size_tx_fifo;

	param->temp_ref =                  config->temp_ref;

	param->rx_polarity_regular =       config->rx_polarity_regular;
	param->bias_polarity_regular =     config->bias_polarity_regular;
	param->mod_polarity_regular =      config->mod_polarity_regular;

	param->temp_alarm_red_set =        config->temp_alarm_red_set;
	param->temp_alarm_red_clear =      config->temp_alarm_red_clear;
	param->temp_alarm_yellow_set =     config->temp_alarm_yellow_set;
	param->temp_alarm_yellow_clear =   config->temp_alarm_yellow_clear;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode goi_range_cfg_set ( struct optic_device *p_dev,
                                         const struct optic_range_config
                                     	 *param )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_range *range = &(p_ctrl->config.range);
	uint32_t memsize;
	uint16_t temp_diff, extcorr_min_old, extcorr_max_old,
	         extnom_min_old, extnom_max_old;
	uint8_t i;


	if (param == NULL)
		return OPTIC_STATUS_ERR;

	if ((param->tabletemp_extcorr_min == 0) ||
	    (param->tabletemp_extcorr_max == 0) ||
	    (param->tabletemp_extcorr_min >= param->tabletemp_extcorr_max))
		return OPTIC_STATUS_POOR;

	if ((param->tabletemp_extnom_min == 0) ||
	    (param->tabletemp_extnom_max == 0) ||
	    (param->tabletemp_extnom_min >= param->tabletemp_extnom_max))
		return OPTIC_STATUS_POOR;

	if ((param->tabletemp_intcorr_min == 0) ||
	    (param->tabletemp_intcorr_max == 0) ||
	    (param->tabletemp_intcorr_min >= param->tabletemp_intcorr_max))
		return OPTIC_STATUS_POOR;

	if ((param->tabletemp_intnom_min == 0) ||
	    (param->tabletemp_intnom_max == 0) ||
	    (param->tabletemp_intnom_min >= param->tabletemp_intnom_max))
		return OPTIC_STATUS_POOR;

	extcorr_min_old = range->tabletemp_extcorr_min;
	extcorr_max_old = range->tabletemp_extcorr_max;

	extnom_min_old = range->tabletemp_extnom_min;
	extnom_max_old = range->tabletemp_extnom_max;

	range->tabletemp_extcorr_min = param->tabletemp_extcorr_min;
	range->tabletemp_extcorr_max = param->tabletemp_extcorr_max;
	range->tabletemp_extnom_min  = param->tabletemp_extnom_min;
	range->tabletemp_extnom_max  = param->tabletemp_extnom_max;
	range->tabletemp_intcorr_min = param->tabletemp_intcorr_min;
	range->tabletemp_intcorr_max = param->tabletemp_intcorr_max;
	range->tabletemp_intnom_min  = param->tabletemp_intnom_min;
	range->tabletemp_intnom_max  = param->tabletemp_intnom_max;

	range->ibias_max             = param->ibias_max;
	range->imod_max              = param->imod_max;
	range->ibiasimod_max         = param->ibiasimod_max;
	for (i=OPTIC_BIAS; i<=OPTIC_MOD; i++)
		range->intcoeff_max[i] = param->intcoeff_max[i];

	range->vapd_min              = param->vapd_min;
	range->vapd_max              = param->vapd_max;
	range->sat_min               = param->sat_min;
	range->sat_max               = param->sat_max;
	range->vcore_min             = param->vcore_min;
	range->vcore_max             = param->vcore_max;
	range->vddr_min              = param->vddr_min;
	range->vddr_max              = param->vddr_max;

	/* this block is configured and needed in monitor since
		confiugred in MPD */
	p_ctrl->config.monitor.oc_ibias_thr = param->oc_ibias_thr;
	p_ctrl->config.monitor.oc_imod_thr = param->oc_imod_thr;
	p_ctrl->config.monitor.oc_ibias_imod_thr = param->oc_ibias_imod_thr;
	if ((extcorr_min_old !=  range->tabletemp_extcorr_min) ||
	    (extcorr_max_old !=  range->tabletemp_extcorr_max) ||
	    (p_ctrl->table_temperature_corr == NULL)) {
		/* for min, max and all temperatures between -> +1 */
		temp_diff = range->tabletemp_extcorr_max -
			    range->tabletemp_extcorr_min + 1;

		/* create temperature table */
#ifndef OPTIC_LIBRARY
		if (p_ctrl->table_temperature_corr != NULL)
			IFXOS_MemFree(p_ctrl->table_temperature_corr);
#endif
		memsize = sizeof(struct optic_table_temperature_corr) *
		          temp_diff;
		/** \todo use static memory if possible instead */
#ifdef OPTIC_LIBRARY
		p_ctrl->table_temperature_corr = optic_malloc(memsize, MEM_TBL_TEMP_CORR);
#else
		p_ctrl->table_temperature_corr = IFXOS_MemAlloc(memsize);
#endif
		if (p_ctrl->table_temperature_corr == NULL)
			return OPTIC_STATUS_ALLOC_ERR;

		/* init tables (reset quality flag) */
		for (i=OPTIC_TABLETYPE_TEMP_CORR_MIN;
		     i<=OPTIC_TABLETYPE_TEMP_CORR_MAX; i++) {
			ret = optic_init_temptable ( p_ctrl, i );
			if (ret != OPTIC_STATUS_OK)
				return ret;
		}
	}

	if ((extnom_min_old !=  range->tabletemp_extnom_min) ||
	    (extnom_max_old !=  range->tabletemp_extnom_max) ||
	    (p_ctrl->table_temperature_nom == NULL)) {
		/* for min, max and all temperatures between -> +1 */
		temp_diff = range->tabletemp_extnom_max -
			    range->tabletemp_extnom_min + 1;

		/* create temperature table */
		if (p_ctrl->table_temperature_nom != NULL)
			IFXOS_MemFree(p_ctrl->table_temperature_nom);

		memsize = sizeof(struct optic_table_temperature_nom) *
			  temp_diff;
#ifdef OPTIC_LIBRARY
		p_ctrl->table_temperature_nom = optic_malloc(memsize, MEM_TBL_TEMP_NOM);
#else
		p_ctrl->table_temperature_nom = IFXOS_MemAlloc(memsize);
#endif
		if (p_ctrl->table_temperature_nom == NULL)
			return OPTIC_STATUS_ALLOC_ERR;
		/* init tables (reset quality flag) */
		for (i=OPTIC_TABLETYPE_TEMP_NOM_MIN;
		     i<=OPTIC_TABLETYPE_TEMP_NOM_MAX; i++) {
			ret = optic_init_temptable ( p_ctrl, i );
			if (ret != OPTIC_STATUS_OK)
				return ret;
		}
	}

	/* ready to read tables & read configs */
	p_ctrl->state.config_read[OPTIC_CONFIGTYPE_RANGE] = true;
	optic_state_set ( p_ctrl, OPTIC_STATE_CONFIG );

	return ret;
}

enum optic_errorcode goi_range_cfg_get ( struct optic_device *p_dev,
                                         struct optic_range_config *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_range *range = &(p_ctrl->config.range);
	uint8_t i;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_range_config) );

	param->tabletemp_extcorr_min = range->tabletemp_extcorr_min;
	param->tabletemp_extcorr_max = range->tabletemp_extcorr_max;
	param->tabletemp_extnom_min  = range->tabletemp_extnom_min;
	param->tabletemp_extnom_max  = range->tabletemp_extnom_max;
	param->tabletemp_intcorr_min = range->tabletemp_intcorr_min;
	param->tabletemp_intcorr_max = range->tabletemp_intcorr_max;
	param->tabletemp_intnom_min  = range->tabletemp_intnom_min;
	param->tabletemp_intnom_max  = range->tabletemp_intnom_max;

	param->ibias_max             = range->ibias_max;
	param->imod_max              = range->imod_max;
	param->ibiasimod_max         = range->ibiasimod_max;
	for (i=OPTIC_BIAS; i<=OPTIC_MOD; i++)
		param->intcoeff_max[i] = range->intcoeff_max[i];

	param->vapd_min              = range->vapd_min;
	param->vapd_max              = range->vapd_max;
	param->sat_min               = range->sat_min;
	param->sat_max               = range->sat_max;
	param->vcore_min             = range->vcore_min;
	param->vcore_max             = range->vcore_max;
	param->vddr_min              = range->vddr_min;
	param->vddr_max              = range->vddr_max;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode goi_table_set ( struct optic_device *p_dev,
                                     const struct optic_transfer_table_set
                                     *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret;
	uint16_t temp_min, temp_max;
	uint8_t t = param->table_type - OPTIC_TABLETYPE_INTERN_MIN;
	bool complete = true;

	if (param->table_type > OPTIC_TABLETYPE_INTERN_MAX)
		return OPTIC_STATUS_POOR;

	if (p_ctrl->state.config_read[OPTIC_CONFIGTYPE_GOI] == false) {
		OPTIC_DEBUG_ERR("call goi_cfg_set() first");
		return OPTIC_STATUS_ERR;
	}

	/* don't init table (in config phase) few times.. */
	if ((p_ctrl->state.current_state == OPTIC_STATE_CONFIG)
	    && (p_ctrl->state.table_read[t] == true)) {
		return OPTIC_STATUS_OK;
	}

	if (IFXOS_MutexGet(&p_ctrl->access.table_lock) != IFX_SUCCESS)
		return OPTIC_STATUS_ERR;

	ret = optic_write_temptable ( p_ctrl, param->table_type,
				      param->table_depth, param->p_data,
				      &temp_min, &temp_max, &complete);
	if (ret != OPTIC_STATUS_OK) {
		IFXOS_MutexRelease(&p_ctrl->access.table_lock);
		return ret;
	}

	/* table complete or gaps -> interpolation? */
	if (complete == false) {
   		ret = optic_complete_table ( p_ctrl, param->table_type,
					     temp_min, temp_max );
		IFXOS_MutexRelease(&p_ctrl->access.table_lock);

		if (ret != OPTIC_STATUS_OK)
			return ret;
	} else
		IFXOS_MutexRelease(&p_ctrl->access.table_lock);

	/* mark table as read */
	p_ctrl->state.table_read[t] = true;

	/* don't init table (in config phase) few times.. */
	if (p_ctrl->state.current_state == OPTIC_STATE_CONFIG)
		optic_state_set ( p_ctrl, OPTIC_STATE_TABLE_INIT );

	return ret;
}

enum optic_errorcode goi_table_get ( struct optic_device *p_dev,
                                     const struct optic_transfer_table_get_in
				     *param_in,
				     struct optic_transfer_table_get_out
				     *param_out )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret;
	uint8_t t = param_in->table_type - OPTIC_TABLETYPE_INTERN_MIN;

	param_out->table_depth = 0;

	if (param_in->table_type > OPTIC_TABLETYPE_INTERN_MAX)
		return OPTIC_STATUS_POOR;

	if (p_ctrl->state.table_read[t] == false)
		return OPTIC_STATUS_TABLE_UNINIT;

	if (IFXOS_MutexGet(&p_ctrl->access.table_lock) != IFX_SUCCESS)
		return OPTIC_STATUS_ERR;

	ret = optic_read_temptable ( p_ctrl,
					   param_in->table_type,
					   param_in->table_depth,
					   param_in->p_data,
					   param_in->quality,
					   &(param_out->table_depth));

	IFXOS_MutexRelease(&p_ctrl->access.table_lock);

	return ret;
}

/** The goi_init function is called upon GPON system startup to provide initial
    settings for the GPON Optical Interface hardware module.

    Fused calibration values (from chip production) are read and stored in
    hardware registers and software variables.

    Configuration settings and calibration parameters (from system production,
    system = SoC + PCB + BOSA/OMU) are read from an external non-volatile memory
    and stored in internal tables and variables.
*/
enum optic_errorcode goi_init ( struct optic_device *p_dev )
{
	return goi_init_ctrl (p_dev->p_ctrl);
}

/** The GOI_StatusGet function provides a summary of status information
    that is available for the GPON Optical Interface hardware module.
*/
/*  Hardware Programming Details
     The status information is read from the following hardware registers:
     -
*/
enum optic_errorcode goi_status_get ( struct optic_device *p_dev,
			              struct optic_status *param)
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_omu *omu = &(p_ctrl->config.omu);
	struct optic_interrupts *irq = &(p_ctrl->state.interrupts);
	enum optic_errorcode ret;
	bool lol, los;
	enum optic_activation mode, predrv_mode;

	memset(param, 0x00, sizeof(struct optic_status));
	
	param->mode = p_ctrl->config.mode;
	switch (p_ctrl->state.current_state) {
		case OPTIC_STATE_PLL_ERROR:
			param->goi_ready = 255;
			break;
		case OPTIC_STATE_RUN:
		case OPTIC_STATE_MEASURE:
			param->goi_ready = 1;
			break;
		default:
			param->goi_ready = 0;
			break;
	}

	/* rx/tx enable */
	if ((p_ctrl->config.mode == OPTIC_OMU) ||
	    (p_ctrl->config.mode == OPTIC_BOSA) ||
	    (p_ctrl->config.mode == OPTIC_BOSA_2)) {

		/* read rx state */
		ret = optic_ll_pll_module_get ( OPTIC_PLL_RX, &mode );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		param->rx_enable = (mode == OPTIC_ENABLE) ? true : false;

		/* read tx state */
		ret = optic_ll_pll_module_get ( OPTIC_PLL_TX, &mode );
		if (ret != OPTIC_STATUS_OK)
			return ret;
		if (p_ctrl->config.mode == OPTIC_BOSA) {
			/* read bosa tx state */
			ret = optic_ll_fcsi_predriver_switch_get (&predrv_mode);
			if (ret == OPTIC_STATUS_OK && predrv_mode == OPTIC_DISABLE)
				mode = OPTIC_DISABLE;
		}
		param->tx_enable = (mode == OPTIC_ENABLE) ? true : false;
	} else {
		param->rx_enable = false;
		param->tx_enable = false;
	}

	switch (p_ctrl->config.mode) {
	case OPTIC_OMU:
		/* don't use packed structure-element directly */
		ret = optic_ll_int_omu_get ( omu->signal_detect_avail,
					     irq, &los, &lol );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		param->loss_of_signal = los;
		break;
	case OPTIC_BOSA:
	case OPTIC_BOSA_2:
		param->loss_of_signal = irq->signal_lost;
		break;
	default:
		param->loss_of_signal = true;
		break;
	}

	return OPTIC_STATUS_OK;
}


/** The GOI_StatusGet function provides a summary of status information
    that is available for the GPON Optical Interface hardware module.
*/
/*  Hardware Programming Details
     The status information is read from the following hardware registers:
     -
*/
enum optic_errorcode goi_ext_status_get ( struct optic_device *p_dev,
			              struct optic_ext_status *param)
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_omu *omu = &(p_ctrl->config.omu);
	struct optic_interrupts *irq = &(p_ctrl->state.interrupts);
	enum optic_errorcode ret;
	enum optic_statetype state[OPTIC_STATE_HISTORY_DEPTH];
	uint8_t i, max;
	uint16_t cur;
	bool lol, los;
	enum optic_activation mode, predrv_mode;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);

	memset(param, 0x00, sizeof(struct optic_ext_status));

	param->chip = chip_version;
	param->fuse_format = p_ctrl->config.fuses.format;

	ret = optic_state_get ( p_ctrl, state );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	for (i=0; i<OPTIC_STATE_HISTORY_DEPTH; i++)
		param->state_history[i] = state[i];

	max = sizeof(param->config_read) / sizeof(param->config_read[0]);
	for (i=0; i<max; i++)
		param->config_read[i] = p_ctrl->state.config_read[i];

	max = sizeof(param->table_read) / sizeof(param->table_read[0]);
	for (i=0; i<max; i++)
		param->table_read[i] = p_ctrl->state.table_read[i];

	param->mode = p_ctrl->config.mode;
	param->rx_offset = p_ctrl->calibrate.rx_offset;
	param->bias_max = p_ctrl->config.monitor.bias_max <<
			  OPTIC_FLOAT2INTSHIFT_CURRENT;
	param->mod_max = p_ctrl->config.monitor.mod_max <<
	                 OPTIC_FLOAT2INTSHIFT_CURRENT;

	/* rx/tx enable */
	if ((p_ctrl->config.mode == OPTIC_OMU) ||
	    (p_ctrl->config.mode == OPTIC_BOSA) ||
	    (p_ctrl->config.mode == OPTIC_BOSA_2)) {

		/* read rx state */
		ret = optic_ll_pll_module_get ( OPTIC_PLL_RX, &mode );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		param->rx_enable = (mode == OPTIC_ENABLE) ? true : false;

		/* read tx state */
		ret = optic_ll_pll_module_get ( OPTIC_PLL_TX, &mode );
		if (ret != OPTIC_STATUS_OK)
			return ret;
		if (p_ctrl->config.mode == OPTIC_BOSA) {
			/* read bosa tx state */
			ret = optic_ll_fcsi_predriver_switch_get (&predrv_mode);
			if (ret == OPTIC_STATUS_OK && predrv_mode == OPTIC_DISABLE)
				mode = OPTIC_DISABLE;
		}

		param->tx_enable = (mode == OPTIC_ENABLE) ? true : false;
	} else {
		param->rx_enable = false;
		param->tx_enable = false;
	}

	/** read abias/amod (not "init" value)*/
	/* don't use packed structure-element directly */
	ret = optic_mpd_bias_get ( p_ctrl, false, &cur);
	if (ret != OPTIC_STATUS_OK)
			return ret;

	param->bias_current = cur;

	/* don't use packed structure-element directly */
	ret = optic_mpd_mod_get ( p_ctrl, false, &cur );
	if (ret != OPTIC_STATUS_OK)
			return ret;

	param->modulation_current = cur;

	param->meas_power_1490_rssi   = cal->meas_power_1490_rssi;
	param->meas_power_1550_rssi   = cal->meas_power_1550_rssi;
	param->meas_power_1550_rf     = cal->meas_power_1550_rf;

	param->meas_voltage_1490_rssi = cal->meas_voltage_1490_rssi;
	param->meas_current_1490_rssi = cal->meas_current_1490_rssi;
	param->meas_current_1490_rssi_is_positive =
					cal->meas_current_1490_rssi_is_positive;
	param->meas_voltage_1550_rssi = cal->meas_voltage_1550_rssi;
	param->meas_voltage_1550_rf   = cal->meas_voltage_1550_rf;

	/** \todo: lol (bosa) feedback */
	switch (p_ctrl->config.mode) {
	case OPTIC_OMU:
		/* don't use packed structure-element directly */
		ret = optic_ll_int_omu_get ( omu->signal_detect_avail,
					     irq, &los, &lol );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		param->loss_of_signal = los;
		param->loss_of_lock = lol;
		break;
	case OPTIC_BOSA:
	case OPTIC_BOSA_2:
		param->loss_of_signal = irq->signal_lost;
		param->loss_of_lock = irq->rx_lock_lost;
		break;
	default:
		param->loss_of_signal = true;
		param->loss_of_lock = true;
		break;
	}

	/* get PLL lock status */
	ret = optic_ll_pll_check ( );
	if (ret == OPTIC_STATUS_PLL_LOCKED)
		param->pll_lock_status = true;
	else if (ret == OPTIC_STATUS_PLL_NOTLOCKED)
		param->pll_lock_status = false;
	else
		return ret;

	param->temp_alarm_yellow = p_ctrl->state.interrupts.temp_alarm_yellow;
	param->temp_alarm_red = p_ctrl->state.interrupts.temp_alarm_red;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode goi_lts_cfg_set ( struct optic_device *p_dev,
				       const struct optic_lts_config *param )
{
	uint8_t i;
	uint32_t pattern[20];
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config *config = &(p_ctrl->config);

	config->lts_enable = param->enable;

	for (i=0; i<(param->pattern_length+3)/4; i++) {
		pattern[i] = (param->pattern[i+0] << 24) |
			     (param->pattern[i+1] << 16) |
			     (param->pattern[i+2] << 8) |
			     (param->pattern[i+3]);
	}

	return optic_ll_gtc_pattern_config_set ( OPTIC_PATTERNMODE_LTS,
					         pattern,
						 param->pattern_length );
}

enum optic_errorcode goi_lts_cfg_get ( struct optic_device *p_dev,
				       struct optic_lts_config *param )
{
	enum optic_errorcode ret;
	uint8_t i;
	uint32_t pattern[20];
	enum optic_patternmode gtc_mode;
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config *config = &(p_ctrl->config);

	memset ( param, 0x00, sizeof(struct optic_lts_config) );

	ret =  optic_ll_gtc_pattern_config_get ( &gtc_mode,
						 pattern,
						 &(param->pattern_length) );

	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (gtc_mode != OPTIC_PATTERNMODE_LTS)
		return OPTIC_STATUS_ERR;

	param->enable = config->lts_enable;

	for (i=0; i<(param->pattern_length+3)/4; i++) {

		if (i >= sizeof(pattern))
			break;

		if ((i*4 +3) >= ((uint8_t) sizeof(param->pattern)))
			break;

		param->pattern[i*4 +0] = (pattern[i] >> 24) & 0xFF;
		param->pattern[i*4 +1] = (pattern[i] >> 16) & 0xFF;
		param->pattern[i*4 +2] = (pattern[i] >> 8) & 0xFF;
		param->pattern[i*4 +3] = (pattern[i]) & 0xFF;
	}

	return ret;
}

enum optic_errorcode goi_lts_trigger ( void )
{
	struct optic_control *p_ctrl = &(optic_ctrl[0]);
	struct optic_config *config = &(p_ctrl->config);
	if(config->lts_enable)
		return optic_ll_gtc_set ( OPTIC_ENABLE );
	else
		return OPTIC_STATUS_OK;
}

enum optic_errorcode goi_video_cfg_set ( struct optic_device *p_dev,
				         const struct optic_video_config
				         *param )
{
	(void) p_dev;

	return optic_ll_fcsi_video_cfg_set ( param->video_word,
					     param->video_range_low );

}

enum optic_errorcode goi_video_cfg_get ( struct optic_device *p_dev,
				         struct optic_video_config *param )
{
	(void) p_dev;

	memset(param, 0x00, sizeof(struct optic_video_config));

	return optic_ll_fcsi_video_cfg_get ( &(param->video_word),
					     &(param->video_range_low) );
}

enum optic_errorcode goi_video_enable ( struct optic_device *p_dev )
{
	(void) p_dev;

	return optic_ll_fcsi_video_set ( OPTIC_ENABLE );
}

enum optic_errorcode goi_video_disable ( struct optic_device *p_dev )
{
	(void) p_dev;

	return optic_ll_fcsi_video_set ( OPTIC_DISABLE );
}

enum optic_errorcode goi_video_status_get ( struct optic_device *p_dev,
				            struct optic_video_status *param )
{
	enum optic_errorcode ret;
	enum optic_activation mode;

	(void) p_dev;

	memset(param, 0x00, sizeof(struct optic_video_status));

	ret =  optic_ll_fcsi_video_get ( &mode );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	param->video_enable = (mode == OPTIC_ENABLE)? true : false;

	return ret;
}

#ifdef INCLUDE_DEBUG_SUPPORT
enum optic_errorcode goi_mm_interval_cfg_set ( struct optic_device *p_dev,
	const struct optic_mm_interval_config *param )
{
	if (param->measure_interval < 10)
		return OPTIC_STATUS_INVAL;
	((struct optic_control *)p_dev->p_ctrl)->mm_interval =
							param->measure_interval;

	return OPTIC_STATUS_OK;
}
#endif

/* ----------------------------- NON IOCTL ---------------------------------- */

/**
	Start system.

	- set PLL, wait for lock
	- PLL: set OMU/BOSA mode (rx/tx clock source))
	- FCSI initialisation: optic_ll_fcsi_init(Omu/Bosa)
	- enable clock to GOI before writing to registers
	  (SBS2.SYS_GPON.CLKEN.PMATX; ACT.PMATX)
	- APD DCDC initialisation: optic_ll_apd_init()
	- fuse information is read from hardware register FBS0.STATUS:
	  optic_ll_status_fuses_get()
	- store fusing values fuses.tbgp, fuses.vbgp, fuses.irefbgp in FCSI.CBIAS.CTRL1
	  optic_ll_fcsi_fuses_set()
	- measurement path initialization: optic_ll_mm_init()
	  + MM offset/gain correction calibration: optic_ll_mm_calibrate()
	  (called by optic_ll_mm_init() !)
	- MPD initialisation: optic_ll_mpd_init()
	- Evaluate the Coarse DAC to Fine DAC ratio: optic_ll_mpd_ratio_measure()
	  (offset cancelation is part of this function)
	  \note: coarse/fine ratio calculation only needen for BOSA,
	  anyway at the moment initialized in each case (for later switch)
	- measure internal temperature: optic_ll_mm_measure_temp_int
	- measure external temperature (needed for MPD calibration):
	  optic_ll_mm_measure_temp_ext()
	  \note: coarse/fine ratio calculation only needen for BOSA,
	  anyway at the moment initialized in each case (for later switch)
	- BOSA mode:
	  - init bosa: optic_bosa_init()
	  - calibrate MPD gain setting: optic_ll_mpd_calibrate()
	    (called by optic_bosa_init())
	- OMU mode:
	  - init bosa: optic_omu_init()
	- start temperature measurement timer

    \todo Production-test specific initialization to be checked, controlled by bProductionEnable.
*/
enum optic_errorcode goi_init_ctrl ( struct optic_control *p_ctrl )
{
/*	struct optic_device *p_dev = p_ctrl->p_dev_head;*/
	enum optic_errorcode ret;
	bool ignore_error;

	ignore_error = (p_ctrl->config.run_mode &
	                (1<<OPTIC_RUNMODE_ERROR_IGNORE)) ? true : false;

	switch (p_ctrl->state.current_state) {
	case OPTIC_STATE_NOMODE:
		OPTIC_DEBUG_ERR("call optic_mode_set() first !");
		return OPTIC_STATUS_INIT_FAIL;
	case OPTIC_STATE_INIT:
		OPTIC_DEBUG_ERR("call *_cfg_set() first !");
		return OPTIC_STATUS_INIT_FAIL;
	case OPTIC_STATE_CONFIG:
		OPTIC_DEBUG_ERR("configure tables via goi_table_set() first !");
		return OPTIC_STATUS_INIT_FAIL;
	case OPTIC_STATE_CALIBRATE:
	case OPTIC_STATE_RUN:
		ret = optic_ctrl_reset ( p_ctrl, false );
		if (ret != OPTIC_STATUS_OK) {
	 		OPTIC_DEBUG_ERR("goi_init/optic_ctrl_reset: %d",
	 				ret);
			if (! ignore_error)
				return OPTIC_STATUS_INIT_FAIL;
		}
		break;
	case OPTIC_STATE_TABLE_CALC:
	case OPTIC_STATE_MODECHANGE:
		if (p_ctrl->config.mode == OPTIC_NOMODE) {
			optic_state_set ( p_ctrl, OPTIC_STATE_NOMODE );
			return OPTIC_STATUS_INIT_FAIL;
		}
		break;
	case OPTIC_STATE_RESET:
		break;
	default:
		OPTIC_DEBUG_ERR("internal mode = %d",
				p_ctrl->state.current_state);
		return OPTIC_STATUS_INIT_FAIL;
	}
#if (OPTIC_MM_MEASUREMENT_LOOP == ACTIVE)
	optic_timer_stop (OPTIC_TIMER_ID_MEASURE);
#endif

	/* init ext. temperature for DC DC APD update */
	p_ctrl->calibrate.temperature_ext = p_ctrl->config.temp_ref <<
					    OPTIC_FLOAT2INTSHIFT_TEMPERATURE;

	/* config FCSI bfd (init FCSI already done) */
	ret = optic_ll_fcsi_bfd_cfg ( &(p_ctrl->config.fcsi) );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("goi_init/optic_ll_fcsi_bfd_cfg: %d",
	 			ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}


	/* read fusing info */
	ret = optic_ll_status_fuses_get ( &p_ctrl->config.fuses );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("goi_init/optic_ll_status_fuses_get: %d",
	 			ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	/* update fcsi fusing values */
	ret = optic_ll_fcsi_fuses_set ( p_ctrl->config.fuses.tbgp,
					      p_ctrl->config.fuses.vbgp,
					      p_ctrl->config.fuses.irefbgp );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("goi_init/optic_ll_status_fuses_set: %d",
	 			ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

#if (OPTIC_MM_MEASUREMENT_LOOP == ACTIVE)
	/* init MM path */
	ret = optic_mm_init ( p_ctrl );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("goi_init/optic_ll_mm_init: %d", ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}
#endif

	/* activate data/bias path for bert */
	ret = optic_ll_tx_path_bert_set (OPTIC_DISABLE );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("goi_init/optic_ll_tx_path_bert_set: %d",
	 			ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	/* init BERT */
	ret = optic_ll_bert_init ( );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("goi_init/optic_ll_bert_init: %d",
	 			ret);
		if (!ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_ll_int_reset ( &(p_ctrl->state.interrupts) );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("goi_init/optic_ll_int_init: %d",
				ret);
		return ret;
	}

	switch (p_ctrl->config.mode) {
	case OPTIC_OMU:
		/* init omu module */
		ret = omu_init ( p_ctrl );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("goi_init/omu_init: %d", ret);
			if (!ignore_error)
				return OPTIC_STATUS_INIT_FAIL;
		}
		break;
	case OPTIC_BOSA:
	case OPTIC_BOSA_2:
		/* init bosa module */
		ret = optic_bosa_init ( p_ctrl );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("goi_init/optic_bosa_init: %d", ret);
			if (!ignore_error)
				return OPTIC_STATUS_INIT_FAIL;
		}
		break;
	default:
		return OPTIC_STATUS_POOR;
	}
#if (OPTIC_MM_MEASUREMENT_LOOP == ACTIVE)
	optic_state_set ( p_ctrl, OPTIC_STATE_CALIBRATE );
	optic_timer_start ( OPTIC_TIMER_ID_MEASURE,
			    OPTIC_TIMER_MEASURE_CALIBRATION);
#else
	optic_state_set ( p_ctrl, OPTIC_STATE_RUN );
#endif

	optic_irq_set ( p_ctrl->config.mode, OPTIC_ENABLE );

	return ret;
}

void optic_tx_enable (bool enable)
{
	struct optic_control *p_ctrl = (struct optic_control *) &optic_ctrl[0];
	struct optic_device *p_dev = p_ctrl->p_dev_head;

	if (p_ctrl->config.mode == OPTIC_OMU) {
		if (enable == true)
			omu_tx_enable(p_dev);
		else
			omu_tx_disable (p_dev);
	}
	else {
		if (enable == true)
			bosa_tx_enable (p_dev);
		else
			bosa_tx_disable (p_dev);
	}
}


/* ------------------------------------------------------------------------- */

const struct optic_entry goi_function_table[OPTIC_GOI_MAX] = {

/*  0 */  TE0    (FIO_GOI_INIT,                 goi_init),
/*  1 */  TE1in  (FIO_GOI_CFG_SET,              sizeof(struct optic_goi_config),
						goi_cfg_set),
/*  2 */  TE1out (FIO_GOI_CFG_GET,              sizeof(struct optic_goi_config),
						goi_cfg_get),
/*  3 */  TE1in  (FIO_GOI_RANGE_CFG_SET,        sizeof(struct optic_range_config),
						goi_range_cfg_set),
/*  4 */  TE1out (FIO_GOI_RANGE_CFG_GET,        sizeof(struct optic_range_config),
						goi_range_cfg_get),
/*  5 */  TE1in  (FIO_GOI_TABLE_SET,            sizeof(struct optic_transfer_table_set),
						goi_table_set),
/*  6 */  TE2    (FIO_GOI_TABLE_GET,            sizeof(struct optic_transfer_table_get_in),
                                                sizeof(struct optic_transfer_table_get_out),
                                                goi_table_get),
/*  7 */  TE1out (FIO_GOI_STATUS_GET,           sizeof(struct optic_status),
						goi_status_get),
/*  8 */  TE1in  (FIO_GOI_LTS_CFG_SET,          sizeof(struct optic_lts_config),
                                                goi_lts_cfg_set),
/*  9 */  TE1out (FIO_GOI_LTS_CFG_GET,          sizeof(struct optic_lts_config),
                                                goi_lts_cfg_get),
/* 10 */  TE1in  (FIO_GOI_VIDEO_CFG_SET,        sizeof(struct optic_video_config),
                                                goi_video_cfg_set),
/* 11 */  TE1out (FIO_GOI_VIDEO_CFG_GET,        sizeof(struct optic_video_config),
                                                goi_video_cfg_get),
/* 12 */  TE0    (FIO_GOI_VIDEO_ENABLE,         goi_video_enable),
/* 13 */  TE0    (FIO_GOI_VIDEO_DISABLE,        goi_video_disable),
/* 14 */  TE1out (FIO_GOI_VIDEO_STATUS_GET,     sizeof(struct optic_video_status),
                                                goi_video_status_get),
/* 15 */  TE1out (FIO_GOI_EXT_STATUS_GET,       sizeof(struct optic_ext_status),
						goi_ext_status_get),
#ifdef INCLUDE_DEBUG_SUPPORT
/* 19 */  TE1in  (FIO_GOI_MM_INTERVAL_SET,      sizeof(struct optic_mm_interval_config),
                                                goi_mm_interval_cfg_set),
#endif
};

/*! @} */

/*! @} */
