/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, MM Interface - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_MM_INTERNAL Measurement Interface - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_mm_interface.h"
#include "drv_optic_mm.h"
#include "drv_optic_ll_mm.h"
#include "drv_optic_calc.h"
#include "drv_optic_ll_mpd.h"

/** Precalc first cycles - each 10 measurements of RSSI data */
#define OPTIC_MM_RSSI_AVERAGE_DEPTH 2
/** weigth factor for latest RSSI value */
#define OPTIC_MM_FILTER_RSSI 10

/* must start with 2 (for internal temp measurement gain selector) and toggle
   between <3, >2 to enable/disable p/n junction measurement each second time */
uint8_t gain_select_sequence[6] = { 2, 3, 1, 4, 0, 5 };


static enum optic_errorcode optic_mm_prepare ( struct optic_control *p_ctrl,
					       const enum optic_measure_type
					       type );
static enum optic_errorcode optic_mm_measure ( struct optic_control *p_ctrl );
static enum optic_errorcode optic_mm_powervoltage_get ( struct optic_control
						        *p_ctrl,
						        const enum
						        optic_measure_type
						 	type );



/**
   Read mm configuration data into the context.
*/
enum optic_errorcode mm_cfg_set ( struct optic_device *p_dev,
                                  const struct optic_mm_config *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_measurement *cm = &(p_ctrl->config.measurement);

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	/* measurement */
	cm->tscal_ref =           param->tscal_ref;
	cm->pn_r =                param->pn_r;
	cm->pn_iref =             param->pn_iref;

	cm->rssi_1490_mode =      param->rssi_1490_mode;
	cm->rssi_1490_dark_corr = param->rssi_1490_dark_corr;
	cm->rssi_1490_shunt_res = param->rssi_1490_shunt_res;
	cm->rssi_1550_vref =      param->rssi_1550_vref;
	cm->rf_1550_vref =        param->rf_1550_vref;
	cm->rssi_1490_scal_ref =  param->rssi_1490_scal_ref;
	cm->rssi_1550_scal_ref =  param->rssi_1550_scal_ref;
	cm->rf_1550_scal_ref =    param->rf_1550_scal_ref;

	cm->rssi_1490_parabolic_ref = param->rssi_1490_parabolic_ref;
	cm->meas_dark_current_1490_rssi = param->rssi_1490_dark_ref;

	cm->RSSI_autolevel = param->RSSI_autolevel;
	/* uW -> mW and scaling to integer power values */
	cm->RSSI_1490threshold_low =
		optic_uint_div_rounded(
			param->RSSI_1490threshold_low <<
			OPTIC_FLOAT2INTSHIFT_POWER, 1000);
	cm->RSSI_1490threshold_high =
			optic_uint_div_rounded(
			param->RSSI_1490threshold_high <<
			OPTIC_FLOAT2INTSHIFT_POWER, 1000);

	p_ctrl->state.config_read[OPTIC_CONFIGTYPE_MM] = true;
	optic_state_set ( p_ctrl, OPTIC_STATE_CONFIG );

	return OPTIC_STATUS_OK;
}

/**
   Returns mm configuration.
*/
enum optic_errorcode mm_cfg_get ( struct optic_device *p_dev,
				  struct optic_mm_config *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_measurement *cm = &(p_ctrl->config.measurement);

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_mm_config) );

	/* measurement */
	param->tscal_ref =           cm->tscal_ref;
	param->pn_r =                cm->pn_r;
	param->pn_iref =             cm->pn_iref;

	param->rssi_1490_mode =      cm->rssi_1490_mode;
	param->rssi_1490_shunt_res = cm->rssi_1490_shunt_res;
	param->rssi_1490_dark_corr = cm->rssi_1490_dark_corr;
	param->rssi_1550_vref =      cm->rssi_1550_vref;
	param->rf_1550_vref =        cm->rf_1550_vref;
	param->rssi_1490_scal_ref =  cm->rssi_1490_scal_ref;
	param->rssi_1550_scal_ref =  cm->rssi_1550_scal_ref;
	param->rf_1550_scal_ref =    cm->rf_1550_scal_ref;

	param->rssi_1490_parabolic_ref = cm->rssi_1490_parabolic_ref;
	param->rssi_1490_dark_ref = cm->meas_dark_current_1490_rssi;

	param->RSSI_autolevel = cm->RSSI_autolevel;
	param->RSSI_1490threshold_low =
			optic_uint_div_rounded(
					cm->RSSI_1490threshold_low * 1000,
					1 << OPTIC_FLOAT2INTSHIFT_POWER);
	param->RSSI_1490threshold_high =
			optic_uint_div_rounded(
					cm->RSSI_1490threshold_high * 1000,
					1 << OPTIC_FLOAT2INTSHIFT_POWER);

	return OPTIC_STATUS_OK;
}

/**
	Reads back the result of the latest on-chip temperature measurement.
	Note, temperatures are not shiftet to use integer format.
*/
enum optic_errorcode mm_die_temperature_get ( struct optic_device *p_dev,
   					      struct optic_temperature
   					      *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint16_t temp = (p_ctrl->calibrate.temperature_int) +
			(1<<(OPTIC_FLOAT2INTSHIFT_TEMPERATURE-1));
	temp = temp >> OPTIC_FLOAT2INTSHIFT_TEMPERATURE;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset(param, 0x00, sizeof(struct optic_temperature));

	if (temp < p_ctrl->config.range.tabletemp_intcorr_min) {
		param->temperature = 0xFFFF;
            	return OPTIC_STATUS_INTTEMP_UNDERRUN;
	}
	if (temp > p_ctrl->config.range.tabletemp_intcorr_max) {
		param->temperature = 0xFFFF;
            	return OPTIC_STATUS_INTTEMP_OVERFLOW;
	}

	param->temperature = temp;
	return OPTIC_STATUS_OK;
}

/**
	Reads back the result of the latest external temperature measurement.
	Note, temperatures are not shiftet to use integer format.
*/
enum optic_errorcode mm_laser_temperature_get ( struct optic_device *p_dev,
   					        struct optic_temperature
   					        *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint16_t temp = (p_ctrl->calibrate.temperature_ext) +
			(1<<(OPTIC_FLOAT2INTSHIFT_TEMPERATURE-1));
	temp = temp >> OPTIC_FLOAT2INTSHIFT_TEMPERATURE;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset(param, 0x00, sizeof(struct optic_temperature));

	if (temp < p_ctrl->config.range.tabletemp_extcorr_min) {
		param->temperature = 0xFFFF;
            	return OPTIC_STATUS_INTTEMP_UNDERRUN;
	}
	if (temp > p_ctrl->config.range.tabletemp_extcorr_max) {
		param->temperature = 0xFFFF;
            	return OPTIC_STATUS_INTTEMP_OVERFLOW;
	}

	param->temperature = temp;
	return OPTIC_STATUS_OK;
}

enum optic_errorcode mm_1490_optical_voltage_get ( struct optic_device *p_dev,
					           struct optic_voltage_fine
					           *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset(param, 0x00, sizeof(struct optic_voltage));

	param->voltage_fine_val = p_ctrl->calibrate.meas_voltage_1490_rssi;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode mm_1490_optical_current_get ( struct optic_device *p_dev,
						   struct optic_current_fine
						   *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset(param, 0x00, sizeof(struct optic_current));

	param->current_fine_val = p_ctrl->calibrate.meas_current_1490_rssi;
	param->is_positive =
			p_ctrl->calibrate.meas_current_1490_rssi_is_positive;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode mm_1490_optical_power_get ( struct optic_device *p_dev,
						 struct optic_power *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset(param, 0x00, sizeof(struct optic_power));

	param->power_val = p_ctrl->calibrate.meas_power_1490_rssi;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode mm_1550_optical_voltage_get ( struct optic_device *p_dev,
					           struct optic_voltage_fine
					           *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset(param, 0x00, sizeof(struct optic_voltage));

	param->voltage_fine_val = p_ctrl->calibrate.meas_voltage_1550_rssi;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode mm_1550_electrical_voltage_get ( struct optic_device
                                                      *p_dev,
					              struct optic_voltage_fine
					              *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset(param, 0x00, sizeof(struct optic_voltage));

	param->voltage_fine_val = p_ctrl->calibrate.meas_voltage_1550_rf;

	return OPTIC_STATUS_OK;
}

/* ----------------------------- NON IOCTL ---------------------------------- */

static enum optic_errorcode optic_mm_prepare ( struct optic_control *p_ctrl,
					       const enum optic_measure_type
					       type )
{
	enum optic_errorcode ret;
	struct optic_config_measurement *cf_m = &(p_ctrl->config.measurement);
	struct optic_measurement *meas = &(p_ctrl->calibrate.measurement);
	uint8_t gain_selector, i, start, end;

	switch (type) {
	case OPTIC_MEASURE_GAIN_GS0:
	case OPTIC_MEASURE_GAIN_GS1:
	case OPTIC_MEASURE_GAIN_GS2:
	case OPTIC_MEASURE_GAIN_GS3:
	case OPTIC_MEASURE_GAIN_GS4:
	case OPTIC_MEASURE_GAIN_GS5:
		gain_selector = type - OPTIC_MEASURE_GAIN_GS0;
		break;
	case OPTIC_MEASURE_OFFSET_GS0:
	case OPTIC_MEASURE_OFFSET_GS1:
	case OPTIC_MEASURE_OFFSET_GS2:
	case OPTIC_MEASURE_OFFSET_GS3:
	case OPTIC_MEASURE_OFFSET_GS4:
	case OPTIC_MEASURE_OFFSET_GS5:
		gain_selector = type - OPTIC_MEASURE_OFFSET_GS0;
		break;
	case OPTIC_MEASURE_VDD_HALF:
	case OPTIC_MEASURE_VBE1:
	case OPTIC_MEASURE_VBE2:
		gain_selector = OPTIC_GAIN_SELECTOR_TEMP_INT;
		break;
	case OPTIC_MEASURE_VOLTAGE_PN:
		gain_selector = meas->gain_selector_pn;
		break;
	case OPTIC_MEASURE_POWER_RSSI_1490:
		gain_selector = meas->gain_selector_1490rx;
		break;
	case OPTIC_MEASURE_POWER_RF_1550:
		gain_selector = meas->gain_selector_1550rf;
		break;
	case OPTIC_MEASURE_POWER_RSSI_1550:
		gain_selector = meas->gain_selector_1550rx;
		break;
	default:
		OPTIC_DEBUG_ERR("optic_mm_prepare: invalid type %d", type);
		return OPTIC_STATUS_POOR;
	}

	/* run mode: one measurement per channel */
	if (p_ctrl->state.current_state == OPTIC_STATE_RUN &&
	    p_ctrl->calibrate.measurement.mode != OPTIC_MEASUREMODE_RSSI) {
		if (meas->channel[type] < OPTIC_MM_CHANNELS) {
			/* usually: measure type -> channel */
			start = meas->channel[type];
			end = start;
		} else {
			/* offset, gain measurement: channel 0.. 2 */
			start = 0;
			end = meas->channel[type] - OPTIC_MM_CHANNELS;
		}
	} else {
		/* calibration mode: all channels configured identically OR
		 * internal RSSI measurement mode on all channels */
		start = 0;
		end = 9;
	}

	ret = optic_ll_mm_prepare ( type, gain_selector,
				    cf_m->rssi_1490_mode,
		                    cf_m->rssi_1550_vref,
		                    cf_m->rf_1550_vref,
		                    start, end );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	for (i=start; i<=end; i++)
		meas->measure_type[i] = type;

	return OPTIC_STATUS_OK;
}

static enum optic_errorcode mm_rssi_measure (struct optic_control *p_ctrl,
					     uint8_t i, uint8_t type, 
					     int16_t read, int32_t* p_temp)
{
	enum optic_errorcode ret;
	uint16_t voltage, j;
	struct optic_measurement *meas = &(p_ctrl->calibrate.measurement);
	uint8_t *gain_selector = &(meas->gain_selector_1490rx);
#if (OPTIC_OCAL_SUPPORT == ACTIVE)
	struct optic_ocal *ocal = &(meas->ocal);
#endif

#if (OPTIC_OCAL_SUPPORT == ACTIVE)
	if (((ocal->measure_index >= ocal->measure_number) ||
		(ocal->measure_buffer == NULL)) &&
		meas->mode != OPTIC_MEASUREMODE_RSSI)
		return OPTIC_STATUS_OK;
#else
	if (meas->mode != OPTIC_MEASUREMODE_RSSI)
		return OPTIC_STATUS_OK;
#endif
	/* for both conditions the type has to 
	* be the same for all channels */
	if (type != OPTIC_MEASURE_POWER_RSSI_1490)
		return OPTIC_STATUS_IGNORE;

	/* automatic gain correction in optic_calc_voltage() */
	ret = optic_calc_voltage (
		OPTIC_MEASURE_POWER_RSSI_1490, OPTIC_VREF_0MV,
		&(meas->gain[*gain_selector]), read,
		gain_selector, &voltage);

	if (ret == OPTIC_STATUS_GAIN_SELECTOR_UPDATED) {
#if (OPTIC_OCAL_SUPPORT == ACTIVE)
		ocal->measure_index = 0;
#endif
		ret = optic_mm_prepare (p_ctrl, type);
		if (ret != OPTIC_STATUS_OK)
			return ret;

		return OPTIC_STATUS_GAIN_SELECTOR_UPDATED;
	}

	if (ret != OPTIC_STATUS_OK)
		return ret;
#if (OPTIC_PERIODIC_RSSI == ACTIVE)
#if (OPTIC_OCAL_SUPPORT == ACTIVE)
	if (meas->mode != OPTIC_MEASUREMODE_RSSI) {
		/* OCAL CALL */
		ocal->measure_buffer[ocal->measure_index] = voltage;
		ocal->measure_index ++;
	}
	else
#endif
	{	/* sum up all channel values */
		*p_temp += read;
		if (i == (OPTIC_MM_CHANNELS - 1)) {
			/* current unfiltered average */
			*p_temp = (int16_t) optic_int_div_rounded (*p_temp,
				OPTIC_MM_CHANNELS);
			if (meas->measure_index[OPTIC_MEASURE_POWER_RSSI_1490] >= 
				OPTIC_MM_RSSI_AVERAGE_DEPTH) {
				*p_temp = (*p_temp * OPTIC_MM_FILTER_RSSI) +
					meas->average[type] *
					(100 - OPTIC_MM_FILTER_RSSI);
				meas->average[type] = (int16_t)
					optic_int_div_rounded (*p_temp, 100);
			}
			else {
				/* fill init-average table */
				meas->measure_history
					[type][meas->measure_index[type]] = 
					*p_temp;
				meas->measure_index[type]++;
				if (meas->measure_index[type] == 
					OPTIC_MM_RSSI_AVERAGE_DEPTH) {
					/* calculate first filtered average */
					for (j = 0; j < OPTIC_MM_RSSI_AVERAGE_DEPTH - 1; j++)
						*p_temp += meas->measure_history[type][j];
					meas->average[type] = (uint16_t)
					optic_int_div_rounded (*p_temp,
						OPTIC_MM_RSSI_AVERAGE_DEPTH);
				}
			}
		}

	}
#else
#if (OPTIC_OCAL_SUPPORT == ACTIVE)
	ocal->measure_buffer[ocal->measure_index] = voltage;
	ocal->measure_index ++;
#endif
#endif

	return OPTIC_STATUS_IGNORE;
}

/** prepare the average array till a moving average can be used. */
static enum optic_errorcode mm_prepare_avg (struct optic_control *p_ctrl,
					     uint8_t type, int16_t read)
{
	struct optic_measurement *meas = &(p_ctrl->calibrate.measurement);
	uint8_t *m_index = meas->measure_index;
	uint8_t j;
	int32_t temp = 0;

	/* fill init-average table */
	meas->measure_history[type][m_index[type]] = read;

	/* build average */
	for (j=0; j < m_index[type]; j++) {
#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_MMSTACK == ACTIVE))
		OPTIC_DEBUG_ERR("optic_mm_measure(%d): hist %d",
				type, meas->measure_history[type][j]);
#endif
		temp += meas->measure_history[type][j];
	}
	if (j > 0)
		meas->average[type] = (int16_t)optic_int_div_rounded (temp, j);

	m_index[type] ++;

	return OPTIC_STATUS_OK;
}

static enum optic_errorcode optic_mm_measure ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	struct optic_measurement *meas = &(cal->measurement);
	uint8_t i, type;
	int16_t read[OPTIC_MM_CHANNELS];
	int32_t temp = 0;

	ret = optic_ll_mm_measure ( meas->measure_type, read );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	for (i=0; i < OPTIC_MM_CHANNELS; i++) {
		type = meas->measure_type[i];
		if (type >= OPTIC_MEASURE_MAX)
			continue;
		/* internal RSSI mode and RSSI state triggered from command */
		if (p_ctrl->state.current_state == OPTIC_STATE_MEASURE ||
			meas->mode == OPTIC_MEASUREMODE_RSSI) {
			ret = mm_rssi_measure (p_ctrl, i, 
				type, read[i], &temp);
			/* continue with the next value of another channel */
			if (ret == OPTIC_STATUS_IGNORE)
				continue;
			/*if (ret != OPTIC_STATUS_OK)*/
			/* check always return if not ???
			if (type != OPTIC_MEASURE_POWER_RSSI_1490)
				return OPTIC_STATUS_IGNORE;
			*/
			return ret;
		}
#if (OPTIC_PERIODIC_RSSI == ACTIVE)
		/* RSSI1490 measurement is not working in cyclic condition,
		  so ignore this value  */
		if (type == OPTIC_MEASURE_POWER_RSSI_1490)
			continue;
#endif
		/* initial measurement for buildinng up first average */
		if (meas->measure_index[type] < OPTIC_MM_INIT_AVERAGE_DEPTH) {
			ret = mm_prepare_avg (p_ctrl, type, read[i]);
			/* continue with the next value of another channel */
			continue;
		}
		/* filter new value */
		if (type > OPTIC_MEASURE_OFFSET_GS5){
			temp = meas->average[type] *
				(100 - OPTIC_MM_FILTER_FACTOR_MEASURE);
			temp += (read[i] * OPTIC_MM_FILTER_FACTOR_MEASURE);
		} else {
			/* filter gain and offset MM even more
			  in order to reduce noisy Temperature and RSSI MM */
			temp = meas->average[type] *
					(100 - OPTIC_MM_FILTER_FACTOR_GAIN_OFFS);
			temp += (read[i] * OPTIC_MM_FILTER_FACTOR_GAIN_OFFS);
		}
		meas->average[type] = (int16_t)
				optic_int_div_rounded( temp, 100 );
	}

	return OPTIC_STATUS_OK;
}

/**
	measure rx voltage for RX power measurement

	- configure M_SET for type -> optic_ll_mm_init()
	- measure raw voltage (M_RESULT)
	- correct gain, if needed .. and measure again
	- voltage_corr = voltage_measured / gain_factor[gain] * gain_correction[gain]
			 - offset_corr[gain]

*/

static enum optic_errorcode optic_mm_powervoltage_get ( struct optic_control
						        *p_ctrl,
						        const enum
						        optic_measure_type
						 	type )
{
	enum optic_errorcode ret;

	struct optic_state *state = &(p_ctrl->state);
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	struct optic_measurement *meas = &(cal->measurement);
	enum optic_vref vref;
	uint8_t *p_gain_selector;
	uint16_t *p_meas_voltage;

	if (state->buffer[state->index_buffer] == OPTIC_STATE_MEASURE)
		return OPTIC_STATUS_ERR;
	
	switch (type) {
	case OPTIC_MEASURE_POWER_RSSI_1490:
		vref = OPTIC_VREF_0MV;
		p_gain_selector = &(meas->gain_selector_1490rx);
		p_meas_voltage = &(cal->meas_voltage_1490_rssi);
		break;
	case OPTIC_MEASURE_POWER_RF_1550:
		if (cal->measurement.measure_index[type] < OPTIC_MM_INIT_AVERAGE_DEPTH)
			return OPTIC_STATUS_GAIN_SELECTOR_UPDATED;
		vref = p_ctrl->config.measurement.rf_1550_vref;
		p_gain_selector = &(meas->gain_selector_1550rf);
		p_meas_voltage = &(cal->meas_voltage_1550_rf);
		break;
	case OPTIC_MEASURE_POWER_RSSI_1550:
		if (cal->measurement.measure_index[type] < OPTIC_MM_INIT_AVERAGE_DEPTH)
			return OPTIC_STATUS_GAIN_SELECTOR_UPDATED;
		vref = p_ctrl->config.measurement.rssi_1550_vref;
		p_gain_selector = &(meas->gain_selector_1550rx);
		p_meas_voltage = &(cal->meas_voltage_1550_rssi);
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	/* automatic gain correction in optic_calc_voltage() */
	ret = optic_calc_voltage ( type, vref,
				   &(meas->gain[*p_gain_selector]),
				   meas->average[type],
				   p_gain_selector,
				   p_meas_voltage );

	if (ret == OPTIC_STATUS_GAIN_SELECTOR_UPDATED) {
		meas->measure_index[type] = 0;

		ret = optic_mm_prepare ( p_ctrl, type );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		return OPTIC_STATUS_GAIN_SELECTOR_UPDATED;
	}

	return ret;
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
enum optic_errorcode optic_mm_init ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	uint8_t *chan = cal->measurement.channel;
	uint8_t i;

	ret = optic_ll_mm_init ();
	if (ret != OPTIC_STATUS_OK)
		return ret;

	for (i=0; i<OPTIC_MM_CHANNELS; i++)
		cal->measurement.measure_type[i] = OPTIC_MEASURE_NONE;

	cal->thresh_codeword_ovl = 0xFFFF;
	cal->thresh_codeword_los = 0x0000;
	ret = optic_mm_thresh_set ( p_ctrl );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	for (i=0; i<OPTIC_MEASURE_MAX; i++)
		cal->measurement.measure_index[i] = 0;

	/* init channel assignment */
	for (i=OPTIC_MEASURE_OFFSET_GS0; i<=OPTIC_MEASURE_OFFSET_GS5; i++)
		chan[i] = OPTIC_CHANNEL_MEASURE_OFFSET;
	for (i=OPTIC_MEASURE_GAIN_GS0; i<=OPTIC_MEASURE_GAIN_GS5; i++)
		chan[i] = OPTIC_CHANNEL_MEASURE_GAIN;

	chan[OPTIC_MEASURE_VDD_HALF] =    OPTIC_CHANNEL_MEASURE_VDD_HALF;
	chan[OPTIC_MEASURE_VBE1] =        OPTIC_CHANNEL_MEASURE_VBE1;
	chan[OPTIC_MEASURE_VBE2] =        OPTIC_CHANNEL_MEASURE_VBE2;
	chan[OPTIC_MEASURE_VOLTAGE_PN] =  OPTIC_CHANNEL_MEASURE_VOLTAGE_PN;
	chan[OPTIC_MEASURE_POWER_RSSI_1490] =
					  OPTIC_CHANNEL_MEASURE_POWER_RSSI_1490;
	chan[OPTIC_MEASURE_POWER_RF_1550] =
					  OPTIC_CHANNEL_MEASURE_POWER_RF_1550;
	chan[OPTIC_MEASURE_POWER_RSSI_1550] =
					  OPTIC_CHANNEL_MEASURE_POWER_RSSI_1550;

	/* init gain settings */
	cal->measurement.gain[0].factor =  1; /* factor= 0,25 */
	cal->measurement.gain[1].factor =  2; /* factor=  0,5 */
	cal->measurement.gain[2].factor =  4; /* factor=  1,0 */
	cal->measurement.gain[3].factor =  8; /* factor=  2,0 */
	cal->measurement.gain[4].factor = 16; /* factor=  4,0 */
	cal->measurement.gain[5].factor = 64; /* factor= 16,0 */

	for (i=0; i<6; i++) {
		cal->measurement.gain[i].correction =
					(1 << OPTIC_FLOAT2INTSHIFT_CORRFACTOR);
		cal->measurement.gain[i].offset = 0;
	}

	/* init gain selectors */
	ret = optic_calc_pn_gain_sel ( p_ctrl );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	cal->measurement.gain_selector_1490rx = OPTIC_GAIN_SELECTOR_POWER_INIT;
	cal->measurement.gain_selector_1550rf = OPTIC_GAIN_SELECTOR_POWER_INIT;
	cal->measurement.gain_selector_1550rx = OPTIC_GAIN_SELECTOR_POWER_INIT;

	cal->measurement.rssi1490 = 0;
	cal->measurement.intermediate_rssi1490 = 0;

	ret = optic_mm_prepare ( p_ctrl, OPTIC_MEASURE_GAIN_GS0 );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/* reset control in case of state change */
	ret = optic_mm_control ( p_ctrl );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return OPTIC_STATUS_OK;
}

static enum optic_errorcode optic_mm_control_run ( struct optic_control *p_ctrl)
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_measurement *meas = &(p_ctrl->calibrate.measurement);
	uint8_t measure_type, gain_select;
	static int8_t counter = OPTIC_CHANNEL_MEASURE_UPDATE_CYCLE + 1;
	static int8_t gain_select_old;
	static int8_t rssi_counter = OPTIC_CHANNEL_MEASURE_RSSI_UPDATE_CYCLE + 1;
	static uint8_t meas_type_old;

	switch (meas->mode) {
	case OPTIC_MEASUREMODE_INIT:
#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_MMTIME == ACTIVE))
		print_measure_jiffies(meas->measure_history);
#endif
		/* an internal RSSI measurement was ongoing in the step before */
		if(meas->intermediate_rssi1490) {
			/* proceed from last gain/offset measurment */
			measure_type = meas_type_old; 
			meas->intermediate_rssi1490 = 0;
		}
		else { /* after startup or any state change */
			measure_type = OPTIC_MEASURE_OFFSET_GS0 +
			gain_select_sequence[meas->gain_selector_cal_index];
		}
		ret = optic_mm_prepare ( p_ctrl, measure_type );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		ret = optic_mm_prepare (p_ctrl, OPTIC_MEASURE_VDD_HALF);
		if (ret != OPTIC_STATUS_OK)
			return ret;

		ret = optic_mm_prepare (p_ctrl, OPTIC_MEASURE_VBE1);
		if (ret != OPTIC_STATUS_OK)
			return ret;

		ret = optic_mm_prepare (p_ctrl, OPTIC_MEASURE_VBE2);
		if (ret != OPTIC_STATUS_OK)
			return ret;

		ret = optic_mm_prepare (p_ctrl, OPTIC_MEASURE_VOLTAGE_PN);
		if (ret != OPTIC_STATUS_OK)
			return ret;

		ret = optic_mm_prepare ( p_ctrl, OPTIC_MEASURE_POWER_RF_1550);
		if (ret != OPTIC_STATUS_OK)
			return ret;

		ret = optic_mm_prepare (p_ctrl, OPTIC_MEASURE_POWER_RSSI_1550);
		if (ret != OPTIC_STATUS_OK)
			return ret;

		/* only update if calibration was done before */
		if(meas->rssi1490 == 0) 
			counter = OPTIC_CHANNEL_MEASURE_UPDATE_CYCLE + 1;

		rssi_counter = OPTIC_CHANNEL_MEASURE_RSSI_UPDATE_CYCLE + 1;
		meas->mode = OPTIC_MEASUREMODE_PARALLEL;
		break;
	case OPTIC_MEASUREMODE_PARALLEL:
		ret = optic_mm_measure ( p_ctrl );
		if (ret != OPTIC_STATUS_OK)
			return ret;
#if (OPTIC_PERIODIC_RSSI == ACTIVE)
		/* trigger internal RSSI measurement */
		if (--rssi_counter <= 0) {
			/* remember actual gain/offset measurement setting */
			meas_type_old = meas->measure_type[0];

			/* prepare internal RSSI measurement */
			meas->mode = OPTIC_MEASUREMODE_RSSI;
			ret = optic_mm_prepare (p_ctrl,
						OPTIC_MEASURE_POWER_RSSI_1490);
			if (ret != OPTIC_STATUS_OK)
				return ret;
			
			/* set internal RSSI synchronization bit */
			meas->rssi1490 = 1;
			break;
		} else
#endif
		{
#if (OPTIC_MM_CALIBRATION_UPDATE == ACTIVE)
		if (--counter <= 0) {
			gain_select = meas->gain_selector_cal_index;

#if (OPTIC_MM_GAIN_CORRECTION == ACTIVE)
			/* last measurement was "offset" */
			if ((!is_falcon_chip_a11()) &&
				(meas->measure_type[0] ==
				OPTIC_MEASURE_OFFSET_GS0 +
				gain_select_sequence[gain_select])) {
				measure_type = OPTIC_MEASURE_GAIN_GS0 +
					gain_select_sequence[gain_select];
			} else
#endif
				/* last measurement was "gain" */
				{
					gain_select_old =
						gain_select_sequence[gain_select];
					/* next offset configuration */
					meas->gain_selector_cal_index++;
					if (meas->gain_selector_cal_index >= 6)
						meas->gain_selector_cal_index=0;
					gain_select =
						meas->gain_selector_cal_index;
					measure_type = OPTIC_MEASURE_OFFSET_GS0
						+ gain_select_sequence[gain_select];
				}
				ret = optic_mm_prepare ( p_ctrl, measure_type );
				if (ret != OPTIC_STATUS_OK)
					return ret;

				meas->mode = OPTIC_MEASUREMODE_CALIBRATE;
			}
		}
		break;
	case OPTIC_MEASUREMODE_CALIBRATE:
		gain_select = meas->gain_selector_cal_index;

		if (meas->measure_type[0] == OPTIC_MEASURE_OFFSET_GS0 +
			gain_select_sequence[gain_select]) {
			ret = optic_mm_calibrate ( p_ctrl, gain_select_old);
			if (ret != OPTIC_STATUS_OK)
				return ret;
		}

		counter = OPTIC_CHANNEL_MEASURE_UPDATE_CYCLE + 1;
#endif
		meas->mode = OPTIC_MEASUREMODE_PARALLEL;
		/* release internal RSSI synchronisation bit */
		meas->rssi1490 = 0;
		break;
#if (OPTIC_OCAL_SUPPORT == ACTIVE)
	case OPTIC_MEASUREMODE_OCAL:
		meas->gain_selector_cal_index = 0;
		ret = optic_state_set (p_ctrl, OPTIC_STATE_MEASURE);
		if (ret != OPTIC_STATUS_OK)
			return ret;
		meas->mode = OPTIC_MEASUREMODE_INIT;
		break;
#endif
	case OPTIC_MEASUREMODE_RSSI:
		ret = optic_mm_measure ( p_ctrl );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		meas->mode = OPTIC_MEASUREMODE_INIT;
		/* set syncronisation information for changes 
		 * between internal RSSI and parallel measurement modes */
		meas->intermediate_rssi1490 = 1;
		break;

	default:
		return OPTIC_STATUS_ERR;
	}

	return ret;
}

#if (OPTIC_OCAL_SUPPORT == ACTIVE)
static enum optic_errorcode optic_mm_ctrl_rssi1490 (struct optic_control *p_ctrl)
{
	struct optic_measurement *meas = &(p_ctrl->calibrate.measurement);
	enum optic_errorcode ret = OPTIC_STATUS_OK;

	switch (meas->mode) {
	case OPTIC_MEASUREMODE_INIT:
#if (OPTIC_CAL_RSSI1490_USE_ALL_CHANNELS == ACTIVE)
		ret = optic_mm_prepare (p_ctrl, OPTIC_MEASURE_POWER_RSSI_1490);
		if (ret != OPTIC_STATUS_OK)
			return ret;
#endif
		meas->mode = OPTIC_MEASUREMODE_PARALLEL;
		break;

	case OPTIC_MEASUREMODE_PARALLEL:
		ret = optic_mm_measure ( p_ctrl );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		if (meas->ocal.measure_index == meas->ocal.measure_number) {

				ret = optic_state_set (p_ctrl, OPTIC_STATE_RUN);
				if (ret != OPTIC_STATUS_OK)
					return ret;
				meas->mode = OPTIC_MEASUREMODE_INIT;
#ifndef OPTIC_LIBRARY
				IFXOS_EventWakeUp (&(meas->ocal.event_measure));
#endif
		}
		break;
	case OPTIC_MEASUREMODE_OCAL:
		meas->gain_selector_cal_index = 0;
		ret = optic_state_set (p_ctrl, OPTIC_STATE_MEASURE);
		if (ret != OPTIC_STATUS_OK)
			return ret;
		meas->mode = OPTIC_MEASUREMODE_INIT;
		break;


	default:
		return OPTIC_STATUS_ERR;
	}

	return OPTIC_STATUS_OK;
}
#endif

enum optic_errorcode optic_mm_control ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint8_t state = p_ctrl->state.current_state;
	struct optic_measurement *meas = &(p_ctrl->calibrate.measurement);
	uint8_t type, gain_select;

	if (state == OPTIC_STATE_CALIBRATE) {
	    	switch (meas->mode) {
			case OPTIC_MEASUREMODE_INIT:
				ret = optic_mm_measure ( p_ctrl );
				if (ret != OPTIC_STATUS_OK)
					return ret;

				/* necessary number of measurements collected for
				   type? -> next one */
				type = meas->measure_type[0];

				if (meas->measure_index[type] <
					OPTIC_MM_INIT_AVERAGE_DEPTH)
						return ret;

				if (++type < OPTIC_MEASURE_MAX) {
					/* skip RSSI, not part of cyclic measurements */
					if (type == OPTIC_MEASURE_POWER_RSSI_1490)
						type++;
					ret = optic_mm_prepare (p_ctrl, type);
					if (ret != OPTIC_STATUS_OK)
						return ret;
				} else {
					meas->mode = OPTIC_MEASUREMODE_CALIBRATE;
				}
				break;
			case OPTIC_MEASUREMODE_CALIBRATE:
				for (gain_select=0; gain_select<6; gain_select++) {
					ret = optic_mm_calibrate (p_ctrl, gain_select);
					if (ret != OPTIC_STATUS_OK)
						return ret;
				}

				meas->gain_selector_cal_index = 0;
				ret = optic_state_set ( p_ctrl, OPTIC_STATE_RUN );
				if (ret != OPTIC_STATUS_OK)
					return ret;
				meas->mode = OPTIC_MEASUREMODE_INIT;
#if (OPTIC_BOSA_IRQ == ACTIVE)

				/* enable rougue ont interrupt */
				if ((p_ctrl->config.monitor.rogue_interburst) ||
					(p_ctrl->config.monitor.rogue_intraburst))
					optic_ll_mpd_rogue_int_set (
						p_ctrl->config.monitor.rogue_interburst,
						p_ctrl->config.monitor.rogue_intraburst);
#endif
				break;
			default:
				return OPTIC_STATUS_ERR;
		}
	} else {

		/* measurement phase (rotating measurements) */
		if (state == OPTIC_STATE_RUN) {
			ret = optic_mm_control_run (p_ctrl);
		}

#if (OPTIC_OCAL_SUPPORT == ACTIVE)
		/* special measurement phase (RSSI 1490 exclussivly) */
		if (state == OPTIC_STATE_MEASURE) {
			ret = optic_mm_ctrl_rssi1490 (p_ctrl);
		}
#endif
	}

	return ret;
}

/**
	Calibrate the Measurement Module (MM).
	Use channel 0 as the automatic re-calibration channel.

	- Select channel 0 as the calibration channel
	- Write SBS2.GPON_MM_SLICE_PDI.M_SET_0 as below to configure the channel
	- Read RESULT_0 as result, average 8 measurements to reduce noise effects.
	- First run the offset calibration once for each of the 6 gain stages
	- Then run the gain calibration once for each of the 6 gain stages
	- While calculating the calibration values, the following fuses must
	  be taken into account:
		nFuseVcalmm20 : calibrates the 20 uA current source
		nFuseVcalmm100: calibrates the 100 uA current source
		nFuseVcalmm400: calibrates the 400 uA current source

	- Store the gain and offset correction values

	   1. Calibrate offset at gain = 0.25
	      M_SET_0 = 0x0020 2000
	      (pn_short = 1, gain = 0, lock = 1, all other bits are 0)
	      nGOI_ADC_offsetCorrection(0) = M_RESULT_0

	   2. Calibrate offset at gain = 0.5
	      M_SET_0 = 0x0021 2000
	      (pn_short = 1, gain = 1, lock = 1, all other bits are 0)
	      nGOI_ADC_offsetCorrection(1) = M_RESULT_0

	   3. Calibrate offset at gain = 1
	      M_SET_0 = 0x0022 2000
	      (pn_short = 1, gain = 2, lock = 1, all other bits are 0)
	      nGOI_ADC_offsetCorrection(2) = M_RESULT_0

	   4. Calibrate offset at gain = 2
	      M_SET_0 = 0x0023 2000
	      (pn_short = 1, gain = 3, lock = 1, all other bits are 0)
	      nGOI_ADC_offsetCorrection(3) = M_RESULT_0

	   5. Calibrate offset at gain = 4
	      M_SET_0 = 0x0024 2000
	      (pn_short = 1, gain = 4, lock = 1, all other bits are 0)
	      nGOI_ADC_offsetCorrection(4) = M_RESULT_0

	   6. Calibrate offset at gain 0 16
	      M_SET_0 = 0x0025 2000
	      (pn_short = 1, gain = 5, lock = 1, all other bits are 0)
	      nGOI_ADC_offsetCorrection(5) = M_RESULT_0

	   7. Calibrate gain at gain = 0.25, current = 400 uA
	      M_SET_0 = 0x0020 0008
	      (irefval = 1 (100 uA), gain = 0, lock = 1, all other bits are 0)
	      FCSI.CBBIAS.CTRL1.MCAL = 1 (300 uA)
	      nGOI_ADC_gainCorrection(0) = M_RESULT_0

	   8. Calibrate gain at gain = 0.5, current = 400 uA
	      M_SET_0 = 0x0021 0008
	      (irefval = 1 (100 uA),gain = 1, lock = 1, all other bits are 0)
	      FCSI.CBBIAS.CTRL1.MCAL = 1 (300 uA)
	      nGOI_ADC_gainCorrection(1) = M_RESULT_0

	   9. Calibrate gain at gain = 1, current = 400 uA
	      M_SET_0 = 0x0022 0008
	      (irefval = 1 (100 uA),gain = 2, lock = 1, all other bits are 0)
	      FCSI.CBBIAS.CTRL1.MCAL = 1 (300 uA)
	      nGOI_ADC_gainCorrection(2) = M_RESULT_0

	   10. Calibrate gain at gain = 2, current = 100 uA
	      M_SET_0 = 0x0023 0008
	      (irefval = 1 (100 uA),gain = 3, lock = 1, all other bits are 0)
	      FCSI.CBBIAS.CTRL1.MCAL = 1 (300 uA)
	      nGOI_ADC_gainCorrection(3) = M_RESULT_0

	   11. Calibrate gain at gain = 4, current = 100 uA
	      M_SET_0 = 0x0024 0008
	      (irefval = 1 (100 uA),gain = 4, lock = 1, all other bits are 0)
	      FCSI.CBBIAS.CTRL1.MCAL = 1 (300 uA)
	      nGOI_ADC_gainCorrection(4) = M_RESULT_0

	   12. Calibrate gain at gain = 16, current = 20 uA
	      M_SET_0 = 0x0025 0000
	      (irefval = 0 (20 uA),gain = 5, lock = 1, all other bits are 0)
	      FCSI.CBBIAS.CTRL1.MCAL = 0 (0 uA)
	      nGOI_ADC_gainCorrection(5) = M_RESULT_0

	\return
	- OPTIC_STATUS_OK - MM successfully calibrated,
	- OPTIC_STATUS_ERR - MM not calibrated

*/

enum optic_errorcode optic_mm_calibrate ( struct optic_control *p_ctrl,
					  uint8_t gain_selector )
{
	struct optic_measurement *measure = &(p_ctrl->calibrate.measurement);
	struct optic_table_mm_gain *gain = measure->gain;
	uint8_t fuse;
	int16_t read, fuse_factor, vref;
	int32_t temp;

	if (gain_selector > 5)
		return OPTIC_STATUS_POOR;

	gain[gain_selector].offset = measure->average[OPTIC_MEASURE_OFFSET_GS0 +
						      gain_selector];
	read = measure->average[OPTIC_MEASURE_GAIN_GS0 + gain_selector];

	switch (gain_selector) {
	/* 400 uA: 100 uA via IFREFVAL, +300 uA via FCSI */
	case 0:
	case 1:
	case 2:
		if (is_falcon_chip_a2x()) {
			vref = 400;
			fuse = p_ctrl->config.fuses.vcal_mm400;
		} else {
			/* FCSI 300uA not working for A11, A12 */
			vref = 100;
			fuse = p_ctrl->config.fuses.vcal_mm100;
		}
		break;
	/* 100 uA: 100 uA via IFREFVAL */
	case 3:
	case 4:
		vref = 100;
		fuse = p_ctrl->config.fuses.vcal_mm100;
		break;
	/* 20 uA: 20 uA via IFREFVAL */
	case 5:
		vref = 20;
		fuse = p_ctrl->config.fuses.vcal_mm20;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	/**
	                       fuse * 0,2            fuse
	 	fuse factor = ----------- + 0,9 =  --------- + 0,9
			           64                64 * 5

				fuse + 288
		fuse factor =  -------------
				 1<<6 * 5

		fuse factor [*1000]

				(fuse + 288) * 1000
		fuse factor =  ---------------------
				     5 << 6
	*/
	temp = fuse + 288;
	temp *= 1000;
	fuse_factor = optic_int_div_rounded ( temp, 5 << 6 );

	/**
	gain_factor = 0,25 .. 16
	vref = 0,4 0,1 0,02
	fuse = 1,0 +/- 10%  ->  0,8 .. 1,1
	VDACref = 1
	offset = 16 bit int, low
	read_data = 16 bit uint, high
		      (vref * gain_factor[i] * 2^9)
		   ( -------------------------------  + 0,5  ) * 2^7
			    fuse * VDACref
	corr[i] = ----------------------------------------------------
				read_data - offset[i]

	we use scaled values (integer):
	gain_factor = < <<2 >      1..64
	vref = < *1000 >           400 100 20
	fuse = < *1000 >           800.. 1100
	VDACref =                  1

		   vref / 1000 * (gain_factor >> 2) * 2^9
		 ( --------------------------------------  + 0,5 ) * 2^7
			fuse / 1000 * 1
	corr[i] = -----------------------------------------------------
				read_data - offset[i]

		    vref  * gain_factor * 2^7
		  ( -------------------------  + 0,5 ) * 2^7
			   fuse  * 1
	corr[i] = -------------------------------------------
				read_data - offset[i]

		  vref  * gain_factor * 2^(7+7)
		  -----------------------------   +  (0,5  * 2^7)
				fuse
	corr[i] = -----------------------------------------------
			read_data - offset[i]

		    vref  * gain_factor * 2^14
		   ----------------------------  + 64
			      fuse
	corr[i] = ------------------------------------
			read_data - offset[i]


	save corr[i] with << OPTIC_FLOAT2INTSHIFT_CORRFACTOR
	*/

	temp = ((vref * gain[gain_selector].factor) << 14);

	temp = optic_int_div_rounded ( temp, fuse_factor );

	/* << OPTIC_FLOAT2INTSHIFT_CORRFACTOR but round compensation */
	temp = (temp + 64) * (1 << OPTIC_FLOAT2INTSHIFT_CORRFACTOR);

	read -= gain[gain_selector].offset;

	temp = optic_int_div_rounded ( temp, read );

#if (OPTIC_MM_GAIN_CORRECTION == ACTIVE)
	if (!is_falcon_chip_a11())
		gain[gain_selector].correction = (int16_t) temp;
#endif

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_MMSTACK == ACTIVE))
	if (p_ctrl->state.current_state == OPTIC_STATE_RUN) {
		OPTIC_DEBUG_ERR("mm_dump(offset %d): %7d", gain_selector,
				measure->average[OPTIC_MEASURE_OFFSET_GS0
				+ gain_selector]);
		OPTIC_DEBUG_ERR("mm_dump( gain %d ): %7d", gain_selector,
				measure->average[OPTIC_MEASURE_GAIN_GS0
				+ gain_selector]);
	}
#endif
	return OPTIC_STATUS_OK;
}

/**
	measure internal temperature

	- configure M_SET for VDD/2, VBE1, VBE2 -> optic_ll_mm_init()
	- measure VDD/2, VBE1, VBE2
	- calculate internal temp:
		T = q/n/k * (VBE1-VBE2) / ln (80 * (VDD-VBE2)/(VDD-VBE1))
*/
enum optic_errorcode optic_mm_temp_int_get ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	enum optic_measure_type type;
	enum optic_measure_type types[] = { OPTIC_MEASURE_VDD_HALF,
					    OPTIC_MEASURE_VBE1,
					    OPTIC_MEASURE_VBE2 };
	uint8_t t, counter = 0;

	uint8_t gain_selector = OPTIC_GAIN_SELECTOR_TEMP_INT;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	struct optic_measurement *meas = &(cal->measurement);
	uint16_t *temp_int = &(cal->temperature_int);
	uint16_t voltage[3] = {0, 0, 0};
	uint16_t t_nom;
#if (OPTIC_AVERAGE_NOM_TEMP_INT == ACTIVE)
	int32_t temp;
	static uint16_t t_nom_average = 0;
#endif

	/**
	Vref = 0,5 V
	gain_factor = 0,25 .. 16
	offset = 16 bit int, low
   	gain_correction = factor ~ 1
	read_data = 16 bit uint, high

			    (read_data - offset[2]) * gain_correction[2]
	VDD/2, VBE1, VBE2 = --------------------------------------------  + Vref
					2^16 * gain_factor[2]
	*/

	for (t=0; t <sizeof(types)/sizeof(types[0]); t ++) {
		type = types[t];

		if (type >= OPTIC_MEASURE_MAX)
			return OPTIC_STATUS_ERR;
		/* automatic gain correction in optic_calc_voltage() */
		ret = optic_calc_voltage ( type, OPTIC_VREF_500MV,
			&(meas->gain[gain_selector]), meas->average[type],
			&gain_selector, &voltage[counter] );

		if (ret == OPTIC_STATUS_GAIN_SELECTOR_UPDATED) {
			meas->measure_index[type] = 0;

			ret = optic_mm_prepare ( p_ctrl, type );
			if (ret != OPTIC_STATUS_OK)
				return ret;

			return OPTIC_STATUS_GAIN_SELECTOR_UPDATED;
		}

		if (ret != OPTIC_STATUS_OK)
			return ret;

		counter++;
	}

	ret = optic_calc_temperature_int ( voltage[0], voltage[1],
		voltage[2], &t_nom );
	if (ret != OPTIC_STATUS_OK)
		return ret;

#if 0
	/* avoid range check for raw non averaged values */
	ret = optic_rangecheck_itemp_nom ( &(p_ctrl->config.range), t_nom );
	if (ret != OPTIC_STATUS_OK)
		return ret;
#endif

#if (OPTIC_AVERAGE_NOM_TEMP_INT == ACTIVE)
	/* measured nominal external temperature + old average value */
	if (t_nom_average != 0) {
		temp = t_nom_average * (100 - OPTIC_MM_FILTER_FACTOR_TEMP_INT)
		       + (t_nom * OPTIC_MM_FILTER_FACTOR_TEMP_INT);
		t_nom = optic_uint_div_rounded ( temp, 100 );
	}

	t_nom_average = t_nom;
#endif

	ret = optic_fusecorrect_temp ( &(p_ctrl->config.fuses),
					     t_nom, temp_int );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	
	if (p_ctrl->temp_measure < OPTIC_MIN_TEMP_MEASURES) {
		p_ctrl->temp_measure++;
		/* avoid range check for first collected values */
		return ret;
	}
	ret = optic_rangecheck_itemp_nom ( &(p_ctrl->config.range),
							*temp_int );
	if (ret == OPTIC_STATUS_INTTEMP_OVERFLOW) {
		OPTIC_DEBUG_ERR("iTemp temp_int overflow (%d >> 4), DCDC disabled", *temp_int);
	}
	if (ret != OPTIC_STATUS_OK)
		return ret;
	return ret;
}

/**
	measure nominal external temperature via p/n junction

	- calculate Umax, estimate gain -> optic_ll_mm_init()
	- configure M_SET for p/n junction -> optic_ll_mm_init()
	- measure raw voltage (M_RESULT)
	- voltage_corr = voltage_measured / gain_factor[gain] * gain_correction[gain]
			 - offset_corr[gain]

*/
enum optic_errorcode optic_mm_temp_ext_get ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	struct optic_config *config = &(p_ctrl->config);
	struct optic_measurement *meas = &(cal->measurement);

	uint16_t u_corr;
	uint16_t t_nom;
	uint16_t *temp_ext = &(cal->temperature_ext);
#if (OPTIC_AVERAGE_NOM_TEMP_EXT == ACTIVE)
	int32_t temp;
	static uint16_t t_nom_average = 0;
#endif

	/**
	Vref = 0 V
	gain_factor = 0,25 .. 16
	offset = 16 bit int, low
   	gain_correction = factor ~ 1
	read_data = 16 bit uint, high

		 (read_data - offset[gain]) * gain_correction[gain]
	U_corr = -------------------------------------------------- + Vref
			2^16 * gain_factor[gain]
	*/

	/* automatic gain correction in optic_calc_voltage() */
	ret = optic_calc_voltage ( OPTIC_MEASURE_VOLTAGE_PN,
					OPTIC_VREF_0MV,
					&(meas->gain[meas->gain_selector_pn]),
					meas->average[OPTIC_MEASURE_VOLTAGE_PN],
					&(meas->gain_selector_pn),
					&u_corr );

	if (ret == OPTIC_STATUS_GAIN_SELECTOR_UPDATED) {
		meas->measure_index[OPTIC_MEASURE_VOLTAGE_PN] = 0;

		ret = optic_mm_prepare ( p_ctrl, OPTIC_MEASURE_VOLTAGE_PN );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		return OPTIC_STATUS_GAIN_SELECTOR_UPDATED;
	}

	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_calc_temperature_ext ( meas->voltage_offset_pn,
						 config->measurement.tscal_ref,
						 u_corr, &t_nom );
	if (ret != OPTIC_STATUS_OK)
		return ret;

/*
OPTIC_DEBUG_ERR( "ext t_nom =%d", (t_nom+8)/16);
*/

	ret = optic_rangecheck_etemp_nom ( &(p_ctrl->config.range),
	                                         t_nom, NULL );
	if (ret != OPTIC_STATUS_OK)
		return ret;

#if (OPTIC_AVERAGE_NOM_TEMP_EXT == ACTIVE)
	/* measured nominal external temperature + old average value */
	if (t_nom_average == 0) {
		temp = t_nom_average * (100 - OPTIC_MM_FILTER_FACTOR_TEMP_EXT)
		       + (t_nom * OPTIC_MM_FILTER_FACTOR_TEMP_EXT);
		t_nom = optic_uint_div_rounded ( temp, 100 );
	}

	t_nom_average = t_nom;
#endif

	/* temp_nom -> temp_corr */
	ret = optic_temperature_nom2corr ( &(p_ctrl->config.range),
						 p_ctrl->table_temperature_nom,
						 t_nom, temp_ext );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_rangecheck_itemp_nom ( &(p_ctrl->config.range),
	                                         *temp_ext );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}


enum optic_errorcode optic_mm_power_get ( struct optic_control *p_ctrl )
{
	enum optic_measure_type types[3] = { OPTIC_MEASURE_POWER_RSSI_1490,
					     OPTIC_MEASURE_POWER_RF_1550,
					     OPTIC_MEASURE_POWER_RSSI_1550 };
	uint8_t t;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	struct optic_config_measurement *meas = &(p_ctrl->config.measurement);
	enum optic_errorcode ret;

	for (t=0; t <sizeof(types)/sizeof(types[0]); t ++) {
	     	ret = optic_mm_powervoltage_get ( p_ctrl, types[t] );
	     	if (ret != OPTIC_STATUS_OK)
			return ret;
	}

	ret = optic_calc_current_1490 ( meas->rssi_1490_mode,
				cal->meas_voltage_1490_rssi,
				p_ctrl->config.dcdc_apd.ext_att,
				meas->rssi_1490_shunt_res,
				cal->current_offset,
				&(p_ctrl->config.fuses),
				&(cal->meas_current_1490_rssi),
				&(cal->meas_current_1490_rssi_is_positive));
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_calc_power ( OPTIC_CFACTOR_RSSI1490,
				 &(p_ctrl->config.range),
				 cal->temperature_ext,
				 p_ctrl->table_temperature_corr,
				 meas->rssi_1490_scal_ref,
				 cal->meas_current_1490_rssi,
				 &(cal->meas_power_1490_rssi),
				 meas->rssi_1490_parabolic_ref,
				 meas->meas_dark_current_1490_rssi);
	/* GPONSW-685 */
	if(!cal->meas_current_1490_rssi_is_positive)
		cal->meas_power_1490_rssi = 0;

	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_calc_power ( OPTIC_CFACTOR_RSSI1550,
				 &(p_ctrl->config.range),
				 cal->temperature_ext,
				 p_ctrl->table_temperature_corr,
				 meas->rssi_1550_scal_ref,
				 cal->meas_voltage_1550_rssi,
				 &(cal->meas_power_1550_rssi),
				 0, 0);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_calc_power ( OPTIC_CFACTOR_RF1550,
				 &(p_ctrl->config.range),
				 cal->temperature_ext,
				 p_ctrl->table_temperature_corr,
				 meas->rf_1550_scal_ref,
				 cal->meas_voltage_1550_rf,
				 &(cal->meas_power_1550_rf),
				 0, 0);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

enum optic_errorcode optic_mm_thresh_calc ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	struct optic_measurement *measure = &(cal->measurement);
	uint8_t gain_selector = measure->gain_selector_1490rx;
	uint16_t ovl_cw, los_cw;

	/* calculate voltage -> codeword for RSSI 1490 ovl and los */
	ret = optic_calc_digitword ( OPTIC_VREF_0MV,
				     &(measure->gain[gain_selector]),
				     cal->thresh_voltage_ovl,
				     &ovl_cw );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_mm_thresh_set(ovl) = %d, ret");
		return ret;
	}

	ret = optic_calc_digitword ( OPTIC_VREF_0MV,
				     &(measure->gain[gain_selector]),
				     cal->thresh_voltage_los,
				     &los_cw );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_mm_thresh_set(los) = %d, ret");
		return ret;
	}

	cal->thresh_codeword_ovl = ovl_cw;
	cal->thresh_codeword_los = los_cw;

	return ret;
}

enum optic_errorcode optic_mm_thresh_set ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);

	ret = optic_ll_mm_thresh_reg_set ( cal->thresh_codeword_ovl,
					   cal->thresh_codeword_los );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

/* ------------------------------------------------------------------------- */

const struct optic_entry mm_function_table[OPTIC_MM_MAX] =
{
/*  0 */  TE1in  (FIO_MM_CFG_SET,                       sizeof(struct optic_mm_config),
							mm_cfg_set),
/*  1 */  TE1out (FIO_MM_CFG_GET,                       sizeof(struct optic_mm_config),
							mm_cfg_get),
/*  2 */  TE1out (FIO_MM_DIE_TEMPERATURE_GET,           sizeof(struct optic_temperature),
							mm_die_temperature_get),
/*  3 */  TE1out (FIO_MM_LASER_TEMPERATURE_GET,         sizeof(struct optic_temperature),
							mm_laser_temperature_get),
/*  4 */  TE1out (FIO_MM_1490_OPTICAL_VOLTAGE_GET,      sizeof(struct optic_current),
							mm_1490_optical_voltage_get),
/*  5 */  TE1out (FIO_MM_1490_OPTICAL_CURRENT_GET,      sizeof(struct optic_current),
							mm_1490_optical_current_get),
/*  6 */  TE1out (FIO_MM_1490_OPTICAL_POWER_GET,        sizeof(struct optic_power),
							mm_1490_optical_power_get),
/*  7 */  TE1out (FIO_MM_1550_OPTICAL_VOLTAGE_GET,      sizeof(struct optic_voltage),
							mm_1550_optical_voltage_get),
/*  8 */  TE1out (FIO_MM_1550_ELECTRICAL_VOLTAGE_GET,   sizeof(struct optic_voltage),
							mm_1550_electrical_voltage_get),

};

/*! @} */

/*! @} */
