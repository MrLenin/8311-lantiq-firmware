/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, DC/DC APD Interface - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_DCDC_APD_INTERNAL DC/DC APD Interface - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_dcdc_apd_interface.h"

#include "drv_optic_calc.h"
#include "drv_optic_dcdc_apd.h"
#include "drv_optic_ll_dcdc_apd.h"

/**
   Read apd configuration data into the context.
*/
enum optic_errorcode dcdc_apd_cfg_set ( struct optic_device *p_dev,
                                        const struct optic_dcdc_apd_config
                                        *param )
{
	uint8_t i;
	uint32_t temp;
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	p_ctrl->config.dcdc_apd.v_ext = param->v_ext;

	for (i=0; i<2; i++)
		p_ctrl->config.dcdc_apd.r_diff[i] = param->r_diff[i];

       /* r_diff[1] = Rdiv_high
          r_diff[0] = Rdiv_low
          ext_att = (r_diff[1] + r_diff[0]) / r_diff[0] */

 	temp = (p_ctrl->config.dcdc_apd.r_diff[0] +
	        p_ctrl->config.dcdc_apd.r_diff[1])
		<< OPTIC_FLOAT2INTSHIFT_EXTATT;

	temp = optic_uint_div_rounded ( temp,
					p_ctrl->config.dcdc_apd.r_diff[0] );

	p_ctrl->config.dcdc_apd.ext_att = (uint16_t) temp;

	/* ready to read tables & read configs */
	p_ctrl->state.config_read[OPTIC_CONFIGTYPE_DCDC_APD] = true;
	optic_state_set ( p_ctrl, OPTIC_STATE_CONFIG );

	return OPTIC_STATUS_OK;
}

/**
   Returns apd configuration.
*/
enum optic_errorcode dcdc_apd_cfg_get ( struct optic_device *p_dev,
				        struct optic_dcdc_apd_config *param )
{
	uint8_t i;
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_dcdc_apd_config) );

	for (i=0; i<2; i++)
		param->r_diff[i] = p_ctrl->config.dcdc_apd.r_diff[i];

	param->v_ext = p_ctrl->config.dcdc_apd.v_ext;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode dcdc_apd_enable ( struct optic_device *p_dev )
{
	(void) p_dev;
	return optic_ll_dcdc_apd_set ( OPTIC_ENABLE );
}

enum optic_errorcode dcdc_apd_disable ( struct optic_device *p_dev )
{
	(void) p_dev;
	return optic_ll_dcdc_apd_set ( OPTIC_DISABLE );
}

bool dcdc_apd_disabled (void) {
	enum optic_activation mode;

	optic_ll_dcdc_apd_get(&mode);

	return (mode == OPTIC_DISABLE)? true : false;
}

enum optic_errorcode dcdc_apd_status_get ( struct optic_device *p_dev,
                                           struct optic_dcdc_apd_status
                                           *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret;
	enum optic_activation mode;
	uint16_t voltage;
	int32_t temp;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_dcdc_apd_status) );

	ret = optic_ll_dcdc_apd_get ( &mode );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	param->enable = (mode == OPTIC_ENABLE)? true : false;

	param->target_voltage = p_ctrl->calibrate.vapd_target;

	ret = optic_dcdc_apd_voltage_get ( p_ctrl, &voltage,
					   &(param->regulation_error) );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (mode == OPTIC_ENABLE) {
		temp = voltage;
		temp = temp - param->regulation_error;
		param->voltage = (int16_t) temp;
	} else { /* OPTIC_DISABLE */
		param->voltage = (int16_t) p_ctrl->config.dcdc_apd.v_ext;
	}

	ret = optic_ll_dcdc_apd_saturation_get ( &(param->saturation) );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

/* ----------------------------- NON IOCTL ---------------------------------- */

/**
	set DCDC APD voltage - at maximum in range of 1V, in this case timer
	will be started to set target voltage (or next step) in next cycle
*/
enum optic_errorcode optic_dcdc_apd_voltage_set ( struct optic_control *p_ctrl,
						  const uint16_t vapd_desired,
						  const uint8_t sat )
{
	struct optic_fuses *fuses = &(p_ctrl->config.fuses);
	struct optic_config *config = &(p_ctrl->config);
	uint16_t vapd_actual;
	static uint16_t vapd_actual_cnt = 0;
	uint8_t sat_target = sat;
	enum optic_errorcode ret;

	if (p_ctrl->calibrate.vapd_target != vapd_desired) {
		/* first "loop" of timer -> apd voltage set */
		ret = optic_rangecheck_dcdc ( &(p_ctrl->config.range),
					      OPTIC_DCDC_APD, vapd_desired );
		if (ret != OPTIC_STATUS_OK)
			return ret;
#if (OPTIC_APD_DEBUG == ACTIVE)
		OPTIC_DEBUG_ERR("optic_dcdc_apd_voltage_set(): vapd_desired=%d, sat=%d",
				vapd_desired, sat);
#endif
		p_ctrl->calibrate.vapd_target = vapd_desired;
		p_ctrl->calibrate.sat_target = sat;
	}

	/* ret = 0 -> no adaptation necessary */

	ret = optic_ll_dcdc_apd_voltage_set ( fuses->offset_dcdc_apd,
					      	  	  	  	  fuses->gain_dcdc_apd,
					      	  	  	  	  config->dcdc_apd.ext_att,
	                                      vapd_desired,
	                                      &vapd_actual );

	switch(ret) {
	case OPTIC_STATUS_DCDC_APD_RAMP_WAIT:
		vapd_actual_cnt++;
		/* If the HW loop does not converge, we
		   cannot wait too much, therefore we wait up to 10*10ms
		   Note: the HW loop always runs in background.
		   We monitor the regulation every 10ms. */
		if(vapd_actual_cnt >= OPTIC_TIMER_DCDCAPD_REG_CYCLE_MAX) {
			OPTIC_DEBUG_ERR("optic_dcdc_apd_voltage_set() regulation"
					"error after %d tries",
					vapd_actual_cnt);
			vapd_actual_cnt = 0;
			return OPTIC_STATUS_REGULATION;
		}

		/* reload timer: 10 ms */
#if (OPTIC_APD_DEBUG == ACTIVE)
		OPTIC_DEBUG_ERR("reload APD timer ...");
#endif
		optic_timer_start (OPTIC_TIMER_ID_APD_ADAPT,
				   	   	   OPTIC_TIMER_DCDCAPD_RAMP);
		ret = OPTIC_STATUS_OK;
		break;

	case OPTIC_STATUS_DCDC_APD_RAMP:
		/* count for each 1V voltage step from 0 */
		vapd_actual_cnt = 0;

		/* saturation for vapd step */
		if (vapd_actual != vapd_desired) {
			/* search for saturation value */
			ret = optic_search_apd_saturation ( p_ctrl,
								vapd_actual,
							    &sat_target );

#if (OPTIC_APD_DEBUG == ACTIVE)
			OPTIC_DEBUG_ERR("vapd_actual: %d vapd_desired: %d, sat_target: %d",
					vapd_actual, vapd_desired, sat_target);
#endif

			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR("search_apd_saturation(): %d",
						ret);
			}

			ret = optic_ll_dcdc_apd_saturation_set ( sat_target );
		}

		/* reload timer: 10 ms */
#if (OPTIC_APD_DEBUG == ACTIVE)
		OPTIC_DEBUG_ERR("reload APD timer ...");
#endif
		optic_timer_start (OPTIC_TIMER_ID_APD_ADAPT,
				   	   	   OPTIC_TIMER_DCDCAPD_RAMP);
		ret = OPTIC_STATUS_OK;
		break;

	case OPTIC_STATUS_DCDC_APD_CHANGE:
#if (OPTIC_APD_DEBUG == ACTIVE)
			OPTIC_DEBUG_ERR("sat: %d", sat);
#endif

		ret = optic_ll_dcdc_apd_saturation_set ( sat );
		break;
	default:
		break;
	}

	return ret;
}

/**
	timer for next step of SW ramp
*/
void optic_timer_dcdc_apd_adapt ( struct optic_control *p_ctrl )
{
	/* set target voltage (maybe in next step of SW ramp */
#if (OPTIC_APD_DEBUG == ACTIVE)
	OPTIC_DEBUG_ERR("optic_timer_dcdc_apd_adapt vapd: %d, sat:%d ",
			p_ctrl->calibrate.vapd_target,
			 p_ctrl->calibrate.sat_target );
#endif

	optic_dcdc_apd_voltage_set ( p_ctrl, p_ctrl->calibrate.vapd_target,
	                             p_ctrl->calibrate.sat_target );
}


enum optic_errorcode optic_dcdc_apd_voltage_get ( struct optic_control *p_ctrl,
						  uint16_t *vapd,
						  int16_t *regulation_error )
{
	struct optic_fuses *fuses = &(p_ctrl->config.fuses);
	struct optic_config *config = &(p_ctrl->config);
	enum optic_errorcode ret;
	enum optic_activation mode;

	ret = optic_ll_dcdc_apd_get(&mode);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (mode == OPTIC_ENABLE) {
		ret = optic_ll_dcdc_apd_voltage_get ( fuses->offset_dcdc_apd,
						      fuses->gain_dcdc_apd,
						      config->dcdc_apd.ext_att,
						      vapd, regulation_error );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		/*
			ret = optic_rangecheck_dcdc ( &(p_ctrl->config.range),
							    OPTIC_DCDC_APD, *vapd);
			if (ret != OPTIC_STATUS_OK)
				return ret;
		*/
	} else {
		*vapd = (uint16_t) p_ctrl->config.dcdc_apd.v_ext;
		*regulation_error = 0;
	}

	return ret;
}

/**
	Updates vapd target and duty cycle saturation for current external
	temperature.
*/
enum optic_errorcode optic_dcdc_apd_update ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret;
	uint16_t temp_index;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	struct optic_table_temperature_corr *tab;
	static uint16_t temp_index_old = 0;

	ret = optic_rangecheck_etemp_corr ( &(p_ctrl->config.range),
					    cal->temperature_ext,
				            &temp_index );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (temp_index != temp_index_old) {
		temp_index_old = temp_index;
		tab = &(p_ctrl->table_temperature_corr[temp_index]);

		OPTIC_DEBUG_MSG("update dcdc apd settings: "
				"vref=%d.%02d, sat=%d",
				tab->vapd.vref >> OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				((tab->vapd.vref * 100) % 100)
				>> OPTIC_FLOAT2INTSHIFT_VOLTAGE,
				tab->vapd.sat);

		if (p_ctrl->config.debug_mode == true)
			return ret;

		ret = optic_dcdc_apd_voltage_set ( p_ctrl,
						   tab->vapd.vref,
						   tab->vapd.sat );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_dcdc_apd_voltage_set(): %d",
					ret);
			return ret;
		}
	}

	return ret;
}

/* ------------------------------------------------------------------------- */

const struct optic_entry dcdc_apd_function_table[OPTIC_DCDC_APD_MAX] =
{
/*  0 */  TE1in  (FIO_DCDC_APD_CFG_SET,         sizeof(struct optic_dcdc_apd_config),
						dcdc_apd_cfg_set),
/*  1 */  TE1out (FIO_DCDC_APD_CFG_GET,         sizeof(struct optic_dcdc_apd_config),
						dcdc_apd_cfg_get),
/*  2 */  TE0    (FIO_DCDC_APD_ENABLE,          dcdc_apd_enable),
/*  3 */  TE0    (FIO_DCDC_APD_DISABLE,         dcdc_apd_disable),
/*  4 */  TE1out (FIO_DCDC_APD_STATUS_GET,      sizeof(struct optic_dcdc_apd_status),
						dcdc_apd_status_get),
};

/*! @} */

/*! @} */
