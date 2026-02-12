/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, Calibration Interface - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_CAL_INTERNAL Calibration and Debug Interface - Internal
   @{
*/


#include "drv_optic_api.h"
#include "drv_optic_common.h"
#if (OPTIC_OCAL_SUPPORT == ACTIVE)
#include "drv_optic_cal_interface.h"

#include "drv_optic_calc.h"
#include "drv_optic_fcsi.h"
#include "drv_optic_dcdc_apd.h"
#include "drv_optic_dcdc_core.h"
#include "drv_optic_dcdc_ddr.h"
#include "drv_optic_mpd.h"
#include "drv_optic_ll_mpd.h"
#include "drv_optic_ll_tx.h"
#include "drv_optic_ll_rx.h"
#include "drv_optic_ll_mm.h"
#include "drv_optic_ll_dcdc_apd.h"
#include "drv_optic_ll_dcdc_core.h"
#include "drv_optic_ll_dcdc_ddr.h"
#include "ifxos_memory_alloc.h"

/**
	Activates debug mode. Now special debug setting is used instead of
	powerlevel depending configuration
*/
enum optic_errorcode cal_debug_enable ( struct optic_device *p_dev )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_powerlevel powerlevel = p_ctrl->calibrate.powerlevel;
	struct optic_config_debug *debug = &(p_ctrl->config.debug);
	struct optic_config_monitor *monitor = &(p_ctrl->config.monitor);
	struct optic_calibrate *cal= &(p_ctrl->calibrate);
	enum optic_gainbank gainbank_active;
	enum optic_errorcode ret = OPTIC_STATUS_OK;

	p_ctrl->config.debug_mode = true;

	ret = optic_powerlevel2gainbank ( powerlevel, &gainbank_active );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (debug->dcal_ref_p0 == 0)
		debug->dcal_ref_p0 = monitor->dcal_ref_p0[powerlevel];

	if (debug->dcal_ref_p1 == 0)
		debug->dcal_ref_p1 = monitor->dcal_ref_p1[powerlevel];

	if (debug->dref_p0 == 0)
		debug->dref_p0 = monitor->dref_p0[powerlevel];

	if (debug->dref_p1 == 0)
		debug->dref_p1 = monitor->dref_p1[powerlevel];

	if (IFXOS_MutexGet(&p_ctrl->access.dac_lock) != IFX_SUCCESS)
		return ret;

	ret = optic_mpd_gainctrl_set ( p_ctrl, gainbank_active,
					     OPTIC_CAL_OFF );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/* GPONSW-818 */
	cal->dbg_dac_offset_tia_c = cal->dac_offset_tia_c[gainbank_active];
	cal->dbg_dac_offset_tia_f = cal->dac_offset_tia_f[gainbank_active];
	cal->dbg_dac_offset_delta_p1_c = cal->dac_offset_delta_p1_c[gainbank_active];
	cal->dbg_dac_offset_delta_p1_f = cal->dac_offset_delta_p1_f[gainbank_active];
	/* GPONSW-818 end */

	ret = optic_mpd_tia_offset_set ( p_ctrl, gainbank_active );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	IFXOS_MutexRelease(&p_ctrl->access.dac_lock);

	return ret;
}

/**
	Deactivates debug mode. In normal mode power level depending
	configuration is used.
*/
enum optic_errorcode cal_debug_disable ( struct optic_device *p_dev )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_powerlevel powerlevel = p_ctrl->calibrate.powerlevel;
	enum optic_gainbank gainbank_active;
	enum optic_errorcode ret;

	p_ctrl->config.debug_mode = false;

	/* recover normal mode configuration */

	ret = optic_powerlevel2gainbank ( powerlevel, &gainbank_active );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_fcsi_predriver_update ( powerlevel,
					    &(p_ctrl->config.fcsi) );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (IFXOS_MutexGet(&p_ctrl->access.dac_lock) != IFX_SUCCESS)
		return ret;

	ret = optic_mpd_gainctrl_set ( p_ctrl, gainbank_active,
					     OPTIC_CAL_OFF );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_mpd_tia_offset_set ( p_ctrl, gainbank_active );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	IFXOS_MutexRelease(&p_ctrl->access.dac_lock);

	return ret;
}

/**
	Re-activates background measurement cycle
*/
enum optic_errorcode cal_mm_enable ( struct optic_device *p_dev )
{
#if (OPTIC_MM_MEASUREMENT_LOOP == ACTIVE)
	optic_timer_start ( OPTIC_TIMER_ID_MEASURE, 
		((struct optic_control *)p_dev->p_ctrl)->mm_interval);
	return OPTIC_STATUS_OK;
#else
	return OPTIC_STATUS_ERR;
#endif
}

/**
	Deactivates background measurement cycle
*/
enum optic_errorcode cal_mm_disable ( struct optic_device *p_dev )
{
	(void) p_dev;

	optic_timer_stop (OPTIC_TIMER_ID_MEASURE);
	return OPTIC_STATUS_OK;
}

/**
	Reads back, if debug mode was activated (true) or not (false).
*/
enum optic_errorcode cal_debug_status_get ( struct optic_device *p_dev,
					    struct optic_debug_status *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	param->debug_enable = p_ctrl->config.debug_mode;

	return OPTIC_STATUS_OK;
}

/**
	Reads back the laser age / system timestamp in seconds
*/
enum optic_errorcode cal_laser_age_get ( struct optic_device *p_dev,
				         struct optic_timestamp *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_timestamp) );

	param->seconds = p_ctrl->calibrate.timestamp;

	return OPTIC_STATUS_OK;
}

/**
	Sets the Ibias/Imod tupel + timestamp for a specified corrected
	external temperature and the specified power level.

	Note: Ibias and Imod values are shiftet by OPTIC_FLOAT2INTSHIFT_CURRENT
	      and OPTIC_FLOAT2INTSHIFT_CURRENT to use integer format.
*/
enum optic_errorcode cal_ibiasimod_table_set ( struct optic_device *p_dev,
					       const struct optic_ibiasimod_set
					       *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint16_t temp;
	struct optic_table_temperature_corr *tab;
	struct optic_config_range *range = &(p_ctrl->config.range);
	uint8_t t = OPTIC_TABLETYPE_IBIASIMOD -
		    OPTIC_TABLETYPE_TEMP_CORR_MIN;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	if (param->powerlevel >= OPTIC_POWERLEVEL_MAX)
		return OPTIC_STATUS_POOR;

	if (p_ctrl->state.config_read[OPTIC_CONFIGTYPE_RANGE] == false)
	    	return OPTIC_STATUS_ERR;

	if ((param->temperature < range->tabletemp_extcorr_min) ||
	    (param->temperature > range->tabletemp_extcorr_max))
	    	return OPTIC_STATUS_POOR;

	if (param->ibias > range->ibias_max)
	    	return OPTIC_STATUS_POOR;

	if (param->imod > range->imod_max)
	    	return OPTIC_STATUS_POOR;

	if ((param->ibias + param->imod) > range->ibiasimod_max)
	    	return OPTIC_STATUS_POOR;

	temp = param->temperature - range->tabletemp_extcorr_min;

	if (p_ctrl->state.table_read[OPTIC_TABLETYPE_IBIASIMOD -
	    OPTIC_TABLETYPE_INTERN_MIN] == false)
	    	return OPTIC_STATUS_ERR;

	tab = &(p_ctrl->table_temperature_corr[temp]);
	tab->ibiasimod.ibias[param->powerlevel] = param->ibias;
	tab->ibiasimod.imod[param->powerlevel] = param->imod;
	tab->quality[t] = OPTIC_TABLEQUAL_FIXSET;

	return OPTIC_STATUS_OK;
}

/**
	Reads back the Ibias/Imod tupel + timestamp and quality flag of a
	specified corrected external temperature and the specified power level.

	Note: Ibias and Imod values are shiftet by OPTIC_FLOAT2INTSHIFT_CURRENT
	      and OPTIC_FLOAT2INTSHIFT_CURRENT to use integer format.
*/
enum optic_errorcode cal_ibiasimod_table_get ( struct optic_device *p_dev,
					       const struct
					       optic_ibiasimod_get_in
					       *param_in,
					       struct optic_ibiasimod_get_out
					       *param_out )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint16_t temp;
	uint8_t pl;
	struct optic_table_temperature_corr *tab;
	struct optic_config_range *range = &(p_ctrl->config.range);
	uint8_t t = OPTIC_TABLETYPE_IBIASIMOD -
		    OPTIC_TABLETYPE_TEMP_CORR_MIN;

	if ((param_in == NULL) || (param_out == NULL))
		return OPTIC_STATUS_ERR;

	if (param_in->powerlevel >= OPTIC_POWERLEVEL_MAX)
		return OPTIC_STATUS_POOR;

	if (p_ctrl->state.config_read[OPTIC_CONFIGTYPE_RANGE] == false)
	    	return OPTIC_STATUS_ERR;

	if ((param_in->temperature < range->tabletemp_extcorr_min) ||
	    (param_in->temperature > range->tabletemp_extcorr_max))
	    	return OPTIC_STATUS_POOR;

	temp = param_in->temperature - range->tabletemp_extcorr_min;
	pl = param_in->powerlevel;

	memset ( param_out, 0, sizeof(struct optic_ibiasimod_get_out) );

	if (p_ctrl->state.table_read[OPTIC_TABLETYPE_IBIASIMOD -
	    OPTIC_TABLETYPE_INTERN_MIN] == false)
	    	return OPTIC_STATUS_ERR;

	tab = &(p_ctrl->table_temperature_corr[temp]);

	param_out->ibias   = tab->ibiasimod.ibias[pl];
	param_out->imod    = tab->ibiasimod.imod[pl];
	param_out->quality = tab->quality[t];

	return OPTIC_STATUS_OK;
}

/**
	Sets the Ith/SE tupel + timestamp for a specified corrected
	external temperature.

	Note: Ibias and Imod values are shiftet by OPTIC_FLOAT2INTSHIFT_CURRENT
	      and OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY to use integer format.
*/
enum optic_errorcode cal_laserref_table_set ( struct optic_device *p_dev,
					      const struct optic_laserref_set
					      *param )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint16_t temp;
	struct optic_table_temperature_corr *tab;
	struct optic_config_range *range = &(p_ctrl->config.range);
	uint8_t t = OPTIC_TABLETYPE_LASERREF -
		    OPTIC_TABLETYPE_TEMP_CORR_MIN;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	if (p_ctrl->state.config_read[OPTIC_CONFIGTYPE_RANGE] == false)
	    	return OPTIC_STATUS_ERR;

	if ((param->temperature < range->tabletemp_extcorr_min) ||
	    (param->temperature > range->tabletemp_extcorr_max))
	    	return OPTIC_STATUS_POOR;

	temp = param->temperature - range->tabletemp_extcorr_min;

	if (p_ctrl->state.table_read[OPTIC_TABLETYPE_LASERREF -
	    OPTIC_TABLETYPE_INTERN_MIN] == false)
	    	return OPTIC_STATUS_ERR;

	tab = &(p_ctrl->table_temperature_corr[temp]);

	tab->laserref.ith = param->ith;
	tab->laserref.se = param->se;
	tab->laserref.age = p_ctrl->calibrate.timestamp;
	tab->quality[t] = OPTIC_TABLEQUAL_FIXSET;

	/* synchronize Ibias/Imod tables (for all power levels)  */
	ret = optic_calc_ibiasimod ( p_ctrl );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

/**
	Reads back the Ith/SE tupel + timestamp and quality flag of a
	specified corrected external temperature.

	Note: Ibias and Imod values are shiftet by OPTIC_FLOAT2INTSHIFT_CURRENT
	      and OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY to use integer format.
*/
enum optic_errorcode cal_laserref_table_get ( struct optic_device *p_dev,
					      const struct optic_laserref_get_in
					      *param_in,
					      struct optic_laserref_get_out
					      *param_out )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint16_t temp;
	struct optic_table_temperature_corr *tab;
	struct optic_config_range *range = &(p_ctrl->config.range);
	uint8_t t = OPTIC_TABLETYPE_LASERREF -
		    OPTIC_TABLETYPE_TEMP_CORR_MIN;

	if ((param_in == NULL) || (param_out == NULL))
		return OPTIC_STATUS_ERR;

	if (p_ctrl->state.config_read[OPTIC_CONFIGTYPE_RANGE] == false)
	    	return OPTIC_STATUS_ERR;

	if ((param_in->temperature < range->tabletemp_extcorr_min) ||
	    (param_in->temperature > range->tabletemp_extcorr_max))
	    	return OPTIC_STATUS_POOR;

	temp = param_in->temperature - range->tabletemp_extcorr_min;

	memset ( param_out, 0, sizeof(struct optic_laserref_get_out) );

	if (p_ctrl->state.table_read[OPTIC_TABLETYPE_LASERREF -
	    OPTIC_TABLETYPE_INTERN_MIN] == false)
	    	return OPTIC_STATUS_ERR;

	tab = &(p_ctrl->table_temperature_corr[temp]);

	param_out->ith  = tab->laserref.ith;
	param_out->se   = tab->laserref.se;
	param_out->age  = tab->laserref.age;
	param_out->quality = tab->quality[t];

	return OPTIC_STATUS_OK;
}

/**
	Sets the VAPD value for a specified corrected external temperature.

	Note: VAPD values are shiftet by OPTIC_TABLETYPE_VAPD to use
	      integer format.
*/
enum optic_errorcode cal_vapd_table_set ( struct optic_device *p_dev,
					  const struct optic_vapd_set *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint16_t temp;
	struct optic_table_temperature_corr *tab;
	struct optic_config_range *range = &(p_ctrl->config.range);
	uint8_t t = OPTIC_TABLETYPE_VAPD -
		    OPTIC_TABLETYPE_TEMP_CORR_MIN;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	if (p_ctrl->state.config_read[OPTIC_CONFIGTYPE_RANGE] == false)
	    	return OPTIC_STATUS_ERR;

	if ((param->temperature < range->tabletemp_extcorr_min) ||
	    (param->temperature > range->tabletemp_extcorr_max))
	    	return OPTIC_STATUS_POOR;

	if ((param->vref < range->vapd_min) || (param->vref > range->vapd_max))
	    	return OPTIC_STATUS_POOR;

	temp = param->temperature - range->tabletemp_extcorr_min;

	if (p_ctrl->state.table_read[OPTIC_TABLETYPE_VAPD -
	    OPTIC_TABLETYPE_INTERN_MIN] == false)
	    	return OPTIC_STATUS_ERR;

	tab = &(p_ctrl->table_temperature_corr[temp]);
	tab->vapd.vref  = param->vref;
	tab->vapd.sat   = param->sat;
	tab->quality[t] = OPTIC_TABLEQUAL_FIXSET;

	return OPTIC_STATUS_OK;
}

/**
	Reads back the VAPD value of a specified corrected external temperature.

	Note: VAPD values are shiftet by OPTIC_TABLETYPE_VAPD to use
	      integer format.
*/
enum optic_errorcode cal_vapd_table_get ( struct optic_device *p_dev,
					  const struct optic_vapd_get_in
					  *param_in,
					  struct optic_vapd_get_out
					  *param_out )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint16_t temp;
	struct optic_table_temperature_corr *tab;
	struct optic_config_range *range = &(p_ctrl->config.range);
	uint8_t t = OPTIC_TABLETYPE_VAPD -
		    OPTIC_TABLETYPE_TEMP_CORR_MIN;

	if ((param_in == NULL) || (param_out == NULL))
		return OPTIC_STATUS_ERR;

	if (p_ctrl->state.config_read[OPTIC_CONFIGTYPE_RANGE] == false)
	    	return OPTIC_STATUS_ERR;

	if ((param_in->temperature < range->tabletemp_extcorr_min) ||
	    (param_in->temperature > range->tabletemp_extcorr_max))
	    	return OPTIC_STATUS_POOR;

	temp = param_in->temperature - range->tabletemp_extcorr_min;

	memset ( param_out, 0, sizeof(struct optic_vapd_get_out) );

	if (p_ctrl->state.table_read[OPTIC_TABLETYPE_VAPD -
	    OPTIC_TABLETYPE_INTERN_MIN] == false)
	    	return OPTIC_STATUS_ERR;

	tab = &(p_ctrl->table_temperature_corr[temp]);

	param_out->vref    = tab->vapd.vref;
	param_out->sat     = tab->vapd.sat;
	param_out->quality = tab->quality[t];

	return OPTIC_STATUS_OK;
}

/**
	Sets the correction factor for a specified table and a corrected
	external temperature.

	Note: correction factors are shiftet by
	      OPTIC_FLOAT2INTSHIFT_CORRFACTOR to use integer format.
*/
enum optic_errorcode cal_corr_table_set ( struct optic_device *p_dev,
					  const struct optic_corr_set *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	return optic_cfactor_table_set ( p_ctrl, param->type,
					 param->temperature,
					 param->corr_factor );
}

/**
	Reads back the correction factor of a specified table and a corrected
	external temperature.

	Note: correction factors are shiftet by
	      OPTIC_FLOAT2INTSHIFT_CORRFACTOR to use integer format.
*/
enum optic_errorcode cal_corr_table_get ( struct optic_device *p_dev,
				          const struct optic_corr_get_in
					  *param_in,
					  struct optic_corr_get_out
					  *param_out )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint16_t temperature;
	enum optic_cfactor type;

	temperature = param_in->temperature;
	type = param_in->type;

	memset ( param_out, 0, sizeof(struct optic_corr_get_out) );

	return optic_cfactor_table_get ( p_ctrl, type, temperature,
					 &(param_out->corr_factor),
					 &(param_out->quality) );
}

/**
	Sets the corrected external temparature in the translation table
	for a specified nominal external temperature.

	Note: Temperatures are not shiftet to use integer format.
*/
enum optic_errorcode cal_tcorrext_table_set ( struct optic_device *p_dev,
					      const struct optic_tcorrext_set
					      *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint16_t temp;
	struct optic_table_temperature_nom *tab;
	struct optic_config_range *range = &(p_ctrl->config.range);
	uint8_t t = OPTIC_TABLETYPE_TEMPTRANS -
		    OPTIC_TABLETYPE_TEMP_NOM_MIN;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	if ((param->temperature < range->tabletemp_extnom_min) ||
	    (param->temperature > range->tabletemp_extnom_max))
	    	return OPTIC_STATUS_POOR;

	if ((param->temp_corr < range->tabletemp_extcorr_min) ||
	    (param->temp_corr > range->tabletemp_extnom_max))
	    	return OPTIC_STATUS_POOR;

	temp = param->temperature - range->tabletemp_extnom_min;
	tab = &(p_ctrl->table_temperature_nom[temp]);
	tab->temptrans.temp_corr = param->temp_corr;
	tab->quality[t] = OPTIC_TABLEQUAL_FIXSET;

	return OPTIC_STATUS_OK;
}

/**
	Reads back the corrected external temparature from the
	translation table of a specified nominal external temperature.

	Note: Temperatures are not shiftet to use integer format.
*/
enum optic_errorcode cal_tcorrext_table_get ( struct optic_device *p_dev,
					      const struct optic_tcorrext_get_in
					      *param_in,
					      struct optic_tcorrext_get_out
					      *param_out )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint16_t temp;
	struct optic_table_temperature_nom *tab;
	struct optic_config_range *range = &(p_ctrl->config.range);
	uint8_t t = OPTIC_TABLETYPE_TEMPTRANS -
		    OPTIC_TABLETYPE_TEMP_NOM_MIN;

	if ((param_in == NULL) || (param_out == NULL))
		return OPTIC_STATUS_ERR;

	if ((param_in->temperature < range->tabletemp_extnom_min) ||
	    (param_in->temperature > range->tabletemp_extnom_max))
	    	return OPTIC_STATUS_POOR;

	temp = param_in->temperature - range->tabletemp_extnom_min;

	memset ( param_out, 0, sizeof(struct optic_tcorrext_get_out) );

	tab = &(p_ctrl->table_temperature_nom[temp]);

	param_out->temp_corr = tab->temptrans.temp_corr;
	param_out->quality = tab->quality[t];

	return OPTIC_STATUS_OK;
}

/**
	Writes the initial bias current directly into MPD module.

	Note: Ibias values are shiftet by OPTIC_FLOAT2INTSHIFT_CURRENT
	      to use integer format.
*/
enum optic_errorcode cal_init_bias_current_set ( struct optic_device *p_dev,
			 		         const struct optic_bias
			 		         *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	return optic_mpd_bias_set ( p_ctrl, param->bias_current );
}

/**
	Reads back the initial bias current directly from MPD module.

	Note: Ibias values are shiftet by OPTIC_FLOAT2INTSHIFT_CURRENT
	      to use integer format.
*/
enum optic_errorcode cal_init_bias_current_get ( struct optic_device *p_dev,
					         struct optic_bias *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_bias) );

	/* read (init) bias current */
	return optic_mpd_bias_get ( p_ctrl, true, &(param->bias_current) );
}

/**
	Writes the initial modulation current directly into MPD module.

	Note: Ibias values are shiftet by OPTIC_FLOAT2INTSHIFT_CURRENT
	      to use integer format.
*/
enum optic_errorcode cal_init_mod_current_set ( struct optic_device *p_dev,
					        const struct optic_mod *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	return optic_mpd_mod_set ( p_ctrl, param->modulation_current );
}

/**
	Reads back the initial modulation current directly from MPD module.

	Note: Mod values are shiftet by OPTIC_FLOAT2INTSHIFT_CURRENT
	      to use integer format.
*/
enum optic_errorcode cal_init_mod_current_get ( struct optic_device *p_dev,
				    	        struct optic_mod *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_mod) );

	/* read (init) modulation current */
	return optic_mpd_mod_get ( p_ctrl, true, &(param->modulation_current) );
}

/**
	Reads back the actual modulation current directly from MPD module.

	Note: Bias values are shiftet by OPTIC_FLOAT2INTSHIFT_CURRENT
	      to use integer format.
*/
enum optic_errorcode cal_actual_bias_current_get ( struct optic_device *p_dev,
					           struct optic_bias *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_bias) );

	/* read (actual) bias current */
	return optic_mpd_bias_get ( p_ctrl, false, &(param->bias_current) );
}

/**
	Reads back the actual modulation current directly from MPD module.

	Note: AMod values are shiftet by OPTIC_FLOAT2INTSHIFT_CURRENT
	      to use integer format.
*/
enum optic_errorcode cal_actual_mod_current_get ( struct optic_device *p_dev,
					          struct optic_mod *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;


	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_mod) );

	/* read (actual) modulation current */
	return optic_mpd_mod_get ( p_ctrl, false,
					   &(param->modulation_current) );
}


/**
	Configures the TIA gain selector for the specified power level
	or global setting.

	Note: Tia gain selector specifies one of 4 fcsi settings
*/
enum optic_errorcode cal_mpd_gain_set ( struct optic_device *p_dev,
				        const struct optic_gain_set
				        *param )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_powerlevel powerlevel = p_ctrl->calibrate.powerlevel;
	struct optic_config_monitor *monitor = &p_ctrl->config.monitor;
	enum optic_gainbank gainbank, gainbank_active;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	gainbank =  param->gainbank;

	ret = optic_powerlevel2gainbank ( powerlevel, &gainbank_active );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (param->tia_gain_selector > 3)
		return OPTIC_STATUS_POOR;

	monitor->tia_gain_selector[gainbank] = param->tia_gain_selector;
	monitor->tia_gain_selector_quality[gainbank]= OPTIC_QUALITY_CALIBRATION;

	if ((p_ctrl->config.debug_mode == false) &&
	    (gainbank == gainbank_active)) {
		ret = optic_mpd_gainctrl_set ( p_ctrl, gainbank_active,
		                                     OPTIC_CAL_OFF );
		if (ret != OPTIC_STATUS_OK)
			return ret;
	}

	return OPTIC_STATUS_OK;
}

/**
	Reads back the TIA gain selector of the specified power level or
	global setting.

	Note: Tia gain selector specifies one of 4 fcsi settings
*/
enum optic_errorcode cal_mpd_gain_get ( struct optic_device *p_dev,
					const struct optic_gain_get_in
					*param_in,
					struct optic_gain_get_out
					*param_out )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_monitor *monitor = &p_ctrl->config.monitor;
	enum optic_gainbank gainbank;

	if ((param_in == NULL) || (param_out == NULL))
		return OPTIC_STATUS_ERR;

	gainbank = param_in->gainbank;

	memset ( param_out, 0, sizeof(struct optic_gain_get_out) );

	param_out->tia_gain_selector = monitor->tia_gain_selector[gainbank];
	param_out->quality = monitor->tia_gain_selector_quality[gainbank];

	return OPTIC_STATUS_OK;
}

/**
	Configures the TIA gain selector specially for the debug mode.
	Debug mode can be deaktivated for this.

	Note: Tia gain selector specifies one of 4 fcsi settings
*/
enum optic_errorcode cal_mpd_dbg_gain_set ( struct optic_device *p_dev,
					       const struct
					       optic_dbg_gain *param )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	if (param->tia_gain_selector > 3)
		return OPTIC_STATUS_POOR;

	p_ctrl->config.debug.tia_gain_selector = param->tia_gain_selector;

	if (p_ctrl->config.debug_mode == true) {
		/* debug mode detected -> special configuration */
		ret = optic_mpd_gainctrl_set ( p_ctrl,
						     OPTIC_GAINBANK_MAX,
						     OPTIC_CAL_OFF );
		if (ret != OPTIC_STATUS_OK)
			return ret;
	}

	return OPTIC_STATUS_OK;
}

/**
	Reads back the TIA gain selector and the calibration current
	specially of the debug mode. Debug mode can be deaktivated for this.

	Note: Tia gain selector specifies one of 4 fcsi settings,
	      range of calibration current is limited to 2 (100uA) and 3 (1mA).
*/
enum optic_errorcode cal_mpd_dbg_gain_get ( struct optic_device *p_dev,
					    struct optic_dbg_gain *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_debug *debug = &(p_ctrl->config.debug);

	if (param== NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_dbg_gain) );

	param->tia_gain_selector = debug->tia_gain_selector;

	return OPTIC_STATUS_OK;
}

/**
	Configures the calibration current for the specified power level
	or global setting.

	Note: range of calibration current is limited to 1 (open),
	      2 (100uA) and 3 (1mA).
*/
enum optic_errorcode cal_mpd_cal_current_set ( struct optic_device *p_dev,
				               const struct optic_cal_set
				               *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_gainbank gainbank;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	gainbank =  param->gainbank;

	if ((param->cal_current != OPTIC_CAL_OFF) &&
	    (param->cal_current != OPTIC_CAL_OPEN) &&
	    (param->cal_current != OPTIC_CAL_100UA) &&
	    (param->cal_current != OPTIC_CAL_1MA))
		return OPTIC_STATUS_POOR;

	p_ctrl->config.monitor.cal_current[gainbank] = param->cal_current;
	p_ctrl->config.monitor.cal_current_quality[gainbank] =
						OPTIC_QUALITY_CALIBRATION;

	return OPTIC_STATUS_OK;
}


/**
	Reads back the calibration current of the specified power level
	or global setting.

	Note: range of calibration current is limited to 1 (open),
	      2 (100uA) and 3 (1mA).
*/
enum optic_errorcode cal_mpd_cal_current_get ( struct optic_device *p_dev,
				               const struct optic_cal_get_in
				               *param_in,
				               struct optic_cal_get_out
				               *param_out )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_gainbank gainbank;

	if ((param_in == NULL) || (param_out == NULL))
		return OPTIC_STATUS_ERR;

	gainbank = param_in->gainbank;

	memset ( param_out, 0, sizeof(struct optic_cal_get_out) );

	param_out->cal_current = p_ctrl->config.monitor.cal_current[gainbank];
	param_out->quality =
			p_ctrl->config.monitor.cal_current_quality[gainbank];

	return OPTIC_STATUS_OK;
}

/**
	Configures the calibration current specially for the debug mode.
	Debug mode can be deaktivated for this.

	Note: range of calibration current is limited to 1 (open),
	      2 (100uA) and 3 (1mA).
*/
enum optic_errorcode cal_mpd_dbg_cal_current_set ( struct optic_device *p_dev,
					           const struct optic_dbg_cal
					           *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	if ((param->cal_current != OPTIC_CAL_OFF) &&
	    (param->cal_current != OPTIC_CAL_OPEN) &&
	    (param->cal_current != OPTIC_CAL_100UA) &&
	    (param->cal_current != OPTIC_CAL_1MA))
		return OPTIC_STATUS_POOR;

	p_ctrl->config.debug.cal_current = param->cal_current;

	return OPTIC_STATUS_OK;
}


/**
	Reads back the TIA gain selector and the calibration current
	specially of the debug mode. Debug mode can be deaktivated for this.

	Note: range of calibration current is limited to 2 (100uA) and 3 (1mA).
*/
enum optic_errorcode cal_mpd_dbg_cal_current_get ( struct optic_device *p_dev,
					           struct optic_dbg_cal *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_debug *debug = &(p_ctrl->config.debug);

	if (param== NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_dbg_cal) );

	param->cal_current = debug->cal_current;

	return OPTIC_STATUS_OK;
}

/**
	Sets the reference codewords Dref and Dcal_ref for P0 and P1 for
	the specified power level.

	Note: Reference codewords are shifted by OPTIC_FLOAT2INTSHIFT_DREF
	      to use integer format.
*/
enum optic_errorcode cal_mpd_ref_codeword_set ( struct optic_device *p_dev,
					        const struct
					        optic_refcw_set *param )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	int16_t dac_coarse[2], dac_fine[2];
	static const bool calibrate[2] = { OPTIC_MPD_CALIBRATE_P0,
		OPTIC_MPD_CALIBRATE_P1 };
	enum optic_powerlevel powerlevel_set;
	enum optic_powerlevel powerlevel_act = p_ctrl->calibrate.powerlevel;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	powerlevel_set = param->powerlevel;

	if (powerlevel_set > OPTIC_POWERLEVEL_MAX)
		return OPTIC_STATUS_ERR;

	p_ctrl->config.monitor.dcal_ref_p0[powerlevel_set] = param->dcal_ref_p0;
	p_ctrl->config.monitor.dcal_ref_p1[powerlevel_set] = param->dcal_ref_p1;
	p_ctrl->config.monitor.dref_p0[powerlevel_set] =     param->dref_p0;
	p_ctrl->config.monitor.dref_p1[powerlevel_set] =     param->dref_p1;

	p_ctrl->config.monitor.dref_quality[powerlevel_set] =
						OPTIC_QUALITY_CALIBRATION;

	if ((p_ctrl->config.debug_mode == false) &&
	    (powerlevel_set == powerlevel_act)) {
		ret = optic_mpd_calibrate_level (p_ctrl, 
			OPTIC_MPD_CALIBRATE_OFFSET, calibrate,
			dac_coarse, dac_fine);
		if (ret != OPTIC_STATUS_OK)
			return ret;

		ret = optic_mpd_codeword_calc ( p_ctrl, calibrate,
						OPTIC_MPD_CALIBRATE_OFFSET,
						dac_coarse, dac_fine );
		if (ret != OPTIC_STATUS_OK)
			return ret;
	}

	return OPTIC_STATUS_OK;
}

/**
	Reads back the reference codewords Dref and Dcal_ref for P0 and P1 of
	the specified power level.

	Note: Reference codewords are shifted by OPTIC_FLOAT2INTSHIFT_DREF
	      to use integer format.
*/
enum optic_errorcode cal_mpd_ref_codeword_get ( struct optic_device *p_dev,
					        const struct optic_refcw_get_in
					        *param_in,
					        struct optic_refcw_get_out
					        *param_out )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_powerlevel powerlevel;

	if ((param_in == NULL) || (param_out == NULL))
		return OPTIC_STATUS_ERR;

	powerlevel = param_in->powerlevel;

	memset ( param_out, 0, sizeof(struct optic_refcw_get_out) );

	param_out->dcal_ref_p0 = p_ctrl->config.monitor.dcal_ref_p0[powerlevel];
	param_out->dcal_ref_p1 = p_ctrl->config.monitor.dcal_ref_p1[powerlevel];
	param_out->dref_p0 =     p_ctrl->config.monitor.dref_p0[powerlevel];
	param_out->dref_p1 =     p_ctrl->config.monitor.dref_p1[powerlevel];

	return OPTIC_STATUS_OK;
}

/**
	Sets the reference codewords Dref and Dcal_ref for P0 and P1
	specially for the debug mode. Debug mode can be deaktivated for this.

	Note: Reference codewords are shifted by OPTIC_FLOAT2INTSHIFT_DREF
	      to use integer format.
*/
enum optic_errorcode cal_mpd_dbg_ref_codeword_set ( struct optic_device *p_dev,
					            const struct optic_dbg_refcw
					            *param )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	int16_t dac_coarse[2], dac_fine[2];
	static const bool calibrate[2] = { OPTIC_MPD_CALIBRATE_P0, 
		OPTIC_MPD_CALIBRATE_P1 };

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	p_ctrl->config.debug.dcal_ref_p0 = param->dcal_ref_p0;
	p_ctrl->config.debug.dcal_ref_p1 = param->dcal_ref_p1;
	p_ctrl->config.debug.dref_p0 =     param->dref_p0;
	p_ctrl->config.debug.dref_p1 =     param->dref_p1;

	if (p_ctrl->config.debug_mode == true) {
		ret = optic_mpd_calibrate_level (p_ctrl,
			OPTIC_MPD_CALIBRATE_OFFSET, calibrate,
			dac_coarse, dac_fine);
		if (ret != OPTIC_STATUS_OK)
			return ret;

		ret = optic_mpd_codeword_calc (p_ctrl, calibrate,
			OPTIC_MPD_CALIBRATE_OFFSET, dac_coarse, dac_fine);
		if (ret != OPTIC_STATUS_OK)
			return ret;
	}

	return OPTIC_STATUS_OK;
}

/**
	Reads back the reference codewords Dref and Dcal_ref for P0 and P1
	specially of the debug mode. Debug mode can be deaktivated for this.

	Note: Reference codewords are shifted by OPTIC_FLOAT2INTSHIFT_DREF
	      to use integer format.
*/
enum optic_errorcode cal_mpd_dbg_ref_codeword_get ( struct optic_device *p_dev,
					            struct optic_dbg_refcw
					            *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_powerlevel powerlevel = p_ctrl->calibrate.powerlevel;
	struct optic_config_debug *debug = &(p_ctrl->config.debug);
	struct optic_config_monitor *monitor = &(p_ctrl->config.monitor);

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_dbg_refcw) );

	if (debug->dcal_ref_p0)
		param->dcal_ref_p0 = debug->dcal_ref_p0;
	else
		param->dcal_ref_p0 = monitor->dcal_ref_p0[powerlevel];

	if (debug->dcal_ref_p1)
		param->dcal_ref_p1 = debug->dcal_ref_p1;
	else
		param->dcal_ref_p1 = monitor->dcal_ref_p1[powerlevel];

	if (debug->dref_p0)
		param->dref_p0 = debug->dref_p0;
	else
		param->dref_p0 = monitor->dref_p0[powerlevel];

	if (debug->dref_p1)
		param->dref_p1 = debug->dref_p1;
	else
		param->dref_p1 = monitor->dref_p1[powerlevel];

	return OPTIC_STATUS_OK;
}

/**
	Sets the TIA offset and P1 offset delta for the specified power level
	or the global setting (used for coarse/fine ratio calculation).
	Offsets can be measured by driver by offset cancellation.

	Note: Offset values are not shifted to use integer format.
*/
enum optic_errorcode cal_mpd_tia_offset_set ( struct optic_device *p_dev,
					      const struct optic_tia_offset_set
					      *param )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	enum optic_powerlevel powerlevel = p_ctrl->calibrate.powerlevel;
	enum optic_gainbank gainbank, gainbank_active;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	gainbank =  param->gainbank;

	ret = optic_powerlevel2gainbank ( powerlevel, &gainbank_active );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	cal->dac_offset_tia_c[gainbank] =      param->tia_offset_coarse;
	cal->dac_offset_tia_f[gainbank] =      param->tia_offset_fine;
	cal->dac_offset_delta_p1_c[gainbank] = param->tia_offset_p1_coarse;
	cal->dac_offset_delta_p1_f[gainbank] = param->tia_offset_p1_fine;

	if ((p_ctrl->config.debug_mode == false) &&
	    (gainbank == gainbank_active)) {
		ret = optic_mpd_tia_offset_set ( p_ctrl, gainbank );
		if (ret != OPTIC_STATUS_OK)
			return ret;
	}

	return OPTIC_STATUS_OK;
}

/**
	Reads back the TIA offset and P1 offset delta of the specified
	powerlevel or the global setting (used for coarse/fine ratio
	calculation).
	Offsets can be measured by driver by offset cancellation.

	Note: Offset values are not shifted to use integer format.
*/
enum optic_errorcode cal_mpd_tia_offset_get ( struct optic_device *p_dev,
					      const struct
					      optic_tia_offset_get_in
					      *param_in,
					      struct optic_tia_offset_get_out
					      *param_out )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	enum optic_gainbank gainbank;

	if ((param_in == NULL) || (param_out == NULL))
		return OPTIC_STATUS_ERR;

	gainbank = param_in->gainbank;

	memset ( param_out, 0, sizeof(struct optic_tia_offset_get_out) );

	param_out->tia_offset_coarse =    cal->dac_offset_tia_c[gainbank];
	param_out->tia_offset_fine =      cal->dac_offset_tia_f[gainbank];
	param_out->tia_offset_p1_coarse = cal->dac_offset_delta_p1_c[gainbank];
	param_out->tia_offset_p1_fine =   cal->dac_offset_delta_p1_f[gainbank];

	return OPTIC_STATUS_OK;
}

/**
	Sets the TIA offset and P1 offset delta specially for the debug mode.
	Offsets can be measured by driver via offset cancellation.

	Note: Offset values are not shifted to use integer format.
*/
enum optic_errorcode cal_mpd_dbg_tia_offset_set ( struct optic_device *p_dev,
					          const struct
					          optic_dbg_tia_offset *param )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	cal->dbg_dac_offset_tia_c =      param->tia_offset_coarse;
	cal->dbg_dac_offset_tia_f =      param->tia_offset_fine;
	cal->dbg_dac_offset_delta_p1_c = param->tia_offset_p1_coarse;
	cal->dbg_dac_offset_delta_p1_f = param->tia_offset_p1_fine;

	if (p_ctrl->config.debug_mode == true) {
		/* debug mode will be detected -> special tia offset */
		ret = optic_mpd_tia_offset_set ( p_ctrl,
						       OPTIC_GAINBANK_MAX );
		if (ret != OPTIC_STATUS_OK)
			return ret;
	}

	return OPTIC_STATUS_OK;
}

/**
	Reads back the TIA offset and P1 offset delta specially of
	the debug mode.
	Offsets can be measured by driver via offset cancellation.

	Note: Offset values are not shifted to use integer format.
*/
enum optic_errorcode cal_mpd_dbg_tia_offset_get ( struct optic_device *p_dev,
					          struct optic_dbg_tia_offset
					          *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_dbg_tia_offset) );

	param->tia_offset_coarse =    cal->dbg_dac_offset_tia_c;
	param->tia_offset_fine =      cal->dbg_dac_offset_tia_f;
	param->tia_offset_p1_coarse = cal->dbg_dac_offset_delta_p1_c;
	param->tia_offset_p1_fine =   cal->dbg_dac_offset_delta_p1_f;

	return OPTIC_STATUS_OK;
}

/**
	Starts the offset cancellation.
	In case of debug mode: TIA offset and P1 offset delta are measured
	for corresponding debug TIA gain / calibration current.
	In case of normal mode: TIA offset and P1 offset delta are measured
	for all 3 power level and the global TIA gain / calibration current
	(global offset is used for coarse/fineratio calculation)

	Note: In normal mode offset cancellation is always followed by
	      new DAC level configuration, so offset cancellation don't
	      care about recovering level DAC.
	      Therefore calibration/debug start of offset cancellation have
	      to recover DAC level setting.
	Note: All MPD DAC accessing routines have to block access via dac_lock!
*/
enum optic_errorcode cal_mpd_tia_offset_find ( struct optic_device *p_dev )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret;

	if (p_ctrl->config.mode == OPTIC_OMU) {
		OPTIC_DEBUG_ERR("Offset Cancellation not usable in OMU mode"
				" (MPD inactive)");
		return OPTIC_STATUS_ERR;
	}
	/* disable rougue ont interrupt */
	if ((p_ctrl->config.monitor.rogue_interburst) ||
	    (p_ctrl->config.monitor.rogue_intraburst))
		optic_ll_mpd_rogue_int_set (0 ,0);

	ret = optic_mpd_offset_cancel ( p_ctrl );

	/* enable rougue ont interrupt */
	if ((p_ctrl->config.monitor.rogue_interburst) ||
	    (p_ctrl->config.monitor.rogue_intraburst))
		optic_ll_mpd_rogue_int_set (
			p_ctrl->config.monitor.rogue_interburst,
			p_ctrl->config.monitor.rogue_intraburst);

	if (ret != OPTIC_STATUS_OK)
		return ret;

	return OPTIC_STATUS_OK;
}

/**
	Sets the level DAC codeword for P0 or P1 level DAC.
	Level DAC codewords can be measured by driver via MPD calibration.

	Note: codewords are shifted by OPTIC_FLOAT2INTSHIFT_DREF
	      to use integer format.
	Note: All MPD DAC accessing routines have to block access via dac_lock!
*/
enum optic_errorcode cal_mpd_level_set ( struct optic_device *p_dev,
					 const struct optic_level_set *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret;
	bool p0;

	switch (param->level_select) {
	case 0:
		p_ctrl->calibrate.digit_codeword_p0 = param->level_value;
		p0 = true;
		break;
	case 1:
		p_ctrl->calibrate.digit_codeword_p1 = param->level_value;
		p0 = false;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	if (IFXOS_MutexGet(&p_ctrl->access.dac_lock) != IFX_SUCCESS)
		return OPTIC_STATUS_ERR;

	ret = optic_mpd_codeword_set ( p_ctrl, p0 );

	IFXOS_MutexRelease(&p_ctrl->access.dac_lock);

	return ret;
}

/**
	Reads back the level DAC codeword of P0 or P1 level DAC.
	Level DAC codewords can be measured by driver via MPD calibration.

	Note: codewords are shifted by OPTIC_FLOAT2INTSHIFT_DREF
	      to use integer format.
*/
enum optic_errorcode cal_mpd_level_get ( struct optic_device *p_dev,
					 const struct optic_level_get_in
					 *param_in,
					 struct optic_level_get_out
					 *param_out )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	uint8_t level_select;

	if ((param_in == NULL) || (param_in == NULL))
		return OPTIC_STATUS_ERR;

	level_select = param_in->level_select;

	memset ( param_out, 0, sizeof(struct optic_level_get_out) );

	switch (level_select) {
	case 0:
		param_out->gain_correction = p_ctrl->calibrate.gain_correct_p0;
		param_out->level_value = p_ctrl->calibrate.digit_codeword_p0;
		break;
	case 1:
		param_out->gain_correction = p_ctrl->calibrate.gain_correct_p1;
		param_out->level_value = p_ctrl->calibrate.digit_codeword_p1;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}

/**
	Starts the MPD calibration to calculate and set P0 and P1 level DAC
	codewords.
	Starting with offset cancelation (like in internal flow) is optional.

	Note: All MPD DAC accessing routines have to block access via dac_lock!
	      This is covered by internal routine optic_ll_mpd_calibrate()
*/
enum optic_errorcode cal_mpd_level_find ( struct optic_device *p_dev,
				          const struct optic_level_find_in
					  *param_in,
					  struct optic_level_find_out
					  *param_out )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	bool calibrate[2], offset_cancellation;
	uint16_t *p_ratio[2] = { &(p_ctrl->calibrate.ratio_p0),
	                         &(p_ctrl->calibrate.ratio_p1) };
	int16_t dac_coarse[2] = { 0, 0 } , dac_fine[2] = { 0, 0 };
	int16_t *p_level[2] = { &(param_out->level_p0),
				&(param_out->level_p1) };
	int32_t temp;
	uint8_t i;


/** \todo debug setting in cal_mpd_level_find! */
/* debug */
	if (param_in->calibrate_p0 && param_in->calibrate_p1)
		p_ctrl->calibrate.dualloop_control = 2;
	else
		p_ctrl->calibrate.dualloop_control = 1;

/* /debug */

	offset_cancellation = param_in->offset_cancellation;
	calibrate[0] = param_in->calibrate_p0;
	calibrate[1] = param_in->calibrate_p1;

	memset ( param_out, 0, sizeof(struct optic_level_find_out) );

	ret = optic_mpd_calibrate_level ( p_ctrl, offset_cancellation,
					  calibrate, dac_coarse,
					  dac_fine );

	if (ret != OPTIC_STATUS_OK)
		return ret;

	/* in case of debug mode (== ocal calibration) calculate
	 * cf value and shift the return value for the ocal */
	for (i=0; i<2; i++) {
		if (calibrate[i] == false) {
			*(p_level[i]) = OPTIC_INT16_MIN;
			continue;
		}

		temp = dac_coarse[i] * (*(p_ratio[i]));
		temp += (dac_fine[i] *
				(1 << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO));
		if (temp < 0)
			temp -= (1 << (OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO-1));
		else
			temp += (1 << (OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO-1));

		*(p_level[i]) = (int16_t) (temp /
				(1 << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO));

		if (p_ctrl->config.debug_mode == true) {
			if (i==0)
				p_ctrl->config.debug.dref_p0=*(p_level[0])<<OPTIC_FLOAT2INTSHIFT_DREF;
			else
				p_ctrl->config.debug.dref_p1=*(p_level[1])<<OPTIC_FLOAT2INTSHIFT_DREF;
		}

	}
	/*OPTIC_DEBUG_ERR("cal_mpd_level_find(): *(p_level[0])=%d *(p_level[1])=%d",*(p_level[0]),*(p_level[1]));*/

	ret = optic_mpd_codeword_calc ( p_ctrl, calibrate, offset_cancellation,
					dac_coarse, dac_fine );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

/**
	Sets the level DAC coarse/fine ratio for P0 and P1 level DAC.
	Coarse/fine ratio can be calculated by driver.

	Note: codewords are shifted by OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO
	      to use integer format.
*/
enum optic_errorcode cal_mpd_cfratio_set ( struct optic_device *p_dev,
					   const struct optic_cfratio
					   *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	p_ctrl->calibrate.ratio_p0 = param->ratio_p0;
	p_ctrl->calibrate.ratio_p1 = param->ratio_p1;

	return OPTIC_STATUS_OK;
}

/**
	Reads back the level DAC coarse/fine ratio of P0 and P1 level DAC.
	Coarse/fine ratio can be calculated by driver.

	Note: codewords are shifted by OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO
	      to use integer format.
*/
enum optic_errorcode cal_mpd_cfratio_get ( struct optic_device *p_dev,
					   struct optic_cfratio *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_cfratio) );

	param->ratio_p0 = p_ctrl->calibrate.ratio_p0;
	param->ratio_p1 = p_ctrl->calibrate.ratio_p1;

	return OPTIC_STATUS_OK;
}

/**
	Starts the internal coarse/fine ratio calculation for P0 and P1
	level DAC.

	Note: All MPD DAC accessing routines have to block access via dac_lock!
	      This is covered by internal routine optic_ll_mpd_ratio_measure()
*/
enum optic_errorcode cal_mpd_cfratio_find ( struct optic_device *p_dev )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	return optic_mpd_ratio_measure ( p_ctrl );
}

enum optic_errorcode cal_mpd_powersave_set ( struct optic_device *p_dev,
					     const struct optic_powersave
					     *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	p_ctrl->config.monitor.powersave = param->powersave;

	return optic_powersave_set ( p_ctrl );
}

enum optic_errorcode cal_mpd_powersave_get ( struct optic_device *p_dev,
					     struct optic_powersave *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_activation powerdown;
	enum optic_errorcode ret;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_powersave) );

	param->powersave = p_ctrl->config.monitor.powersave;

	ret = optic_ll_mpd_powersave_get ( &powerdown );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (p_ctrl->config.monitor.powersave != powerdown)
		return OPTIC_STATUS_ERR;

	return OPTIC_STATUS_OK;
}


/**
	Writes FCSI predriver settings directly to the hardware.
*/
enum optic_errorcode cal_fcsi_predriver_set ( struct optic_device *p_dev,
					      const struct optic_fcsi_predriver
					      *param )
{
	(void) p_dev;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	return optic_fcsi_predriver_set ( param->dd_loadn,
					  param->dd_bias_en,
					  param->dd_loadp,
					  param->dd_cm_load,
					  param->bd_loadn,
					  param->bd_bias_en,
					  param->bd_loadp,
					  param->bd_cm_load );
}

/**
	Reads back FCSI predriver settings directly from the hardware.
*/
enum optic_errorcode cal_fcsi_predriver_get ( struct optic_device *p_dev,
					      struct optic_fcsi_predriver
					      *param )
{
	(void) p_dev;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_fcsi_predriver) );

	return optic_fcsi_predriver_get ( &(param->dd_loadn),
					  &(param->dd_bias_en),
					  &(param->dd_loadp),
					  &(param->dd_cm_load),
					  &(param->bd_loadn),
					  &(param->bd_bias_en),
					  &(param->bd_loadp),
					  &(param->bd_cm_load) );
}

enum optic_errorcode cal_dcdc_apd_voltage_set ( struct optic_device *p_dev,
					        const struct optic_voltage
					        *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint16_t vapd = param->voltage_val;
	uint8_t sat;

	/* search for saturation value */
	ret = optic_search_apd_saturation ( p_ctrl, vapd, &sat );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("search_apd_saturation(): %d", ret);
		return ret;
	}
#if (OPTIC_APD_DEBUG == ACTIVE)
	OPTIC_DEBUG_ERR("calling optic_dcdc_apd_voltage_set() now (sat = %d)... ", sat);
#endif
	ret = optic_dcdc_apd_voltage_set ( p_ctrl, vapd, sat );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

enum optic_errorcode cal_dcdc_apd_voltage_get ( struct optic_device *p_dev,
					        struct optic_voltage *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint16_t voltage;
	int16_t reg_error;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_voltage) );

	ret = optic_dcdc_apd_voltage_get ( p_ctrl, &voltage, &reg_error );

	/* do not consider reg_error as it is only a single
	 * point of measure inside the regulation loop */
	param->voltage_val = voltage;

	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

enum optic_errorcode cal_dcdc_core_voltage_set ( struct optic_device *p_dev,
					         const struct optic_voltage
					         *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint16_t vcore = param->voltage_val;
	uint8_t min = 0, max = 0;

	/* calculate duty_cycle value */

	ret = optic_calc_duty_cycle ( p_ctrl, OPTIC_DCDC_CORE, vcore,
					    &min, &max );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_calc_duty_cycle(): %d", ret);
		return ret;
	}

	ret = optic_dcdc_core_voltage_set ( p_ctrl, vcore );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_dcdc_core_dutycycle_set ( min, max );
	if (ret != OPTIC_STATUS_OK)
		return ret;
#if OPTIC_USE_DCDC_DEADZONE == ACTIVE
	ret = optic_ll_dcdc_core_deadzone_set ( p_ctrl->config.dcdc_core.
								pmos_on_delay,
						p_ctrl->config.dcdc_core.
								nmos_on_delay );
	if (ret != OPTIC_STATUS_OK)
		return ret;
#endif

	return ret;
}

enum optic_errorcode cal_dcdc_core_voltage_get ( struct optic_device *p_dev,
					         struct optic_voltage *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_voltage) );

	ret = optic_dcdc_core_voltage_get ( p_ctrl,
						  &(param->voltage_val) );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

enum optic_errorcode cal_dcdc_ddr_voltage_set ( struct optic_device *p_dev,
					        const struct optic_voltage
					        *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint16_t vddr = param->voltage_val;
	uint8_t min = 0, max = 0;

	/* calculate duty_cycle value */

	ret = optic_calc_duty_cycle ( p_ctrl, OPTIC_DCDC_DDR, vddr,
					    &min, &max );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_calc_duty_cycle(): %d", ret);
		return ret;
	}

	ret = optic_dcdc_ddr_voltage_set ( p_ctrl, vddr );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_dcdc_ddr_dutycycle_set ( min, max );
	if (ret != OPTIC_STATUS_OK)
		return ret;

#if OPTIC_USE_DCDC_DEADZONE == ACTIVE
	ret = optic_ll_dcdc_ddr_deadzone_set ( p_ctrl->config.dcdc_ddr.
								pmos_on_delay,
					       p_ctrl->config.dcdc_ddr.
								nmos_on_delay );
	if (ret != OPTIC_STATUS_OK)
		return ret;
#endif
	return ret;
}

enum optic_errorcode cal_dcdc_ddr_voltage_get ( struct optic_device *p_dev,
					        struct optic_voltage *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_voltage) );

	ret = optic_dcdc_ddr_voltage_get ( p_ctrl,
						 &(param->voltage_val) );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

enum optic_errorcode cal_laser_delay_set ( struct optic_device *p_dev,
					   const struct optic_laserdelay
					   *param )
{
	(void) p_dev;

	return optic_ll_tx_laserdelay_set ( param->bitdelay );
}

enum optic_errorcode cal_laser_delay_get ( struct optic_device *p_dev,
					   struct optic_laserdelay *param )
{
	(void) p_dev;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_laserdelay) );

	return optic_ll_tx_laserdelay_get ( &(param->bitdelay) );
}

enum optic_errorcode cal_mm_dark_corr_set ( struct optic_device *p_dev,
					    const struct optic_rssi_1490_dark
					    *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;

	p_ctrl->config.measurement.rssi_1490_dark_corr = param->corr_factor;

	ret = optic_calc_offset_and_thresh ( p_ctrl );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

enum optic_errorcode cal_mm_dark_corr_get ( struct optic_device *p_dev,
					    struct optic_rssi_1490_dark
					    *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_rssi_1490_dark) );

	param->corr_factor = p_ctrl->config.measurement.rssi_1490_dark_corr;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode cal_mm_dark_corr_find ( struct optic_device *p_dev )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;

	if ((p_ctrl->config.mode != OPTIC_BOSA) &&
	    (p_ctrl->config.mode != OPTIC_BOSA_2)) {
		OPTIC_DEBUG_ERR("only valid for BOSA mode");
		return OPTIC_STATUS_ERR;
	}

	if (p_ctrl->config.measurement.rssi_1490_mode !=
	    OPTIC_RSSI_1490_DIFFERENTIAL) {
		OPTIC_DEBUG_ERR("only valid for RSSI 1490 differential "
				"measurement mode");
		return OPTIC_STATUS_ERR;
	}

	ret = optic_calc_rssi_1490_dark_corr (
			p_ctrl->calibrate.meas_voltage_1490_rssi,
			p_ctrl->config.dcdc_apd.ext_att,
			p_ctrl->calibrate.vapd_target,
			p_ctrl->config.dcdc_apd.r_diff,
			p_ctrl->config.measurement.rssi_1490_shunt_res,
			&(p_ctrl->config.measurement.rssi_1490_dark_corr) );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_calc_offset_and_thresh ( p_ctrl );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

enum optic_errorcode cal_fusing_get ( struct optic_device *p_dev,
				      struct optic_fusing *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_fusing) );

	param->format           = p_ctrl->config.fuses.format;

	param->vcal_mm20        = p_ctrl->config.fuses.vcal_mm20;
	param->vcal_mm100       = p_ctrl->config.fuses.vcal_mm100;
	param->vcal_mm400       = p_ctrl->config.fuses.vcal_mm400;
	param->rcal_mm          = p_ctrl->config.fuses.rcal_mm;
	param->temp_mm          = p_ctrl->config.fuses.temp_mm;
	param->tbgp             = p_ctrl->config.fuses.tbgp;
	param->vbgp             = p_ctrl->config.fuses.vbgp;
	param->irefbgp          = p_ctrl->config.fuses.irefbgp;
	param->gain_dac_drive   = p_ctrl->config.fuses.gain_dac_drive;
	param->gain_dac_bias    = p_ctrl->config.fuses.gain_dac_bias;
	param->offset_dcdc_ddr  = p_ctrl->config.fuses.offset_dcdc_ddr;
	param->gain_dcdc_ddr    = p_ctrl->config.fuses.gain_dcdc_ddr;
	param->offset_dcdc_core = p_ctrl->config.fuses.offset_dcdc_core;
	param->gain_dcdc_core   = p_ctrl->config.fuses.gain_dcdc_core;
	param->offset_dcdc_apd  = p_ctrl->config.fuses.offset_dcdc_apd;
	param->gain_dcdc_apd    = p_ctrl->config.fuses.gain_dcdc_apd;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode cal_tscalref_set( struct optic_device *p_dev,
				       const struct optic_tscalref *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;

	p_ctrl->config.measurement.tscal_ref = param->tscal_ref;

	/* init gain selectors */
	ret = optic_calc_pn_gain_sel ( p_ctrl );
	if (ret != OPTIC_STATUS_OK)
		return ret;


	return OPTIC_STATUS_OK;
}

enum optic_errorcode cal_tscalref_get( struct optic_device *p_dev,
				       struct optic_tscalref *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_tscalref) );

	param->tscal_ref = p_ctrl->config.measurement.tscal_ref;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode cal_measure_rssi_1490_get ( struct optic_device *p_dev,
	const struct optic_measure_rssi_1490_get_in *param_in,
	struct optic_measure_rssi_1490_get_out *param_out )

{
	uint8_t i;
	uint16_t rssi1490_current;
	int32_t sum = 0;
	bool is_positive;
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	struct optic_config_measurement *meas = &(p_ctrl->config.measurement);
	struct optic_ocal *ocal = &(p_ctrl->calibrate.measurement.ocal);
	enum optic_errorcode ret = OPTIC_STATUS_OK;

	if (param_in->number == 0)
		return OPTIC_STATUS_INVAL;
	if (p_ctrl->state.buffer[p_ctrl->state.index_buffer] != OPTIC_STATE_RUN)
		return OPTIC_STATUS_WRONG_STATE;
#ifndef OPTIC_LIBRARY
	if (IFXOS_EventInit ( &(ocal->event_measure) ) != IFX_SUCCESS )
		return OPTIC_STATUS_INIT_FAIL;
	ocal->measure_buffer = (uint16_t*) IFXOS_MemAlloc( sizeof(uint16_t) *
							   param_in->number );
	if (ocal->measure_buffer == NULL) {
		IFXOS_EventDelete ( &(ocal->event_measure) );
		return OPTIC_STATUS_ALLOC_ERR;
	}
#endif

	ocal->measure_number = param_in->number;
	ocal->measure_index = 0;
	p_ctrl->calibrate.measurement.mode = OPTIC_MEASUREMODE_OCAL;

#ifndef OPTIC_LIBRARY
	/* wait for Activating */
	if (IFXOS_EventWait ( &(ocal->event_measure), 10000, NULL )
		!= IFX_SUCCESS) {

		ret = optic_state_set ( p_ctrl, OPTIC_STATE_RUN );
		p_ctrl->calibrate.measurement.mode = OPTIC_MEASUREMODE_INIT;

		goto RSSI_1490_GET_END;
	}
#endif

	for (i=0; i<ocal->measure_number; i++) {
		ret = optic_calc_current_1490 ( meas->rssi_1490_mode,
						ocal->measure_buffer[i],
						p_ctrl->config.dcdc_apd.ext_att,
						meas->rssi_1490_shunt_res,
	                    cal->current_offset,
	                    &(p_ctrl->config.fuses),
						&rssi1490_current,
						&is_positive );
		if (is_positive)
			sum += rssi1490_current;
		else
			sum -= rssi1490_current;

		if (param_in->p_data != NULL)
			param_in->p_data[i] = rssi1490_current;

		if (ret != OPTIC_STATUS_OK)
			break;
	}

#ifndef OPTIC_LIBRARY
RSSI_1490_GET_END:
	IFXOS_MemFree (ocal->measure_buffer);
	IFXOS_EventDelete ( &(ocal->event_measure) );
#endif
	param_out->average = (uint16_t) optic_uint_div_rounded ( abs(sum),
							ocal->measure_number );
	if (sum < 0)
		param_out->is_positive = false;
	else
		param_out->is_positive = true;

	return ret;
}

enum optic_errorcode cal_current_offset_get( struct optic_device *p_dev,
				             struct optic_current_fine *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_current_fine) );

	param->current_fine_val = p_ctrl->calibrate.current_offset;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode cal_rx_offset_set ( struct optic_device *p_dev,
					 const struct optic_rx_offset *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	p_ctrl->calibrate.rx_offset = param->rx_offset;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode cal_rx_offset_get ( struct optic_device *p_dev,
					 struct optic_rx_offset *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_rx_offset) );

	param->rx_offset = p_ctrl->calibrate.rx_offset;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode cal_rx_offset_find ( struct optic_device *p_dev )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret;

	switch (p_ctrl->config.mode) {
	case OPTIC_OMU:
		ret = optic_ll_rx_offset_cancel ( OPTIC_RX_DATA_HIGH,
						  &(p_ctrl->calibrate.
								   rx_offset) );
		break;
	case OPTIC_BOSA:
		ret = optic_ll_rx_offset_cancel ( OPTIC_RX_DATA_LOW,
						  &(p_ctrl->calibrate.
								   rx_offset) );
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_ll_rx_offset_cancel: %d", ret);
		return ret;
	}

	return ret;
}


/* ------------------------------------------------------------------------- */

const struct optic_entry cal_function_table[OPTIC_CAL_MAX] =
{
/*  0 */  TE0    (FIO_CAL_DEBUG_ENABLE,                 cal_debug_enable),
/*  1 */  TE0    (FIO_CAL_DEBUG_DISABLE,                cal_debug_disable),
/*  2 */  TE0    (FIO_CAL_MM_ENABLE,                    cal_mm_enable),
/*  3 */  TE0    (FIO_CAL_MM_DISABLE,                   cal_mm_disable),
/*  4 */  TE1out (FIO_CAL_DEBUG_STATUS_GET,             sizeof(struct optic_debug_status),
							cal_debug_status_get),
/*  5 */  TE1out (FIO_CAL_LASER_AGE_GET,                sizeof(struct optic_timestamp),
                                        	        cal_laser_age_get),
/*  6 */  TE1in  (FIO_CAL_LASERREF_TABLE_SET,           sizeof(struct optic_laserref_set),
                                        		cal_laserref_table_set),
/*  7 */  TE2    (FIO_CAL_LASERREF_TABLE_GET,           sizeof(struct optic_laserref_get_in),
						        sizeof(struct optic_laserref_get_out),
							cal_laserref_table_get),
/*  8 */  TE1in  (FIO_CAL_IBIASIMOD_TABLE_SET,          sizeof(struct optic_ibiasimod_set),
                                        		cal_ibiasimod_table_set),
/*  9 */  TE2    (FIO_CAL_IBIASIMOD_TABLE_GET,          sizeof(struct optic_ibiasimod_get_in),
						        sizeof(struct optic_ibiasimod_get_out),
							cal_ibiasimod_table_get),
/* 10 */  TE1in  (FIO_CAL_VAPD_TABLE_SET,               sizeof(struct optic_vapd_set),
                                        		cal_vapd_table_set),
/* 11 */  TE2    (FIO_CAL_VAPD_TABLE_GET,               sizeof(struct optic_vapd_get_in),
						        sizeof(struct optic_vapd_get_out),
							cal_vapd_table_get),
/* 12 */  TE1in  (FIO_CAL_CORR_TABLE_SET,               sizeof(struct optic_corr_set),
                                        		cal_corr_table_set),
/* 13 */  TE2    (FIO_CAL_CORR_TABLE_GET,               sizeof(struct optic_corr_get_in),
						        sizeof(struct optic_corr_get_out),
							cal_corr_table_get),
/* 14 */  TE1in  (FIO_CAL_TCORREXT_TABLE_SET,           sizeof(struct optic_tcorrext_set),
                                        		cal_tcorrext_table_set),
/* 15 */  TE2    (FIO_CAL_TCORREXT_TABLE_GET,           sizeof(struct optic_tcorrext_get_in),
						        sizeof(struct optic_tcorrext_get_out),
							cal_tcorrext_table_get),
/* 16 */  TE1in  (FIO_CAL_INIT_BIAS_CURRENT_SET,        sizeof(struct optic_bias),
                                        		cal_init_bias_current_set),
/* 17 */  TE1out (FIO_CAL_INIT_BIAS_CURRENT_GET,        sizeof(struct optic_bias),
                                        		cal_init_bias_current_get),
/* 18 */  TE1in  (FIO_CAL_INIT_MOD_CURRENT_SET,         sizeof(struct optic_mod),
                                        		cal_init_mod_current_set),
/* 19 */  TE1out (FIO_CAL_INIT_MOD_CURRENT_GET,         sizeof(struct optic_mod),
                                        	        cal_init_mod_current_get),
/* 20 */  TE1out (FIO_CAL_ACT_BIAS_CURRENT_GET,         sizeof(struct optic_bias),
                                        		cal_actual_bias_current_get),
/* 21 */  TE1out (FIO_CAL_ACT_MOD_CURRENT_GET,          sizeof(struct optic_mod),
                                        	        cal_actual_mod_current_get),
/* 22 */  TE1in  (FIO_CAL_MPD_GAIN_SET,                 sizeof(struct optic_gain_set),
                                        		cal_mpd_gain_set),
/* 23 */  TE2    (FIO_CAL_MPD_GAIN_GET,                 sizeof(struct optic_gain_get_in),
						        sizeof(struct optic_gain_get_out),
                                        		cal_mpd_gain_get),
/* 24 */  TE1in  (FIO_CAL_MPD_DBG_GAIN_SET,             sizeof(struct optic_dbg_gain),
                                        		cal_mpd_dbg_gain_set),
/* 25 */  TE1out (FIO_CAL_MPD_DBG_GAIN_GET,             sizeof(struct optic_dbg_gain),
							cal_mpd_dbg_gain_get),
/* 26 */  TE1in  (FIO_CAL_MPD_CAL_CURRENT_SET,          sizeof(struct optic_cal_set),
                                        		cal_mpd_cal_current_set),
/* 27 */  TE2    (FIO_CAL_MPD_CAL_CURRENT_GET,          sizeof(struct optic_cal_get_in),
						        sizeof(struct optic_cal_get_out),
                                        		cal_mpd_cal_current_get),
/* 28 */  TE1in  (FIO_CAL_MPD_DBG_CAL_CURRENT_SET,      sizeof(struct optic_dbg_cal),
                                        		cal_mpd_dbg_cal_current_set),
/* 29 */  TE1out (FIO_CAL_MPD_DBG_CAL_CURRENT_GET,      sizeof(struct optic_dbg_cal),
							cal_mpd_dbg_cal_current_get),
/* 30 */  TE1in  (FIO_CAL_MPD_REF_CODEWORD_SET,         sizeof(struct optic_refcw_set),
                                        		cal_mpd_ref_codeword_set),
/* 31 */  TE2    (FIO_CAL_MPD_REF_CODEWORD_GET,         sizeof(struct optic_refcw_get_in),
						        sizeof(struct optic_refcw_get_out),
							cal_mpd_ref_codeword_get),
/* 32 */  TE1in  (FIO_CAL_MPD_DBG_REF_CODEWORD_SET,     sizeof(struct optic_dbg_refcw),
                                        		cal_mpd_dbg_ref_codeword_set),
/* 33 */  TE1out (FIO_CAL_MPD_DBG_REF_CODEWORD_GET,     sizeof(struct optic_dbg_refcw),
							cal_mpd_dbg_ref_codeword_get),
/* 34 */  TE1in  (FIO_CAL_MPD_TIA_OFFSET_SET,           sizeof(struct optic_tia_offset_set),
                                        		cal_mpd_tia_offset_set),
/* 35 */  TE2    (FIO_CAL_MPD_TIA_OFFSET_GET,           sizeof(struct optic_tia_offset_get_in),
						        sizeof(struct optic_tia_offset_get_out),
							cal_mpd_tia_offset_get),
/* 36 */  TE1in  (FIO_CAL_MPD_DBG_TIA_OFFSET_SET,       sizeof(struct optic_dbg_tia_offset),
                                        		cal_mpd_dbg_tia_offset_set),
/* 37 */  TE1out (FIO_CAL_MPD_DBG_TIA_OFFSET_GET,       sizeof(struct optic_dbg_tia_offset),
							cal_mpd_dbg_tia_offset_get),
/* 38 */  TE0    (FIO_CAL_MPD_TIA_OFFSET_FIND,          cal_mpd_tia_offset_find),
/* 39 */  TE1in  (FIO_CAL_MPD_LEVEL_SET,                sizeof(struct optic_level_set),
                                        		cal_mpd_level_set),
/* 40 */  TE2    (FIO_CAL_MPD_LEVEL_GET,                sizeof(struct optic_level_get_in),
							sizeof(struct optic_level_get_out),
                                        		cal_mpd_level_get),
/* 41 */  TE2    (FIO_CAL_MPD_LEVEL_FIND,               sizeof(struct optic_level_find_in),
							sizeof(struct optic_level_find_out),
							cal_mpd_level_find),
/* 42 */  TE1in  (FIO_CAL_MPD_CFRATIO_SET,              sizeof(struct optic_cfratio),
                                        		cal_mpd_cfratio_set),
/* 43 */  TE1out (FIO_CAL_MPD_CFRATIO_GET,              sizeof(struct optic_cfratio),
                                        		cal_mpd_cfratio_get),
/* 44 */  TE0    (FIO_CAL_MPD_CFRATIO_FIND,             cal_mpd_cfratio_find),
/* 45 */  TE1in  (FIO_CAL_MPD_POWERSAVE_SET,            sizeof(struct optic_powersave),
                                        		cal_mpd_powersave_set),
/* 46 */  TE1out (FIO_CAL_MPD_POWERSAVE_GET,            sizeof(struct optic_powersave),
                                        		cal_mpd_powersave_get),
/* 47 */  TE1in  (FIO_CAL_FCSI_PREDRIVER_SET,           sizeof(struct optic_fcsi_predriver),
                                        		cal_fcsi_predriver_set),
/* 48 */  TE1out (FIO_CAL_FCSI_PREDRIVER_GET,           sizeof(struct optic_fcsi_predriver),
                                        		cal_fcsi_predriver_get),
/* 49 */  TE1in  (FIO_CAL_DCDC_APD_VOLTAGE_SET,         sizeof(struct optic_voltage),
                                        		cal_dcdc_apd_voltage_set),
/* 50 */  TE1out (FIO_CAL_DCDC_APD_VOLTAGE_GET,         sizeof(struct optic_voltage),
                                        		cal_dcdc_apd_voltage_get),
/* 51 */  TE1in  (FIO_CAL_DCDC_CORE_VOLTAGE_SET,        sizeof(struct optic_voltage),
                                        		cal_dcdc_core_voltage_set),
/* 52 */  TE1out (FIO_CAL_DCDC_CORE_VOLTAGE_GET,        sizeof(struct optic_voltage),
                                        		cal_dcdc_core_voltage_get),
/* 53 */  TE1in  (FIO_CAL_DCDC_DDR_VOLTAGE_SET,         sizeof(struct optic_voltage),
                                        		cal_dcdc_ddr_voltage_set),
/* 54 */  TE1out (FIO_CAL_DCDC_DDR_VOLTAGE_GET,         sizeof(struct optic_voltage),
                                        		cal_dcdc_ddr_voltage_get),
/* 55 */  TE1in  (FIO_CAL_LASERDELAY_SET,               sizeof(struct optic_laserdelay),
                                        		cal_laser_delay_set),
/* 56 */  TE1out (FIO_CAL_LASERDELAY_GET,               sizeof(struct optic_laserdelay),
                                        		cal_laser_delay_get),
/* 57 */  TE1in  (FIO_CAL_MM_DARK_CORR_SET,             sizeof(struct optic_rssi_1490_dark),
                                        		cal_mm_dark_corr_set),
/* 58 */  TE1out (FIO_CAL_MM_DARK_CORR_GET,             sizeof(struct optic_rssi_1490_dark),
                                        		cal_mm_dark_corr_get),
/* 59 */  TE0    (FIO_CAL_MM_DARK_CORR_FIND,            cal_mm_dark_corr_find),
/* 60 */  TE1out (FIO_CAL_FUSES_GET,                    sizeof(struct optic_fusing),
                                        		cal_fusing_get),
/* 61 */  TE1in  (FIO_CAL_TSCALREF_SET,                 sizeof(struct optic_tscalref),
                                        		cal_tscalref_set),
/* 62 */  TE1out (FIO_CAL_TSCALREF_GET,                 sizeof(struct optic_tscalref),
                                        		cal_tscalref_get),
/* 63 */  TE2    (FIO_CAL_MEASURE_RSSI_1490_GET,        sizeof(struct optic_measure_rssi_1490_get_in),
                                                        sizeof(struct optic_measure_rssi_1490_get_out),
                                        		cal_measure_rssi_1490_get),
/* 64 */  TE1out (FIO_CAL_CURRENT_OFFSET_GET,           sizeof(struct optic_current_fine),
                                        		cal_current_offset_get),
/* 65 */  TE1in (FIO_CAL_RX_OFFSET_SET,                 sizeof(struct optic_rx_offset),
                                        		cal_rx_offset_set),
/* 66 */  TE1out (FIO_CAL_RX_OFFSET_GET,                sizeof(struct optic_rx_offset),
                                        		cal_rx_offset_get),
/* 67 */  TE0 (FIO_CAL_RX_OFFSET_FIND,                  cal_rx_offset_find),


};

#endif

/*! @} */

/*! @} */
