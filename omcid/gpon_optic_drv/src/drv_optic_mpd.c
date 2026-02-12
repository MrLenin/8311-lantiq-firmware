/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, MPD Interface - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_MPD_INTERNAL MPD Interface - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_mpd_interface.h"
#include "drv_optic_mpd.h"

#include "drv_optic_calc.h"
#include "drv_optic_ll_mpd.h"
#include "drv_optic_ll_bert.h"
#include "drv_optic_ll_dcdc_apd.h"
#include "drv_optic_ll_int.h"

/** Chip dependend settings of max bias current */
#define DEFAULT_A12_BIASMAX 78
#define DEFAULT_A21_BIASMAX DEFAULT_A12_BIASMAX
/** Chip dependend settings of max modulation current */
#define DEFAULT_A12_MODMAX 130
#define DEFAULT_A21_MODMAX 95
/**
   Read MPD configuration data into the context.
*/
enum optic_errorcode mpd_cfg_set ( struct optic_device *p_dev,
                                   const struct optic_mpd_config *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_monitor *monitor = &(p_ctrl->config.monitor);
	uint8_t gb, pl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	/* monitor */
	for (gb=0; gb<OPTIC_GAINBANK_MAX; gb++) {
		if (param->tia_gain_selector[gb] > 3)
			return OPTIC_STATUS_POOR;

		monitor->tia_gain_selector[gb] = param->tia_gain_selector[gb];
		monitor->tia_gain_selector_quality[gb]  = OPTIC_QUALITY_CONFIG;

		if ((param->cal_current[gb] != OPTIC_CAL_OFF) &&
		    (param->cal_current[gb] != OPTIC_CAL_OPEN) &&
		    (param->cal_current[gb] != OPTIC_CAL_100UA) &&
		    (param->cal_current[gb] != OPTIC_CAL_1MA))
			return OPTIC_STATUS_POOR;

		monitor->cal_current[gb]         = param->cal_current[gb];
		monitor->cal_current_quality[gb] = OPTIC_QUALITY_CONFIG;
	}

	for (pl=0; pl<OPTIC_POWERLEVEL_MAX; pl++) {
		monitor->scalefactor_mod[pl]  = param->scalefactor_mod[pl];

		monitor->dcal_ref_p0[pl]      = param->dcal_ref_p0[pl];
		monitor->dcal_ref_p1[pl]      = param->dcal_ref_p1[pl];
		monitor->dref_p0[pl]          = param->dref_p0[pl];
		monitor->dref_p1[pl]          = param->dref_p1[pl];
		monitor->dref_quality[pl]     = OPTIC_QUALITY_CONFIG;
	}

	monitor->ratio_coarse_fine = param->ratio_coarse_fine;
	monitor->powersave         = param->powersave;

	monitor->cid_size_p0       = param->cid_size_p0;
	monitor->cid_size_p1       = param->cid_size_p1;
	monitor->cid_match_all_p0  = param->cid_match_all_p0;
	monitor->cid_match_all_p1  = param->cid_match_all_p1;
	monitor->cid_mask_p0       = param->cid_mask_p0;
	monitor->cid_mask_p1       = param->cid_mask_p1;
	monitor->rogue_interburst = param->rogue_interburst;
	monitor->rogue_intraburst = 0;

	/* ready to read tables & read configs */
	p_ctrl->state.config_read[OPTIC_CONFIGTYPE_MPD] = true;
	optic_state_set ( p_ctrl, OPTIC_STATE_CONFIG );

	return OPTIC_STATUS_OK;
}

/**
   Returns MPD configuration.
*/
enum optic_errorcode mpd_cfg_get ( struct optic_device *p_dev,
				   struct optic_mpd_config *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_monitor *monitor = &(p_ctrl->config.monitor);
	uint8_t gb, pl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_mpd_config) );

	/* monitor */
	for (gb=0; gb<OPTIC_GAINBANK_MAX; gb++) {
		param->tia_gain_selector[gb] = monitor->tia_gain_selector[gb];
		param->cal_current[gb]       = monitor->cal_current[gb];
	}

	for (pl=0; pl<OPTIC_POWERLEVEL_MAX; pl++) {
		param->scalefactor_mod[pl]  = monitor->scalefactor_mod[pl];

		param->dcal_ref_p0[pl]      = monitor->dcal_ref_p0[pl];
		param->dcal_ref_p1[pl]      = monitor->dcal_ref_p1[pl];
		param->dref_p0[pl]          = monitor->dref_p0[pl];
		param->dref_p1[pl]          = monitor->dref_p1[pl];
	}

	param->ratio_coarse_fine = monitor->ratio_coarse_fine;
	param->powersave         = monitor->powersave;

	param->cid_size_p0       = monitor->cid_size_p0;
	param->cid_size_p1       = monitor->cid_size_p1;
	param->cid_match_all_p0  = monitor->cid_match_all_p0;
	param->cid_match_all_p1  = monitor->cid_match_all_p1;
	param->cid_mask_p0       = monitor->cid_mask_p0;
	param->cid_mask_p1       = monitor->cid_mask_p1;
	param->rogue_interburst  = monitor->rogue_interburst;
	param->rogue_intraburst  = monitor->rogue_intraburst;

	return OPTIC_STATUS_OK;
}

/**
   Returns MPD trace register.
*/
enum optic_errorcode mpd_trace_get ( struct optic_device *p_dev,
			             struct optic_mpd_trace *param )

{
	(void) p_dev;

 	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_mpd_trace) );

	return optic_ll_mpd_trace_get ( &(param->correlator_trace_p0),
					&(param->correlator_trace_p1),
					&(param->trace_pattern_p0),
					&(param->trace_pattern_p1) );
}

/* ----------------------------- NON IOCTL ---------------------------------- */

enum optic_errorcode optic_mpd_init ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret;
	struct optic_config_monitor *p_mon = &(p_ctrl->config.monitor);

	optic_mpd_biasmod_max_set ( &(p_mon->bias_max),
				    &(p_mon->mod_max) );
	/* check invalid parameter */
	if ((p_mon->oc_ibias_thr == 0) || (p_mon->oc_imod_thr == 0) ||
	    (p_mon->oc_ibias_thr > p_mon->bias_max) ||
	    (p_mon->oc_imod_thr > p_mon->mod_max)) {
		return OPTIC_STATUS_INVAL_OCTHR;
	}

	ret = optic_ll_mpd_init (p_mon, p_ctrl->config.bosa.loop_mode);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_mpd_saturation_set ( p_ctrl,
					 p_ctrl->config.range.ibias_max,
					 p_ctrl->config.range.imod_max );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

/**
	Calibrate DAC level.

	\param type - level type for which DAC calibration should be performed
   		      can be offset DAC, p0 dac, p1 DAC -
   		      each in coarse or fine mood
	\param level - level to calibrate (all other offset values and the
   		       corresponding partner level (coarse-fine) have to be
   		       initialized before!

   	- read comparator
   	- correct by stepwidth (dependent of comperator result increase or
   				decrease by stepwith (initial=10))
	- doublecheck saturation (range check level)
	- write corrected level
	- if correction direction toggled, divide stepwith by 2
	- if stepwith = 1 (no further decreasing!), add level values of next 10
	  correction direction toggle points
	- repeat loop until 10 level values at correction direction
	  toggle points (stepwidth = 1) are added
	- calibrated level is level sum / 10

	\return
	- OPTIC_STATUS_OK - MPD offsets canceled successfully,
	- OPTIC_STATUS_ERR - error
	- OPTIC_STATUS_MPD_SATURATION - level calibration error (saturation)
	- OPTIC_STATUS_MPD_COMPTIMEOUT - level calibration error
                                         (no comperator update)

	\remark loop mode is either OPTIC_LOOPMODE_INTRABURST or
	OPTIC_LOOPMODE_OFFSET_CANCEL
*/
enum optic_errorcode optic_mpd_level_search ( struct optic_control *p_ctrl,
					      const enum optic_search_type type,
					      int16_t *level, int16_t *level_c )
{
/* 1<<MEAN_CNT loops via optic_ll_mpd_level_find !! */
#define MEAN_CNT 0

	enum optic_errorcode ret;
	int32_t gain;
	uint8_t cnt_change = 0;
	bool read_p0 = false;
					/* switch will forced anyway, but start
					   with "no burst" */
	enum optic_loop_mode burstmode = OPTIC_LOOPMODE_INTERBURST;
	enum optic_activation mode;
	uint8_t az_delay[2];
	int16_t level_all=0;
	int16_t loop=16;
	/*int16_t max=-20*256, min=20*256;*/

	if ((level_c == NULL) || (level == NULL))
		return OPTIC_STATUS_ERR;

      /* even without P0_POWER_SAVE_BFD_EN / P1_POWER_SAVE_BFD_EN manipulation
           in powersave mode needed */
	if (p_ctrl->config.monitor.powersave == OPTIC_ENABLE) {
		ret = optic_ll_mpd_powersave_set ( OPTIC_DISABLE );
		if (ret !=  OPTIC_STATUS_OK)
			return ret;
	}

	/* disable rougue ont interrupt */
	if ((p_ctrl->config.monitor.rogue_interburst) ||
	    (p_ctrl->config.monitor.rogue_intraburst))
		optic_ll_mpd_rogue_int_set (0, 0);

	/* store az_delay for P0 and P1 dualloop */
	ret = optic_ll_mpd_az_delay_get (&(az_delay[0]), &(az_delay[1]));
	if (ret != OPTIC_STATUS_OK)
		goto END_MPD_LEVEL_SEARCH;

	ret = optic_ll_bert_analyzer_get ( &mode );
	if (ret != OPTIC_STATUS_OK)
		goto END_MPD_LEVEL_SEARCH;

	if (mode == OPTIC_ENABLE) {
		burstmode = OPTIC_LOOPMODE_INTRABURST;
	}

	optic_ll_mpd_disable_powersave();

	do {
		*level=0;
		switch (burstmode) {
		case OPTIC_LOOPMODE_INTERBURST:
			ret = optic_ll_mpd_loop_set ( &(p_ctrl->config.monitor),
						p_ctrl->calibrate.loopmode,
						OPTIC_LOOPMODE_INTERBURST,
						OPTIC_LOOPMODE_INTERBURST );
			OPTIC_ASSERT_RETURN (ret == OPTIC_STATUS_OK, ret);
			break;
		case OPTIC_LOOPMODE_INTRABURST:
			ret = optic_ll_mpd_loop_set ( &(p_ctrl->config.monitor),
						p_ctrl->calibrate.loopmode,
						OPTIC_LOOPMODE_INTRABURST,
						OPTIC_LOOPMODE_INTRABURST );
			OPTIC_ASSERT_RETURN (ret == OPTIC_STATUS_OK, ret);
			break;
		default:
			OPTIC_DEBUG_WRN(" optic_mpd_level_search(): "
					"invalid burstmode %d", burstmode );
			ret = OPTIC_STATUS_ERR;
			goto END_MPD_LEVEL_SEARCH;
		}

		switch (type) {
		case OPTIC_SEARCH_OFFSET_COARSE:
		case OPTIC_SEARCH_OFFSET_FINE:
			gain = 10;
			read_p0 = true;
			break;
		case OPTIC_SEARCH_P0_COARSE:
		case OPTIC_SEARCH_P0_FINE:
			gain = -10;
			read_p0 = true;
			break;
		case OPTIC_SEARCH_P1_COARSE:
		case OPTIC_SEARCH_P1_FINE:
			gain = 10;
			read_p0 = false;
			break;
		default:
			ret = OPTIC_STATUS_POOR;
			goto END_MPD_LEVEL_SEARCH;
		}

		if ((type != OPTIC_SEARCH_P1_COARSE) &&
		    (type != OPTIC_SEARCH_P1_FINE)) {

			/* IB-CHECK = interburst <- if not in BERT mode */
			if (burstmode == OPTIC_LOOPMODE_INTERBURST)
				gain *= -1;
		}

		/* LOOP (try to improve repeatability) */

		level_all=0;

#if 0
		/* debug output */
		switch (type) {
		case OPTIC_SEARCH_OFFSET_COARSE:
			OPTIC_DEBUG_ERR( "optic_mpd_level_search(): OPTIC_SEARCH_OFFSET_COARSE");
			break;
		case OPTIC_SEARCH_OFFSET_FINE:
			OPTIC_DEBUG_ERR( "optic_mpd_level_search(): OPTIC_SEARCH_OFFSET_FINE");
			break;
		case OPTIC_SEARCH_P0_COARSE:
			OPTIC_DEBUG_ERR( "optic_mpd_level_search(): OPTIC_SEARCH_P0_COARSE");
			break;
		case OPTIC_SEARCH_P0_FINE:
			OPTIC_DEBUG_ERR( "optic_mpd_level_search(): OPTIC_SEARCH_P0_FINE");
			break;
		case OPTIC_SEARCH_P1_COARSE:
			OPTIC_DEBUG_ERR( "optic_mpd_level_search(): OPTIC_SEARCH_P1_COARSE");
			break;
		case OPTIC_SEARCH_P1_FINE:
			OPTIC_DEBUG_ERR( "optic_mpd_level_search(): OPTIC_SEARCH_P1_FINE");
			break;
		default:
			break;
		}
#endif
		loop=(1<<MEAN_CNT);
		while(loop--){
			ret = optic_ll_mpd_level_find ( burstmode, type, read_p0, gain, level, level_c );


			if ( ret == OPTIC_STATUS_MPD_COMPTIMEOUT ) {
				if (cnt_change >= 3) {
					OPTIC_DEBUG_WRN(" optic_mpd_level_search(): "
							"COMPARATOR TIMEOUT "
							" type=%d (~gain~=%d)",
							type, gain);
					ret = OPTIC_STATUS_MPD_COMPTIMEOUT;
					goto END_MPD_LEVEL_SEARCH;
				}

				/* INTERBURST -> INTRABURST */
				if (burstmode == OPTIC_LOOPMODE_INTERBURST) {
					burstmode = OPTIC_LOOPMODE_INTRABURST;
				}
				else /* INTRABURST -> INTERBURST */
					if (burstmode == OPTIC_LOOPMODE_INTRABURST) {
						burstmode = OPTIC_LOOPMODE_INTERBURST;
					} else {
						OPTIC_DEBUG_ERR( "optic_mpd_level_search(): "
								"no INTER/INTRAburst switch possible");
						ret = OPTIC_STATUS_ERR;
						goto END_MPD_LEVEL_SEARCH;
					}
				cnt_change ++;
			} else {
				if (ret != OPTIC_STATUS_OK)
					goto END_MPD_LEVEL_SEARCH;

				level_all += *level;
			}

		}
		*level = level_all/(1<<MEAN_CNT);

	} while (ret == OPTIC_STATUS_MPD_COMPTIMEOUT);


END_MPD_LEVEL_SEARCH:
	/* restore az_delay for P0 and P1 dualloop */
	optic_ll_mpd_az_delay_set (az_delay[0], az_delay[1]);

	if (ret != OPTIC_STATUS_OK)
		return ret;


	if (p_ctrl->config.bosa.loop_mode == OPTIC_BOSA_DUALLOOP ) {
		optic_ll_mpd_loop_set ( &(p_ctrl->config.monitor),
					p_ctrl->calibrate.loopmode,
					OPTIC_LOOPMODE_DUALLOOP,
					OPTIC_LOOPMODE_DUALLOOP );
	} else
	if (p_ctrl->config.bosa.loop_mode == OPTIC_BOSA_COMBILOOP ) {
		optic_ll_mpd_loop_set ( &(p_ctrl->config.monitor),
					p_ctrl->calibrate.loopmode,
					OPTIC_LOOPMODE_INTERBURST,
					OPTIC_LOOPMODE_DUALLOOP );
	}

	if (p_ctrl->config.monitor.powersave == OPTIC_ENABLE) {
		ret = optic_ll_mpd_powersave_set ( OPTIC_ENABLE );
	}

	/* update level */
	ret = optic_ll_mpd_level_set ( type, *level );

	return OPTIC_STATUS_OK;
}

/**
	Perform MPD offset correction.

	Note: All MPD DAC accessing routines have to block access via dac_lock!
	      This is not done in this routine - so all calling routines
	      have to care about!

	- disable HW dual loop, enable interburst check
	for each gain bank (debug level: only once with specific settings):
	- config gain tia, calibration = open, reset p0 p1 levels
	- calibrate dac_offset_tia_coarse (optic_mpd_level_search)
	- store dac_offset_tia_coarse in HW and
	  p_ctrl->calibrate[].dac_offset_tia_c
	- calibrate dac_offset_tia_fine (optic_mpd_level_search)
	- store dac_offset_tia_fine in HW and
	  p_ctrl->calibrate[].dac_offset_tia_f
	- calibrate dac_offset_delta_p1_coarse (optic_mpd_level_search)
	- step back dac_offset_delta_p1_coarse to avoid range overflow for ~fine
	- store dac_offset_delta_p1_coarse in HW and
	  p_ctrl->calibrate[].dac_offset_delta_p1_c
	- calibrate dac_offset_delta_p1_fine (optic_mpd_level_search)
	- store dac_offset_delta_p1_coarse in p_ctrl->calibrate[].dac_offset_delta_p1_f

	\return
	- OPTIC_STATUS_OK - MPD offsets canceled successfully,
	- OPTIC_STATUS_ERR - error
	- OPTIC_STATUS_MPD_SATURATION - level calibration error (saturation)
	- OPTIC_STATUS_MPD_COMPTIMEOUT - level calibration error
                                         (no comperator update)

	\remark	This function may only called in bosa mode
*/
enum optic_errorcode optic_mpd_offset_cancel ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret;
	enum optic_errorcode result;
	enum optic_powerlevel powerlevel = p_ctrl->calibrate.powerlevel;
	enum optic_gainbank gainbank = OPTIC_GAINBANK_PL0;
	int16_t dac_offset_tia_coarse = 0, dac_offset_tia_fine = 0;
	int16_t dac_offset_delta_p1_coarse = 0, dac_offset_delta_p1_fine = 0;
	int16_t dac_c[OPTIC_DAC_MAX], dac_f[OPTIC_DAC_MAX];
	uint8_t d;
	int16_t dac_offset_delta_p1_c = 0, dac_offset_delta_p1_f = 0;
	int32_t found_codeword, offset_codeword;


#if (OPTIC_DEBUG_PRINTOUT_MPD_OFFSET == ACTIVE)
	OPTIC_DEBUG_WRN("INFO: Offset cancellation started");
#endif

	if (IFXOS_MutexGet (&p_ctrl->access.dac_lock) != IFX_SUCCESS)
		return OPTIC_STATUS_ERR;

	/* store old DAC settings */
	for (d = OPTIC_DAC_P0_LEVEL; d < OPTIC_DAC_MAX; d++) {
		ret = optic_ll_mpd_dac_get (d, &(dac_c[d]), &(dac_f[d]));
		if (ret != OPTIC_STATUS_OK)
			goto END_MPD_OFFSET_CANCEL;
	}

	do {
		ret = optic_mpd_gainctrl_set ( p_ctrl, gainbank,
					       OPTIC_CAL_OPEN );
		if (ret != OPTIC_STATUS_OK)
			break;
		/* fine & coarse level reset */
		dac_offset_tia_coarse = 0;
		dac_offset_tia_fine = 0;
		dac_offset_delta_p1_coarse = 0;
		dac_offset_delta_p1_fine = 0;

		ret = optic_ll_mpd_dac_set ( OPTIC_DAC_TIA_OFFSET, 0, 0 );
		if (ret != OPTIC_STATUS_OK)
			break;

		ret = optic_ll_mpd_dac_set ( OPTIC_DAC_P0_LEVEL, 0, 0 );
		if (ret != OPTIC_STATUS_OK)
			break;

		ret = optic_ll_mpd_dac_set ( OPTIC_DAC_P1_LEVEL, 0, 0 );
		if (ret != OPTIC_STATUS_OK)
			break;

		/* calibrate TIA offset DAC (coarse) -> dac_offset_tia_coarse */
		/* calibrate TIA offset DAC (fine) -> dac_offset_tia_fine     */
		ret = optic_mpd_dac_level_search ( p_ctrl, true,
		                                   OPTIC_SEARCH_OFFSET_COARSE,
		                                   OPTIC_SEARCH_OFFSET_FINE,
		                                   &dac_offset_tia_coarse,
						   &dac_offset_tia_fine );

		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_ll_mpd_dac_cal(#%d: %d, %d)= %d",
					gainbank,
					OPTIC_SEARCH_OFFSET_COARSE,
					OPTIC_SEARCH_OFFSET_FINE,
					ret);
			break;
		}

		/* store TIA offset DAC (coarse, fine) */
		if (p_ctrl->config.debug_mode == true) {
			p_ctrl->calibrate.dbg_dac_offset_tia_c =
							dac_offset_tia_coarse;
			p_ctrl->calibrate.dbg_dac_offset_tia_f =
							dac_offset_tia_fine;
		} else {
			p_ctrl->calibrate.dac_offset_tia_c[gainbank] =
							dac_offset_tia_coarse;
			p_ctrl->calibrate.dac_offset_tia_f[gainbank] =
							dac_offset_tia_fine;
		}
#if (OPTIC_MPD_P1_DELTA_OFFSET == ACTIVE)
		/* calibr. p1 levl DAC (coarse) -> dac_offset_delta_p1_coarse */
		/* calibr. p1 levl DAC (fine) -> dac_offset_delta_p1_fine     */
		/* NOTE: offset calibration is done without P1 delta offset substraction! */
		ret = optic_mpd_dac_level_search ( p_ctrl, true,
		                                   OPTIC_SEARCH_P1_COARSE,
						   OPTIC_SEARCH_P1_FINE,
						   &dac_offset_delta_p1_coarse,
						   &dac_offset_delta_p1_fine );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_mpd_dac_level_search(#%d: %d,%d)= %d",
					gainbank,
					OPTIC_SEARCH_P1_COARSE,
					OPTIC_SEARCH_P1_FINE,
					ret);
			break;
		}
		/* DO THIS HERE IN fineDAC UNITS (c*20+f) to avoid negative signs!! */
		/* update old P1 dac value */
		/* get old offset correction */
		if (p_ctrl->config.debug_mode == true) {
			dac_offset_delta_p1_c = p_ctrl->calibrate.dbg_dac_offset_delta_p1_c;
			dac_offset_delta_p1_f = p_ctrl->calibrate.dbg_dac_offset_delta_p1_f;
		} else {
			dac_offset_delta_p1_c = p_ctrl->calibrate.dac_offset_delta_p1_c[gainbank];
			dac_offset_delta_p1_f = p_ctrl->calibrate.dac_offset_delta_p1_f[gainbank];
		}
		/* store p1 level DAC as p1 offset delta (coarse) */
		if (p_ctrl->config.debug_mode == true) {
			p_ctrl->calibrate.dbg_dac_offset_delta_p1_c =
						dac_offset_delta_p1_coarse;
			p_ctrl->calibrate.dbg_dac_offset_delta_p1_f =
						dac_offset_delta_p1_fine;
		} else {
			p_ctrl->calibrate.dac_offset_delta_p1_c[gainbank] =
						dac_offset_delta_p1_coarse;
			p_ctrl->calibrate.dac_offset_delta_p1_f[gainbank] =
						dac_offset_delta_p1_fine;
		}
		/* add the old offset codeword */
		offset_codeword = dac_offset_delta_p1_c * p_ctrl->calibrate.ratio_p1;
		offset_codeword += (dac_offset_delta_p1_f << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO);
		found_codeword = dac_c[OPTIC_DAC_P1_LEVEL] * p_ctrl->calibrate.ratio_p1;
		found_codeword += dac_f[OPTIC_DAC_P1_LEVEL] << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO;
		found_codeword += offset_codeword;
		/* subtract the new offset codeword */
		offset_codeword = dac_offset_delta_p1_coarse * p_ctrl->calibrate.ratio_p1;
		offset_codeword += (dac_offset_delta_p1_fine << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO);
		found_codeword -= offset_codeword;
		/* recalculate coarse and fine dac */
		dac_c[OPTIC_DAC_P1_LEVEL] = (int16_t) ((found_codeword) / p_ctrl->calibrate.ratio_p1);
		dac_f[OPTIC_DAC_P1_LEVEL] = (int16_t) (((found_codeword) - (dac_c[OPTIC_DAC_P1_LEVEL] * p_ctrl->calibrate.ratio_p1))
				      >> OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO);

#else
		ret = OPTIC_STATUS_OK;
		dac_offset_delta_p1_coarse = 0;
		dac_offset_delta_p1_fine = 0;
		/* store p1 level DAC as p1 offset delta (coarse) */
		if (p_ctrl->config.debug_mode == true) {
			p_ctrl->calibrate.dbg_dac_offset_delta_p1_c = 0;
			p_ctrl->calibrate.dbg_dac_offset_delta_p1_f = 0;
		} else {
			p_ctrl->calibrate.dac_offset_delta_p1_c[gainbank] = 0;
			p_ctrl->calibrate.dac_offset_delta_p1_f[gainbank] = 0;
		}
		/* recalculate coarse and fine dac */
		dac_c[OPTIC_DAC_P1_LEVEL] = 0;
		dac_f[OPTIC_DAC_P1_LEVEL] = 0;
#endif

		gainbank ++;
	} while ((p_ctrl->config.debug_mode == false) &&
	         (gainbank < OPTIC_GAINBANK_MAX));

END_MPD_OFFSET_CANCEL:
	/* save overall status for function return */
	result = ret;
	/* reset gain ctrl */
	optic_powerlevel2gainbank ( powerlevel, &gainbank );
	optic_mpd_gainctrl_set ( p_ctrl, gainbank, OPTIC_CAL_OFF );

	/* reset TIA offset levels (calibrated by offset cancellation) */
	optic_mpd_tia_offset_set ( p_ctrl, gainbank );

	/* recover DAC settings P0, P1 */
	for (d = OPTIC_DAC_P0_LEVEL; d <= OPTIC_DAC_P1_LEVEL; d++ ) {
		ret = optic_ll_mpd_dac_set ( d, dac_c[d], dac_f[d] );
		if (ret != OPTIC_STATUS_OK)
			return ret;
	}

	IFXOS_MutexRelease(&p_ctrl->access.dac_lock);

	/* return overall status */
	if (result == OPTIC_STATUS_OK)
		return ret;

	return result;
}

/**
	measure gain coarse/fine ratio for each power level

	Note: All MPD DAC accessing routines have to block access via dac_lock!

   	- offset cancellation (optic_ll_mpd_offset_cancel)
	for gain bank, defined by config file: OPTIC_GAINBANK_GLOBAL
	- config gain tia, calibration (.monitor.tia, .cal), reset p0 p1 levels
	- init TIA offset levels (calibrated by offset cancellation)
	- calibrate dac_gain_p0_coarse (optic_mpd_level_search)
	- step back dac_gain_p0_coarse to avoid range overflow for ~fine
	- calibrate dac_gain_p0_fine_1 (optic_mpd_level_search)
	- check, which factor fits for n of dac_gain_p0_fine_n
	- step back dac_gain_p0_coarse by n,
	  estimate rough dac_gain_p0_fine_n roughly
	- calibrate dac_gain_p0_fine_n (optic_mpd_level_search)
	- calculate ratio_p0 = (dac_gain_p0_fine_n - dac_gain_p0_fine_1) / n
	- calibrate dac_gain_p1_coarse (optic_mpd_level_search)
	- step back dac_gain_p1_coarse to avoid range overflow for ~fine
	- calibrate dac_gain_p1_fine_1 (optic_mpd_level_search)
	- check, which factor fits for n of dac_gain_p1_fine_n
	- step back dac_gain_p1_coarse by n,
	  estimate rough dac_gain_p1_fine_n roughly
	- calibrate dac_gain_p1_fine_n (optic_mpd_level_search)
	- calculate ratio_p1 = (dac_gain_p1_fine_n - dac_gain_p1_fine_1) / n

	\return
	- OPTIC_STATUS_OK - MPD offsets canceled successfully,
	- OPTIC_STATUS_ERR - error
	- OPTIC_STATUS_MPD_SATURATION - level calibration error (saturation)
	- OPTIC_STATUS_MPD_COMPTIMEOUT - level calibration error
                                         (no comperator update)
*/
enum optic_errorcode optic_mpd_ratio_measure ( struct optic_control *p_ctrl )
{
/* used average n=(1<<RATIO_MEAN_CNT) for c/f ratio */
#define RATIO_MEAN_CNT 4

	enum optic_errorcode ret;
	uint8_t d;
	int16_t dac_c[OPTIC_DAC_MAX], dac_f[OPTIC_DAC_MAX];
	enum optic_powerlevel powerlevel = p_ctrl->calibrate.powerlevel;
	enum optic_gainbank gainbank_active;
	int16_t dac_gain_coarse, dac_gain_fine_1, dac_gain_fine_n;
	uint8_t type_c[2] = {OPTIC_SEARCH_P0_COARSE, OPTIC_SEARCH_P1_COARSE};
	uint8_t type_f[2] = {OPTIC_SEARCH_P0_FINE, OPTIC_SEARCH_P1_FINE};
	uint8_t p;
	int16_t n,i,n_up;
	uint32_t z;
	uint32_t z_all;

	if (p_ctrl->config.mode == OPTIC_OMU) {
		OPTIC_DEBUG_ERR("Coarse/Fine Ratio Calculation not usable"
				" in OMU mode (MPD inactive)");
		return OPTIC_STATUS_ERR;
	}

	if (IFXOS_MutexGet(&p_ctrl->access.dac_lock) != IFX_SUCCESS)
		return OPTIC_STATUS_ERR;


	/* store old DAC settings */
	for (d=OPTIC_DAC_TIA_OFFSET; d<OPTIC_DAC_MAX; d++) {
		ret = optic_ll_mpd_dac_get ( d, &(dac_c[d]), &(dac_f[d]) );
		if (ret != OPTIC_STATUS_OK)
			goto END_MPD_RATIO_MEASURE;
	}

       	/* configure gain & calibration +
	   init TIA offset levels (calibrated by offset cancellation) */
	ret = optic_mpd_gainctrl_set ( p_ctrl, OPTIC_GAINBANK_GLOBAL,
					     OPTIC_CAL_CONFIG );
	if (ret != OPTIC_STATUS_OK)
		goto END_MPD_RATIO_MEASURE;
	ret = optic_mpd_tia_offset_set ( p_ctrl, OPTIC_GAINBANK_GLOBAL );
	if (ret != OPTIC_STATUS_OK)
		goto END_MPD_RATIO_MEASURE;

	for (p=0; p<2; p++) {
		z_all=0;
		for (i=0; i<(1<<RATIO_MEAN_CNT); i++) {

			/* calibrate level DAC (coarse) -> dac_gain_coarse */
			/*
			dac_gain_coarse = 0;
			dac_gain_fine_1 = 0;
			*/
			/* in case of P1: subtract P1 delta offset */
			/* NOTE: c/f ratio is done without P1 delta offset subtraction! */
			ret = optic_mpd_dac_level_search ( p_ctrl, true,
							   type_c[p],
							   type_f[p],
							   &dac_gain_coarse,
							   &dac_gain_fine_1 );

			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR("optic_ll_mpd_dac_cal(%d, %d) = %d",
						type_c[p], type_f[p], ret);
				goto END_MPD_RATIO_MEASURE;
			}

			/*
			 OPTIC_DEBUG_ERR("1.) optic_ll_ratio_measure: dac_gain_coarse=%d dac_gain_fine_1=%d",dac_gain_coarse,dac_gain_fine_1);
			*/
			n_up = dac_gain_coarse;
			dac_gain_coarse = n_up-8;
			if (dac_gain_coarse < 0)
				dac_gain_coarse=0;

			/* store level DAC (coarse) */
			ret = optic_ll_mpd_level_set ( type_c[p],
							dac_gain_coarse );
			if (ret != OPTIC_STATUS_OK)
				goto END_MPD_RATIO_MEASURE;
			/*
			OPTIC_DEBUG_ERR("2.) optic_ll_ratio_measure: dac_gain_coarse=%d dac_gain_fine_1=%d",dac_gain_coarse,dac_gain_fine_1);
			*/
			ret = optic_mpd_level_search ( p_ctrl,
							type_f[p],
							&dac_gain_fine_n,
							&dac_gain_coarse);
			if (ret != OPTIC_STATUS_OK)
				goto END_MPD_RATIO_MEASURE;
			/*
			OPTIC_DEBUG_ERR("3.) optic_ll_ratio_measure: dac_gain_coarse=%d dac_gain_fine_n=%d",dac_gain_coarse,dac_gain_fine_n);
			*/
			n = n_up-dac_gain_coarse;
			z = abs (dac_gain_fine_n - dac_gain_fine_1);
			z = (z << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO) /
					abs(n);
			/*
			OPTIC_DEBUG_ERR("4.) optic_ll_ratio_measure: n=%d z=%d",n,z);
			*/
			z_all += z;
		}
		z = z_all>>RATIO_MEAN_CNT;
		if (p==0)
			p_ctrl->calibrate.ratio_p0 = (uint16_t) z;
		else
			p_ctrl->calibrate.ratio_p1 = (uint16_t) z;
	}

	END_MPD_RATIO_MEASURE:
	/* reset gain ctrl */
	optic_powerlevel2gainbank ( powerlevel, &gainbank_active );
	optic_mpd_gainctrl_set ( p_ctrl, gainbank_active, OPTIC_CAL_OFF );

	/* reset TIA offset levels (calibrated by offset cancellation) */
	optic_mpd_tia_offset_set ( p_ctrl, gainbank_active );

	/* recover DAC settings P0, P1 */
	for (d = OPTIC_DAC_P0_LEVEL; d <= OPTIC_DAC_P1_LEVEL; d++ ) {
		ret = optic_ll_mpd_dac_set ( d, dac_c[d], dac_f[d] );
		if (ret != OPTIC_STATUS_OK)
			return ret;
	}


	IFXOS_MutexRelease(&p_ctrl->access.dac_lock);

	return ret;
}

/**
	Calibrate the MPD.

	Note: All MPD DAC accessing routines have to block access via dac_lock!

	- coarse / fine DAC offset cancellation for TIA and P1
	- configure gain, iref dependent of power level
	- measure DAC coarse/fine for P0, P1
	- calculate gain_correction = (coarse * ratio + fine) / Dcalref
	  for P0, P1
	- calculate D (digital codeword) for P0, P1
	  D = MPD_resp_corr[Tbosa] * gain_correct * Dref
	- calculate coarse/fine level DAC setting and reconfigure:
	  optic_ll_mpd_codeword_set()
	- NOTE: DUAL LOOP hast to been restarted afterwards

	\return
	- OPTIC_STATUS_OK - MPD successfully calibrated,
	- OPTIC_STATUS_ERR - MPD not calibrated
*/
enum optic_errorcode optic_mpd_calibrate_level ( struct optic_control *p_ctrl,
					         const bool offset_cancel,
					         const bool calibrate[2],
					         int16_t dac_coarse[2],
					         int16_t dac_fine[2] )
{
	enum optic_errorcode ret;
	enum optic_powerlevel powerlevel = p_ctrl->calibrate.powerlevel;
	enum optic_gainbank gainbank_active;

	if (p_ctrl->config.mode == OPTIC_OMU) {
		OPTIC_DEBUG_ERR("MPD Calibration not usable in OMU mode"
				" (MPD inactive)");
		return OPTIC_STATUS_ERR;
	}

	ret = optic_powerlevel2gainbank ( powerlevel, &gainbank_active );
	if (ret != OPTIC_STATUS_OK)
		goto END_MPD_CALIBRATE_LEVEL;

	if (offset_cancel == true) {
		ret = optic_mpd_offset_cancel ( p_ctrl );
		if (ret != OPTIC_STATUS_OK)
			goto END_MPD_CALIBRATE_LEVEL;
	}

	if (IFXOS_MutexGet (&p_ctrl->access.dac_lock) != IFX_SUCCESS)
		return OPTIC_STATUS_ERR;


	/* set gain ctrl */
	ret = optic_mpd_gainctrl_set ( p_ctrl, gainbank_active,
				       OPTIC_CAL_CONFIG );
	if (ret != OPTIC_STATUS_OK)
		goto END_MPD_CALIBRATE_LEVEL;

	if (calibrate[0] == true) {
		/* fine & coarse level reset */
		/*
		ret = optic_ll_mpd_dac_set ( OPTIC_DAC_P0_LEVEL, 0, 0 );
		if (ret != OPTIC_STATUS_OK)
			goto END_MPD_CALIBRATE_LEVEL;
		*/
		/* calibrate p0 DAC */
		ret = optic_mpd_dac_level_search ( p_ctrl, false,
		                                   OPTIC_SEARCH_P0_COARSE,
		                                   OPTIC_SEARCH_P0_FINE,
		                                   &(dac_coarse[0]),
		                                   &(dac_fine[0]) );
		if (ret != OPTIC_STATUS_OK)
			goto END_MPD_CALIBRATE_LEVEL;
	} else {
		dac_coarse[0] = 0;
		dac_fine[0] = 0;
	}

	if (calibrate[1] == true) {
		/*
		ret = optic_ll_mpd_dac_set ( OPTIC_DAC_P1_LEVEL, 0, 0 );
		if (ret != OPTIC_STATUS_OK)
			goto END_MPD_CALIBRATE_LEVEL;
		*/
		/* calibrate p1 DAC (subtract P1 delta offset) */
		ret = optic_mpd_dac_level_search ( p_ctrl, false,
		                                   OPTIC_SEARCH_P1_COARSE,
		                                   OPTIC_SEARCH_P1_FINE,
		                                   &(dac_coarse[1]),
		                                   &(dac_fine[1]) );
		if (ret != OPTIC_STATUS_OK)
			goto END_MPD_CALIBRATE_LEVEL;
	} else {
		dac_coarse[1] = 0;
		dac_fine[1] = 0;
	}

	/* restart dual loop */
END_MPD_CALIBRATE_LEVEL:

	/* reset gain ctrl */
	optic_mpd_gainctrl_set ( p_ctrl, gainbank_active, OPTIC_CAL_OFF );

	/* enable rougue ont interrupt */
	if ((p_ctrl->state.current_state == OPTIC_STATE_RUN) &&
	    ((p_ctrl->config.monitor.rogue_interburst ||
	     (p_ctrl->config.monitor.rogue_intraburst))))
		optic_ll_mpd_rogue_int_set ( p_ctrl->config.monitor.
							rogue_interburst,
					     p_ctrl->config.monitor.
							rogue_intraburst);

	IFXOS_MutexRelease (&p_ctrl->access.dac_lock);

	return ret;
}

/**
	Calibrates a DAC (coarse/fine)

	\remark callers to this function must set the loop mode to non
	dual loop
*/
enum optic_errorcode optic_mpd_dac_level_search (struct optic_control *p_ctrl,
	const bool offset_calibration, const uint8_t type_coarse,
	const uint8_t type_fine,  int16_t *dac_coarse, int16_t *dac_fine)
{
	enum optic_errorcode ret;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	enum optic_gainbank gb;
	uint8_t cnt = 10;
	int16_t dac_offset_delta_p1_c = 0, dac_offset_delta_p1_f = 0;
	int32_t temp;
	int16_t dummy;
	int32_t found_codeword, offset_codeword, digit_codeword;
	
	dummy=0;
	if ((dac_coarse == NULL) || (dac_fine == NULL))
		return OPTIC_STATUS_ERR;

	/* check both level search types */
	if ((type_coarse+1) != type_fine)
		return OPTIC_STATUS_LEVELSEARCH_TYPE_CONFLICT;

	/* calibrate level DAC (coarse) -> dac_gain_coarse */
	*dac_coarse = 0;
	*dac_fine = 0;

	/* fine & coarse level reset, so that search starts with defined levels */
	ret = optic_ll_mpd_level_set ( type_coarse, *dac_coarse );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_mpd_level_set ( type_fine, *dac_fine );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_mpd_level_search ( p_ctrl, type_coarse, dac_coarse, &dummy);
	/*
	OPTIC_DEBUG_ERR("optic_mpd_dac_level_search() ret=%d : dac_coarse= %d",ret,*dac_coarse);
	*/
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/* fine dac calibration (+ saturation check -> coarse dac adaptation) */
	do {
		/* store level DAC (coarse) */
		ret = optic_ll_mpd_level_set ( type_coarse, *dac_coarse );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		/* calibrate level DAC (fine) -> dac_gain_fine */
		ret = optic_mpd_level_search ( p_ctrl, type_fine, dac_fine, dac_coarse );

		if (((type_coarse == OPTIC_SEARCH_P0_COARSE) &&
		     (type_fine == OPTIC_SEARCH_P0_FINE)) ||
		    ((type_coarse == OPTIC_SEARCH_P1_COARSE) &&
		     (type_fine == OPTIC_SEARCH_P1_FINE))) {
			temp = (*dac_coarse);
			temp *= (*dac_fine);
		     	if (temp < 0)
		     		ret = OPTIC_STATUS_MPD_SATURATION;
		}

		if (ret == OPTIC_STATUS_MPD_SATURATION) {
			cnt--;
			if (*dac_fine > 0)
				(*dac_coarse) ++;
			else if (*dac_fine < 0)
				(*dac_coarse) --;

			OPTIC_DEBUG_MSG("optic_mpd_dac_level_search() "
					"coarse level adaptation: %d",
					*dac_coarse);
		}

	} while ((cnt > 0 ) && (ret == OPTIC_STATUS_MPD_SATURATION));

	if (ret != OPTIC_STATUS_OK)
		return ret;

	/* P1 delta offset subtraction
	   there is one special case: calculation of P1 offset - here (old)
	   P1 offset should not subtracted! */
	if ((offset_calibration == false) &&
	    (type_coarse == OPTIC_SEARCH_P1_COARSE) &&
	    (type_fine == OPTIC_SEARCH_P1_FINE)) {

		if (p_ctrl->config.debug_mode == true) {
			dac_offset_delta_p1_c = cal->dbg_dac_offset_delta_p1_c;
			dac_offset_delta_p1_f = cal->dbg_dac_offset_delta_p1_f;
		} else {
			ret = optic_powerlevel2gainbank ( cal->powerlevel,&gb );
			if (ret != OPTIC_STATUS_OK)
				return ret;

			dac_offset_delta_p1_c = cal->dac_offset_delta_p1_c[gb];
			dac_offset_delta_p1_f = cal->dac_offset_delta_p1_f[gb];
		}

		offset_codeword = dac_offset_delta_p1_c *
						p_ctrl->calibrate.ratio_p1;

		offset_codeword += (dac_offset_delta_p1_f <<
					OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO);

		found_codeword = (*dac_coarse) * p_ctrl->calibrate.ratio_p1;

		found_codeword += (*dac_fine) <<
					OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO;

		digit_codeword = found_codeword - offset_codeword;

		*dac_coarse = (int16_t) ((digit_codeword) /
						p_ctrl->calibrate.ratio_p1);

		*dac_fine = (int16_t) (
			((digit_codeword) -
				((*dac_coarse) * p_ctrl->calibrate.ratio_p1))
				      >> OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO);

	}

	/* store level DAC (fine & coarse)
	 * makes only sense for TIA OFFSET ?*/
	/*
	ret = optic_ll_mpd_level_set ( type_coarse, *dac_coarse );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_mpd_level_set ( type_fine, *dac_fine );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	*/
	return ret;
}

/**
	Calibrate the MPD.

	Note: All MPD DAC accessing routines have to block access via dac_lock!

	- coarse / fine DAC offset cancellation for TIA and P1
	- configure gain, iref dependent of power level
	- measure DAC coarse/fine for P0, P1
	- calculate gain_correction = (coarse * ratio + fine) / Dcalref
	  for P0, P1
	- calculate D (digital codeword) for P0, P1
	  D = MPD_resp_corr[Tbosa] * gain_correct * Dref
	- calculate coarse/fine level DAC setting and reconfigure:
	  optic_ll_mpd_codeword_set()
	- NOTE: DUAL LOOP hast to been restarted afterwards

	\return
	- OPTIC_STATUS_OK - MPD successfully calibrated,
	- OPTIC_STATUS_ERR - MPD not calibrated
*/
enum optic_errorcode optic_mpd_codeword_calc ( struct optic_control *p_ctrl,
					       const bool calibrate[2],
					       const bool offset_cancellation,
					       const int16_t dac_coarse[2],
					       const int16_t dac_fine[2] )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_calibrate *cal= &(p_ctrl->calibrate);
	uint16_t temp_ext_corr;

        temp_ext_corr = optic_shift_temp_back ( p_ctrl->calibrate.
        				        temperature_ext );
        /* do only gain calibration if also offset calibration is scheduled - 
         * then the MPD input must be switched to the calibration current
         */
	/***********************************************************
	 * 	P0  Level
	 * ********************************************************/
	if (calibrate[0] == true) {
		/* calculate gain correction */
		if (offset_cancellation == true) {
			ret = optic_calc_gain_correct (p_ctrl, true,
					dac_coarse[0],	dac_fine[0],
					&(cal->gain_correct_p0));
			if (ret != OPTIC_STATUS_OK)
				return ret;
		}
	}

	/* Codeword set moved here: we do it in any case.
	 * Either we use the most actual values from the offset and gain
	 * calibrations or we re-use the old ones (MPD_TIMEOUT)
	 */
	ret = optic_calc_codeword ( p_ctrl, true, temp_ext_corr,
	                            cal->gain_correct_p0,
				    &(cal->digit_codeword_p0) );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_mpd_codeword_set ( p_ctrl, true );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/***********************************************************
	 * 	P1  Level
	 * ********************************************************/

        /* do only gain calibration if also offset calibration is scheduled - 
         * then the MPD input must be switched to the calibration current
         */
	if (calibrate[1] == true) {
		/* calculate gain correction */
		if (offset_cancellation == true) {
			ret = optic_calc_gain_correct ( p_ctrl, true,
					dac_coarse[1], dac_fine[1],
					&(cal->gain_correct_p1));
			if (ret != OPTIC_STATUS_OK)
				return ret;
			/* Work around for "believed" wrong P1 gain control
			 * REMOVE THIS IF REASON FOR WRONG P1 OFFSET IS KNOWN
			 * This has to do with correct PLL start
			 * -> sometimes P1 offset
			 * is correct after start (and stays correct)
			 * -> sometimes the P1 offset is wrong and this
			 * leads to incorrect gain
			 * correction settings for P1*/
			cal->gain_correct_p1 =
					p_ctrl->calibrate.gain_correct_p0;
			/* END Work Around */
		}
	}
	ret = optic_calc_codeword ( p_ctrl, false, temp_ext_corr,
					cal->gain_correct_p1,
					&(cal->digit_codeword_p1) );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_mpd_codeword_set ( p_ctrl, false );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return OPTIC_STATUS_OK;
}

/**
	calculate from digital codeword D0 / D1 coarse/fine DAC level
	and set corresponding register

	Note: All MPD DAC accessing routines have to block access via dac_lock!
	      This is not done in this routine - so all calling routines
	      have to care about!

	- calculate coarse/fine level DAC setting and reconfigure

	\return
	- OPTIC_STATUS_OK - MPD successfully calibrated,
	- OPTIC_STATUS_ERR - MPD not calibrated
*/

enum optic_errorcode optic_mpd_codeword_set ( struct optic_control *p_ctrl,
                                              bool p0 )
{
	enum optic_errorcode ret;
	int16_t dac_coarse, dac_fine;
	int16_t dac_offset_delta_p1_coarse, dac_offset_delta_p1_fine;
	uint8_t type_c, type_f;
	uint8_t powerlevel = p_ctrl->calibrate.powerlevel;
	int32_t offset_codeword, digit_codeword;
	uint16_t ratio;
	int8_t shift = OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO -
		       OPTIC_FLOAT2INTSHIFT_DREF;

	if (p0 == true) {
		type_c = OPTIC_SEARCH_P0_COARSE;
		type_f = OPTIC_SEARCH_P0_FINE;
		ratio = p_ctrl->calibrate.ratio_p0;
		offset_codeword = 0;
		digit_codeword = p_ctrl->calibrate.digit_codeword_p0;
	} else {
		type_c = OPTIC_SEARCH_P1_COARSE;
		type_f = OPTIC_SEARCH_P1_FINE;
		ratio = p_ctrl->calibrate.ratio_p1;

		/* !! P1 offset !! */
		if (p_ctrl->config.debug_mode == true) {
			dac_offset_delta_p1_coarse = p_ctrl->calibrate.
						dbg_dac_offset_delta_p1_c;
			dac_offset_delta_p1_fine = p_ctrl->calibrate.
						dbg_dac_offset_delta_p1_f;
		} else {
			dac_offset_delta_p1_coarse = p_ctrl->calibrate.
					dac_offset_delta_p1_c[powerlevel];
			dac_offset_delta_p1_fine = p_ctrl->calibrate.
					dac_offset_delta_p1_f[powerlevel];
		}

		/**
			offset = coarse * ratio + fine
			offset: << OPTIC_FLOAT2INTSHIFT_DREF
			ratio: << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO
			shift = OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO - OPTIC_FLOAT2INTSHIFT_DREF;

			offset = ((coarse * ratio) + (fine << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO)) >> shift
		*/


		offset_codeword = dac_offset_delta_p1_coarse *
				  p_ctrl->calibrate.ratio_p1;
		offset_codeword += (dac_offset_delta_p1_fine <<
				    OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO);

		digit_codeword = p_ctrl->calibrate.digit_codeword_p1 +
						       (offset_codeword>>shift);

	}

	/* calculate P0/1 coarse / fine */
	/**
	coarse = D / ratio;
	D: << OPTIC_FLOAT2INTSHIFT_DREF
	ratio: << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO

	shift = OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO - OPTIC_FLOAT2INTSHIFT_DREF;
	coarse = (D << shift) / ratio
	fine = ((D << shift) - (coarse * ratio)) >> OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO
	*/

	dac_coarse = (int16_t) ((digit_codeword << shift) / ratio);

	dac_fine = (int16_t) (((digit_codeword << shift) - (dac_coarse * ratio))
			      >> OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO);

	/* set coarse / fine level DAC */

	/* store level DAC (coarse) */
	ret = optic_ll_mpd_level_set ( type_c, dac_coarse );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/* store level DAC (fine) */
	ret = optic_ll_mpd_level_set ( type_f, dac_fine );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

enum optic_errorcode optic_mpd_biasmod_average ( struct optic_control *p_ctrl,
					         const enum optic_current_type
					         type )
{
	enum optic_errorcode ret;
	uint32_t temp;
	uint16_t abias, amod;

	switch (type) {
	case OPTIC_BIAS:
		/* read new amod value */
		ret = optic_mpd_bias_get ( p_ctrl, false, &abias );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		temp = p_ctrl->calibrate.abias_average * 80;
		temp += (abias * 20);

		p_ctrl->calibrate.abias_average =
					optic_uint_div_rounded ( temp, 100 );
		break;
	case OPTIC_MOD:
		/* read new amod value */
		ret = optic_mpd_mod_get ( p_ctrl, false, &amod );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		temp = p_ctrl->calibrate.amod_average * 80;
		temp += (amod * 20);

		p_ctrl->calibrate.amod_average = optic_uint_div_rounded ( temp,
									  100 );
		break;
	default:
		return OPTIC_STATUS_ERR;
	}

	return OPTIC_STATUS_OK;
}



/**
	decide about stable criteria for bias and modulation current
*/
enum optic_errorcode optic_mpd_stable_get ( struct optic_control *p_ctrl,
					    const enum optic_current_type type,
					    const uint16_t average,
					    bool *reset)
{
	enum optic_errorcode ret;
	static uint16_t abias_average_old = 0, amod_average_old = 0;
	uint16_t abias_average_new = 0, amod_average_new = 0;
	uint16_t ibias, imod, temp_index;
	uint32_t temp;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	enum optic_powerlevel pl = p_ctrl->calibrate.powerlevel;
	struct optic_table_temperature_corr *table =
						p_ctrl->table_temperature_corr;

	ret = optic_rangecheck_etemp_corr ( &(p_ctrl->config.range),
					    cal->temperature_ext,
					    &temp_index );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (reset == NULL)
		return OPTIC_STATUS_ERR;

	*reset = false;

	switch (type) {
	case OPTIC_BIAS:
		/* get current average value */
		abias_average_new = average;
		ibias = table[temp_index].ibiasimod.ibias[pl];

		/* variation new average <-> init value */
		temp = abs(abias_average_new - ibias);
		temp = optic_uint_div_rounded ( temp * 100, ibias);

		/*   abs(abias - ibias)      Reset threshold
		     ------------------  =   ---------------
		              ibias              100
		*/

		/* variation new average / init value <-> reset threshold */
		if (temp > p_ctrl->config.bosa.resetthreshold[OPTIC_BIAS]) {
			cal->stable[OPTIC_BIAS] = false;
			*reset = true;
			OPTIC_DEBUG_ERR("bias regulated out of range (%d percentage)"
					" -> reset", temp);
		} else {
			/* variation new average <-> old average */
			temp = abs(abias_average_new - abias_average_old);
			temp = optic_uint_div_rounded ( temp * 100,
							abias_average_old);

			/*   abs(abias_new - abias_old)      stable threshold
			     --------------------------  =   ----------------
				      abias_old                    100
			*/

			/* variation new average / old average
			   <-> stable threshold */
			if (temp >
			    p_ctrl->config.bosa.stablethreshold[OPTIC_BIAS]) {
				cal->stable[OPTIC_BIAS] = false;
			} else {
				cal->stable[OPTIC_BIAS] = true;
			}
		}

		abias_average_old = abias_average_new;
		break;
	case OPTIC_MOD:
		/* get current average value */
		amod_average_new = average;
		imod = table[temp_index].ibiasimod.imod[pl];

		/* variation new average <-> init value */
		temp = abs(amod_average_new - imod);
		temp = optic_uint_div_rounded ( temp * 100, imod);

		/*   abs(amod - imod)      Reset threshold
		     ------------------  =   ---------------
		              imod              100
		*/

		/* variation new average / init value <-> reset threshold */
		if (temp > p_ctrl->config.bosa.resetthreshold[OPTIC_MOD]) {
			cal->stable[OPTIC_MOD] = false;
			*reset = true;
			OPTIC_DEBUG_ERR("mod regulated out of range (%d percentage)"
					" -> reset", temp);
		} else {
			/* variation new average <-> old average */
			temp = abs(amod_average_new - amod_average_old);
			temp = optic_uint_div_rounded ( temp * 100,
							amod_average_old);

			/*   abs(amod_new - amod_old)        stable threshold
			     --------------------------  =   ----------------
				      amod_old                    100
			*/

			/* variation new average / old average
			   <-> stable threshold */
			if (temp >
			    p_ctrl->config.bosa.stablethreshold[OPTIC_MOD]) {
				cal->stable[OPTIC_MOD] = false;
			} else {
				cal->stable[OPTIC_MOD] = true;
			}
		}

		amod_average_old = amod_average_new;
		break;
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_mpd_regulation_get ( struct optic_control *p_ctrl,
						const enum optic_current_type
					        type,
						bool *update,
 						uint16_t *average,
 						bool *reset_bias_low)
{
	enum optic_errorcode ret;
	static uint8_t abias_index = 0, amod_index = 0;
	static uint16_t abias_old = 0, amod_old = 0;
	static uint16_t abias_average_old = 0, amod_average_old = 0;
	static uint32_t abias_sum = 0, amod_sum = 0;
	static uint16_t abias_noupdate_cnt = 0, amod_noupdate_cnt = 0;
	uint16_t abias, amod;
	
	/* GPONSW-593 */
	static uint32_t p0_cnt_old = 0;
	uint32_t p0_cnt;	
	static uint32_t ib_check_old = 0;
	uint32_t ib_check_temp;
	uint16_t ibias;
	uint16_t temp_index;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	int32_t temp_low;
	enum optic_powerlevel pl = p_ctrl->calibrate.powerlevel;
	
	struct optic_table_temperature_corr *table =
						p_ctrl->table_temperature_corr;

	ret = optic_rangecheck_etemp_corr ( &(p_ctrl->config.range),
					    cal->temperature_ext,
					    &temp_index );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	/* GPONSW-593 end */

	if (is_falcon_chip_a2x()) {
		/* In A21 a regulation update is determined by
		 * counters, that are incremented in INTRABURST only*/
		ret = optic_ll_mpd_update_get ( type,
					p_ctrl->calibrate.intcoeff[type],
					update );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		if ((*update == false) && (type==OPTIC_BIAS))
			abias_noupdate_cnt++;
		else
			abias_noupdate_cnt=0;

		if (abias_noupdate_cnt >= OPTIC_NOUPDATE_MAX) {
			abias_noupdate_cnt = 0;
			/*just assign value to average before leaving */
				*average = abias_average_old;
			return OPTIC_STATUS_MPD_NOUPDATE_TIMEOUT;
		}
		if ((*update == false) && (type==OPTIC_MOD))
			amod_noupdate_cnt++;
		else
			amod_noupdate_cnt=0;

		if (amod_noupdate_cnt >= OPTIC_NOUPDATE_MAX) {
			amod_noupdate_cnt = 0;
			/*just assign value to average before leaving */
				*average = amod_average_old;
			return OPTIC_STATUS_MPD_NOUPDATE_TIMEOUT;
		}
	}

	switch (type) {
	case OPTIC_BIAS:


		/* read new abias value */
		ret = optic_mpd_bias_get ( p_ctrl, false, &abias );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		abias_sum += abias;
		abias_index ++;

		if (is_falcon_chip_a1x())
			*update = false;

		/** GPONSW-593 (try to bring bias up to nominal level*/
		/* calculate with the actual bias deviation from threshold
		 * (not using average)*/
		ret = optic_mpd_bias_get (p_ctrl, false, &abias);
		if (ret != OPTIC_STATUS_OK)
			return ret;

		ibias = table[temp_index].ibiasimod.ibias[pl];
		temp_low = abias - ibias;
		temp_low = optic_int_div_rounded (temp_low * 100, ibias);


		/* if the actual bias is below threshold, trigger the workaround */
		if (temp_low < 
			    -(p_ctrl->config.bosa.resetthreshold[OPTIC_BIAS])) {
			/* the first time or any other occurrence,
			 * save the old IB bit setting */
			if (*reset_bias_low == false)
				optic_ll_mpd_ib_handle(&ib_check_old, 0);

			/* trigger the reset action for dualloop main function */
			*reset_bias_low = true;
			/* just in case intermediate calibration was ongoing and
			 * IB was changed, force IB to zero again */
			optic_ll_mpd_ib_handle(&ib_check_temp, 0);
		}
		else { /* normal operating mode, no zero bias any more */

			/* transition from true-> false detected */
			if (*reset_bias_low == true) {
				/* restore old IB bit setting */
				optic_ll_mpd_ib_handle(&ib_check_old, 1);
			}
			/* release trigger for dualloop main function */
			*reset_bias_low = false;
		}

		if (*reset_bias_low == true) { /* no INTERBURST check ongoing */
			/* use counter as update criterion */
			optic_ll_mpd_p0cnt_get(&p0_cnt);
			if (p0_cnt != p0_cnt_old)
				*update = true;
			else
				*update = false;

			p0_cnt_old = p0_cnt;
		}
		/* GPONSW-593 end */

		if (abias_index < OPTIC_DUALLOOP_STABLE_DEPTH) {
			*average = abias_average_old;
			return OPTIC_STATUS_MPD_AVERAGE_NOT_COMPLETE;
		}

		*average = (uint16_t) optic_uint_div_rounded ( abias_sum, abias_index );

		abias_average_old = *average;
		abias_index = 0;
		abias_sum = 0;

		/* use IBIAS delta as update criterion only if
		 * reset_bias_low is not active (GPONSW-593) */
		if (*reset_bias_low == false) {
			if ((abias != abias_old)) {
				abias_old = abias;
				abias_noupdate_cnt = 0;

				/* average calculation finished */
				if (is_falcon_chip_a1x())
					*update = true;

			} else {
				if (is_falcon_chip_a1x()) {
					*update = false;

					abias_noupdate_cnt++;
					if (abias_noupdate_cnt >= OPTIC_NOUPDATE_MAX) {
						abias_noupdate_cnt = 0;
						return OPTIC_STATUS_MPD_NOUPDATE_TIMEOUT;
					}
				}
			}
		} /* *reset_bias_low == false */
		break;
	case OPTIC_MOD:
		/* read new amod value */
		ret = optic_mpd_mod_get ( p_ctrl, false, &amod );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		amod_sum += amod;
		amod_index ++;

		if (amod_index < OPTIC_DUALLOOP_STABLE_DEPTH) {
			if (is_falcon_chip_a1x())
				*update = false;
			*average = amod_average_old;
			return OPTIC_STATUS_MPD_AVERAGE_NOT_COMPLETE;
		}

		*average = (uint16_t) optic_uint_div_rounded ( amod_sum,
							       amod_index );

		amod_average_old = *average;
		amod_index = 0;
		amod_sum = 0;

		if (amod != amod_old) {
			amod_noupdate_cnt = 0;
			amod_old = amod;

			/* average calculation finished */
			if (is_falcon_chip_a1x())
				*update = true;
		} else {
			if (is_falcon_chip_a1x()) {
				*update = false;

				amod_noupdate_cnt++;
				if (amod_noupdate_cnt >= OPTIC_NOUPDATE_MAX) {
				    	amod_noupdate_cnt = 0;
					return OPTIC_STATUS_MPD_NOUPDATE_TIMEOUT;
				}
			}
		}
		break;
	default:
		return OPTIC_STATUS_ERR;
	}


	return OPTIC_STATUS_OK;
}


/**
	set Ibias/Imod dependent of difference between actual bias/mod and
	configured Ibias/Imod (for given temperature and power level) -
	according update threshold setting
*/
enum optic_errorcode optic_mpd_biasmod_update ( struct optic_control *p_ctrl,
						const enum optic_current_type
						type )
{
	enum optic_errorcode ret;
	uint16_t temp_index, ibias, imod, abias, amod;
	uint32_t temp, temp_percentage;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	enum optic_powerlevel pl = p_ctrl->calibrate.powerlevel;
	struct optic_config_bosa *bosa = &(p_ctrl->config.bosa);
	struct optic_table_temperature_corr *table =
						p_ctrl->table_temperature_corr;

	ret = optic_rangecheck_etemp_corr ( &(p_ctrl->config.range),
						  cal->temperature_ext,
						  &temp_index );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (pl >= OPTIC_POWERLEVEL_MAX)
		return OPTIC_STATUS_ERR;

	switch (type) {
	case OPTIC_BIAS:
		ibias = table[temp_index].ibiasimod.ibias[pl];
		/* use average bias current */
		abias = p_ctrl->calibrate.abias_average;

		/*
			abs (abias-ibias)      update threshold
			-----------------   =  ----------------
			    ibias                    100
		*/

		temp = abs(abias-ibias) * 100;
		temp_percentage = bosa->updatethreshold[OPTIC_BIAS] * ibias;

		if (temp > temp_percentage) {
			OPTIC_DEBUG_MSG("update ibias settings: ibias=%d.xx",
				ibias >> OPTIC_FLOAT2INTSHIFT_CURRENT );

			if (p_ctrl->config.debug_mode == true)
				return ret;


			ret = optic_mpd_bias_set ( p_ctrl, ibias );
			if (ret != OPTIC_STATUS_OK)
				return ret;
		} else
			return OPTIC_STATUS_MPD_UPDATE_THRES_NOT_REACHED;
		break;
	case OPTIC_MOD:
		imod = table[temp_index].ibiasimod.imod[pl];
		/* use average mod current */
		amod = p_ctrl->calibrate.amod_average;

		/*
			abs (amod-imod)        update trheshold
			-----------------   =  ----------------
			    imod                    100
		*/

		temp = abs(amod-imod) * 100;
		temp_percentage = bosa->updatethreshold[OPTIC_MOD] * imod;

		if (temp > temp_percentage) {
			OPTIC_DEBUG_MSG("update ibias settings: imod=%d.xx",
				imod >> OPTIC_FLOAT2INTSHIFT_CURRENT );

			if (p_ctrl->config.debug_mode == true)
				return ret;

			ret = optic_mpd_mod_set ( p_ctrl, imod );
			if (ret != OPTIC_STATUS_OK)
				return ret;
		} else
			return OPTIC_STATUS_MPD_UPDATE_THRES_NOT_REACHED;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return ret;
}


/**
	GPONSW-593
	This function is a workaround in case BIAS current drops below
	"ResetThreshold_Bias" limit from goi_config
	(add OPTIC_DUALLOOP_ZERO_P0INC fine DAC steps to P0 DAC in monitor path)
*/
enum optic_errorcode optic_mpd_p0_correct ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret;

	if (IFXOS_MutexGet(&p_ctrl->access.dac_lock) != IFX_SUCCESS)
		return OPTIC_STATUS_ERR;

	p_ctrl->calibrate.digit_codeword_p0 +=
			(OPTIC_DUALLOOP_ZERO_P0INC << OPTIC_FLOAT2INTSHIFT_DREF);
	ret = optic_mpd_codeword_set ( p_ctrl, true);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	IFXOS_MutexRelease (&p_ctrl->access.dac_lock);

	return OPTIC_STATUS_OK;
}

/**
	update Ibias/Imod lookup table entry dependent of difference between
	actual bias/mod and configured Ibias/Imod
	(for given temperature and power level) - according learn
	threshold setting
*/
enum optic_errorcode optic_mpd_biasmod_learn ( struct optic_control *p_ctrl,
					       const enum optic_current_type
					       type,
					       bool *learn )
{
	enum optic_errorcode ret;
	uint16_t temp_index, ibias, imod;
	uint32_t temp, temp_percentage;
	struct optic_calibrate *cal = &(p_ctrl->calibrate);
	enum optic_powerlevel pl = p_ctrl->calibrate.powerlevel;
	struct optic_config_bosa *bosa = &(p_ctrl->config.bosa);
	struct optic_table_temperature_corr *table =
						p_ctrl->table_temperature_corr;

	ret = optic_rangecheck_etemp_corr ( &(p_ctrl->config.range),
					    cal->temperature_ext,
					    &temp_index );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (pl >= OPTIC_POWERLEVEL_MAX)
		return OPTIC_STATUS_ERR;

	/* GPONSW-908, disable selflearning */
	if(bosa->learnthreshold[OPTIC_BIAS] > bosa->resetthreshold[OPTIC_BIAS] ||
	   bosa->learnthreshold[OPTIC_MOD] > bosa->resetthreshold[OPTIC_MOD] ) {
		*learn = false;
		return ret;
	}

	switch (type) {
	case OPTIC_BIAS:
		ibias = table[temp_index].ibiasimod.ibias[pl];

		/*
			abs (learn_value-ibias)      learn treshold
			-----------------------   =  ----------------
			        ibias                    100
		*/

		temp = abs(p_ctrl->calibrate.abias_average - ibias) * 100;
		temp_percentage = bosa->learnthreshold[OPTIC_BIAS] * ibias;

		if (learn != NULL)
			*learn = (temp > temp_percentage)? true : false;

		break;
	case OPTIC_MOD:
		imod = table[temp_index].ibiasimod.imod[pl];

		/*
			abs (learn_value - imod)      learn treshold
			-----------------------   =  ----------------
			        imod                      100
		*/

		temp = abs(p_ctrl->calibrate.amod_average - imod) * 100;
		temp_percentage = bosa->learnthreshold[OPTIC_MOD] * imod;

		if (learn != NULL)
			*learn = (temp > temp_percentage)? true : false;

		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return ret;
}

void optic_mpd_biasmod_max_set ( uint8_t *bias_max,
				 uint8_t *mod_max )
{
	switch (chip_version) {
	case 0xA21:
		*bias_max = DEFAULT_A21_BIASMAX;
		*mod_max  = DEFAULT_A21_MODMAX;
		break;

	default:
		*bias_max = DEFAULT_A12_BIASMAX;
		*mod_max  = DEFAULT_A12_MODMAX;
		break;
	}
}

/**
	Calculate Bias (init) current to register value
	and write register.

	\param ibias - write bias current
*/
enum optic_errorcode optic_mpd_saturation_set ( struct optic_control *p_ctrl,
				                const uint16_t bias_sat,
				                const uint16_t mod_sat )
{
	enum optic_errorcode ret;
	enum optic_powerlevel powerlevel = p_ctrl->calibrate.powerlevel;
	struct optic_fuses *fuses = &(p_ctrl->config.fuses);
	struct optic_config_monitor *monitor = &(p_ctrl->config.monitor);
	uint16_t dbias_sat, dmod_sat;

	ret = optic_calc_bias2reg ( fuses->gain_dac_bias,
				    monitor->bias_max,
				    bias_sat, &dbias_sat );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	if (powerlevel >= OPTIC_POWERLEVEL_MAX)
		return OPTIC_STATUS_ERR;

	ret = optic_calc_mod2reg ( fuses->gain_dac_drive,
				   monitor->scalefactor_mod[powerlevel],
				   monitor->mod_max,
				   mod_sat, &dmod_sat );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	ret = optic_ll_mpd_saturation_write ( dbias_sat, dmod_sat );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	return OPTIC_STATUS_OK;
}



/**
	Calculate Bias (init) current to register value
	and write register.

	\param ibias - write bias current
*/
enum optic_errorcode optic_mpd_bias_set ( struct optic_control *p_ctrl,
				          const uint16_t ibias )
{
	enum optic_errorcode ret;
	uint16_t dbias;

	ret = optic_calc_bias2reg ( p_ctrl->config.fuses.gain_dac_bias,
				    p_ctrl->config.monitor.bias_max,
				    ibias, &dbias );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	ret = optic_ll_mpd_bias_write ( dbias );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	p_ctrl->calibrate.dbias = dbias;

	return OPTIC_STATUS_OK;
}
enum optic_errorcode optic_mpd_biaslowsat_set ( struct optic_control *p_ctrl,
				          const uint16_t ibias )
{
	enum optic_errorcode ret;
	uint16_t dbias;

	ret = optic_calc_bias2reg ( p_ctrl->config.fuses.gain_dac_bias,
				    p_ctrl->config.monitor.bias_max,
				    ibias, &dbias );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	ret = optic_ll_mpd_biaslowsat_write ( dbias );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	p_ctrl->calibrate.dbias = dbias;

	return OPTIC_STATUS_OK;
}


/**
	read bias current

	\param init - select reading init or current bias current
	\param mod - read bias current
*/
enum optic_errorcode optic_mpd_bias_get ( struct optic_control *p_ctrl,
					  const bool init,
					  uint16_t *bias )
{
	enum optic_errorcode ret;
	enum optic_activation mode;
	uint16_t dbias;

	if (bias == NULL)
		return OPTIC_STATUS_ERR;

	if (init == true) {
		dbias = p_ctrl->calibrate.dbias;
	} else {
		ret = optic_ll_dcdc_apd_get ( &mode );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		if (mode == OPTIC_ENABLE &&
			p_ctrl->state.interrupts.tx_p0_interburst_alarm == false) {
			ret = optic_ll_mpd_bias_read ( &dbias );
			if (ret != OPTIC_STATUS_OK)
				return ret;
		} else {
			*bias = 0;
			return OPTIC_STATUS_OK;
		}

	}

	ret = optic_calc_reg2bias ( p_ctrl->config.fuses.gain_dac_bias,
				    p_ctrl->config.monitor.bias_max,
				    dbias, bias );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	return OPTIC_STATUS_OK;
}

/**
	Calculate Modulation (init) current to register value
	and write register.

	\param imod - write modulation current
*/
enum optic_errorcode optic_mpd_mod_set ( struct optic_control *p_ctrl,
                                         const uint16_t imod )
{
	enum optic_errorcode ret;
	enum optic_powerlevel powerlevel = p_ctrl->calibrate.powerlevel;
	struct optic_fuses *fuses = &(p_ctrl->config.fuses);
	struct optic_config_monitor *monitor = &(p_ctrl->config.monitor);
	uint16_t dmod;

	if (powerlevel >= OPTIC_POWERLEVEL_MAX)
		return OPTIC_STATUS_ERR;

	ret = optic_calc_mod2reg ( fuses->gain_dac_drive,
				   monitor->scalefactor_mod[powerlevel],
				   monitor->mod_max,
				   imod, &dmod );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	ret = optic_ll_mpd_mod_write ( dmod );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	p_ctrl->calibrate.dmod = dmod;

	return OPTIC_STATUS_OK;
}

/**
	read modulation current

	\param init - select reading init or current modulation current
	\param mod - read modulation current
*/
enum optic_errorcode optic_mpd_mod_get ( struct optic_control *p_ctrl,
					 const bool init,
					 uint16_t *mod )
{
	enum optic_errorcode ret;
	enum optic_powerlevel powerlevel = p_ctrl->calibrate.powerlevel;
	struct optic_fuses *fuses = &(p_ctrl->config.fuses);
	struct optic_config_monitor *monitor = &(p_ctrl->config.monitor);
	enum optic_activation mode;
	uint16_t dmod;

	if (mod == NULL)
		return OPTIC_STATUS_ERR;

	if (init == true) {
		dmod = p_ctrl->calibrate.dmod;
	} else {
		ret = optic_ll_dcdc_apd_get ( &mode );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		if (mode == OPTIC_ENABLE &&
			p_ctrl->state.interrupts.tx_p0_interburst_alarm == false) {
			ret = optic_ll_mpd_mod_read ( &dmod );
			if (ret != OPTIC_STATUS_OK)
				return ret;
		} else {
			*mod = 0;
			return OPTIC_STATUS_OK;
		}
	}

	ret = optic_calc_reg2mod ( fuses->gain_dac_drive,
				   monitor->scalefactor_mod[powerlevel],
				   monitor->mod_max,
				   dmod, mod );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	return OPTIC_STATUS_OK;
}


/**
	Sets the integration coefficient for Bias/Modulation.
*/
enum optic_errorcode optic_mpd_cint_set ( struct optic_control *p_ctrl,
					  const enum optic_current_type type,
                                          const uint8_t intcoeff )
{
	enum optic_errorcode ret;
	uint16_t saturation;

	if (is_falcon_chip_a1x()){
		if (intcoeff > 7)
			return OPTIC_STATUS_POOR;
		saturation = 1 << (7 - intcoeff);
	} else {
		if (intcoeff > 10)
			return OPTIC_STATUS_POOR;
		saturation = 1 << (10 - intcoeff);
	}
	if (saturation > 32)
		saturation = 32;

	ret = optic_ll_mpd_cint_set ( type, intcoeff, saturation );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	p_ctrl->calibrate.intcoeff[type] = intcoeff;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_mpd_loopmode ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	struct optic_config_bosa *bosa = &(p_ctrl->config.bosa);

	switch (bosa->loop_mode) {
	case OPTIC_BOSA_NOLOOP:
	case OPTIC_BOSA_OPENLOOP:
		ret = optic_ll_mpd_loop_set ( &(p_ctrl->config.monitor),
					      p_ctrl->calibrate.loopmode,
					      OPTIC_LOOPMODE_INTERBURST,
					      OPTIC_LOOPMODE_INTERBURST );
		if (ret != OPTIC_STATUS_OK)
			return ret;
		break;
	case OPTIC_BOSA_DUALLOOP:
		ret = optic_ll_mpd_loop_set ( &(p_ctrl->config.monitor),
					      p_ctrl->calibrate.loopmode,
					      OPTIC_LOOPMODE_DUALLOOP,
					      OPTIC_LOOPMODE_DUALLOOP );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		ret = optic_mpd_cint_set ( p_ctrl, OPTIC_BIAS,
					   bosa->intcoeff_init[OPTIC_BIAS] );
		if ( ret != OPTIC_STATUS_OK)
			return ret;

		ret = optic_mpd_cint_set ( p_ctrl, OPTIC_MOD,
					   bosa->intcoeff_init[OPTIC_MOD] );
		if (ret != OPTIC_STATUS_OK)
			return ret;
		break;
	case OPTIC_BOSA_COMBILOOP:
		ret = optic_ll_mpd_loop_set ( &(p_ctrl->config.monitor),
					      p_ctrl->calibrate.loopmode,
					      OPTIC_LOOPMODE_INTERBURST,
					      OPTIC_LOOPMODE_DUALLOOP );
		if ( ret != OPTIC_STATUS_OK)
			return ret;

		ret = optic_mpd_cint_set ( p_ctrl, OPTIC_BIAS,
					   bosa->intcoeff_init[OPTIC_BIAS] );
		if (ret != OPTIC_STATUS_OK)
			return ret;
		break;
	}

	return ret;
}

enum optic_errorcode optic_mpd_gainctrl_set ( struct optic_control *p_ctrl,
                                              const enum optic_gainbank
                                              gainbank,
                                              const enum optic_cal_current
                                              cal_current )
{
	enum optic_errorcode ret;
	struct optic_config_monitor *monitor = &(p_ctrl->config.monitor);
	uint8_t tia_gain_selector, calibration_current = 0;

	if (cal_current != OPTIC_CAL_CONFIG)
		calibration_current = (uint8_t) cal_current;

	if (p_ctrl->config.debug_mode == true) {
		tia_gain_selector = p_ctrl->config.debug.tia_gain_selector;
		if (cal_current == OPTIC_CAL_CONFIG)
			calibration_current = p_ctrl->config.debug.cal_current;
	} else {
		tia_gain_selector = monitor->tia_gain_selector[gainbank];
		if (cal_current == OPTIC_CAL_CONFIG)
			calibration_current = monitor->cal_current[gainbank];
	}

	ret = optic_ll_mpd_gainctrl_set ( tia_gain_selector,
					  calibration_current );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

enum optic_errorcode optic_mpd_tia_offset_set ( struct optic_control *p_ctrl,
						const enum optic_gainbank
						gainbank )
{
	enum optic_errorcode ret;
	struct optic_calibrate *cal= &(p_ctrl->calibrate);
	int16_t dac_offset_tia_coarse, dac_offset_tia_fine;

	if (p_ctrl->config.debug_mode == true) {
		dac_offset_tia_coarse = cal->dbg_dac_offset_tia_c;
		dac_offset_tia_fine = cal->dbg_dac_offset_tia_f;
	} else {
		dac_offset_tia_coarse = cal->dac_offset_tia_c[gainbank];
		dac_offset_tia_fine = cal->dac_offset_tia_f[gainbank];
	}

	ret =  optic_ll_mpd_dac_set ( OPTIC_DAC_TIA_OFFSET,
				      dac_offset_tia_coarse,
				      dac_offset_tia_fine );
	if (ret != OPTIC_STATUS_OK)
		return ret;


	return ret;
}

/* ------------------------------------------------------------------------- */

const struct optic_entry mpd_function_table[OPTIC_MPD_MAX] =
{
/*  0 */  TE1in  (FIO_MPD_CFG_SET,     sizeof(struct optic_mpd_config),         mpd_cfg_set),
/*  1 */  TE1out (FIO_MPD_CFG_GET,     sizeof(struct optic_mpd_config),         mpd_cfg_get),
/*  2 */  TE1out (FIO_MPD_TRACE_GET,   sizeof(struct optic_mpd_trace),          mpd_trace_get),
};

/*! @} */

/*! @} */
