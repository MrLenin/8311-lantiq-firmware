/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, MPD Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_MPD_INTERNAL MPD Interface - Internal
   @{
*/

#include "drv_optic_ll_fcsi.h"
#include "drv_optic_ll_mpd.h"
#include "drv_optic_register.h"
#include "drv_optic_calc.h"
#include "drv_optic_ll_bert.h"
#include "drv_optic_ll_tx.h"
#include "drv_optic_ll_int.h"
#include "drv_optic_reg_pma.h"
#include "drv_optic_reg_pma_inttx.h"

/* dual loop default values */
#define DEFAULT_DUAL_LOOP_ALARM		127
#define DEFAULT_DUAL_LOOP_MIN_AZ	15
#define DEFAULT_DUAL_LOOP_MIN_DET_BITS	1
#define DEFAULT_DUAL_LOOP_CAPTURE_WIDTH 0x7
#define DEFAULT_DUAL_LOOP_CAPTURE_DELAY 0x3
#define DEFAULT_DUAL_LOOP_AZ_DELAY	0x1

#define OPTIC_BFD_DATA_DELAY_DATA_DELAY 0
#define OPTIC_BFD_DATA_DELAY_BURST_CUT_A21 6
#define OPTIC_BFD_DATA_DELAY_BURST_CUT_OFFSET_A21 2

static enum optic_errorcode optic_ll_mpd_path_cfg_set ( const enum optic_p_type
							p_type,
                                                        const bool flip,
						        const bool invert );
static enum optic_errorcode optic_ll_mpd_path_cfg_set ( const enum optic_p_type
							p_type,
                                                        const bool flip,
						        const bool invert )
{
	uint32_t reg;

	switch (p_type) {
	case OPTIC_P0:
		reg = pma_r32 (gpon_bfd_slice_pdi_p0_datapath);

		if (flip == true)
			reg |= PMA_P0_DATAPATH_P0_FLIP;
		else
			reg &= ~PMA_P0_DATAPATH_P0_FLIP;

		if (invert == true)
			reg |= PMA_P0_DATAPATH_P0_INV;
		else
			reg &= ~PMA_P0_DATAPATH_P0_INV;

		pma_w32 ( reg, gpon_bfd_slice_pdi_p0_datapath);
		break;
	case OPTIC_P1:
		reg = pma_r32 (gpon_bfd_slice_pdi_p1_datapath);

		if (flip == true)
			reg |= PMA_P0_DATAPATH_P0_FLIP;
		else
			reg &= ~PMA_P0_DATAPATH_P0_FLIP;

		if (invert == true)
			reg |= PMA_P0_DATAPATH_P0_INV;
		else
			reg &= ~PMA_P0_DATAPATH_P0_INV;

		pma_w32 ( reg, gpon_bfd_slice_pdi_p1_datapath);
		break;
	default:
		return OPTIC_STATUS_POOR;
	}
	return OPTIC_STATUS_OK;
}

/**
	Initilized MPD module

	Note: All MPD DAC accessing routines have to block access via dac_lock!
*/
enum optic_errorcode optic_ll_mpd_init ( const struct optic_config_monitor
					 *monitor,
					 const enum optic_bosa_loop_mode
					 loop_mode)
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint32_t reg, mod_thr, bias_thr;

	pma_w32 ( 0, gpon_bfd_slice_pdi_dual_loop_mod_status );
	pma_w32 ( 0, gpon_bfd_slice_pdi_dual_loop_bias_status );

	/* configure dual loop */
	reg = ((monitor->cid_match_all_p0 == true) ?
	       PMA_P0_DUAL_LOOP_P0_MATCH_ALL : 0 ) |
	      PMA_P0_DUAL_LOOP_P0_TRACEREG_EN |
	      ((monitor->cid_size_p0 <<
	               PMA_P0_DUAL_LOOP_P0_MIN_BITS_OFFSET) &
		       PMA_P0_DUAL_LOOP_P0_MIN_BITS_MASK) |
		((DEFAULT_DUAL_LOOP_MIN_AZ <<
			PMA_P0_DUAL_LOOP_P0_MIN_AZ_OFFSET) &
			PMA_P0_DUAL_LOOP_P0_MIN_AZ_MASK) |
		((DEFAULT_DUAL_LOOP_MIN_DET_BITS <<
			PMA_P0_DUAL_LOOP_P0_MIN_DET_BITS_OFFSET) &
			PMA_P0_DUAL_LOOP_P0_MIN_DET_BITS_MASK) |
		((DEFAULT_DUAL_LOOP_CAPTURE_WIDTH <<
			PMA_P0_DUAL_LOOP_P0_CAPTURE_WIDTH_OFFSET) &
			PMA_P0_DUAL_LOOP_P0_CAPTURE_WIDTH_MASK) |
		((DEFAULT_DUAL_LOOP_CAPTURE_DELAY <<
			PMA_P0_DUAL_LOOP_P0_CAPTURE_DELAY_OFFSET) &
			PMA_P0_DUAL_LOOP_P0_CAPTURE_DELAY_MASK) |
		((DEFAULT_DUAL_LOOP_AZ_DELAY <<
			PMA_P0_DUAL_LOOP_P0_AZ_DELAY_OFFSET) &
			PMA_P0_DUAL_LOOP_P0_AZ_DELAY_MASK);

	pma_w32 ( reg, gpon_bfd_slice_pdi_p0_dual_loop );

	/* program default value in BFD */
	if(is_falcon_chip_a2x())
		pma_w32 ( OPTIC_BFD_DATA_DELAY_DATA_DELAY |
				(OPTIC_BFD_DATA_DELAY_BURST_CUT_A21 <<
						OPTIC_BFD_DATA_DELAY_BURST_CUT_OFFSET_A21)
				, gpon_bfd_slice_pdi_data_delay );
	else
		pma_w32 ( OPTIC_BFD_DATA_DELAY_DATA_DELAY, gpon_bfd_slice_pdi_data_delay );

	/* configure dual loop, no alarm for P1 */
	reg = ((monitor->cid_match_all_p1 == true) ?
	       PMA_P1_DUAL_LOOP_P1_MATCH_ALL : 0 ) |
	      PMA_P1_DUAL_LOOP_P1_TRACEREG_EN |
	      ((monitor->cid_size_p1 <<
	               PMA_P1_DUAL_LOOP_P1_MIN_BITS_OFFSET) &
		       PMA_P1_DUAL_LOOP_P1_MIN_BITS_MASK) |
		((DEFAULT_DUAL_LOOP_MIN_AZ <<
			PMA_P1_DUAL_LOOP_P1_MIN_AZ_OFFSET) &
			PMA_P1_DUAL_LOOP_P1_MIN_AZ_MASK) |
		((DEFAULT_DUAL_LOOP_MIN_DET_BITS <<
			PMA_P1_DUAL_LOOP_P1_MIN_DET_BITS_OFFSET) &
			PMA_P1_DUAL_LOOP_P1_MIN_DET_BITS_MASK) |
		((DEFAULT_DUAL_LOOP_CAPTURE_WIDTH <<
			PMA_P1_DUAL_LOOP_P1_CAPTURE_WIDTH_OFFSET) &
			PMA_P1_DUAL_LOOP_P1_CAPTURE_WIDTH_MASK) |
		((DEFAULT_DUAL_LOOP_CAPTURE_DELAY <<
			PMA_P1_DUAL_LOOP_P1_CAPTURE_DELAY_OFFSET) &
			PMA_P1_DUAL_LOOP_P1_CAPTURE_DELAY_MASK) |
		((DEFAULT_DUAL_LOOP_AZ_DELAY <<
			PMA_P1_DUAL_LOOP_P1_AZ_DELAY_OFFSET) &
			PMA_P1_DUAL_LOOP_P1_AZ_DELAY_MASK);
	pma_w32 ( reg, gpon_bfd_slice_pdi_p1_dual_loop );

        /* configure the regulation speed parameters */
	reg = /* PMA_LOOP_REGULATION_BIAS_MOD_COMP | */
	      ((256 << PMA_LOOP_REGULATION_BIAS_C_SAT_OFFSET) &
	               PMA_LOOP_REGULATION_BIAS_C_SAT_MASK) |
	      ((4 << PMA_LOOP_REGULATION_BIAS_C_ALPHA_OFFSET) &
		     PMA_LOOP_REGULATION_BIAS_C_ALPHA_MASK) |
	      ((32 << PMA_LOOP_REGULATION_BIAS_C_FAST_OFFSET) &
	              PMA_LOOP_REGULATION_BIAS_C_FAST_MASK);

	if (loop_mode == OPTIC_BOSA_DUALLOOP) {
		reg |= ((1 << PMA_LOOP_REGULATION_BIAS_CONTROL_TYPE_OFFSET) &
			      PMA_LOOP_REGULATION_BIAS_CONTROL_TYPE_MASK);
	}

	pma_w32 ( reg, gpon_bfd_slice_pdi_loop_regulation_bias );

	reg = /* PMA_LOOP_REGULATION_MODULATION_RESERVED | */
	      ((256 << PMA_LOOP_REGULATION_MODULATION_C_SAT_OFFSET) &
	               PMA_LOOP_REGULATION_MODULATION_C_SAT_MASK) |
	      ((4 << PMA_LOOP_REGULATION_MODULATION_C_ALPHA_OFFSET) &
		     PMA_LOOP_REGULATION_MODULATION_C_ALPHA_MASK) |
	      ((32 << PMA_LOOP_REGULATION_MODULATION_C_FAST_OFFSET) &
	              PMA_LOOP_REGULATION_MODULATION_C_FAST_MASK);

	if (loop_mode == OPTIC_BOSA_DUALLOOP) {
		reg |= ((1 <<
			PMA_LOOP_REGULATION_MODULATION_CONTROL_TYPE_OFFSET) &
			PMA_LOOP_REGULATION_MODULATION_CONTROL_TYPE_MASK);
	}

	pma_w32 ( reg, gpon_bfd_slice_pdi_loop_regulation_modulation );

	reg = ((monitor->cid_mask_p1 <<
		PMA_COMPAREPATTERN_P1_CP_OFFSET) &
		PMA_COMPAREPATTERN_P1_CP_MASK) |
	      ((monitor->cid_mask_p0 <<
		PMA_COMPAREPATTERN_P0_CP_OFFSET) &
		PMA_COMPAREPATTERN_P0_CP_MASK);
	pma_w32 ( reg, gpon_bfd_slice_pdi_comparepattern );

	/* force to power up 1mA bias & modulation current DAC */
	reg = ((0x0
	        << PMA_POWERSAVE_BIAS_PD_OFFSET) &
		   PMA_POWERSAVE_BIAS_PD_MASK) |
	      ((0x0
	        << PMA_POWERSAVE_MODULATION_PD_OFFSET) &
		   PMA_POWERSAVE_MODULATION_PD_MASK) |
	      ((monitor->powersave == OPTIC_ENABLE)?
	       PMA_POWERSAVE_POWER_UP_EN : PMA_POWERSAVE_POWER_UP_OVR);
	pma_w32 ( reg, gpon_bfd_slice_pdi_powersave );

	reg = ((3 << PMA_DAC_CTRL_BIAS_EN_OFFSET) &
	             PMA_DAC_CTRL_BIAS_EN_MASK) |
	      ((3 << PMA_DAC_CTRL_MODULATION_EN_OFFSET) &
	             PMA_DAC_CTRL_MODULATION_EN_MASK);
	pma_w32 ( reg, gpon_bfd_slice_pdi_dac_ctrl );

	/* For OVL following registers need to be initialized */
	/* The digital value for BIAS and MODULATION DAC
	    at which the alarm  should be rised */
	/* bias max 78 mA (from fuse), default 60 / 78 * 2^11 = 1575 */
	bias_thr = monitor->oc_ibias_thr * 2^11 / monitor->bias_max;
	/* max 130 mA, default 60 / 130 * 2^11 = 945 */
	mod_thr = monitor->oc_imod_thr * 2^11 / monitor->mod_max;
	reg = ((bias_thr << PMA_THRESHOLD_CTRL_BIAS_THR_OFFSET) &
	             PMA_THRESHOLD_CTRL_BIAS_THR_MASK) |
	      ((mod_thr << PMA_THRESHOLD_CTRL_MODULATION_THR_OFFSET) &
	             PMA_THRESHOLD_CTRL_MODULATION_THR_MASK);
	pma_w32 (reg, gpon_bfd_slice_pdi_threshold_ctrl );
	/* This sum is completely independent of the individual thresholds above.
	   For the sum an "approximation" is needed:
	   The configured sum current needs to be divided euqally in Bias and
	   Modulation part (e.g. sum=100mA, so mod=50mA and bias=50mA),
	   for each part the respective DAC codeword needs to be calculated with the
	   fuse formula, and the sum has to be configured by multipling the bias
	   codeword with 72 and the modulation codeword with 122:
	   sum_thr=limit_mod(10:0)*122mA+limit_bias(10:0)*72mA	*/
	reg = (monitor->oc_ibias_imod_thr / 2) * (122 + 72);
	pma_w32 ( reg, gpon_bfd_slice_pdi_threshold_sumctrl );
	/* set to maximal value */
	pma_w32 ( 0xffff, gpon_bfd_slice_pdi_threshold_sum_persistency );

	/* flip datapath P0 */
	ret = optic_ll_mpd_path_cfg_set ( OPTIC_P0, true, false );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/* flip datapath P1 */
	ret = optic_ll_mpd_path_cfg_set ( OPTIC_P1, true, false );
	if (ret != OPTIC_STATUS_OK)
		return ret;


#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_MPD == ACTIVE))
	optic_ll_mpd_dump ();
#endif

	return ret;
}

enum optic_errorcode optic_ll_mpd_exit ( void )
{
	enum optic_errorcode ret;

	/* configure dual loop */
	pma_w32 ( P0_DUAL_LOOP_RESET , gpon_bfd_slice_pdi_p0_dual_loop );
	pma_w32 ( P1_DUAL_LOOP_RESET , gpon_bfd_slice_pdi_p1_dual_loop );

        /* configure the regulation speed parameters */
	pma_w32 ( LOOP_REGULATION_BIAS_RESET,
		  gpon_bfd_slice_pdi_loop_regulation_bias );
	pma_w32 ( LOOP_REGULATION_MODULATION_RESET,
	          gpon_bfd_slice_pdi_loop_regulation_modulation );

	pma_w32 ( 0, gpon_bfd_slice_pdi_comparepattern );

	/* force to power up 1mA bias & modulation current DAC */
	pma_w32 ( 0, gpon_bfd_slice_pdi_powersave );

	pma_w32 ( 0, gpon_bfd_slice_pdi_dac_ctrl );

	/* flip datapath P0 */
	ret = optic_ll_mpd_path_cfg_set ( OPTIC_P0, false, false );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/* flip datapath P1 */
	ret = optic_ll_mpd_path_cfg_set ( OPTIC_P1, false, false );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_mpd_dac_set ( OPTIC_DAC_TIA_OFFSET, 0, 0 );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_mpd_dac_set ( OPTIC_DAC_P0_LEVEL, 0, 0 );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_mpd_dac_set ( OPTIC_DAC_P1_LEVEL, 0, 0 );
	if (ret != OPTIC_STATUS_OK)
		return ret;


	/* use 1 as smallest value, 0 is a hardware meta value */
	pma_w32 ( 1, gpon_bfd_slice_pdi_dual_loop_mod_init );
	pma_w32 ( 1, gpon_bfd_slice_pdi_dual_loop_bias_init );

	pma_w32 ( 0, gpon_bfd_slice_pdi_gain_ctrl );

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_MPD == ACTIVE))
	optic_ll_mpd_dump ();
#endif

	return ret;
}
#if 0
enum optic_errorcode optic_ll_mpd_level_get ( const enum optic_search_type type,
					      int16_t *level )
{
	uint32_t reg;
	switch (type) {
	case OPTIC_SEARCH_OFFSET_COARSE:
		reg=pma_r32 (gpon_bfd_slice_pdi_tiaoffset);
		reg=(reg&PMA_TIAOFFSET_OFFSETCOARSE_MASK)>>PMA_TIAOFFSET_OFFSETCOARSE_OFFSET;
		break;
	case OPTIC_SEARCH_OFFSET_FINE:
		reg=pma_r32 (gpon_bfd_slice_pdi_tiaoffset);
		reg=(reg&PMA_TIAOFFSET_OFFSETFINE_MASK)>>PMA_TIAOFFSET_OFFSETFINE_OFFSET;
		break;
	case OPTIC_SEARCH_P0_COARSE:
		reg=pma_r32 (gpon_bfd_slice_pdi_p0level);
		reg=(reg&PMA_P0LEVEL_LEVELCOARSE_MASK)>>PMA_P0LEVEL_LEVELCOARSE_OFFSET;
		break;
	case OPTIC_SEARCH_P0_FINE:
		reg=pma_r32 (gpon_bfd_slice_pdi_p0level);
		reg=(reg&PMA_P0LEVEL_LEVELFINE_MASK)>>PMA_P0LEVEL_LEVELFINE_OFFSET;
		break;
	case OPTIC_SEARCH_P1_COARSE:
		reg=pma_r32 (gpon_bfd_slice_pdi_p1level);
		reg=(reg&PMA_P1LEVEL_LEVELCOARSE_MASK)>>PMA_P1LEVEL_LEVELCOARSE_OFFSET;
		break;
	case OPTIC_SEARCH_P1_FINE:
		reg=pma_r32 (gpon_bfd_slice_pdi_p1level);
		reg=(reg&PMA_P1LEVEL_LEVELFINE_MASK)>>PMA_P1LEVEL_LEVELFINE_OFFSET;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}
	if (reg & 0x100)
		*level =-abs(reg & 0xff);
	else
		*level = abs(reg & 0xff);

	return OPTIC_STATUS_OK;
}
#endif

enum optic_errorcode optic_ll_mpd_level_set ( const enum optic_search_type type,
					      const int16_t level )
{
	uint16_t sign = (level < 0) ? (1 << 8) : 0;
	uint16_t xlevel = (abs(level) & 0xfe)|((~(abs(level) & 0x1))&0x1);
	uint32_t old;

	switch (type) {
	case OPTIC_SEARCH_OFFSET_COARSE:
		old = pma_r32 ( gpon_bfd_slice_pdi_tiaoffset );
		old = (PMA_TIAOFFSET_OFFSETCOARSE_MASK & old) >>
					      PMA_TIAOFFSET_OFFSETCOARSE_OFFSET;
		if (old==(sign | abs(level)))
			pma_w32_mask ( PMA_TIAOFFSET_OFFSETCOARSE_MASK,
			       ((sign | abs(xlevel)) <<
			       PMA_TIAOFFSET_OFFSETCOARSE_OFFSET) &
			       PMA_TIAOFFSET_OFFSETCOARSE_MASK,
			       gpon_bfd_slice_pdi_tiaoffset);
		pma_w32_mask ( PMA_TIAOFFSET_OFFSETCOARSE_MASK,
			       ((sign | abs(level)) <<
			       PMA_TIAOFFSET_OFFSETCOARSE_OFFSET) &
			       PMA_TIAOFFSET_OFFSETCOARSE_MASK,
			       gpon_bfd_slice_pdi_tiaoffset);
		break;
	case OPTIC_SEARCH_OFFSET_FINE:
		old = pma_r32 ( gpon_bfd_slice_pdi_tiaoffset );
		old = (PMA_TIAOFFSET_OFFSETFINE_MASK & old) >>
						PMA_TIAOFFSET_OFFSETFINE_OFFSET;
		if (old==(sign | abs(level)))
			pma_w32_mask ( PMA_TIAOFFSET_OFFSETFINE_MASK,
			       ((sign | abs(xlevel)) <<
			       PMA_TIAOFFSET_OFFSETFINE_OFFSET) &
			       PMA_TIAOFFSET_OFFSETFINE_MASK,
			       gpon_bfd_slice_pdi_tiaoffset);
		pma_w32_mask ( PMA_TIAOFFSET_OFFSETFINE_MASK,
			       ((sign | abs(level)) <<
			       PMA_TIAOFFSET_OFFSETFINE_OFFSET) &
			       PMA_TIAOFFSET_OFFSETFINE_MASK,
			       gpon_bfd_slice_pdi_tiaoffset);
		break;
	case OPTIC_SEARCH_P0_COARSE:
		old = pma_r32 ( gpon_bfd_slice_pdi_p0level );
		old = (PMA_P0LEVEL_LEVELCOARSE_MASK & old) >>
						 PMA_P0LEVEL_LEVELCOARSE_OFFSET;
		if (old==(sign | abs(level)))
			pma_w32_mask ( PMA_P0LEVEL_LEVELCOARSE_MASK,
			       ((sign | abs(xlevel)) <<
			       PMA_P0LEVEL_LEVELCOARSE_OFFSET) &
			       PMA_P0LEVEL_LEVELCOARSE_MASK,
			       gpon_bfd_slice_pdi_p0level);
		pma_w32_mask ( PMA_P0LEVEL_LEVELCOARSE_MASK,
			       ((sign | abs(level)) <<
			       PMA_P0LEVEL_LEVELCOARSE_OFFSET) &
			       PMA_P0LEVEL_LEVELCOARSE_MASK,
			       gpon_bfd_slice_pdi_p0level);
		break;
	case OPTIC_SEARCH_P0_FINE:
		old = pma_r32 ( gpon_bfd_slice_pdi_p0level );
		old = (PMA_P0LEVEL_LEVELFINE_MASK & old) >>
						   PMA_P0LEVEL_LEVELFINE_OFFSET;
		if (old==(sign | abs(level)))
			pma_w32_mask ( PMA_P0LEVEL_LEVELFINE_MASK,
			       ((sign | abs(xlevel)) <<
			       PMA_P0LEVEL_LEVELFINE_OFFSET) &
			       PMA_P0LEVEL_LEVELFINE_MASK,
			       gpon_bfd_slice_pdi_p0level);
		pma_w32_mask ( PMA_P0LEVEL_LEVELFINE_MASK,
			       ((sign | abs(level)) <<
			       PMA_P0LEVEL_LEVELFINE_OFFSET) &
			       PMA_P0LEVEL_LEVELFINE_MASK,
			       gpon_bfd_slice_pdi_p0level);
		break;
	case OPTIC_SEARCH_P1_COARSE:
		old = pma_r32 ( gpon_bfd_slice_pdi_p1level );
		old = (PMA_P1LEVEL_LEVELCOARSE_MASK & old) >>
						 PMA_P1LEVEL_LEVELCOARSE_OFFSET;
		if (old==(sign | abs(level)))
			pma_w32_mask ( PMA_P1LEVEL_LEVELCOARSE_MASK,
			       ((sign | abs(xlevel)) <<
			       PMA_P1LEVEL_LEVELCOARSE_OFFSET) &
			       PMA_P1LEVEL_LEVELCOARSE_MASK,
			       gpon_bfd_slice_pdi_p1level);
		pma_w32_mask ( PMA_P1LEVEL_LEVELCOARSE_MASK,
			       ((sign | abs(level)) <<
			       PMA_P1LEVEL_LEVELCOARSE_OFFSET) &
			       PMA_P1LEVEL_LEVELCOARSE_MASK,
			       gpon_bfd_slice_pdi_p1level);
		break;
	case OPTIC_SEARCH_P1_FINE:
		old = pma_r32 ( gpon_bfd_slice_pdi_p1level );
		old = (PMA_P1LEVEL_LEVELFINE_MASK & old) >>
						   PMA_P1LEVEL_LEVELFINE_OFFSET;
		if (old==(sign | abs(level)))
			pma_w32_mask ( PMA_P1LEVEL_LEVELFINE_MASK,
			       ((sign | abs(xlevel)) <<
			       PMA_P1LEVEL_LEVELFINE_OFFSET) &
			       PMA_P1LEVEL_LEVELFINE_MASK,
			       gpon_bfd_slice_pdi_p1level);
		pma_w32_mask ( PMA_P1LEVEL_LEVELFINE_MASK,
			       ((sign | abs(level)) <<
			       PMA_P1LEVEL_LEVELFINE_OFFSET) &
			       PMA_P1LEVEL_LEVELFINE_MASK,
			       gpon_bfd_slice_pdi_p1level);
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mpd_level_find ( const enum optic_loop_mode burstmode,const enum optic_search_type
					       type,
					       const bool read_p0,
					       int32_t gain,
					       int16_t *level,
					       int16_t *level_c )
{
#define CNT_REACT_MAX 255
#define CNT_SAT_MAX 16

#define COMB_PERIODS 6 /* use (1<<COMB_PERIODS) for comb periods */
#define REPEAT_SEARCH 0 /* use (1<<REPEAT_SEARCH) for repetition of search */

	enum optic_errorcode ret;
	uint8_t cnt_react = CNT_REACT_MAX, cnt_sat = CNT_SAT_MAX,
		cnt_sat_c = CNT_SAT_MAX;
	int16_t bfd_compdata, bfd_compdata_old;
	uint16_t bfd_cnt, bfd_cnt_old = 0;
	int32_t op;
	uint32_t reg;
	int16_t level_old=0, level_new=0;
	uint32_t opfilt = (1 << OPTIC_LEVEL_BITS) - 1; /* start value, corresponds to 1 */
	uint32_t opfilt_start = opfilt; /* start value, corresponds to 1 */
	int32_t y=0;
	int64_t y_all=0;
	int64_t y_all_loop=0;
	uint64_t x=0;
	uint64_t y1=0;
	uint64_t y2=0;
	uint64_t y3=0;
	uint64_t y4=0;
	uint64_t z1=0;
	uint64_t z2=0;
	uint64_t z3=0;
	uint64_t z4=0;
	int16_t cnt=0;
	int16_t cnt_end=0;
	int8_t zero_sat;
	int16_t loop=1<<REPEAT_SEARCH;
	int32_t gain_save=gain;
	enum optic_search_type type_c;

	/* check if P0/P1 fine DAC search:
	 * in this case the sign must be same as for coarse DAC
	 * so
	 * 1.) regard coarse DAC
	 * 2.) manipulate ....
	 */

	OPTIC_DEBUG_MSG("IN: optic_ll_mpd_level_find: level=%d level_c=%d",*level,*level_c);

	switch (type) {
	case OPTIC_SEARCH_P0_FINE:
		type_c=OPTIC_SEARCH_P0_COARSE;
		zero_sat=1;
		break;
	case OPTIC_SEARCH_P1_FINE:
		type_c=OPTIC_SEARCH_P1_COARSE;
		zero_sat=1;
		break;
	default:
		type_c=0; /* not used */
		zero_sat=0;
		break;
	}

	while(loop--){
		gain=gain_save;

		level_new = (*level);
		bfd_compdata = -1;
		opfilt=opfilt_start;

		/* read comparator */
		if (is_falcon_chip_a2x()){
			if (burstmode == OPTIC_LOOPMODE_INTERBURST)
				reg = pma_r32 ( gpon_bfd_slice_pdi_comparator_statusib);
			else
				reg = pma_r32 ( gpon_bfd_slice_pdi_comparator_status);

		} else {
			reg = pma_r32 ( gpon_bfd_slice_pdi_comparator_status);
		}
		if (read_p0 == true) {
			bfd_cnt_old =
				(reg & PMA_COMPARATOR_STATUS_P0_BFD_CNT_MASK) >>
					PMA_COMPARATOR_STATUS_P0_BFD_CNT_OFFSET;
		} else {
			bfd_cnt_old =
				(reg & PMA_COMPARATOR_STATUS_P1_BFD_CNT_MASK) >>
					PMA_COMPARATOR_STATUS_P1_BFD_CNT_OFFSET;
		}
		while (gain) {
			level_old = level_new;
			bfd_compdata_old = bfd_compdata;

			/* update level */
			ret = optic_ll_mpd_level_set ( type, level_new );
			if (ret != OPTIC_STATUS_OK) {
				OPTIC_DEBUG_ERR(" optic_ll_mpd_level_set(%d): %d",
						type, ret);
				return ret;
			}

			/* read comparator */
			if (is_falcon_chip_a2x()){
				if (burstmode == OPTIC_LOOPMODE_INTERBURST)
					reg = pma_r32 ( gpon_bfd_slice_pdi_comparator_statusib);
				else
					reg = pma_r32 ( gpon_bfd_slice_pdi_comparator_status);

			} else {
				reg = pma_r32 ( gpon_bfd_slice_pdi_comparator_status);
			}
			if (read_p0 == true) {
				bfd_cnt =
				   (reg & PMA_COMPARATOR_STATUS_P0_BFD_CNT_MASK)
						>> PMA_COMPARATOR_STATUS_P0_BFD_CNT_OFFSET;
				bfd_compdata = (reg &
						PMA_COMPARATOR_STATUS_P0_BFD_COMPDATA_MASK) >>
						PMA_COMPARATOR_STATUS_P0_BFD_COMPDATA_OFFSET;
			} else {
				bfd_cnt = (reg & PMA_COMPARATOR_STATUS_P1_BFD_CNT_MASK)
						>> PMA_COMPARATOR_STATUS_P1_BFD_CNT_OFFSET;
				bfd_compdata = (reg &
						PMA_COMPARATOR_STATUS_P1_BFD_COMPDATA_MASK) >>
						PMA_COMPARATOR_STATUS_P1_BFD_COMPDATA_OFFSET;
			}
			OPTIC_DEBUG_MSG("optic_ll_mpd_level_find(): type=%d level=%d"
					"bfd_cnt=%d bfd_compdata=%d (~gain~=%d)",
					type, level_new, bfd_cnt, bfd_compdata, gain);

			/* no new data */
			if (bfd_cnt == bfd_cnt_old) {
				if (--cnt_react == 0) {
					return OPTIC_STATUS_MPD_COMPTIMEOUT;
				}
				continue;
			}

			bfd_cnt_old = bfd_cnt;
			cnt_react = CNT_REACT_MAX;

			/* step size change */			
			 if ((bfd_compdata_old != -1) &&
					(((bfd_compdata != 0) && (bfd_compdata_old == 0)) ||
							((bfd_compdata == 0) && (bfd_compdata_old != 0)))) {
				gain = optic_int_div_rounded ( gain, 2 );
			}

			/* at least one measurement above level */
			if (bfd_compdata > 0) {
				level_new = level_old + gain;
				op = gain;
			} else {
				level_new = level_old - gain;
				op = -gain;
			}

			/* saturation check */
			if (abs(level_new) > 0xFF) {
				cnt_sat --;
				level_new = level_old;

				if (cnt_sat == 0) {
					OPTIC_DEBUG_WRN("optic_ll_mpd_level_find(%d):"
							" SATURATION, level=%d, gain=%d"
							", compdata=%d, opfilt=%d",
							type, level_old, gain,
							bfd_compdata, opfilt);

					*level = level_new;

					return OPTIC_STATUS_MPD_SATURATION;
				}
				continue;
			}
			cnt_sat = CNT_SAT_MAX;

			/* sign saturation check */
			if ((zero_sat == 1) && (((*level_c) * level_new) < 0)){
				OPTIC_DEBUG_MSG("optic_ll_mpd_level_find(): C/F VZ"
						"difference! level_c=%d level_new=%d cnt_sat_c=%d",
						*level_c, level_new, cnt_sat_c);

				cnt_sat_c --;
				if (cnt_sat_c == 0) {
					if (level_new < 0){
						(*level_c)-=1;
					} else {
						(*level_c)+=1;
					}
					level_new = 0;
					ret = optic_ll_mpd_level_set ( type_c, *level_c );
					if (ret != OPTIC_STATUS_OK) {
						OPTIC_DEBUG_ERR(" optic_ll_mpd_level_set(%d): %d",
								type_c, ret);
						return ret;
					}
					opfilt=opfilt_start;

					cnt_sat_c = CNT_SAT_MAX;
				}
				continue;
			}
			cnt_sat_c = CNT_SAT_MAX;

			/*comb*/
			cnt++;
			x = level_new;
			y1=x+z1;
			z1=y1;
			y2=y1+z2;
			z2=y2;
			if(cnt>=64){
				cnt=0;
				cnt_end++;
				y3=y2-z3;
				z3=y2;
				y4=y3-z4;
				z4=y3;
				y=y4>>12;
				y_all+=y; /* sum of all results */
			}

			if (abs(gain)==1){
				/* filter as end criteria*/
				if (abs(opfilt) > OPTIC_GAIN_COEFF){
					opfilt = ((opfilt + op * OPTIC_GAIN_COEFF) *
							(((1 << OPTIC_LEVEL_BITS) - 1)
									- OPTIC_GAIN_COEFF)) >> OPTIC_LEVEL_BITS;
					cnt_end=0;
					y_all=0;
				} else {
					if (cnt_end==(1<<COMB_PERIODS)){
						gain=0;
						y_all_loop+=(y_all>>COMB_PERIODS);
						/*if (loop>0)
							IFXOS_MSecSleep(1);*/
					}
				}
			}

		}
	}
	*level=y_all_loop>>REPEAT_SEARCH;
	OPTIC_DEBUG_MSG("OUT: optic_ll_mpd_level_find: level=%d level_c=%d",*level,*level_c);
#if 0
	switch (type) {
	case OPTIC_SEARCH_P1_COARSE:
		//OPTIC_DEBUG_ERR("<-- OPTIC_SEARCH_P1_COARSE optic_ll_mpd_level_find: level=%d level_c=%d",*level,*level_c);
		break;
	case OPTIC_SEARCH_P1_FINE:
		//OPTIC_DEBUG_ERR("<-- OPTIC_SEARCH_P1_FINE optic_ll_mpd_level_find: level=%d level_c=%d",*level,*level_c);
		break;
	}
#endif
	ret = optic_ll_mpd_level_set ( type, *level );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR(" optic_ll_mpd_level_set(%d): %d",
				type_c, ret);
		return ret;
	}
#if 0
	switch (type) {
	case OPTIC_SEARCH_P1_COARSE:
		//OPTIC_DEBUG_ERR("<-- OPTIC_SEARCH_P1_COARSE optic_ll_mpd_level_find: level=%d level_c=%d",*level,*level_c);
		break;
	case OPTIC_SEARCH_P1_FINE:
		//OPTIC_DEBUG_ERR("<-- OPTIC_SEARCH_P1_FINE optic_ll_mpd_level_find: level=%d level_c=%d",*level,*level_c);
		break;
	}
#endif

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mpd_disable_powersave(void) {
	/* set MPD to no power save, part of GPONSW-593,
	 * just in case via CLI powersave was enabled */
	pma_w32 ( 0, gpon_bfd_slice_pdi_p0_bfd_powersave );
	pma_w32 ( 0, gpon_bfd_slice_pdi_p1_bfd_powersave );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mpd_loop_set ( const struct optic_config_monitor
					     *monitor,
					     enum optic_loop_mode *loopmode,
					     const enum optic_loop_mode
					     loopmode_p0,
					     const enum optic_loop_mode
					     loopmode_p1 )
{
	uint32_t reg;

	switch (loopmode_p0) {
	case OPTIC_LOOPMODE_INTRABURST:
		/* disable HW dual loop */
		pma_w32_mask ( PMA_LOOP_REGULATION_BIAS_CONTROL_TYPE_MASK, (0 <<
		               PMA_LOOP_REGULATION_BIAS_CONTROL_TYPE_OFFSET) &
		               PMA_LOOP_REGULATION_BIAS_CONTROL_TYPE_MASK,
			       gpon_bfd_slice_pdi_loop_regulation_bias );

		/* IB_CHECK has not to be set */
		reg = pma_r32 ( gpon_bfd_slice_pdi_p0_dual_loop );
		reg &= ~(PMA_P0_DUAL_LOOP_P0_COMPARE_METHOD |
			 PMA_P0_DUAL_LOOP_P0_IB_CHECK |
			 PMA_P0_DUAL_LOOP_P0_MIN_BITS_MASK);
		reg |= (PMA_P0_DUAL_LOOP_P0_TRACEREG_EN |
		        ((monitor->cid_size_p0 <<
			  PMA_P0_DUAL_LOOP_P0_MIN_BITS_OFFSET) &
		          PMA_P0_DUAL_LOOP_P0_MIN_BITS_MASK));

		pma_w32 ( reg, gpon_bfd_slice_pdi_p0_dual_loop );
		/* set az_delay = 1 */
		optic_ll_mpd_az_delay_set (1, 1);

		break;
	case OPTIC_LOOPMODE_INTERBURST:
		/* disable HW dual loop, enable interburst check */
		pma_w32_mask ( PMA_LOOP_REGULATION_BIAS_CONTROL_TYPE_MASK, (0 <<
		               PMA_LOOP_REGULATION_BIAS_CONTROL_TYPE_OFFSET) &
		               PMA_LOOP_REGULATION_BIAS_CONTROL_TYPE_MASK,
			       gpon_bfd_slice_pdi_loop_regulation_bias );

		reg = pma_r32 ( gpon_bfd_slice_pdi_p0_dual_loop );
		/* IB_CHECK has to be set */
		reg &= ~(PMA_P0_DUAL_LOOP_P0_COMPARE_METHOD);
		reg |= (PMA_P0_DUAL_LOOP_P0_TRACEREG_EN |
		        PMA_P0_DUAL_LOOP_P0_IB_CHECK |
		        PMA_P0_DUAL_LOOP_P0_MIN_BITS_MASK);
		pma_w32 ( reg, gpon_bfd_slice_pdi_p0_dual_loop );
		/* set az_delay = 3 */
		if (is_falcon_chip_a1x())
			optic_ll_mpd_az_delay_set (3, 3);
		else
			optic_ll_mpd_az_delay_set (1, 1);

		break;
	case OPTIC_LOOPMODE_DUALLOOP:
		/* enable HW dual loop */
		pma_w32_mask ( PMA_LOOP_REGULATION_BIAS_CONTROL_TYPE_MASK, (1 <<
		               PMA_LOOP_REGULATION_BIAS_CONTROL_TYPE_OFFSET) &
		               PMA_LOOP_REGULATION_BIAS_CONTROL_TYPE_MASK,
			       gpon_bfd_slice_pdi_loop_regulation_bias );

		/* IB_CHECK has not to be set */
		reg = pma_r32 ( gpon_bfd_slice_pdi_p0_dual_loop );
		reg &= ~(PMA_P0_DUAL_LOOP_P0_COMPARE_METHOD |
		         PMA_P0_DUAL_LOOP_P0_TRACEREG_EN |
		         PMA_P0_DUAL_LOOP_P0_IB_CHECK |
		         PMA_P0_DUAL_LOOP_P0_MIN_BITS_MASK);

		reg |= ((monitor->cid_size_p0 <<
			 PMA_P0_DUAL_LOOP_P0_MIN_BITS_OFFSET) &
		         PMA_P0_DUAL_LOOP_P0_MIN_BITS_MASK);
		pma_w32 ( reg, gpon_bfd_slice_pdi_p0_dual_loop );
		/* set az_delay = 1 */
		optic_ll_mpd_az_delay_set (1, 1);

		break;

	default:
		return OPTIC_STATUS_POOR;
	}

	switch (loopmode_p1) {
	case OPTIC_LOOPMODE_INTRABURST:
		pma_w32_mask ( PMA_LOOP_REGULATION_MODULATION_CONTROL_TYPE_MASK,
		        (0 <<PMA_LOOP_REGULATION_MODULATION_CONTROL_TYPE_OFFSET)
			& PMA_LOOP_REGULATION_MODULATION_CONTROL_TYPE_MASK,
			gpon_bfd_slice_pdi_loop_regulation_modulation );

		/* IB_CHECK has not to been set */
		reg = pma_r32 ( gpon_bfd_slice_pdi_p1_dual_loop );
		reg &= ~(PMA_P1_DUAL_LOOP_P1_COMPARE_METHOD |
			 PMA_P1_DUAL_LOOP_P1_IB_CHECK |
			 PMA_P1_DUAL_LOOP_P1_MIN_BITS_MASK);
		reg |= (PMA_P1_DUAL_LOOP_P1_TRACEREG_EN |
		        ((monitor->cid_size_p1 <<
			  PMA_P1_DUAL_LOOP_P1_MIN_BITS_OFFSET) &
		          PMA_P1_DUAL_LOOP_P1_MIN_BITS_MASK));
		pma_w32 ( reg, gpon_bfd_slice_pdi_p1_dual_loop );
		/* set az_delay = 1 */
		optic_ll_mpd_az_delay_set (1, 1);

		break;
	case OPTIC_LOOPMODE_INTERBURST:
		pma_w32_mask ( PMA_LOOP_REGULATION_MODULATION_CONTROL_TYPE_MASK,
			(0 <<PMA_LOOP_REGULATION_MODULATION_CONTROL_TYPE_OFFSET)
			& PMA_LOOP_REGULATION_MODULATION_CONTROL_TYPE_MASK,
			gpon_bfd_slice_pdi_loop_regulation_modulation);

		reg = pma_r32 ( gpon_bfd_slice_pdi_p1_dual_loop );
		/* IB_CHECK has to be set */
		reg &= ~(PMA_P1_DUAL_LOOP_P1_COMPARE_METHOD);
		reg |= (PMA_P1_DUAL_LOOP_P1_TRACEREG_EN |
		        PMA_P1_DUAL_LOOP_P1_IB_CHECK |
		        PMA_P1_DUAL_LOOP_P1_MIN_BITS_MASK);
		pma_w32 ( reg, gpon_bfd_slice_pdi_p1_dual_loop );
		/* set az_delay = 3 */
		if (is_falcon_chip_a1x())
			optic_ll_mpd_az_delay_set (3, 3);
		else
			optic_ll_mpd_az_delay_set (1, 1);

		break;
	case OPTIC_LOOPMODE_DUALLOOP:
		/* enable HW dual loop, disable interburst check */
		pma_w32_mask ( PMA_LOOP_REGULATION_MODULATION_CONTROL_TYPE_MASK,
			(1 <<PMA_LOOP_REGULATION_MODULATION_CONTROL_TYPE_OFFSET)
			& PMA_LOOP_REGULATION_MODULATION_CONTROL_TYPE_MASK,
			gpon_bfd_slice_pdi_loop_regulation_modulation );

		/* IB_CHECK has not to been set */
		reg = pma_r32 ( gpon_bfd_slice_pdi_p1_dual_loop );
		reg &= ~(PMA_P1_DUAL_LOOP_P1_COMPARE_METHOD |
		         PMA_P1_DUAL_LOOP_P1_TRACEREG_EN |
		         PMA_P1_DUAL_LOOP_P1_IB_CHECK |
		         PMA_P1_DUAL_LOOP_P1_MIN_BITS_MASK);

		reg |= ((monitor->cid_size_p1 <<
			 PMA_P1_DUAL_LOOP_P1_MIN_BITS_OFFSET) &
		         PMA_P1_DUAL_LOOP_P1_MIN_BITS_MASK);
		pma_w32 ( reg, gpon_bfd_slice_pdi_p1_dual_loop );
		/* set az_delay = 1 */
		optic_ll_mpd_az_delay_set (1, 1);

		break;

	default:
		return OPTIC_STATUS_POOR;
	}

	loopmode[0] = loopmode_p0;
	loopmode[1] = loopmode_p1;

    	return OPTIC_STATUS_OK;
}

/**
	Sets the integration coefficient for Bias/Modulation.
*/
enum optic_errorcode optic_ll_mpd_cint_set ( const enum optic_current_type
                                             type,
                                             const uint8_t intcoeff,
                                             const uint16_t saturation )
{
	uint32_t reg;

	switch (type) {
	case OPTIC_BIAS:
		if (is_falcon_chip_a1x()) {
			reg = ((intcoeff << PMA_LOOP_REGULATION_BIAS_C_INT_OFFSET) &
						PMA_LOOP_REGULATION_BIAS_C_INT_MASK) |
					  ((saturation << PMA_LOOP_REGULATION_BIAS_C_SAT_OFFSET) &
									  PMA_LOOP_REGULATION_BIAS_C_SAT_MASK);

			pma_w32_mask ( PMA_LOOP_REGULATION_BIAS_C_INT_MASK |
						   PMA_LOOP_REGULATION_BIAS_C_SAT_MASK, reg,
					   gpon_bfd_slice_pdi_loop_regulation_bias );
		} else {
			reg = ((intcoeff << PMA_LOOP_REGULATION_BIAS_C_INT_OFFSET_A21) &
					    PMA_LOOP_REGULATION_BIAS_C_INT_MASK_A21) |
		              ((saturation << PMA_LOOP_REGULATION_BIAS_C_SAT_OFFSET) &
		                              PMA_LOOP_REGULATION_BIAS_C_SAT_MASK_A21);

			pma_w32_mask ( PMA_LOOP_REGULATION_BIAS_C_INT_MASK_A21 |
			               PMA_LOOP_REGULATION_BIAS_C_SAT_MASK_A21, reg,
				       gpon_bfd_slice_pdi_loop_regulation_bias );
		}
		break;
	case OPTIC_MOD:
		if (is_falcon_chip_a1x()) {
			reg = ((intcoeff <<
					PMA_LOOP_REGULATION_MODULATION_C_INT_OFFSET) &
					PMA_LOOP_REGULATION_MODULATION_C_INT_MASK) |
			      ((saturation <<
			      		PMA_LOOP_REGULATION_MODULATION_C_SAT_OFFSET) &
					PMA_LOOP_REGULATION_MODULATION_C_SAT_MASK);

			pma_w32_mask ( PMA_LOOP_REGULATION_MODULATION_C_INT_MASK |
			               PMA_LOOP_REGULATION_MODULATION_C_SAT_MASK, reg,
				       gpon_bfd_slice_pdi_loop_regulation_modulation );
		} else {
			reg = ((intcoeff <<
					PMA_LOOP_REGULATION_MODULATION_C_INT_OFFSET_A21) &
					PMA_LOOP_REGULATION_MODULATION_C_INT_MASK_A21) |
			      ((saturation <<
			      		PMA_LOOP_REGULATION_MODULATION_C_SAT_OFFSET) &
					PMA_LOOP_REGULATION_MODULATION_C_SAT_MASK_A21);

			pma_w32_mask ( PMA_LOOP_REGULATION_MODULATION_C_INT_MASK_A21 |
			               PMA_LOOP_REGULATION_MODULATION_C_SAT_MASK_A21, reg,
				       gpon_bfd_slice_pdi_loop_regulation_modulation );
		}
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}

/**
	Sets the DAC values coarse/fine for TIA offset and P0 / P1 level DAC.

	Note: All MPD DAC accessing routines have to block access via dac_lock!
	      This is not done in this routine - so all calling routines
	      have to care about!
*/
enum optic_errorcode optic_ll_mpd_dac_set ( enum optic_dac_type dac,
                                            const int16_t coarse,
					    const int16_t fine )
{
	uint16_t sign_c, sign_f;
	int16_t val_coarse = coarse, val_fine = fine;
	uint32_t reg,old;

	/*  DAC is not triggered if value is already in register, so drive delta
	 * (avoid bootup problem, when analog is floating but digital was reset) */

	sign_c = (val_coarse < 0) ? (1 << 8) : 0;
	sign_f = (val_fine < 0) ? (1 << 8) : 0;
	if (((sign_c != 0) && (sign_f !=0)) &&
			(dac != OPTIC_DAC_TIA_OFFSET) &&
			(sign_c != sign_f))
		return OPTIC_STATUS_DAC_SIGN_CONFLICT;
	switch (dac) {
	case OPTIC_DAC_TIA_OFFSET:
		old = pma_r32 ( gpon_bfd_slice_pdi_tiaoffset );
		reg = (((sign_f | abs(val_fine)) <<
			PMA_TIAOFFSET_OFFSETFINE_OFFSET) &
			PMA_TIAOFFSET_OFFSETFINE_MASK) |
		      (((sign_c | abs(val_coarse)) <<
		      	PMA_TIAOFFSET_OFFSETCOARSE_OFFSET) &
			PMA_TIAOFFSET_OFFSETCOARSE_MASK);
		if (old == reg)
			pma_w32 ( (reg&0x3fdff)|((~((reg>>9)&0x1)&0x1)<<9),
				  gpon_bfd_slice_pdi_tiaoffset );
		pma_w32 ( reg, gpon_bfd_slice_pdi_tiaoffset );
		break;
	case OPTIC_DAC_P0_LEVEL:
		old = pma_r32 ( gpon_bfd_slice_pdi_p0level );
		reg = (((sign_f | abs(val_fine)) <<
			PMA_P0LEVEL_LEVELFINE_OFFSET) &
			PMA_P0LEVEL_LEVELFINE_MASK) |
		      (((sign_c | abs(val_coarse)) <<
		      	PMA_P0LEVEL_LEVELCOARSE_OFFSET) &
			PMA_P0LEVEL_LEVELCOARSE_MASK);
		if (old == reg)
			pma_w32 ( (reg&0x3fdff)|((~((reg>>9)&0x1)&0x1)<<9),
				  gpon_bfd_slice_pdi_p0level );
		pma_w32 ( reg, gpon_bfd_slice_pdi_p0level );


		break;
	case OPTIC_DAC_P1_LEVEL:
		old = pma_r32 ( gpon_bfd_slice_pdi_p1level );
		reg = (((sign_f | abs(val_fine)) <<
			PMA_P1LEVEL_LEVELFINE_OFFSET) &
			PMA_P1LEVEL_LEVELFINE_MASK) |
		      (((sign_c | abs(val_coarse)) <<
		      	PMA_P1LEVEL_LEVELCOARSE_OFFSET) &
			PMA_P1LEVEL_LEVELCOARSE_MASK);
		if (old == reg)
			pma_w32 ( (reg&0x3fdff)|((~((reg>>9)&0x1)&0x1)<<9),
				  gpon_bfd_slice_pdi_p1level );
		pma_w32 ( reg, gpon_bfd_slice_pdi_p1level );
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}

/**
	Reads back the DAC values coarse/fine of TIA offset and
	P0 / P1 level DAC.

	Note: All MPD DAC accessing routines have to block access via dac_lock!
	      This is not done in this routine - so all calling routines
	      have to care about!
*/
enum optic_errorcode optic_ll_mpd_dac_get ( enum optic_dac_type dac,
                                            int16_t *off_c,
					    int16_t *off_f )
{
	uint32_t reg;

	if ((off_c == NULL) || (off_f == NULL ))
		return OPTIC_STATUS_ERR;

	switch (dac) {
	case OPTIC_DAC_TIA_OFFSET:
		reg = pma_r32 ( gpon_bfd_slice_pdi_tiaoffset );

		*off_f = ((reg & PMA_TIAOFFSET_OFFSETFINE_MASK) >>
	                         PMA_TIAOFFSET_OFFSETFINE_OFFSET);
		*off_c = ((reg & PMA_TIAOFFSET_OFFSETCOARSE_MASK) >>
	                         PMA_TIAOFFSET_OFFSETCOARSE_OFFSET);
		break;
	case OPTIC_DAC_P0_LEVEL:
		reg = pma_r32 ( gpon_bfd_slice_pdi_p0level );

		*off_f = ((reg & PMA_P0LEVEL_LEVELFINE_MASK) >>
	                         PMA_P0LEVEL_LEVELFINE_OFFSET);
		*off_c = ((reg & PMA_P0LEVEL_LEVELCOARSE_MASK) >>
	                         PMA_P0LEVEL_LEVELCOARSE_OFFSET);
		break;
	case OPTIC_DAC_P1_LEVEL:
		reg = pma_r32 ( gpon_bfd_slice_pdi_p1level );

		*off_f = ((reg & PMA_P1LEVEL_LEVELFINE_MASK) >>
	                         PMA_P1LEVEL_LEVELFINE_OFFSET);
		*off_c = ((reg & PMA_P1LEVEL_LEVELCOARSE_MASK) >>
	                         PMA_P1LEVEL_LEVELCOARSE_OFFSET);
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	/* sign correction */
	if (*off_f & (1<<8))
		*off_f = (*off_f & 0xFF) * (-1);

	if (*off_c & (1<<8))
		*off_c = (*off_c & 0xFF) * (-1);

	return OPTIC_STATUS_OK;
}

/**
	Reads back the trace registers

	Note: All MPD DAC accessing routines have to block access via dac_lock!
	      This is not done in this routine - so all calling routines
	      have to care about!
*/
enum optic_errorcode optic_ll_mpd_trace_get ( uint16_t *correlator_trace_p0,
					      uint16_t *correlator_trace_p1,
					      uint16_t *trace_pattern_p0,
					      uint16_t *trace_pattern_p1 )
{
	uint32_t reg;

	if ((correlator_trace_p0 == NULL) || (trace_pattern_p0 == NULL))
		return OPTIC_STATUS_ERR;
	if ((correlator_trace_p0 == NULL) || (trace_pattern_p1 == NULL))
		return OPTIC_STATUS_ERR;

	reg = pma_r32 ( gpon_bfd_slice_pdi_p0_trace );
	*trace_pattern_p0    = (reg & PMA_P0_TRACE_TRACE_MASK) >>
				      PMA_P0_TRACE_TRACE_OFFSET;
	*correlator_trace_p0 = (reg & PMA_P0_TRACE_CORR_TRACE_MASK) >>
				      PMA_P0_TRACE_CORR_TRACE_OFFSET;


	reg = pma_r32 ( gpon_bfd_slice_pdi_p1_trace );
	*trace_pattern_p1    = (reg & PMA_P1_TRACE_TRACE_MASK) >>
	 			      PMA_P1_TRACE_TRACE_OFFSET;
	*correlator_trace_p1 = (reg & PMA_P1_TRACE_CORR_TRACE_MASK) >>
				      PMA_P1_TRACE_CORR_TRACE_OFFSET;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mpd_update_get ( const enum optic_current_type
					       type,
					       const uint8_t int_coeff,
					       bool *update )
{
	static uint16_t bfd_cnt[2] = { 0, 0 };
	uint16_t bfd_cnt_new[2];
	uint16_t diff;

	uint32_t reg = pma_r32 ( gpon_bfd_slice_pdi_comparator_status );

	switch (type) {
	case OPTIC_BIAS:
		bfd_cnt_new[OPTIC_BIAS] =
			(reg & PMA_COMPARATOR_STATUS_P0_BFD_CNT_MASK)
			    >> PMA_COMPARATOR_STATUS_P0_BFD_CNT_OFFSET;
		break;
	case OPTIC_MOD:
		bfd_cnt_new[OPTIC_MOD]  =
			(reg & PMA_COMPARATOR_STATUS_P1_BFD_CNT_MASK)
			    >> PMA_COMPARATOR_STATUS_P1_BFD_CNT_OFFSET;
		break;
	default:
		return OPTIC_STATUS_ERR;
	}

	if (bfd_cnt_new[type] >= bfd_cnt[type]) {
		diff = bfd_cnt_new[type] - bfd_cnt[type];
	} else {
		/* 10 bit counters! */
		diff = bfd_cnt_new[type] + (0x3FF - bfd_cnt[type]);
	}

	if (diff >= (1 <<int_coeff) ) {
		bfd_cnt[type] = bfd_cnt_new[type];
		*update = true;
	} else {
		*update = false;
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mpd_saturation_write ( const uint16_t bias_sat,
					             const uint16_t mod_sat )
{
	uint32_t reg;

	reg = ((bias_sat << PMA_SATURATION_BIAS_SAT_OFFSET) &
	                    PMA_SATURATION_BIAS_SAT_MASK) |
	      ((mod_sat << PMA_SATURATION_MODULATION_SAT_OFFSET) &
	                   PMA_SATURATION_MODULATION_SAT_MASK);

	pma_w32 ( reg, gpon_bfd_slice_pdi_saturation );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mpd_saturation_read ( uint16_t *bias_sat,
					            uint16_t *mod_sat )
{
	uint32_t reg;

	if ((bias_sat == NULL) || (mod_sat == NULL))
		return OPTIC_STATUS_ERR;

	reg = pma_r32 ( gpon_bfd_slice_pdi_saturation );

	if (bias_sat != NULL)
		*bias_sat = (reg & PMA_SATURATION_BIAS_SAT_MASK) >>
					PMA_SATURATION_BIAS_SAT_OFFSET;

	if (mod_sat != NULL)
		*mod_sat = (reg & PMA_SATURATION_MODULATION_SAT_MASK) >>
					PMA_SATURATION_MODULATION_SAT_OFFSET;

	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_ll_mpd_bias_write ( const uint16_t dbias )
{
	uint32_t reg;

	reg = (dbias << PMA_DUAL_LOOP_BIAS_INIT_INIT_BIAS_OFFSET) &
	                PMA_DUAL_LOOP_BIAS_INIT_INIT_BIAS_MASK;
	pma_w32 ( reg, gpon_bfd_slice_pdi_dual_loop_bias_init );

	return OPTIC_STATUS_OK;
}
enum optic_errorcode optic_ll_mpd_biaslowsat_write ( const uint16_t dbias )
{
	uint32_t reg;

	reg = (dbias << PMA_DUAL_LOOP_BIASLOWSAT_CTRL_BIASLOW_SAT_OFFSET) &
					PMA_DUAL_LOOP_BIASLOWSAT_CTRL_BIASLOW_SAT_MASK;
	pma_w32 ( reg, gpon_bfd_slice_pdi_biaslowsat_ctrl );

	return OPTIC_STATUS_OK;
}

#if 0
enum optic_errorcode optic_ll_mpd_gain_toggle ()
{
	uint32_t gain_tia;
	uint32_t bfd_calib;
	uint32_t reg, reg_save;
	uint16_t a=100;
	reg_save = pma_r32 ( gpon_bfd_slice_pdi_gain_ctrl );
	reg=reg_save;
	gain_tia = (reg & PMA_GAIN_CTRL_GAIN_TIA_MASK);
	bfd_calib = (reg & PMA_GAIN_CTRL_BFD_CALIBRATION_MASK)>>PMA_GAIN_CTRL_BFD_CALIBRATION_OFFSET;
	while (a--){
		if (gain_tia==0)
			reg=(reg & ~PMA_GAIN_CTRL_GAIN_TIA_MASK)| 0x1;
		else
			reg=(reg & ~PMA_GAIN_CTRL_GAIN_TIA_MASK)| 0x1;
		if (bfd_calib==0)
			reg=(reg & ~PMA_GAIN_CTRL_BFD_CALIBRATION_MASK)| 0x1 << PMA_GAIN_CTRL_BFD_CALIBRATION_OFFSET;
		else
			reg=(reg & ~PMA_GAIN_CTRL_BFD_CALIBRATION_MASK)| 0x0 << PMA_GAIN_CTRL_BFD_CALIBRATION_OFFSET;
	}
	pma_w32 ( (reg_save & ~PMA_GAIN_CTRL_GAIN_TIA_MASK), gpon_bfd_slice_pdi_gain_ctrl );

	return OPTIC_STATUS_OK;
}
# endif
enum optic_errorcode optic_ll_mpd_bias_read ( uint16_t *dbias )
{
	uint32_t reg;

	if (dbias == NULL)
		return OPTIC_STATUS_ERR;

	reg = pma_r32 ( gpon_bfd_slice_pdi_dual_loop_bias_status );

	*dbias = (reg & PMA_DUAL_LOOP_BIAS_STATUS_ACTUAL_BIAS_MASK) >>
		        PMA_DUAL_LOOP_BIAS_STATUS_ACTUAL_BIAS_OFFSET;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mpd_bias_check ( bool *update )
{
	uint32_t reg;

	*update = false;

	reg = pma_r32 ( gpon_bfd_slice_pdi_dual_loop_bias_init );

	if (((reg & PMA_DUAL_LOOP_BIAS_INIT_INIT_BIAS_MASK) >>
	            PMA_DUAL_LOOP_BIAS_INIT_INIT_BIAS_OFFSET) == 0)
		*update = true;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mpd_mod_write ( const uint16_t dmod )
{
	uint32_t reg;

	reg = (dmod << PMA_DUAL_LOOP_MOD_INIT_INIT_MODULATION_OFFSET) &
		       PMA_DUAL_LOOP_MOD_INIT_INIT_MODULATION_MASK;
	pma_w32 ( reg, gpon_bfd_slice_pdi_dual_loop_mod_init );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mpd_mod_read ( uint16_t *dmod )
{
	uint32_t reg;

	if (dmod == NULL)
		return OPTIC_STATUS_ERR;

	reg = pma_r32 ( gpon_bfd_slice_pdi_dual_loop_mod_status );

	*dmod = (reg & PMA_DUAL_LOOP_MOD_STATUS_ACTUAL_MODULATION_MASK) >>
		       PMA_DUAL_LOOP_MOD_STATUS_ACTUAL_MODULATION_OFFSET;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mpd_mod_check ( bool *update )
{
	uint32_t reg;

	*update = false;

	reg = pma_r32 ( gpon_bfd_slice_pdi_dual_loop_mod_init );

	if (((reg & PMA_DUAL_LOOP_MOD_INIT_INIT_MODULATION_MASK) >>
	            PMA_DUAL_LOOP_MOD_INIT_INIT_MODULATION_OFFSET) == 0)
		*update = true;

	return OPTIC_STATUS_OK;
}

void optic_ll_mpd_ib_handle (uint32_t *ib_check_old, bool rw)
{
	if(rw == 0) {
		*ib_check_old = pma_r32 ( gpon_bfd_slice_pdi_p0_dual_loop ) & PMA_P0_DUAL_LOOP_P0_IB_CHECK; /* read ib_check */
		pma_w32_mask (PMA_P0_DUAL_LOOP_P0_IB_CHECK, 0x0,
				gpon_bfd_slice_pdi_p0_dual_loop); /* write 0 to ib_check */
	}
	else {
		pma_w32_mask (PMA_P0_DUAL_LOOP_P0_IB_CHECK, *ib_check_old,
				gpon_bfd_slice_pdi_p0_dual_loop); /* write back ib_check_old */
	}
}

void optic_ll_mpd_p0cnt_get(uint32_t *p0_cnt)
{
	*p0_cnt = pma_r32 ( gpon_bfd_slice_pdi_comparator_status );
	*p0_cnt &= (PMA_COMPARATOR_STATUS_P0_BFD_CNT_MASK) >> PMA_COMPARATOR_STATUS_P0_BFD_CNT_OFFSET;
}

enum optic_errorcode optic_ll_mpd_compstatus_get ( uint16_t *p0_cnt,
					           uint16_t *p1_cnt )
{
	uint32_t reg;

	if ((p0_cnt == NULL) || (p1_cnt == NULL))
		return OPTIC_STATUS_ERR;

	reg = pma_r32 ( gpon_bfd_slice_pdi_comparator_status );

	*p0_cnt = (reg & PMA_COMPARATOR_STATUS_P0_BFD_CNT_MASK) >>
		         PMA_COMPARATOR_STATUS_P0_BFD_CNT_OFFSET;

	*p1_cnt = (reg & PMA_COMPARATOR_STATUS_P0_BFD_CNT_MASK) >>
		         PMA_COMPARATOR_STATUS_P0_BFD_CNT_OFFSET;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mpd_powersave_set ( const enum optic_activation
                                                  powersave )
{
	if (powersave == OPTIC_ENABLE) {
		pma_w32_mask ( PMA_POWERSAVE_POWER_UP_OVR,
		               PMA_POWERSAVE_POWER_UP_EN,
	                       gpon_bfd_slice_pdi_powersave );

	} else {
		pma_w32_mask ( PMA_POWERSAVE_POWER_UP_EN,
		               PMA_POWERSAVE_POWER_UP_OVR,
	                       gpon_bfd_slice_pdi_powersave );

		pma_w32_mask ( PMA_GAIN_CTRL_PD_AUTO_DEMUX_ON |
		               PMA_GAIN_CTRL_PD_AUTO_P0LA_ON |
		               PMA_GAIN_CTRL_PD_AUTO_P1LA_ON, 0,
		               gpon_bfd_slice_pdi_gain_ctrl );
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mpd_powersave_get ( enum optic_activation
						  *powerdown )
{
	uint32_t reg;

	if (powerdown == NULL)
		return OPTIC_STATUS_ERR;

	reg = pma_r32 ( gpon_bfd_slice_pdi_powersave );

	if ((reg & PMA_POWERSAVE_POWER_UP_EN) &&
	    !(reg & PMA_POWERSAVE_POWER_UP_OVR))
		*powerdown = OPTIC_ENABLE;
	else
	if (!(reg & PMA_POWERSAVE_POWER_UP_EN) &&
	    (reg & PMA_POWERSAVE_POWER_UP_OVR))
		*powerdown = OPTIC_DISABLE;
	else {
		return OPTIC_STATUS_ERR;
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_mpd_gainctrl_set ( const uint8_t
						 tia_gain_selector,
                                                 const uint8_t
                                                 calibration_current )
{
	uint32_t reg;

	/* configure gain & calibration */
	reg = pma_r32 ( gpon_bfd_slice_pdi_gain_ctrl );
	reg &= ~(PMA_GAIN_CTRL_GAIN_TIA_MASK |
	         PMA_GAIN_CTRL_BFD_CALIBRATION_MASK);
	reg |= (((tia_gain_selector << PMA_GAIN_CTRL_GAIN_TIA_OFFSET) &
		                       PMA_GAIN_CTRL_GAIN_TIA_MASK) |
	        ((calibration_current << PMA_GAIN_CTRL_BFD_CALIBRATION_OFFSET) &
		                         PMA_GAIN_CTRL_BFD_CALIBRATION_MASK));
	pma_w32 ( reg, gpon_bfd_slice_pdi_gain_ctrl );

	return OPTIC_STATUS_OK;
}


void optic_ll_mpd_az_delay_set (uint8_t p0_az, uint8_t p1_az)
{
	pma_w32_mask ( PMA_P0_DUAL_LOOP_P0_AZ_DELAY_MASK,
			((p0_az << PMA_P0_DUAL_LOOP_P0_AZ_DELAY_OFFSET) &
			PMA_P0_DUAL_LOOP_P0_AZ_DELAY_MASK),
			gpon_bfd_slice_pdi_p0_dual_loop );
	pma_w32_mask ( PMA_P1_DUAL_LOOP_P1_AZ_DELAY_MASK,
			((p1_az << PMA_P1_DUAL_LOOP_P1_AZ_DELAY_OFFSET) &
			PMA_P1_DUAL_LOOP_P1_AZ_DELAY_MASK),
			gpon_bfd_slice_pdi_p1_dual_loop );
}

enum optic_errorcode optic_ll_mpd_az_delay_get (uint8_t *p0_az, uint8_t *p1_az)
{
	uint32_t reg;

	OPTIC_ASSERT_RETURN (p0_az != NULL, OPTIC_STATUS_ERR);
	OPTIC_ASSERT_RETURN (p1_az != NULL, OPTIC_STATUS_ERR);

	reg = pma_r32 ( gpon_bfd_slice_pdi_p0_dual_loop );
	*p0_az = (reg & PMA_P0_DUAL_LOOP_P0_AZ_DELAY_MASK) >>
			PMA_P0_DUAL_LOOP_P0_AZ_DELAY_OFFSET;
	reg = pma_r32 ( gpon_bfd_slice_pdi_p1_dual_loop );
	*p1_az = (reg & PMA_P1_DUAL_LOOP_P1_AZ_DELAY_MASK) >>
			PMA_P1_DUAL_LOOP_P1_AZ_DELAY_OFFSET;

	return OPTIC_STATUS_OK;
}

/** Enable or disable rogue alarms

\param iba_mode Inter-Burst Alarm on or off
\param ba_mode Intra-Burst Alarm on or off
\remark Calling this function assumes that power save is not set
*/
void optic_ll_mpd_rogue_int_set (
	const enum optic_activation iba_mode,
	const enum optic_activation ba_mode)
{
	uint32_t reg;

	optic_disable_irq (FALCON_IRQ_PMA_TX);
	/* reset internal state machine to clear interrupt sources */
	pma_w32_mask (PMA_P0_BFD_POWERSAVE_P0_POWER_SAVE_BFD_EN,
		PMA_P0_BFD_POWERSAVE_P0_POWER_SAVE_BFD_EN,
		gpon_bfd_slice_pdi_p0_bfd_powersave);
	/* wait at least on 311 MHz period */
	/* to reset the alarm, in A21 a 0 in the p0_alarm is sufficient
	 * That's why this is done at this position (for all chip versions)!*/
	pma_w32_mask (PMA_P0_DUAL_LOOP_P0_ALARM_MASK, 0,
		gpon_bfd_slice_pdi_p0_dual_loop);

	if (iba_mode == OPTIC_ENABLE || ba_mode == OPTIC_ENABLE)
		pma_w32_mask (PMA_P0_DUAL_LOOP_P0_ALARM_MASK,
			DEFAULT_DUAL_LOOP_ALARM <<
				PMA_P0_DUAL_LOOP_P0_ALARM_OFFSET,
			gpon_bfd_slice_pdi_p0_dual_loop);

	/* reset power save */
	pma_w32_mask (PMA_P0_BFD_POWERSAVE_P0_POWER_SAVE_BFD_EN, 0,
		gpon_bfd_slice_pdi_p0_bfd_powersave);
	/* Inter-Burst Alarm */
	if (iba_mode == OPTIC_ENABLE) {
		/* enable the interrupt */
		pma_inttx_w32_mask ( 0, PMA_INTTX_IRNEN_BP0IBA_EN, irnen);
		pma_w32_mask (PMA_P0_DUAL_LOOP_P0_IB_CHECK,
			PMA_P0_DUAL_LOOP_P0_IB_CHECK,
			gpon_bfd_slice_pdi_p0_dual_loop);
	} else {
		pma_inttx_w32_mask ( PMA_INTTX_IRNEN_BP0IBA_EN, 0, irnen);
		pma_w32_mask (PMA_P0_DUAL_LOOP_P0_IB_CHECK, 0,
			gpon_bfd_slice_pdi_p0_dual_loop);
		pma_w32_mask (PMA_P0_DUAL_LOOP_P0_IB_CHECK, 0,
			gpon_bfd_slice_pdi_p0_dual_loop);
	}
	/* Intra-Burst Alarm */
	if (ba_mode == OPTIC_ENABLE) {
		pma_inttx_w32_mask (0, PMA_INTTX_IRNEN_BP0BA_EN, irnen);
	} else {
		pma_inttx_w32_mask ( PMA_INTTX_IRNEN_BP0BA_EN, 0, irnen);
	}
	/* acknowledge any interrupts */
	reg = pma_inttx_r32 (irncr);
	/* did we miss anything? */
	pma_inttx_w32 ( reg, irncr);
	optic_enable_irq (FALCON_IRQ_PMA_TX);
}

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_MPD == ACTIVE))
enum optic_errorcode optic_ll_mpd_dump ( void )
{
	uint32_t reg;

	reg = pma_r32 ( gpon_bfd_slice_pdi_threshold_ctrl );
	OPTIC_DEBUG_WRN("MPD THRESHOLD_CTRL: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_threshold_sumctrl );
	OPTIC_DEBUG_WRN("MPD THRESHOLD_SUMCTRL: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_threshold_sum_persistency );
	OPTIC_DEBUG_WRN("MPD THRESHOLD_SUM_PERSISTENCY: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_saturation );
	OPTIC_DEBUG_WRN("MPD SATURATION: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_dual_loop_mod_init );
	OPTIC_DEBUG_WRN("MPD DUAL_LOOP_MOD_INIT: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_dual_loop_bias_init );
	OPTIC_DEBUG_WRN("MPD DUAL_LOOP_BIAS_INIT: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_dual_loop_mod_status );
	OPTIC_DEBUG_WRN("MPD DUAL_LOOP_MOD_STATUS: 0x%08X", reg);

 	reg = pma_r32 ( gpon_bfd_slice_pdi_dual_loop_bias_status );
	OPTIC_DEBUG_WRN("MPD DUAL_LOOP_BIAS_STATUS: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_loop_regulation_bias );
	OPTIC_DEBUG_WRN("MPD LOOP_REGULATION_BIAS: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_loop_regulation_modulation );
	OPTIC_DEBUG_WRN("MPD LOOP_REGULATION_MODULATION: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_tiaoffset );
	OPTIC_DEBUG_WRN("MPD TIAOFFSET: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_p0level );
	OPTIC_DEBUG_WRN("MPD P0LEVEL: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_p1level );
	OPTIC_DEBUG_WRN("MPD P1LEVEL: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_comparator_status );
	OPTIC_DEBUG_WRN("MPD COMPARATOR_STATUS: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_p0_dual_loop );
	OPTIC_DEBUG_WRN("MPD P0_DUAL_LOOP: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_p0_datapath );
	OPTIC_DEBUG_WRN("MPD P0_DATAPATH: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_p1_dual_loop );
	OPTIC_DEBUG_WRN("MPD P1_DUAL_LOOP: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_comparepattern );
	OPTIC_DEBUG_WRN("MPD COMPAREPATTERN: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_p1_datapath );
	OPTIC_DEBUG_WRN("MPD P1_DATAPATH: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_p1_bfd_powersave );
	OPTIC_DEBUG_WRN("MPD P1_BFD_POWERSAVE: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_p0_bfd_powersave );
	OPTIC_DEBUG_WRN("MPD P0_BFD_POWERSAVE: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_powersave );
	OPTIC_DEBUG_WRN("MPD POWERSAVE: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_p0_trace );
	OPTIC_DEBUG_WRN("MPD P0_TRACE: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_p1_trace );
	OPTIC_DEBUG_WRN("MPD P1_TRACE: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_data_delay );
	OPTIC_DEBUG_WRN("MPD DATA_DELAY: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_dac_ctrl );
	OPTIC_DEBUG_WRN("MPD DAC_CTRL: 0x%08X", reg);

	reg = pma_r32 ( gpon_bfd_slice_pdi_gain_ctrl );
	OPTIC_DEBUG_WRN("MPD GAIN_CTRL: 0x%08X", reg);

	return OPTIC_STATUS_OK;
}
#endif

/*! @} */
/*! @} */
