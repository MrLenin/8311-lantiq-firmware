/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, BERT Interface - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_BERT_INTERNAL BERT Interface - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_bert_interface.h"

#include "drv_optic_mpd.h"
#include "drv_optic_register.h"
#include "drv_optic_ll_bert.h"
#include "drv_optic_ll_tx.h"
#include "drv_optic_ll_gtc.h"
#include "drv_optic_ll_pll.h"

/**
	The bert_cfg_set function is used to provide configurations for the
	BERT unit within the GOI module.

	\param param.pattern_mode           this parameter selects, if the BERT
	                                    pattern generator/receiver shall be
	                                    used (0) or the GTCPMAIF buffer (1).
	\param param.pattern_type           selects 4 pattern types for the
	                                    BERT pattern generator.
					    = 0: clock pattern (configurable
					         frequency and duty cycle)
                    			    = 1: PRBS pattern (multiple types)
                     			    = 2: fixed pattern (32 bit)
					    = 3: all-zero
	\param param.pattern_length         selects the length of each part of
	     				    the BERT pattern
	\param param.fixed_pattern          fixed pattern definition
	\param param.clock_period           selects the period of a clock
	                                    sub-pattern
	\param param.clock_high             selects the clock sub-pattern
					    duty cycle
	\param param.prbs_type              selects the PRBS pattern type
	\param param.datarate_tx_high       selects the transmit data rate
						- false: 1.244 Gbit/s
						- true : 2.488 Gbit/s
	\param param.datarate_rx_high       selects the treceive data rate
						- false: 1.244 Gbit/s
						- true : 2.488 Gbit/s
	\param param.loop_enable            enables loop back of transmitted
					    data to the receiver

	- pattern_type:
		(0): 1st part of the pattern -> BERT_CONTROL.mux_sel1
		(1): 2nd part of the pattern -> BERT_CONTROL.mux_sel2
                (2): 3rd part of the pattern -> BERT_CONTROL.mux_sel3
                (3): 4th part of the pattern -> BERT_CONTROL.mux_sel4
	- pattern_length:
		if (pattern_mode == 0)
			(0): write to BERT_CNT.endcounter_1
			(1): write to BERT_CNT.endcounter_2
			(2): write to BERT_CNT.endcounter_3
			(3): write to BERT_CNT.endcounter_4
		if (pattern_mode == 1)
			pattern_length[0] -> GTCPMAIF.LTSC.LEN
	- fixed_pattern:
		if (pattern_mode == 0)
			fixed_pattern[0] -> BERT_PATTERN.fixedin
		if (pattern_mode == 1)
			fixed_pattern[0] -> GTCPMAIF.LTSDATA0
			fixed_pattern[1] -> GTCPMAIF.LTSDATA1
			...
			fixed_pattern[19] -> GTCPMAIF.LTSDATA19
	- clock_period: -> BERT_CLK.genclkperiod
	- clock_high: -> BERT_CLK.genclkhi
	- prbs_type:
      switch(nPrbsType):
		- case(7) : BERT_CONTROL.prbs_sel = 7
		- case(11): BERT_CONTROL.prbs_sel = 11
		- case(15): BERT_CONTROL.prbs_sel = 15
		- case(18): BERT_CONTROL.prbs_sel = 18
		- case(21): BERT_CONTROL.prbs_sel = 21
		- case(23): BERT_CONTROL.prbs_sel = 23
		- case(31): BERT_CONTROL.prbs_sel = 31
		- default: error message
	- datarate_tx_high:
		- true : BERT_CONTROL.MODE_2G5_TX = 1
		- false: BERT_CONTROL.MODE_2G5_TX = 0
	- datarate_rx_high
		- true : BERT_CONTROL.MODE_2G5_RX = 1
		- false: BERT_CONTROL.MODE_2G5_RX = 0
	- loop_enable:
		- true : BERT_CONTROL.LOOPBACK_ENABLE = 1
		- false: BERT_CONTROL.LOOPBACK_ENABLE = 0

*/
enum optic_errorcode bert_cfg_set ( struct optic_device *p_dev,
                                    const struct optic_bert_cfg *param )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint32_t fixed_pattern[20];
	uint8_t i;
	(void) p_dev;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	switch (param->pattern_mode) {
	case 0:
		ret = optic_ll_bert_analyzer_set ( OPTIC_ENABLE );
		fixed_pattern[0] = (param->fixed_pattern[0] << 24) |
				   (param->fixed_pattern[1] << 16) |
				   (param->fixed_pattern[2] << 8) |
				   (param->fixed_pattern[3]);

		break;
	case 1:
		ret = optic_ll_bert_analyzer_set ( OPTIC_DISABLE );
		for (i=0; i<(param->pattern_length[0]+3)/4; i++) {
			fixed_pattern[i] = (param->fixed_pattern[i+0] << 24) |
					   (param->fixed_pattern[i+1] << 16) |
					   (param->fixed_pattern[i+2] << 8) |
					   (param->fixed_pattern[i+3]);
		}

		break;
	default:
		return OPTIC_STATUS_POOR;
	}
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_bert_muxsel_set ( param->pattern_type[0],
                                               param->pattern_type[1],
                                               param->pattern_type[2],
                                               param->pattern_type[3] );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (param->pattern_mode == 0) {
		/* BERT mode */
		ret = optic_ll_bert_pattern_set ( fixed_pattern[0],
						    param->pattern_length[0],
						    param->pattern_length[1],
						    param->pattern_length[2],
						    param->pattern_length[3] );
	} else {
		/* GTC-PMA mode */
		ret = optic_ll_gtc_pattern_config_set ( OPTIC_PATTERNMODE_BERT,
							fixed_pattern,
							param->pattern_length[0]
							);
	}
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_bert_clk_set ( param->clock_period,
					    param->clock_high );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_bert_prbs_set ( param->prbs_type );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_bert_speed_set ( param->datarate_tx_high,
                                              param->datarate_rx_high );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (param->loop_enable)
		ret = optic_ll_bert_loop_set (OPTIC_ENABLE );
	else
		ret = optic_ll_bert_loop_set (OPTIC_DISABLE );

	return ret;
}

/**
   The bert_cfg_get function is used to read back the basic configuration
   of measurement unit within the GOI module.

   Hardware programming details: See bert_cfg_set.
*/
enum optic_errorcode bert_cfg_get ( struct optic_device *p_dev,
                                    struct optic_bert_cfg *param)
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	enum optic_activation mode;
	enum optic_patternmode gtc_mode;
	uint32_t fixed_pattern[20];
	uint8_t i;
	(void) p_dev;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset(param, 0x00, sizeof(struct optic_bert_cfg));

	ret = optic_ll_bert_analyzer_get ( &mode );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	param->pattern_mode = (mode == OPTIC_ENABLE) ? 0 : 1;

	ret = optic_ll_bert_muxsel_get ( &(param->pattern_type[0]),
					       &(param->pattern_type[1]),
                                               &(param->pattern_type[2]),
                                               &(param->pattern_type[3]) );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (param->pattern_mode == 0) {
		/* BERT mode */
		ret = optic_ll_bert_pattern_get (
						&(fixed_pattern[0]),
						&(param->pattern_length[0]),
		 				&(param->pattern_length[1]),
                                                &(param->pattern_length[2]),
                                                &(param->pattern_length[3]) );

                param->fixed_pattern[0] = (fixed_pattern[0] >> 24) & 0xFF;
                param->fixed_pattern[1] = (fixed_pattern[0] >> 16) & 0xFF;
                param->fixed_pattern[2] = (fixed_pattern[0] >> 8) & 0xFF;
                param->fixed_pattern[3] = (fixed_pattern[0]) & 0xFF;

	} else {
		/* GTC-PMA mode */
		ret = optic_ll_gtc_pattern_config_get ( &gtc_mode,
							fixed_pattern,
							&(param->
							   pattern_length[0]) );

		if (gtc_mode != OPTIC_PATTERNMODE_BERT)
			ret = OPTIC_STATUS_ERR;
		else {
			for (i=0; i<(param->pattern_length[0]+3)/4; i++) {

				if (i >= sizeof(fixed_pattern))
					break;

				if ((i*4 +3) >=
				    ((uint8_t) sizeof(param->fixed_pattern)))
					break;

				param->fixed_pattern[i*4 +0] =
						(fixed_pattern[i] >> 24) & 0xFF;
                		param->fixed_pattern[i*4 +1] =
                				(fixed_pattern[i] >> 16) & 0xFF;
                		param->fixed_pattern[i*4 +2] =
                				(fixed_pattern[i] >> 8) & 0xFF;
                		param->fixed_pattern[i*4 +3] =
                				(fixed_pattern[i]) & 0xFF;
			}
		}
	}
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_bert_clk_get ( &param->clock_period,
                                	    &param->clock_high );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_bert_prbs_get ( &param->prbs_type );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_bert_speed_get ( &param->datarate_tx_high,
                                              &param->datarate_rx_high );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_bert_loop_get ( &mode );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	param->loop_enable = (mode == OPTIC_ENABLE) ? true : false;

	return ret;
}

/**
   The bert_enable function is used to enable the
   BERT unit within the GOI module.

*/
enum optic_errorcode bert_enable ( struct optic_device *p_dev )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	bool invert;

	ret = optic_ll_bert_counter_config (OPTIC_BERTCNT_RESET);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (is_falcon_chip_a1x())
		invert = true;
	else
		invert = !(p_ctrl->config.bias_polarity_regular);
	
	/* bias path: flip, invert, burst, power forced */
	optic_ll_tx_path_activate (OPTIC_BIAS, invert);
	if (p_ctrl->config.mode == OPTIC_BOSA &&
		is_falcon_chip_a1x() &&
		p_ctrl->config.bias_polarity_regular == 0)
		/* BIASPATH bit 3 is not working in A12, 
		   therefore data_prg = 0 */
		optic_ll_tx_biaspath_data_set (0);
	else
		optic_ll_tx_biaspath_data_set (0xF);
	/* invert modulation polarity is mode dependend */
	if (p_ctrl->config.mode == OPTIC_OMU)
		invert = !p_ctrl->config.mod_polarity_regular;
	else
		invert = p_ctrl->config.mod_polarity_regular;

	/* data path: flip, invert, burst, power forced */
	optic_ll_tx_path_activate (OPTIC_MOD, invert);

	ret = optic_ll_bert_analyzer_set (OPTIC_ENABLE);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/* activate data/bias path for bert */
	/* only for datapath enable bert! */
	ret = optic_ll_tx_path_bert_set (OPTIC_ENABLE);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_bert_counter_config (OPTIC_BERTCNT_RUN);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

/**
   The bert_disable function is used to disable the
   BERT unit within the GOI module.
   It restores the invert bit settings
*/
enum optic_errorcode bert_disable ( struct optic_device *p_dev )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret = OPTIC_STATUS_OK;

	ret = optic_ll_bert_counter_config ( OPTIC_BERTCNT_FREEZE );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/* reset values */
	optic_ll_tx_path_init (p_ctrl->config.mode,
		!p_ctrl->config.bias_polarity_regular, 
		!p_ctrl->config.mod_polarity_regular);

	ret = optic_ll_bert_analyzer_set (OPTIC_DISABLE);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/* activate data/bias path for bert */
	ret = optic_ll_tx_path_bert_set (OPTIC_DISABLE);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

/**
   The bert_synchronize function is used to force synchronisation of the
   received PRBS pattern to the internal PRBS generator within the GOI module.

*/
enum optic_errorcode bert_synchronize ( struct optic_device *p_dev )
{
	(void) p_dev;

	optic_ll_bert_sync ();
	return OPTIC_STATUS_OK;
}


/**
   The bert_status_get function is used to read back the status
   of measurement unit within the GOI module.

*/
enum optic_errorcode bert_status_get ( struct optic_device *p_dev,
                                       struct optic_bert_status *param )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	enum optic_activation mode;
	(void) p_dev;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset(param, 0x00, sizeof(struct optic_bert_status));

	ret = optic_ll_bert_analyzer_get ( &mode );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	param->bert_enable = (mode == OPTIC_ENABLE) ? true : false;

	ret = optic_ll_bert_counter_get ( &(param->word_cnt),
	                                        &(param->error_cnt) );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return OPTIC_STATUS_OK;
}

/**
   The bert_mode_set function is used to set one of the basic BERT
   configurations.

*/
enum optic_errorcode bert_mode_set ( struct optic_device *p_dev,
                                     const struct optic_bert_mode *param )
{
	struct optic_bert_cfg bert_cfg;
	uint8_t i;

	bert_cfg.pattern_mode = 0;

	switch (param->mode) {
	case OPTIC_BERT_CONST_ZERO:
		for (i=0; i<4; i++) {
			bert_cfg.pattern_type[i] = 2;
			bert_cfg.pattern_length[i] = 1;
			bert_cfg.fixed_pattern[i] = 0;
		}
		bert_cfg.clock_period = 0;
		bert_cfg.clock_high = 0;
		bert_cfg.prbs_type = 0;
		bert_cfg.datarate_tx_high = false;
		bert_cfg.datarate_rx_high = false;
		bert_cfg.loop_enable = false;
		break;
	case OPTIC_BERT_CONST_ONE:
		for (i=0; i<4; i++) {
			bert_cfg.pattern_type[i] = 2;
			bert_cfg.pattern_length[i] = 1;
			bert_cfg.fixed_pattern[i] = 255;
		}
		bert_cfg.clock_period = 0;
		bert_cfg.clock_high = 0;
		bert_cfg.prbs_type = 0;
		bert_cfg.datarate_tx_high = false;
		bert_cfg.datarate_rx_high = false;
		bert_cfg.loop_enable = false;
		break;
	case OPTIC_BERT_CLOCK:
		for (i=0; i<4; i++) {
			bert_cfg.pattern_type[i] = 0;
			bert_cfg.pattern_length[i] = 0;
			bert_cfg.fixed_pattern[i] = 0;
		}
		bert_cfg.pattern_length[0] = 2;

		bert_cfg.clock_period = 4;
		bert_cfg.clock_high = 2;
		bert_cfg.prbs_type = 0;
		bert_cfg.datarate_tx_high = false;
		bert_cfg.datarate_rx_high = true;
		bert_cfg.loop_enable = false;
		break;
	case OPTIC_BERT_PRBS7:
	case OPTIC_BERT_PRBS11:
	case OPTIC_BERT_PRBS15:
	case OPTIC_BERT_PRBS18:
	case OPTIC_BERT_PRBS21:
	case OPTIC_BERT_PRBS23:
	case OPTIC_BERT_PRBS31:
		for (i=0; i<4; i++) {
			bert_cfg.pattern_type[i] = 1;
			bert_cfg.pattern_length[i] = 2;
			bert_cfg.fixed_pattern[i] = 0;
		}
		bert_cfg.clock_period = 0;
		bert_cfg.clock_high = 0;
		bert_cfg.prbs_type = param->mode;
		bert_cfg.datarate_tx_high = false;
		bert_cfg.datarate_rx_high = false;
		bert_cfg.loop_enable = false;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return bert_cfg_set ( p_dev, &bert_cfg );
}

/**
   The bert counters are resetted.

*/
enum optic_errorcode bert_counter_reset ( struct optic_device *p_dev )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	(void) p_dev;

	ret = optic_ll_bert_counter_config ( OPTIC_BERTCNT_RESET );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_bert_counter_config ( OPTIC_BERTCNT_RUN );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}
/* ------------------------------------------------------------------------- */

const struct optic_entry bert_function_table[OPTIC_BERT_MAX] =
{
/*  0 */  TE1in  (FIO_BERT_CFG_SET,     sizeof(struct optic_bert_cfg),
					bert_cfg_set),
/*  1 */  TE1out (FIO_BERT_CFG_GET,     sizeof(struct optic_bert_cfg),
					bert_cfg_get),
/*  2 */  TE0    (FIO_BERT_ENABLE,      bert_enable),
/*  3 */  TE0    (FIO_BERT_DISABLE,     bert_disable),
/*  4 */  TE0    (FIO_BERT_SYNC,        bert_synchronize),
/*  5 */  TE1out (FIO_BERT_STATUS_GET,  sizeof(struct optic_bert_status),
					bert_status_get),
/*  6 */  TE1in  (FIO_BERT_MODE_SET,    sizeof(struct optic_bert_mode),
					bert_mode_set),
/*  7 */  TE0    (FIO_BERT_CNT_RESET,   bert_counter_reset),
};

/*! @} */

/*! @} */
