/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, PMA BERT Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_PMA_BERT_INTERNAL BERT Module - Internal
   @{
*/


#include "drv_optic_ll_bert.h"
#include "drv_optic_register.h"
#include "drv_optic_reg_pma.h"

enum optic_errorcode optic_ll_bert_init ( void )
{
	enum optic_errorcode ret;

	ret = optic_ll_bert_pattern_set ( 0xAAAAAAAA, 1, 1, 1, 1 );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	ret = optic_ll_bert_muxsel_set ( 2, 2, 2, 2 );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	ret = optic_ll_bert_analyzer_set ( OPTIC_DISABLE );
	if (ret != OPTIC_STATUS_OK)
	 	return ret;

	return ret;
}

enum optic_errorcode optic_ll_bert_analyzer_set ( const enum optic_activation
                                                  mode )
{
	pma_w32_mask ( PMA_BERT_CONTROL_ANALYZER_EN,
		       (mode == OPTIC_ENABLE) ? PMA_BERT_CONTROL_ANALYZER_EN: 0,
		       gpon_bert_pdi_bert_control );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_analyzer_get ( enum optic_activation *mode )
{
	uint32_t reg;

	if (mode == NULL)
		return OPTIC_STATUS_ERR;

	reg = pma_r32 (gpon_bert_pdi_bert_control);
	*mode = (reg & PMA_BERT_CONTROL_ANALYZER_EN) ?
		OPTIC_ENABLE : OPTIC_DISABLE;

	return OPTIC_STATUS_OK;
}

/** Toggles the BERT sync bit */
void optic_ll_bert_sync ()
{
	uint32_t reg;

	reg = pma_r32 (gpon_bert_pdi_bert_control);
	/* activate sync */
	pma_w32 (reg | PMA_BERT_CONTROL_SELFSYNC_EN,
			gpon_bert_pdi_bert_control );
	/* clear again, SW should be slow enough */
	pma_w32(reg, gpon_bert_pdi_bert_control);
}

enum optic_errorcode optic_ll_bert_muxsel_set ( const uint8_t muxsel1,
                                                const uint8_t muxsel2,
                                                const uint8_t muxsel3,
                                                const uint8_t muxsel4 )
{
	uint32_t clear, set;

	if ((muxsel1 > 3) || (muxsel2 > 3) || (muxsel3 > 3) || (muxsel4 > 3))
		return OPTIC_STATUS_POOR;

	clear = PMA_BERT_CONTROL_MUX_SEL1_MASK |
	        PMA_BERT_CONTROL_MUX_SEL2_MASK |
	        PMA_BERT_CONTROL_MUX_SEL3_MASK |
	        PMA_BERT_CONTROL_MUX_SEL4_MASK;
	set = ((muxsel1 << PMA_BERT_CONTROL_MUX_SEL1_OFFSET) &
			   PMA_BERT_CONTROL_MUX_SEL1_MASK) |
	      ((muxsel2 << PMA_BERT_CONTROL_MUX_SEL2_OFFSET) &
			   PMA_BERT_CONTROL_MUX_SEL2_MASK) |
	      ((muxsel3 << PMA_BERT_CONTROL_MUX_SEL3_OFFSET) &
			   PMA_BERT_CONTROL_MUX_SEL3_MASK) |
	      ((muxsel4 << PMA_BERT_CONTROL_MUX_SEL4_OFFSET) &
			   PMA_BERT_CONTROL_MUX_SEL4_MASK);

	pma_w32_mask ( clear, set, gpon_bert_pdi_bert_control);
	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_muxsel_get ( uint8_t *muxsel1,
                                                uint8_t *muxsel2,
                                                uint8_t *muxsel3,
                                                uint8_t *muxsel4 )
{
	uint32_t reg;

	if ((muxsel1 == NULL) || (muxsel2 == NULL) ||
	    (muxsel3 == NULL) || (muxsel4 == NULL))
		return OPTIC_STATUS_ERR;

	reg = pma_r32 (gpon_bert_pdi_bert_control);

	*muxsel1 = (reg & PMA_BERT_CONTROL_MUX_SEL1_MASK) >>
			  PMA_BERT_CONTROL_MUX_SEL1_OFFSET;
	*muxsel2 = (reg & PMA_BERT_CONTROL_MUX_SEL2_MASK) >>
			  PMA_BERT_CONTROL_MUX_SEL2_OFFSET;
	*muxsel3 = (reg & PMA_BERT_CONTROL_MUX_SEL3_MASK) >>
			  PMA_BERT_CONTROL_MUX_SEL3_OFFSET;
	*muxsel4 = (reg & PMA_BERT_CONTROL_MUX_SEL4_MASK) >>
			  PMA_BERT_CONTROL_MUX_SEL4_OFFSET;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_pattern_set ( const uint32_t pattern,
                                                 const uint8_t ecount1,
                                                 const uint8_t ecount2,
                                                 const uint8_t ecount3,
                                                 const uint8_t ecount4 )
{
	uint32_t reg;

	reg = (pattern << PMA_BERT_PATTERN_FIXEDIN_OFFSET) &
			  PMA_BERT_PATTERN_FIXEDIN_MASK;

	pma_w32 ( reg, gpon_bert_pdi_bert_pattern);

	reg = ((ecount1 << PMA_BERT_CNT_ENDCOUNTER_1_OFFSET) &
			   PMA_BERT_CNT_ENDCOUNTER_1_MASK) |
	      ((ecount2 << PMA_BERT_CNT_ENDCOUNTER_2_OFFSET) &
			   PMA_BERT_CNT_ENDCOUNTER_2_MASK) |
	      ((ecount3 << PMA_BERT_CNT_ENDCOUNTER_3_OFFSET) &
			   PMA_BERT_CNT_ENDCOUNTER_3_MASK) |
	      ((ecount4 << PMA_BERT_CNT_ENDCOUNTER_4_OFFSET) &
			   PMA_BERT_CNT_ENDCOUNTER_4_MASK);

	pma_w32 ( reg, gpon_bert_pdi_bert_cnt);

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_pattern_get ( uint32_t *pattern,
						 uint8_t *ecount1,
                                                 uint8_t *ecount2,
                                                 uint8_t *ecount3,
                                                 uint8_t *ecount4 )
{
	uint32_t reg;

	if (pattern == NULL)
		return OPTIC_STATUS_ERR;

	if ((ecount1 == NULL) || (ecount2 == NULL) ||
	    (ecount3 == NULL) || (ecount4 == NULL))
		return OPTIC_STATUS_ERR;

	reg = pma_r32 ( gpon_bert_pdi_bert_pattern );

	*pattern = (reg & PMA_BERT_PATTERN_FIXEDIN_MASK) >>
			  PMA_BERT_PATTERN_FIXEDIN_OFFSET;

	reg = pma_r32 (gpon_bert_pdi_bert_cnt);

	*ecount1 = (reg & PMA_BERT_CNT_ENDCOUNTER_1_MASK) >>
			  PMA_BERT_CNT_ENDCOUNTER_1_OFFSET;
	*ecount2 = (reg & PMA_BERT_CNT_ENDCOUNTER_2_MASK) >>
		   	  PMA_BERT_CNT_ENDCOUNTER_2_OFFSET;
	*ecount3 = (reg & PMA_BERT_CNT_ENDCOUNTER_3_MASK) >>
			  PMA_BERT_CNT_ENDCOUNTER_3_OFFSET;
	*ecount4 = (reg & PMA_BERT_CNT_ENDCOUNTER_4_MASK) >>
			  PMA_BERT_CNT_ENDCOUNTER_4_OFFSET;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_clk_set ( const uint8_t clk_period,
                                             const uint8_t clk_high )
{
	uint32_t reg;

	reg = ((clk_period << PMA_BERT_CLK_GENCLKPERIOD_OFFSET) &
			      PMA_BERT_CLK_GENCLKPERIOD_MASK) |
	      ((clk_high << PMA_BERT_CLK_GENCLKHI_OFFSET) &
			    PMA_BERT_CLK_GENCLKHI_MASK);

	pma_w32 ( reg, gpon_bert_pdi_bert_clk );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_clk_get ( uint8_t *clk_period,
                                             uint8_t *clk_high )
{
	uint32_t reg;

	if ((clk_period == NULL) || (clk_high == NULL))
		return OPTIC_STATUS_ERR;

	reg = pma_r32 ( gpon_bert_pdi_bert_clk );

	*clk_period = (reg & PMA_BERT_CLK_GENCLKPERIOD_MASK) >>
			     PMA_BERT_CLK_GENCLKPERIOD_OFFSET;
	*clk_high = (reg & PMA_BERT_CLK_GENCLKHI_MASK) >>
			   PMA_BERT_CLK_GENCLKHI_OFFSET;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_prbs_set ( const uint8_t prbsType )
{
	pma_w32_mask ( PMA_BERT_CONTROL_PRBS_SEL_MASK,
		       (prbsType << PMA_BERT_CONTROL_PRBS_SEL_OFFSET) &
				    PMA_BERT_CONTROL_PRBS_SEL_MASK,
		       gpon_bert_pdi_bert_control );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_prbs_get ( uint8_t *prbs_type )
{
	uint32_t reg;

	if (prbs_type == NULL)
		return OPTIC_STATUS_ERR;

	reg = pma_r32 ( gpon_bert_pdi_bert_control );

	*prbs_type = (reg & PMA_BERT_CONTROL_PRBS_SEL_MASK) >>
			    PMA_BERT_CONTROL_PRBS_SEL_OFFSET;
	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_speed_set ( const bool speedrate_high_tx,
                                               const bool speedrate_high_rx )
{
	uint32_t clear = PMA_BERT_CONTROL_MODE_2G5_TX |
	                 PMA_BERT_CONTROL_MODE_2G5_RX;
	uint32_t set =0;

	if (speedrate_high_tx == true)
		set |= PMA_BERT_CONTROL_MODE_2G5_TX;

	if (speedrate_high_rx == true)
		set |= PMA_BERT_CONTROL_MODE_2G5_RX;

	pma_w32_mask ( clear, set, gpon_bert_pdi_bert_control );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_speed_get ( bool *speedrate_high_tx,
                                               bool *speedrate_high_rx )
{
	uint32_t reg;

	if ((speedrate_high_tx == NULL) || (speedrate_high_rx == NULL))
		return OPTIC_STATUS_ERR;

	reg = pma_r32 ( gpon_bert_pdi_bert_control );

	*speedrate_high_tx = (reg & PMA_BERT_CONTROL_MODE_2G5_TX)? true : false;
	*speedrate_high_rx = (reg & PMA_BERT_CONTROL_MODE_2G5_RX)? true : false;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_loop_set ( const enum optic_activation mode )
{

	pma_w32_mask ( PMA_BERT_CONTROL_LOOPBACK_ENABLE,
		       (mode == OPTIC_ENABLE) ?
		       PMA_BERT_CONTROL_LOOPBACK_ENABLE: 0,
		       gpon_bert_pdi_bert_control );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_loop_get ( enum optic_activation *mode )
{
	uint32_t reg;

	if (mode == NULL)
		return OPTIC_STATUS_ERR;

	reg = pma_r32 (gpon_bert_pdi_bert_control);
	*mode = (reg & PMA_BERT_CONTROL_LOOPBACK_ENABLE) ?
		OPTIC_ENABLE : OPTIC_DISABLE;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_counter_get ( uint32_t *word_cnt,
						 uint32_t *error_cnt )
{
	if (word_cnt != NULL)
		*word_cnt = pma_r32 (gpon_bert_pdi_bert_wrdcnt);

	if (error_cnt != NULL)
		*error_cnt = pma_r32 (gpon_bert_pdi_bert_errcnt);

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_bert_counter_config ( const enum optic_bert_cnt
						    mode )
{
	uint32_t reg;

	switch (mode) {
	case OPTIC_BERTCNT_RESET:
		reg = PMA_BERT_STATUSCTRL_WORD_RESET |
		      PMA_BERT_STATUSCTRL_ERROR_RESET;
		break;
	case OPTIC_BERTCNT_FREEZE:
		reg = PMA_BERT_STATUSCTRL_COUNTER_FREEZE;
		break;
	case OPTIC_BERTCNT_RUN:
		reg = 0;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	pma_w32 (reg, gpon_bert_pdi_bert_statusctrl);

	return OPTIC_STATUS_OK;
}


/*! @} */
/*! @} */
