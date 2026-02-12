/******************************************************************************

                               Copyright (c) 2010
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, PMA TX Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_TX_INTERNAL Transmit Module - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_register.h"
#include "drv_optic_ll_rx.h"
#include "drv_optic_ll_tx.h"
#include "drv_optic_reg_pma.h"

/**
    Initialize data/bias path in transmit direction.

   \param   mode Optical interface operation mode
   \param   bias_invert  enable or disable inverting of data on bias
   \param   mod_invert  enable or disable inverting of data on modulation

   \return
   - OPTIC_STATUS_OK - success,

*/
enum optic_errorcode optic_ll_tx_path_init (const enum optic_manage_mode mode,
	const bool bias_invert, const bool mod_invert)
{
	uint32_t reg;

	/* bias path: flip, invert=bias_polarity (1=invert), 
	   no burst, power from GTC */
	reg = pma_r32 (gpon_tx_slice_pdi_biaspath);
	reg &= ~(PMA_BIASPATH_BIAS_INV |
		PMA_BIASPATH_POWER_UP_OVR | 
		PMA_BIASPATH_BURST_VALID_PRG_EN |
		PMA_BIASPATH_BIAS_PRG_EN | 
		PMA_BIASPATH_BIAS_PRG_DATA_MASK);
	reg |= PMA_BIASPATH_BIAS_FLIP;

	if (bias_invert == true)
		reg |= PMA_BIASPATH_BIAS_INV;
	pma_w32 (reg, gpon_tx_slice_pdi_biaspath);

	/* data path: flip, invert=mod_polarity (1=invert), 
	   no burst, power from GTC */
	reg = pma_r32 (gpon_tx_slice_pdi_datapath);
	reg &= ~(PMA_DATAPATH_DATA_INV | 
		 PMA_DATAPATH_BURST_VALID_PRG_EN |
		 PMA_DATAPATH_POWER_UP_OVR |
		 PMA_DATAPATH_DATA_PRG_EN |
		PMA_DATAPATH_DATA_PRG_DATA_MASK);
	reg |= PMA_DATAPATH_DATA_FLIP;

	/* do not invert for BOSA */
	if ((mod_invert == true && mode == OPTIC_OMU) || 
		(mod_invert == false && mode == OPTIC_BOSA))
		reg |= PMA_DATAPATH_DATA_INV;

	pma_w32 ( reg, gpon_tx_slice_pdi_datapath);
	/* bias path sending to BERT enabled/disabled */
	pma_w32_mask (PMA_BIASPATH_BERT, 0, gpon_tx_slice_pdi_biaspath);

	return OPTIC_STATUS_OK;
}

/**
    Configure data/bias path in transmit direction.

   \param   type  BIAS or MODULATION (data) path
   \param   burst  enable or disable burst valid mode
   \param   power_up  enable or disable power up
   \param   flip  enable or disable flipping of LSB and MSB
   \param   invert  enable or disable inverting of data
*/
void optic_ll_tx_path_activate (const enum optic_current_type type,
                                const bool invert)
{
	uint32_t reg;

	switch (type) {
	case OPTIC_BIAS:
		/* set bias path ctrl */
		reg = pma_r32 (gpon_tx_slice_pdi_biaspath);

		if (invert == true)
			reg |= PMA_BIASPATH_BIAS_INV;
		else
			reg &= ~PMA_BIASPATH_BIAS_INV;
		reg |= PMA_BIASPATH_BURST_VALID_PRG_EN | 
			PMA_BIASPATH_POWER_UP_OVR;
		pma_w32 ( reg, gpon_tx_slice_pdi_biaspath);
		break;
	case OPTIC_MOD:
		/* set data path ctrl */
		reg = pma_r32 (gpon_tx_slice_pdi_datapath);

		if (invert == true)
			reg |= PMA_DATAPATH_DATA_INV;
		else
			reg &= ~PMA_DATAPATH_DATA_INV;

		reg |= PMA_DATAPATH_BURST_VALID_PRG_EN |
			PMA_DATAPATH_POWER_UP_OVR;
		pma_w32 ( reg, gpon_tx_slice_pdi_datapath);
		break;
	}
}

/**
    Configure bias path data.

   \param   activate - set to true to activate otherwise false
   \param   data - data to send
*/
void optic_ll_tx_biaspath_data_set (const uint8_t data)
{
	uint32_t reg;

	/* set bias path ctrl */
	reg = pma_r32 (gpon_tx_slice_pdi_biaspath);
	reg &= ~(PMA_BIASPATH_BIAS_PRG_EN | 
		PMA_BIASPATH_BIAS_PRG_DATA_MASK);
	reg |= ((data << PMA_BIASPATH_BIAS_PRG_DATA_OFFSET) &
		PMA_BIASPATH_BIAS_PRG_DATA_MASK) |
		PMA_BIASPATH_BIAS_PRG_EN;

	pma_w32 (reg, gpon_tx_slice_pdi_biaspath);
}

/**
    Configure data bert sending.

   \param   bert_data  data path sending to BERT enabled/disabled

   \return
   - OPTIC_STATUS_OK - success,

*/
enum optic_errorcode optic_ll_tx_path_bert_set (const enum optic_activation
						bert_data)
{
	pma_w32_mask ( PMA_DATAPATH_BERT, (bert_data == OPTIC_ENABLE) ?
	               PMA_DATAPATH_BERT : 0, gpon_tx_slice_pdi_datapath );

	return OPTIC_STATUS_OK;
}


/**
   Configure TX Fifo.

   \param dalay_enable TX fifo start configuration (in bits)
   \param delay_disable TX fifo stop configuration (in bits)
   \param size_fifo TX fifo size configuration (in bits)

      Configure Tx start/stop offset values for Tx FIFO, from goi config file
      Values given in number of bit, programming in number of nibbles.
      tmp = (
         ELEM_GPON_TX_SLICE_PDI_LASER_ENABLE_ENABLE_DELAY(delay_tx_enable/4)|
         ELEM_GPON_TX_SLICE_PDI_LASER_ENABLE_DISABLE_DELAY(delay_tx_disable/4)|
         ELEM_GPON_TX_SLICE_PDI_LASER_ENABLE_BUFFER_SIZE(nTxEnableFifoSize/4));
      io_write(ADR_GPON_TX_SLICE_PDI_LASER_ENABLE, tmp);

   \return
   - OPTIC_STATUS_OK - success,
*/

enum optic_errorcode optic_ll_tx_fifo_set ( const int16_t delay_enable,
                                            const uint16_t delay_disable,
                                            const uint16_t size_fifo )
{
	uint32_t reg;

	uint8_t delay_enable_nibble = ((abs(delay_enable) + 2) >> 2);
	uint8_t delay_disable_nibble = ((delay_disable + 2) >> 2);
	uint16_t size_fifo_nibble = ((size_fifo + 2) >> 2);

	if(is_falcon_chip_a2x()) {
		reg = ((size_fifo_nibble << PMA_LASER_ENABLE_BUFFER_SIZE_OFFSET) &
			            PMA_LASER_ENABLE_BUFFER_SIZE_MASK_A21) |
	      ((delay_disable_nibble << PMA_LASER_ENABLE_DISABLE_DELAY_OFFSET) &
		                        PMA_LASER_ENABLE_DISABLE_DELAY_MASK) |
	      ((delay_enable_nibble << PMA_LASER_ENABLE_ENABLE_DELAY_OFFSET) &
	                               PMA_LASER_ENABLE_ENABLE_DELAY_MASK);
		if(delay_enable < 0)
			reg |= (1 << PMA_LASER_ENABLE_NEG_ENABLE_DELAY_OFFSET_A21);
	} else {
		reg = ((size_fifo_nibble << PMA_LASER_ENABLE_BUFFER_SIZE_OFFSET) &
				            PMA_LASER_ENABLE_BUFFER_SIZE_MASK) |
		      ((delay_disable_nibble << PMA_LASER_ENABLE_DISABLE_DELAY_OFFSET) &
			                        PMA_LASER_ENABLE_DISABLE_DELAY_MASK) |
		      ((delay_enable_nibble << PMA_LASER_ENABLE_ENABLE_DELAY_OFFSET) &
		                               PMA_LASER_ENABLE_ENABLE_DELAY_MASK);
	}
	pma_w32 ( reg, gpon_tx_slice_pdi_laser_enable );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_tx_fifo_get ( int16_t *delay_enable,
                                            uint16_t *delay_disable,
                                            uint16_t *size_fifo )
{
	uint32_t reg;

	int16_t delay_enable_nibble;
	uint8_t delay_disable_nibble;
	uint16_t size_fifo_nibble;

	reg = pma_r32 ( gpon_tx_slice_pdi_laser_enable );

	if(is_falcon_chip_a2x())
		size_fifo_nibble = (reg & PMA_LASER_ENABLE_BUFFER_SIZE_MASK_A21) >>
	                          PMA_LASER_ENABLE_BUFFER_SIZE_OFFSET;
	else
		size_fifo_nibble = (reg & PMA_LASER_ENABLE_BUFFER_SIZE_MASK) >>
	                          PMA_LASER_ENABLE_BUFFER_SIZE_OFFSET;
	delay_disable_nibble = (reg & PMA_LASER_ENABLE_DISABLE_DELAY_MASK) >>
	                              PMA_LASER_ENABLE_DISABLE_DELAY_OFFSET;

	delay_enable_nibble = (reg & PMA_LASER_ENABLE_ENABLE_DELAY_MASK) >>
	                             PMA_LASER_ENABLE_ENABLE_DELAY_OFFSET;

	if(is_falcon_chip_a2x()) {
		if ((reg & PMA_LASER_ENABLE_NEG_ENABLE_DELAY_MASK_A21)
				>> PMA_LASER_ENABLE_NEG_ENABLE_DELAY_OFFSET_A21 )
			delay_enable_nibble = -delay_enable_nibble;
	}

	if (delay_enable)
		*delay_enable = delay_enable_nibble * 4;

	if (delay_disable)
		*delay_disable = delay_disable_nibble * 4;

	if (size_fifo)
		*size_fifo = size_fifo_nibble * 4;

	return OPTIC_STATUS_OK;
}



void optic_ll_tx_pi_set ( const uint32_t pi_ctrl )
{
	bool enable;

	pma_w32 ( pi_ctrl, gpon_tx_slice_pdi_pi_ctrl );

	enable = ((pi_ctrl & PMA_PI_CTRL_PI_EN) == PMA_PI_CTRL_PI_EN) ?
	         true : false;

	pma_w32_mask ( PMA_MODULATOR_1_MOD_EN,
		       (enable)? PMA_MODULATOR_1_MOD_EN : 0,
		       gpon_tx_slice_pdi_modulator_1);

}


 void optic_ll_tx_delay_set ( const uint8_t data_delay,
					     const uint8_t intrinsic_delay )
{
	uint32_t reg;

	/* configure data delay */
	reg = ((data_delay << PMA_DATA_DELAY_DATA_DELAY_OFFSET) &
	                      PMA_DATA_DELAY_DATA_DELAY_MASK) |
	      ((intrinsic_delay << PMA_DATA_DELAY_INTRINSIC_DELAY_OFFSET) &
		                   PMA_DATA_DELAY_INTRINSIC_DELAY_MASK);

	pma_w32 ( reg, gpon_tx_slice_pdi_data_delay );
}


void optic_ll_tx_powersave_set ( const enum optic_activation
                                                 powersave )
{
	if (powersave == OPTIC_ENABLE)
		pma_w32_mask ( 0, PMA_DATA_DELAY_EN_PMD_TX_PD,
			       gpon_tx_slice_pdi_data_delay );
	else
		pma_w32_mask ( PMA_DATA_DELAY_EN_PMD_TX_PD, 0,
			       gpon_tx_slice_pdi_data_delay );
}

#ifdef CONFIG_WITH_FALCON_A2X
enum optic_errorcode optic_ll_tx_pd_latchoverride_set (
						const enum optic_activation override )
{
	if (override == OPTIC_ENABLE)
		pma_w32_mask ( 0, PMA_DATA_DELAY_EN_PMD_TX_PD_LATCHOR_MASK_A21,
			       gpon_tx_slice_pdi_data_delay );
	else
		pma_w32_mask ( PMA_DATA_DELAY_EN_PMD_TX_PD_LATCHOR_MASK_A21, 0,
			       gpon_tx_slice_pdi_data_delay );

	return OPTIC_STATUS_OK;
}
#endif

enum optic_errorcode optic_ll_tx_laserdelay_set ( const uint8_t bitdelay )
{
	uint32_t reg = bitdelay;

	if (bitdelay > 0x7)
		return OPTIC_STATUS_POOR;

	pma_w32 ( reg, gpon_tx_slice_pdi_laser_bitdelay );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_tx_laserdelay_get ( uint8_t *bitdelay )
{
	if (bitdelay)
		*bitdelay = (uint8_t) pma_r32(gpon_tx_slice_pdi_laser_bitdelay);

	return OPTIC_STATUS_OK;
}

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_TX == ACTIVE))
enum optic_errorcode optic_ll_tx_dump ( void )
{
	OPTIC_DEBUG_WRN("TX DATAPATH: 0x%08X",
			pma_r32(gpon_tx_slice_pdi_datapath));
	OPTIC_DEBUG_WRN("TX BIASPATH: 0x%08X",
			pma_r32(gpon_tx_slice_pdi_biaspath));
	OPTIC_DEBUG_WRN("TX DATA_DELAY: 0x%08X",
			pma_r32(gpon_tx_slice_pdi_data_delay));
	OPTIC_DEBUG_WRN("TX LASER_ENABLE: 0x%08X",
			pma_r32(gpon_tx_slice_pdi_laser_enable));

	OPTIC_DEBUG_WRN("TX LASER_BITDELAY: 0x%08X",
			pma_r32(gpon_tx_slice_pdi_laser_bitdelay));
	OPTIC_DEBUG_WRN("TX PI_CTRL: 0x%08X",
			pma_r32(gpon_tx_slice_pdi_pi_ctrl));
	OPTIC_DEBUG_WRN("TX MODULATOR_1: 0x%08X",
			pma_r32(gpon_tx_slice_pdi_modulator_1));
	OPTIC_DEBUG_WRN("TX MODULATOR_2: 0x%08X",
			pma_r32(gpon_tx_slice_pdi_modulator_2));

	return OPTIC_STATUS_OK;
}
#endif

/*! @} */
/*! @} */
