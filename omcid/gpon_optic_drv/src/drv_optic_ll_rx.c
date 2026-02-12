/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, PMA RX Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_RX_INTERNAL Receiver Module - Internal
   @{
*/

#include "drv_optic_ll_rx.h"
#include "drv_optic_ll_pll.h"
#include "drv_optic_ll_bert.h"
#include "drv_optic_register.h"
#include "drv_optic_reg_pma.h"
#include "drv_optic_reg_gtc.h"

#include "drv_optic_calc.h"
#include "drv_optic_ll_fcsi.h"
#include "drv_optic_reg_fcsic.h"

/**
   Init RX CDR.

       Enable the CDR
      tmp = (
         ELEM_GPON_RX_SLICE_PDI_CALWRITE_OFFS_CDR1(1) |
         ELEM_GPON_RX_SLICE_PDI_CALWRITE_OFFS_CDR2(4) |
         ELEM_GPON_RX_SLICE_PDI_CALWRITE_OFFS_CDR3(31));
      io_write(ADR_GPON_RX_SLICE_PDI_CALWRITE, tmp);

      tmp = (
	 ELEM_GPON_RX_SLICE_PDI_CALCTRL_PI_CDR3_CALC(0) );
      io_write(ADR_GPON_RX_SLICE_PDI_CALCTRL, tmp);

	CDR1: lock on rising edge
      tmp = (
         ELEM_GPON_RX_SLICE_PDI_CDR1_BPD_EN(1) |
         ELEM_GPON_RX_SLICE_PDI_CDR1_SEL_BPD_MODE(1) |
         ELEM_GPON_RX_SLICE_PDI_CDR1_SEL_SATLEV(4) |
         ELEM_GPON_RX_SLICE_PDI_CDR1_SUM_INV(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR1_XOR_INV(1));
      io_write(ADR_GPON_RX_SLICE_PDI_CDR1, tmp);

       tmp = (
         ELEM_GPON_RX_SLICE_PDI_CDR1LF_EXT_PI_CTRL(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR1LF_EID_EN(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR1LF_PI_LOAD_EXT(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR1LF_MI_ZERO(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR1LF_PI_OFFS(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR1LF_SEL_ID_LEV(1) |
         ELEM_GPON_RX_SLICE_PDI_CDR1LF_K_PI(2));
      io_write(ADR_GPON_RX_SLICE_PDI_CDR1LF, tmp);

	CDR2: lock on falling edge
      tmp = (
         ELEM_GPON_RX_SLICE_PDI_CDR2_BPD_EN(1) |
         ELEM_GPON_RX_SLICE_PDI_CDR2_SEL_BPD_MODE(2) |
         ELEM_GPON_RX_SLICE_PDI_CDR2_SEL_SATLEV(4) |
         ELEM_GPON_RX_SLICE_PDI_CDR2_SUM_INV(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR2_XOR_INV(1));
      io_write(ADR_GPON_RX_SLICE_PDI_CDR2, tmp);

       tmp = (
         ELEM_GPON_RX_SLICE_PDI_CDR2LF_EXT_PI_CTRL(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR2LF_EID_EN(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR2LF_PI_LOAD_EXT(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR2LF_MI_ZERO(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR2LF_PI_OFFS(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR2LF_SEL_ID_LEV(1) |
         ELEM_GPON_RX_SLICE_PDI_CDR2LF_K_PI(2));
      io_write(ADR_GPON_RX_SLICE_PDI_CDR2LF, tmp);

	CDR3: lock on rising edge
      tmp = (
         ELEM_GPON_RX_SLICE_PDI_CDR3_BPD_EN(1) |
         ELEM_GPON_RX_SLICE_PDI_CDR3_SEL_BPD_MODE(1) |
         ELEM_GPON_RX_SLICE_PDI_CDR3_SEL_SATLEV(4) |
         ELEM_GPON_RX_SLICE_PDI_CDR3_SUM_INV(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR3_XOR_INV(1));
      io_write(ADR_GPON_RX_SLICE_PDI_CDR3, tmp);

      tmp = (
         ELEM_GPON_RX_SLICE_PDI_CDR3LF_EXT_PI_CTRL(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR3LF_EID_EN(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR3LF_PI_LOAD_EXT(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR3LF_MI_ZERO(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR3LF_PI_OFFS(0) |
         ELEM_GPON_RX_SLICE_PDI_CDR3LF_SEL_ID_LEV(1) |
         ELEM_GPON_RX_SLICE_PDI_CDR3LF_K_PI(2));
      io_write(ADR_GPON_RX_SLICE_PDI_CDR3LF, tmp);

	Monitor: lock on rising edge
      tmp =
	 ELEM_GPON_RX_SLICE_PDI_MONITORCDR_BPD_EN(1) |
	 ELEM_GPON_RX_SLICE_PDI_MONITORCDR_SEL_BPD_MODE(1) |
	 ELEM_GPON_RX_SLICE_PDI_MONITORCDR_SEL_SATLEV(4) |
	 ELEM_GPON_RX_SLICE_PDI_MONITORCDR_SUM_INV(0) |
	 ELEM_GPON_RX_SLICE_PDI_MONITORCDR_XOR_INV(1));
      io_write(ADR_GPON_RX_SLICE_PDI_MONITORCDR, tmp);

      tmp = (
	 ELEM_GPON_RX_SLICE_PDI_MONITORLF_EXT_PI_CTRL(0) |
	 ELEM_GPON_RX_SLICE_PDI_MONITORLF_EID_EN(0) |
	 ELEM_GPON_RX_SLICE_PDI_MONITORLF_PI_LOAD_EXT(0) |
	 ELEM_GPON_RX_SLICE_PDI_MONITORLF_MI_ZERO(0) |
	 ELEM_GPON_RX_SLICE_PDI_MONITORLF_PI_OFFS(0) |
	 ELEM_GPON_RX_SLICE_PDI_MONITORLF_SEL_ID_LEV(1) |
	 ELEM_GPON_RX_SLICE_PDI_MONITORLF_K_PI(2));
      io_write(ADR_GPON_RX_SLICE_PDI_MONITORLF, tmp);

      tmp = (
         ELEM_GPON_RX_SLICE_PDI_CDR3DSM_DSM_CTRL_EN(1) |
         ELEM_GPON_RX_SLICE_PDI_CDR3DSM_DSM_CTRL_OFFS(15797427) |
         ELEM_GPON_RX_SLICE_PDI_CDR3DSM_K_DSM(4));
      io_write(ADR_GPON_RX_SLICE_PDI_CDR3DSM, tmp);

	CDR3: dead zone
      tmp = (
	 ELEM_GPON_RX_SLICE_PDI_CALCTRL_PI_CDR3_CALC(1) ); <- param: dead_zone_elimination (in bosa mode)
      io_write(ADR_GPON_RX_SLICE_PDI_CALCTRL, tmp);

   \return
   - OPTIC_STATUS_OK - success,
*/

enum optic_errorcode optic_ll_rx_cdr_init ( const bool bosa,
					    const bool dead_zone_elimination )
{
	uint32_t reg;

	/* init CDR offset */
	reg = ((31 << PMA_CALWRITE_OFFS_CDR3_OFFSET) &
	              PMA_CALWRITE_OFFS_CDR3_MASK) |
	      ((4 << PMA_CALWRITE_OFFS_CDR2_OFFSET) &
		     PMA_CALWRITE_OFFS_CDR2_MASK) |
	      ((1 << PMA_CALWRITE_OFFS_CDR1_OFFSET) &
	             PMA_CALWRITE_OFFS_CDR1_MASK);
	pma_w32( reg, gpon_rx_slice_pdi_calwrite);

	pma_w32( 0, gpon_rx_slice_pdi_calctrl);

	/** CDR1: lock on rising edge */
	/* enable binary phase detector, falling edge, saturation level 0 */
	reg = PMA_CDR1_XOR_INV | PMA_CDR1_SUM_INV |
	      ((0 << PMA_CDR1_SEL_SATLEV_OFFSET) & PMA_CDR1_SEL_SATLEV_MASK) |
	      ((0 << PMA_CDR1_SEL_BPD_MODE_OFFSET) &
	             PMA_CDR1_SEL_BPD_MODE_MASK) |
	      PMA_CDR1_BPD_EN;
	pma_w32( reg, gpon_rx_slice_pdi_cdr1);

	/* configure cdr data loop filter: PI=0, level=4 */
	reg = ((0 << PMA_CDR1LF_K_PI_OFFSET) &  PMA_CDR1LF_K_PI_MASK) |
	      ((4 << PMA_CDR1LF_SEL_ID_LEV_OFFSET) &
	             PMA_CDR1LF_SEL_ID_LEV_MASK) |
	       PMA_CDR1LF_EID_EN;
	pma_w32( reg | PMA_CDR1LF_MI_ZERO, gpon_rx_slice_pdi_cdr1lf);
	pma_w32( reg, gpon_rx_slice_pdi_cdr1lf);


	/** CDR2: lock on falling edge */
	/* enable binary phase detector, falling edge, saturation level 0 */
	reg = PMA_CDR2_XOR_INV | PMA_CDR2_SUM_INV |
	      ((0 << PMA_CDR2_SEL_SATLEV_OFFSET) & PMA_CDR2_SEL_SATLEV_MASK) |
	      ((0 << PMA_CDR2_SEL_BPD_MODE_OFFSET) &
	             PMA_CDR2_SEL_BPD_MODE_MASK) |
	      PMA_CDR2_BPD_EN;
	pma_w32( reg, gpon_rx_slice_pdi_cdr2);

	/* configure cdr data loop filter: PI=0, level=4*/
	reg = ((0 << PMA_CDR2LF_K_PI_OFFSET) &  PMA_CDR2LF_K_PI_MASK) |
	      ((4 << PMA_CDR2LF_SEL_ID_LEV_OFFSET) &
	             PMA_CDR2LF_SEL_ID_LEV_MASK) |
	       PMA_CDR2LF_EID_EN;
	pma_w32( reg | PMA_CDR2LF_MI_ZERO, gpon_rx_slice_pdi_cdr2lf);
	pma_w32( reg, gpon_rx_slice_pdi_cdr2lf);


	/** CDR3: lock on rising edge */
	/* enable binary phase detector, falling edge, saturation level 0 */
	reg = PMA_CDR3_XOR_INV | PMA_CDR3_SUM_INV |
	      ((0 << PMA_CDR3_SEL_SATLEV_OFFSET) & PMA_CDR3_SEL_SATLEV_MASK) |
	      ((0 << PMA_CDR3_SEL_BPD_MODE_OFFSET) &
	             PMA_CDR3_SEL_BPD_MODE_MASK) |
	      PMA_CDR3_BPD_EN;
	pma_w32( reg, gpon_rx_slice_pdi_cdr3);

	/* configure cdr data loop filter: PI=0, level=4*/
	reg = ((0 << PMA_CDR3LF_K_PI_OFFSET) &  PMA_CDR3LF_K_PI_MASK) |
	      ((4 << PMA_CDR3LF_SEL_ID_LEV_OFFSET) &
	             PMA_CDR3LF_SEL_ID_LEV_MASK) |
	       PMA_CDR3LF_EID_EN;
	pma_w32( reg | PMA_CDR3LF_MI_ZERO, gpon_rx_slice_pdi_cdr3lf);
	pma_w32( reg, gpon_rx_slice_pdi_cdr3lf);

	/** Monitor */
	/* enable binary phase detector, rising edge, saturation level 4 */
	reg = PMA_MONITORCDR_XOR_INV |
	      ((4 << PMA_MONITORCDR_SEL_SATLEV_OFFSET) &
	             PMA_MONITORCDR_SEL_SATLEV_MASK) |
	      ((1 << PMA_MONITORCDR_SEL_BPD_MODE_OFFSET) &
	             PMA_MONITORCDR_SEL_BPD_MODE_MASK);
	      /*PMA_MONITORCDR_BPD_EN*/
	pma_w32( reg, gpon_rx_slice_pdi_monitorcdr);

	/* configure cdr data loop filter: PI=2, level=1*/
	reg = ((2 << PMA_MONITORLF_K_PI_OFFSET) &  PMA_MONITORLF_K_PI_MASK) |
	      ((1 << PMA_MONITORLF_SEL_ID_LEV_OFFSET) &
	             PMA_MONITORLF_SEL_ID_LEV_MASK);
	pma_w32( reg, gpon_rx_slice_pdi_monitorlf);

	/** CDR3 */
	/* configure  data sync in cdr data loop filter:
	   DSM const=4, DSM offs=0xF1197C */
	reg = ((4 << PMA_CDR3DSM_K_DSM_OFFSET) & PMA_CDR3DSM_K_DSM_MASK) |
	      ((OPTIC_RX_DSM_CTRL_OFFS << PMA_CDR3DSM_DSM_CTRL_OFFS_OFFSET) &
			    PMA_CDR3DSM_DSM_CTRL_OFFS_MASK);
/*
	reg = ((4 << PMA_CDR3DSM_K_DSM_OFFSET) & PMA_CDR3DSM_K_DSM_MASK) |
	      ((0xf0e850 << PMA_CDR3DSM_DSM_CTRL_OFFS_OFFSET) &
			    PMA_CDR3DSM_DSM_CTRL_OFFS_MASK);
*/
	pma_w32( reg, gpon_rx_slice_pdi_cdr3dsm);

	/* enable DSM3 */
	pma_w32_mask ( 0, PMA_CDR3DSM_DSM_CTRL_EN, gpon_rx_slice_pdi_cdr3dsm );

	/* CDR3 dead zone calculation */
	if ((bosa == true) &&
	    (dead_zone_elimination == true))
		pma_w32( PMA_CALCTRL_PI_CDR3_CALC, gpon_rx_slice_pdi_calctrl);

	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_ll_rx_cdr_bpd ( const enum optic_activation mode )
{
	pma_w32_mask ( PMA_CDR3_BPD_EN, (mode == OPTIC_ENABLE) ?
	               PMA_CDR3_BPD_EN : 0, gpon_rx_slice_pdi_cdr3 );

	return OPTIC_STATUS_OK;
}

/**
   Configure Loss of Lock Alarm Thresholds

   \param   limit_low, lower limit of DSM control to rise the loss of lock alarm
	    in %
   \param   limit_high, upper limit of DSM control to rise the loss of lock alarm
            in %

      Set the alarm thresholds to inactive
      tmp = (
         ELEM_GPON_RX_SLICE_PDI_LOL_ALARMCFG_LO_LOL_LIMIT(0));
      io_write(ADR_GPON_RX_SLICE_PDI_LOL_ALARMCFG_LO,tmp);

      tmp = (
         ELEM_GPON_RX_SLICE_PDI_LOL_ALARMCFG_LO_LOL_LIMIT(0xFFFF));
      io_write(ADR_GPON_RX_SLICE_PDI_LOL_ALARMCFG_HI,tmp);

   \return
   - OPTIC_STATUS_OK - success,
*/
enum optic_errorcode optic_ll_rx_lolalarm_thresh_set ( const uint8_t limit_low,
						       const uint8_t
						       limit_high )
{
	int32_t low_tresh, high_tresh;
	uint32_t reg;

	/* calculate LOL thresholds */
	optic_calc_lol_thresh(  OPTIC_RX_DSM_CTRL_OFFS,
				limit_low,
				limit_high,
				&low_tresh,
				&high_tresh);

	/* calculate twos complement */
	if (low_tresh < 0)
		low_tresh += (1<<24);

	if (high_tresh < 0)
		high_tresh += (1<<24);

	/* set registers */
	reg = (uint32_t)((low_tresh << PMA_LOL_ALARMCFG_LO_LOL_LIMIT_OFFSET) & 
		PMA_LOL_ALARMCFG_LO_LOL_LIMIT_MASK);
	pma_w32(reg, gpon_rx_slice_pdi_lol_alarmcfg_lo);

	reg = (uint32_t)((high_tresh << PMA_LOL_ALARMCFG_HI_LOL_LIMIT_OFFSET) & 
		PMA_LOL_ALARMCFG_HI_LOL_LIMIT_MASK);
	pma_w32(reg, gpon_rx_slice_pdi_lol_alarmcfg_hi);

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_rx_lolalarm_thresh_get ( uint8_t *limit_low,
                                                       uint8_t *limit_high )
{
	uint32_t reg;
/*
	uint32_t full_low = PMA_LOL_ALARMCFG_LO_LOL_LIMIT_MASK >>
			    PMA_LOL_ALARMCFG_LO_LOL_LIMIT_OFFSET;
	uint32_t full_high = PMA_LOL_ALARMCFG_HI_LOL_LIMIT_MASK >>
			     PMA_LOL_ALARMCFG_HI_LOL_LIMIT_OFFSET;
*/
	uint32_t base, low, high;

	if ((limit_low == NULL) || (limit_high == NULL))
		return OPTIC_STATUS_ERR;

	base  = (pma_r32(gpon_rx_slice_pdi_cdr3dsmread) &
	         PMA_CDR3DSMREAD_DSM_CTRL_MASK) >>
	         PMA_CDR3DSMREAD_DSM_CTRL_OFFSET;


	/* get lower limit */
	reg = pma_r32 ( gpon_rx_slice_pdi_lol_alarmcfg_lo );
	low = (reg & PMA_LOL_ALARMCFG_LO_LOL_LIMIT_MASK) >>
		     PMA_LOL_ALARMCFG_LO_LOL_LIMIT_OFFSET;

	/* round compensation: *200, +1, >>1 */
	*limit_low = ((((base - low) * 200) / base) + 1) >> 1;


	/* get upper limit */
	reg = pma_r32 ( gpon_rx_slice_pdi_lol_alarmcfg_hi );
	high = (reg & PMA_LOL_ALARMCFG_HI_LOL_LIMIT_MASK) >>
		      PMA_LOL_ALARMCFG_HI_LOL_LIMIT_OFFSET;

	/* round compensation: *200, +1, >>1 */
	*limit_high = ((((high - base) * 200) / base) + 1) >> 1;

	return OPTIC_STATUS_OK;
}

/**
   Configure flipping in receive direction.

   \param   type  t.b.d.
   \param   flip  enable or disable flipping of LSB and MSB
   \param   invert  enable or disable inverting of data

      tmp = (
         ELEM_GPON_RX_SLICE_PDI_DATA_LO_DAC_LO(0)|
         ELEM_GPON_RX_SLICE_PDI_DATA_LO_DATA_LO_PRG_EN(0)|
         ELEM_GPON_RX_SLICE_PDI_DATA_LO_DATA_LO_PRG_DATA(0)|
         ELEM_GPON_RX_SLICE_PDI_DATA_LO_DATA_LO_INVERSE(x)|
         ELEM_GPON_RX_SLICE_PDI_DATA_LO_DATA_LO_FLIP(x));
      io_write(ADR_GPON_RX_SLICE_PDI_DATA_LO, tmp);

   \return
   - OPTIC_STATUS_OK - success,
*/
enum optic_errorcode optic_ll_rx_flipinvert_set ( const enum optic_rx_type type,
                                                  const bool flip,
                                                  const bool invert )
{
	uint32_t reg;

	switch (type) {
	case OPTIC_RX_DATA_LOW:
		/* set low data path ctrl */
		reg = pma_r32 (gpon_rx_slice_pdi_data_lo);

		if (flip)
			reg |= PMA_DATA_LO_DATA_LO_FLIP;
		else
			reg &= ~PMA_DATA_LO_DATA_LO_FLIP;

		if (invert)
			reg |= PMA_DATA_LO_DATA_LO_INVERSE;
		else
			reg &= ~PMA_DATA_LO_DATA_LO_INVERSE;

		pma_w32 ( reg, gpon_rx_slice_pdi_data_lo);
		break;
	case OPTIC_RX_DATA_HIGH:
		/* set high data path ctrl */
		reg = pma_r32 (gpon_rx_slice_pdi_data_hi);

		if (flip)
			reg |= PMA_DATA_HI_DATA_HI_FLIP;
		else
			reg &= ~PMA_DATA_HI_DATA_HI_FLIP;

		if (invert)
			reg |= PMA_DATA_HI_DATA_HI_INVERSE;
		else
			reg &= ~PMA_DATA_HI_DATA_HI_INVERSE;

		pma_w32 ( reg, gpon_rx_slice_pdi_data_hi);
		break;
	case OPTIC_RX_EDGE_FALL:
		/* set falling edge ctrl */
		reg = pma_r32 (gpon_rx_slice_pdi_edge_fall);

		if (flip)
			reg |= PMA_EDGE_FALL_EDGE_FALL_FLIP;
		else
			reg &= ~PMA_EDGE_FALL_EDGE_FALL_FLIP;

		if (invert)
			reg |= PMA_EDGE_FALL_EDGE_FALL_INVERSE;
		else
			reg &= ~PMA_EDGE_FALL_EDGE_FALL_INVERSE;

		pma_w32 ( reg, gpon_rx_slice_pdi_edge_fall);
		break;
	case OPTIC_RX_EDGE_RISE:
		/* set rising edge ctrl */
		reg = pma_r32 (gpon_rx_slice_pdi_edge_rise);

		if (flip)
			reg |= PMA_EDGE_RISE_EDGE_RISE_FLIP;
		else
			reg &= ~PMA_EDGE_RISE_EDGE_RISE_FLIP;

		if (invert)
			reg |= PMA_EDGE_RISE_EDGE_RISE_INVERSE;
		else
			reg &= ~PMA_EDGE_RISE_EDGE_RISE_INVERSE;

		pma_w32 ( reg, gpon_rx_slice_pdi_edge_rise);
		break;
	case OPTIC_RX_MONITOR:
		/* set rising edge ctrl */
		reg = pma_r32 (gpon_rx_slice_pdi_monitor);

		if (flip)
			reg |= PMA_MONITOR_MONITOR_FLIP;
		else
			reg &= ~PMA_MONITOR_MONITOR_FLIP;

		if (invert)
			reg |= PMA_MONITOR_MONITOR_INVERSE;
		else
			reg &= ~PMA_MONITOR_MONITOR_INVERSE;

		pma_w32 ( reg, gpon_rx_slice_pdi_monitor);
		break;
	case OPTIC_RX_XTALK:
		/* set dfe ctrl */
		reg = pma_r32 (gpon_rx_slice_pdi_dfectrl);

		if (flip)
			reg |= PMA_DFECTRL_XTALK_FLIP;
		else
			reg &= ~PMA_DFECTRL_XTALK_FLIP;

		if (invert)
			reg |= PMA_DFECTRL_XTALK_INVERSE;
		else
			reg &= ~PMA_DFECTRL_XTALK_INVERSE;

		pma_w32 ( reg, gpon_rx_slice_pdi_dfectrl);
		break;

	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}
enum optic_errorcode optic_ll_rx_flipinvert_get ( const enum optic_rx_type type,
                                                  bool *flip,
                                                  bool *invert )
{
	uint32_t reg;

	switch (type) {
	case OPTIC_RX_DATA_LOW:
		/* set low data path ctrl */
		reg = pma_r32 (gpon_rx_slice_pdi_data_lo);

		if (flip)
			*flip = ((reg & PMA_DATA_LO_DATA_LO_FLIP) ==
				 PMA_DATA_LO_DATA_LO_FLIP)? true : false;

		if (invert)
			*invert = ((reg & PMA_DATA_LO_DATA_LO_INVERSE) ==
				   PMA_DATA_LO_DATA_LO_INVERSE)? true : false;
		break;
	case OPTIC_RX_DATA_HIGH:
		/* set high data path ctrl */
		reg = pma_r32 (gpon_rx_slice_pdi_data_hi);

		if (flip)
			*flip = ((reg & PMA_DATA_HI_DATA_HI_FLIP) ==
				 PMA_DATA_HI_DATA_HI_FLIP)? true : false;

		if (invert)
			*invert = ((reg & PMA_DATA_HI_DATA_HI_INVERSE) ==
				   PMA_DATA_HI_DATA_HI_INVERSE)? true : false;
		break;
	case OPTIC_RX_EDGE_FALL:
		/* set falling edge ctrl */
		reg = pma_r32 (gpon_rx_slice_pdi_edge_fall);

		if (flip)
			*flip = ((reg & PMA_EDGE_FALL_EDGE_FALL_FLIP) ==
				 PMA_EDGE_FALL_EDGE_FALL_FLIP)? true : false;

		if (invert)
			*invert = ((reg & PMA_EDGE_FALL_EDGE_FALL_INVERSE) ==
				   PMA_EDGE_FALL_EDGE_FALL_INVERSE)?
				  true : false;
		break;
	case OPTIC_RX_EDGE_RISE:
		/* set rising edge ctrl */
		reg = pma_r32 (gpon_rx_slice_pdi_edge_rise);

		if (flip)
			*flip = ((reg & PMA_EDGE_RISE_EDGE_RISE_FLIP) ==
				 PMA_EDGE_RISE_EDGE_RISE_FLIP)? true : false;

		if (invert)
			*invert = ((reg & PMA_EDGE_RISE_EDGE_RISE_INVERSE) ==
				   PMA_EDGE_RISE_EDGE_RISE_INVERSE)?
				  true : false;
		break;
	case OPTIC_RX_MONITOR:
		/* set rising edge ctrl */
		reg = pma_r32 (gpon_rx_slice_pdi_monitor);

		if (flip)
			*flip = ((reg & PMA_MONITOR_MONITOR_FLIP) ==
				 PMA_MONITOR_MONITOR_FLIP)? true : false;

		if (invert)
			*invert = ((reg & PMA_MONITOR_MONITOR_INVERSE) ==
				   PMA_MONITOR_MONITOR_INVERSE)?
				  true : false;
		break;
	case OPTIC_RX_XTALK:
		/* set dfe ctrl */
		reg = pma_r32 (gpon_rx_slice_pdi_dfectrl);

		if (flip)
			*flip = ((reg & PMA_DFECTRL_XTALK_FLIP) ==
				 PMA_DFECTRL_XTALK_FLIP)? true : false;

		if (invert)
			*invert = ((reg & PMA_DFECTRL_XTALK_INVERSE) ==
				   PMA_DFECTRL_XTALK_INVERSE)?
				  true : false;
		break;

	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}

/**
   Configure RX AFE control

   \param   rterm, emp of RX data to GTC

      Enable receive data signals to GTC
      tmp = (
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_CALIBRATION_ON(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_OFFSET(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_OUTPUT_CM_SEL(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_EMP(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_DOUBLE_TAILCUR(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_RTERM_SEL(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_RX_TESTBUS_EN(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_PMA_RX_DATA_EN(1));
      io_write(ADR_GPON_RX_SLICE_PDI_AFECTRL, tmp);

   \return
   - OPTIC_STATUS_OK - success,
*/
enum optic_errorcode optic_ll_rx_afectrl_config ( const uint16_t rterm,
                                                  const uint8_t emp )
{
	uint32_t reg = 0;

	reg = ((rterm << PMA_AFECTRL_RTERM_SEL_OFFSET) &
	                 PMA_AFECTRL_RTERM_SEL_MASK) |
	      ((emp << PMA_AFECTRL_EMP_OFFSET) &
	               PMA_AFECTRL_EMP_MASK) |
	      ((4 << PMA_AFECTRL_OUTPUT_CM_SEL_OFFSET) &
	             PMA_AFECTRL_OUTPUT_CM_SEL_MASK);

	pma_w32 ( reg, gpon_rx_slice_pdi_afectrl );

	return OPTIC_STATUS_OK;
}

/**
   Activate/deactivate RX AFE control

   \param   mode, enable or disable sending of RX data to GTC

      Enable receive data signals to GTC
      tmp = (
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_CALIBRATION_ON(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_OFFSET(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_OUTPUT_CM_SEL(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_EMP(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_DOUBLE_TAILCUR(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_RTERM_SEL(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_RX_TESTBUS_EN(0) |
         ELEM_GPON_RX_SLICE_PDI_AFECTRL_PMA_RX_DATA_EN(1));
      io_write(ADR_GPON_RX_SLICE_PDI_AFECTRL, tmp);

   \return
   - OPTIC_STATUS_OK - success,
*/
enum optic_errorcode optic_ll_rx_afectrl_set ( const enum optic_activation
                                               mode,
                                               const bool calibration )
{
	uint32_t reg, reg_old;

	reg = pma_r32 ( gpon_rx_slice_pdi_afectrl );
	reg_old = reg;

	if ( calibration == true )
		reg |= PMA_AFECTRL_CALIBRATION_ON;
	else
		reg &= ~PMA_AFECTRL_CALIBRATION_ON;

	if ( mode == OPTIC_ENABLE )
	     	reg |= PMA_AFECTRL_PMA_RX_DATA_EN;
	else
	     	reg &= ~PMA_AFECTRL_PMA_RX_DATA_EN;

	if (reg != reg_old)
	     	pma_w32 ( reg, gpon_rx_slice_pdi_afectrl );

	return OPTIC_STATUS_OK;
}
/**
   Configure and enable RX DAC offset correction

   \param   level_coarse  RX coarse DAC offset
   \param   level_fine    RX fine DAC offset
   \param   type          t.b.d.

      1. Load receive DAC offset correction values
         - We use only the low threshold.

      nLevelC = nRxDacOffsetLoC (default to 0x00)
      nLevelF = nRxDacOffsetLoF (default to 0x00)
      tmp = (
         ELEM_GPON_RX_SLICE_PDI_DATA_LO_DAC_LO(nLevelC<<8|nLevelF));
      io_write(ADR_GPON_RX_SLICE_PDI_DATA_LO, tmp);

      2. Enable the receive DAC low decision threshold
      tmp = (
         ELEM_GPON_RX_SLICE_PDI_DFECTRL_DFE_DATA_SEL(1));
      io_write(ADR_GPON_RX_SLICE_PDI_DFECTRL, tmp);

   \return
   - OPTIC_STATUS_OK - success,
*/
enum optic_errorcode optic_ll_rx_dac_set ( const enum optic_rx_type type,
					   const bool positive,
                                           const uint8_t level_coarse,
                                           const uint8_t level_fine )
{
	uint32_t dac = level_coarse << 8 | level_fine;
	if (positive == true)
		dac |= (1<<16);

	switch (type) {
	case OPTIC_RX_DATA_LOW:
		/* set receive DAC offset correction ctrl */

		/* workaround to get control after reset (dac = 0) */
		if ((level_coarse == 0) && (level_fine == 0))
			pma_w32_mask ( PMA_DATA_LO_DAC_LO_MASK,
				       ((1<<16) << PMA_DATA_LO_DAC_LO_OFFSET) &
						   PMA_DATA_LO_DAC_LO_MASK,
				       gpon_rx_slice_pdi_data_lo );

		pma_w32_mask ( PMA_DATA_LO_DAC_LO_MASK,
			       (dac << PMA_DATA_LO_DAC_LO_OFFSET) &
			               PMA_DATA_LO_DAC_LO_MASK,
			       gpon_rx_slice_pdi_data_lo );
		break;
	case OPTIC_RX_DATA_HIGH:
		/* set receive DAC offset correction ctrl */

		/* workaround to get control after reset (dac = 0) */
		if ((level_coarse == 0) && (level_fine == 0))
			pma_w32_mask ( PMA_DATA_HI_DAC_HI_MASK,
				       ((1<<16) << PMA_DATA_HI_DAC_HI_OFFSET) &
						   PMA_DATA_HI_DAC_HI_MASK,
				       gpon_rx_slice_pdi_data_hi );

		pma_w32_mask ( PMA_DATA_HI_DAC_HI_MASK,
			       (dac << PMA_DATA_HI_DAC_HI_OFFSET) &
			               PMA_DATA_HI_DAC_HI_MASK,
			       gpon_rx_slice_pdi_data_hi);
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_rx_dac_get ( const enum optic_rx_type type,
					   bool *positive,
                                           uint8_t *level_coarse,
                                           uint8_t *level_fine )
{
	uint32_t reg, dac;

	switch (type) {
	case OPTIC_RX_DATA_LOW:
		reg = pma_r32 (gpon_rx_slice_pdi_data_lo);
		dac = (reg & PMA_DATA_LO_DAC_LO_MASK) >>
			     PMA_DATA_LO_DAC_LO_OFFSET;
		break;
	case OPTIC_RX_DATA_HIGH:
		reg = pma_r32 (gpon_rx_slice_pdi_data_hi);
		dac = (reg & PMA_DATA_HI_DAC_HI_MASK) >>
			     PMA_DATA_HI_DAC_HI_OFFSET;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	if (level_coarse)
		*level_coarse = (dac & 0xFF00) >> 8;
	if (level_fine)
		*level_fine = (dac & 0xFF);

	if (positive)
		*positive = ((dac & 0x10000) == 0x10000)? true : false;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_rx_dac_sel ( const enum optic_rx_type type )
{
	switch (type) {
	case OPTIC_RX_DFECTRL_OFF:
		/* set DFE ctrl data selection = off = 0 */
		pma_w32_mask ( PMA_DFECTRL_DFE_DATA_SEL_MASK,
			       (0 << PMA_DFECTRL_DFE_DATA_SEL_OFFSET) &
			             PMA_DFECTRL_DFE_DATA_SEL_MASK,
			       gpon_rx_slice_pdi_dfectrl );
		break;
	case OPTIC_RX_DATA_LOW:
		/* set DFE ctrl data selection = data low = 1 */
		pma_w32_mask ( PMA_DFECTRL_DFE_DATA_SEL_MASK,
			       (1 << PMA_DFECTRL_DFE_DATA_SEL_OFFSET) &
			             PMA_DFECTRL_DFE_DATA_SEL_MASK,
			       gpon_rx_slice_pdi_dfectrl );
		break;
	case OPTIC_RX_DATA_HIGH:
		/* set DFE ctrl data selection = data high = 2 */
		pma_w32_mask ( PMA_DFECTRL_DFE_DATA_SEL_MASK,
		               (2 << PMA_DFECTRL_DFE_DATA_SEL_OFFSET) &
		                     PMA_DFECTRL_DFE_DATA_SEL_MASK,
			       gpon_rx_slice_pdi_dfectrl);
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}

/**
	 read loss of lock indicator and interprets

      rd_data = _ll_read(ADR_GPON_RX_SLICE_PDI_CALREAD);
      cdr3_pi_ctrl = GET_ELEM_GPON_RX_SLICE_PDI_CALREAD_CDR3_PI_CTRL(rd_data);
      Read multiple times (t.b.d.), declare loss of CDR lock if the
      cdr3_pi_ctrl values differ more than +/- 3 digits
      (max_value - min_value > 6).
*/
enum optic_errorcode optic_ll_rx_lol_get ( bool *lol )
{
	uint8_t i;
	uint16_t cdr3_pi_ctrl, cdr3_pi_ctrl_min = 0, cdr3_pi_ctrl_max = 0;
	uint32_t reg;

	if (lol == NULL)
		return OPTIC_STATUS_ERR;

	for (i=0; i<OPTIC_RX_READ_CYCLES_LOL; i++) {
		reg = pma_r32 ( gpon_rx_slice_pdi_calread );
		cdr3_pi_ctrl = (reg & PMA_CALREAD_CDR3_PI_CTRL_MASK) >>
				      PMA_CALREAD_CDR3_PI_CTRL_OFFSET;
		if (i==0) {
			cdr3_pi_ctrl_min = cdr3_pi_ctrl;
			cdr3_pi_ctrl_max = cdr3_pi_ctrl;
		} else {
			if (cdr3_pi_ctrl < cdr3_pi_ctrl_min)
				cdr3_pi_ctrl_min = cdr3_pi_ctrl;
			else
			if (cdr3_pi_ctrl > cdr3_pi_ctrl_max)
				cdr3_pi_ctrl_max = cdr3_pi_ctrl;
		}
	}

	if ((cdr3_pi_ctrl_max - cdr3_pi_ctrl_min) > 6 )
		*lol = true;
	else
		*lol = false;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_rx_offset_cancel ( const enum optic_rx_type type,
						 int32_t *rx_offset )
{
	#define CNT_SAT_MAX 10
	#define	COMB_PERIODS 8
	#define	COMP_LENGTH 6 /* (1<<COMP_LENGTH) readouts of rx_data */
	#define	RX_LIMIT ((1<<COMP_LENGTH)<<3)

	enum optic_errorcode ret;
	uint8_t cnt_sat = CNT_SAT_MAX;
	int32_t rx_compdata, rx_compdata_old;
	int32_t level=0, level_new=0, level_old=0, op, gain = 10;
	uint32_t opfilt = (1 << OPTIC_LEVEL_BITS) - 1; /* start value, corresponds to 1 */
	uint32_t reg, temp;
	bool invert;
	int32_t y=0;
	int64_t y_all=0;
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
	int16_t i,j;
	uint32_t reg_rxbosactrl;

	ret = optic_ll_rx_flipinvert_get ( type, NULL, &invert );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (invert == false)
		gain *= -1;

	rx_compdata = -1;

	ret = optic_ll_rx_afectrl_set ( OPTIC_ENABLE, true );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/** enable sgmii pd */
	ret = optic_ll_fcsi_read (FCSI_RXBOSA_CTRL, &reg_rxbosactrl);
	if (ret != OPTIC_STATUS_OK)
		return ret;
	reg_rxbosactrl |= RXBOSA_CTRL_ISOM_PD;
	ret = optic_ll_fcsi_write ( FCSI_RXBOSA_CTRL, reg_rxbosactrl );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/* lets use only the coarse DAC, to stay compatible with A21 */
	while (gain) {
		level_old = level_new;
		rx_compdata_old = rx_compdata;

		/* update level */
		temp = abs (level_new);

		ret = optic_ll_rx_dac_set ( type,
					    (level_new >= 0) ? true : false,
					    temp,
					    0x0 );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_ll_rx_dac_set: %d", ret);
			return ret;
		}

		/* read comparator */
		i=0;
		for (j=0;j < (1<<COMP_LENGTH);j++){
			reg = pma_r32 ( gpon_rx_slice_pdi_monitorread );
			rx_compdata =
				(reg & PMA_MONITORREAD_DATA_RX_MASK)
					>> PMA_MONITORREAD_DATA_RX_OFFSET;
			while (rx_compdata){
				if (rx_compdata & 0x1)
					i++;
				rx_compdata=rx_compdata>>1;
			}
		}
		rx_compdata=i;
		/* direction change */
		if ((rx_compdata_old != -1) &&
		    (((rx_compdata > RX_LIMIT) && (rx_compdata_old <= RX_LIMIT)) ||
		     ((rx_compdata <= RX_LIMIT) && (rx_compdata_old > RX_LIMIT)))) {
			gain = optic_int_div_rounded ( gain, 2 );
		}

		/* at least one measurement above level */
		if (rx_compdata > RX_LIMIT) {
			level_new = level_old + gain;
			op = gain;
		} else {
			level_new = level_old - gain;
			op = -gain;
		}

		/* saturation check */
		if (abs(level_new) > 0xFE) {
			cnt_sat --;
			level_new = level_old;

			if (cnt_sat == 0) {
				OPTIC_DEBUG_WRN(" optic_ll_rx_offset_cancel: "
						"SATURATION, level=%d, gain=%d,"
						" compdata=%d", level_old, gain,
								rx_compdata);

				return OPTIC_STATUS_RXDAC_SATURATION;
			}
			continue;
		}
		cnt_sat = CNT_SAT_MAX;

		/*comb*/
		cnt++;
		x = level_new;
		y1=x+z1;
		z1=y1;
		y2=y1+z2;
		z2=y2;
		if (cnt >= 64) {
			cnt = 0;
			cnt_end ++;
			y3 = y2 - z3;
			z3 = y2;
			y4 = y3 - z4;
			z4 = y3;
			y = y4 >> 12;
			y_all += y; /* sum of all results */
		}

		if (abs(gain)==1){
			/* filter as end criteria*/
			if (abs (opfilt) > OPTIC_GAIN_COEFF){
				opfilt = ((opfilt + op * OPTIC_GAIN_COEFF) *
						(((1 << OPTIC_LEVEL_BITS) - 1)
						- OPTIC_GAIN_COEFF)) >> OPTIC_LEVEL_BITS;
				cnt_end = 0;
				y_all = 0;
			} else {
				if (cnt_end == (1 << COMB_PERIODS)){
					gain = 0;
					level = (y_all >> COMB_PERIODS);
				}
			}
		}
	}
	/* update level with filtered result*/
	temp = abs (level);

	ret = optic_ll_rx_dac_set ( type, (level >= 0) ? true : false,
				    temp,
				    0x0 );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_ll_rx_dac_set: %d", ret);
		return ret;
	}

	/** disable sgmii pd */
	ret = optic_ll_fcsi_read (FCSI_RXBOSA_CTRL, &reg_rxbosactrl);
	if (ret != OPTIC_STATUS_OK)
		return ret;
	reg_rxbosactrl &= ~RXBOSA_CTRL_ISOM_PD;
	ret = optic_ll_fcsi_write ( FCSI_RXBOSA_CTRL, reg_rxbosactrl );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_rx_afectrl_set ( OPTIC_ENABLE, false );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (rx_offset != NULL)
		/*shift in order to stay compatible with earlier implementation */
		*rx_offset = level<<8;

#if (OPTIC_DEBUG_PRINTOUT_RX_OFFSET == ACTIVE)
	OPTIC_DEBUG_ERR("RX offset correction: level=%d ", level );
#else
	OPTIC_DEBUG_MSG("RX offset correction: level=%d ", level );
#endif
	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_rx_dsm_switch (const enum optic_activation mode)
{
	pma_w32_mask(PMA_CDR3DSM_DSM_CTRL_EN, mode,
		     gpon_rx_slice_pdi_cdr3dsm);

	return OPTIC_STATUS_OK;
}
/*
 * This function recovers PLL in case of LOL, required in BOSA and OMU mode
 */
enum optic_errorcode optic_ll_rx_dsm_reset (const uint8_t lol_set, const uint8_t lol_clear)
{
	uint32_t reg;
	int32_t temp, low_tresh, high_tresh;
	static uint32_t cnt = OPTIC_RX_ASYN_CNT;
	enum optic_activation mode;
	enum optic_errorcode ret;

	/* if in BERT mode, do nothing */
	ret = optic_ll_bert_analyzer_get ( &mode );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	if (mode == OPTIC_ENABLE)
		return OPTIC_STATUS_OK;

	reg = (pma_r32(gpon_rx_slice_pdi_cdr3dsmread) &
			PMA_CDR3DSMREAD_DSM_CTRL_MASK) >>
			PMA_CDR3DSMREAD_DSM_CTRL_OFFSET;
	temp = reg;
	/* check for 24 bit twos complement value? */
	if (temp & 0x800000)
		temp -= (1<<24);

	/* calculate LOL thresholds */
	optic_calc_lol_thresh(  OPTIC_RX_DSM_CTRL_OFFS,
			lol_set,
			lol_clear,
			&low_tresh,
			&high_tresh);

	/* Only if RX data path is enabled at all,
	 * check for possible DSM reset conditions.
	 *
	 * In case, RX was switched off via "optic bosard" control bit
	 * RX_DATA_EN is disabled and we do not reset DSM and keep constant
	 * frequency and phase for TX slice */
	if(pma_r32 ( gpon_rx_slice_pdi_afectrl ) & PMA_AFECTRL_PMA_RX_DATA_EN) {
		/* check for reset and perform 0->1 transition */
		if (temp < low_tresh || temp > high_tresh) {
			pma_w32_mask(PMA_CDR3DSM_DSM_CTRL_EN, 0x0,
				     gpon_rx_slice_pdi_cdr3dsm);
			pma_w32_mask(0x0, PMA_CDR3DSM_DSM_CTRL_EN,
				     gpon_rx_slice_pdi_cdr3dsm);
		}

		/* check GTC asynchronous behavior,
		 * \todo use an official function to access ONU driver function */
		if (cnt-- == 0) {
			cnt = OPTIC_RX_ASYN_CNT;
			reg = (gtc_r32(downstr_gtc_dsstat_1) &
					GTC_DSSTAT_1_STATE_MASK)
					>> GTC_DSSTAT_1_STATE_OFFSET;

			/* GTC not in synchronous state */
			if (reg != 3) {
				pma_w32_mask(PMA_CDR3DSM_DSM_CTRL_EN, 0x0,
						gpon_rx_slice_pdi_cdr3dsm);
				pma_w32_mask(0x0, PMA_CDR3DSM_DSM_CTRL_EN,
						gpon_rx_slice_pdi_cdr3dsm);
			}
		}
	}

	return OPTIC_STATUS_OK;
}

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_RX == ACTIVE))
enum optic_errorcode optic_ll_rx_dump ( void )
{
	OPTIC_DEBUG_WRN("RX CDR1: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_cdr1));
	OPTIC_DEBUG_WRN("RX CDR2: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_cdr2));
	OPTIC_DEBUG_WRN("RX CDR3: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_cdr3));
	OPTIC_DEBUG_WRN("RX MONITORCDR: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_monitorcdr));

	OPTIC_DEBUG_WRN("RX CDR1LF: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_cdr1lf));
	OPTIC_DEBUG_WRN("RX CDR2LF: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_cdr2lf));
	OPTIC_DEBUG_WRN("RX CDR3KF: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_cdr3lf));
	OPTIC_DEBUG_WRN("RX MONITORLF: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_monitorlf));

	OPTIC_DEBUG_WRN("RX CDR3DSM: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_cdr3dsm));
	OPTIC_DEBUG_WRN("RX CDR3DSMREAD: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_cdr3dsmread));

	OPTIC_DEBUG_WRN("RX DATA_HI: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_data_hi));
	OPTIC_DEBUG_WRN("RX DATA_LO: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_data_lo));

	OPTIC_DEBUG_WRN("RX MONITOR: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_monitor));
	OPTIC_DEBUG_WRN("RX MONITORREAD: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_monitorread));

	OPTIC_DEBUG_WRN("RX EDGE_FALL: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_edge_fall));
	OPTIC_DEBUG_WRN("RX EDGE_RISE: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_edge_rise));

	OPTIC_DEBUG_WRN("RX DFECTRL: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_dfectrl));
	OPTIC_DEBUG_WRN("RX CALCTRL: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_calctrl));
	OPTIC_DEBUG_WRN("RX CALREAD: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_calread));
	OPTIC_DEBUG_WRN("RX CALWRITE: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_calwrite));

	OPTIC_DEBUG_WRN("RX LOL_ALRAMCFG_LO: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_lol_alarmcfg_lo));
	OPTIC_DEBUG_WRN("RX LOL_ALRAMCFG_HI: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_lol_alarmcfg_hi));

	OPTIC_DEBUG_WRN("RX MONITOR_COUNT_CFG: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_monitor_count_cfg));
	OPTIC_DEBUG_WRN("RX MONITOR_DIFF_COUNT: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_monitor_diff_count));
	OPTIC_DEBUG_WRN("RX MONITOR_ERR_COUNT0: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_monitor_err_count0));
	OPTIC_DEBUG_WRN("RX MONITOR_ERR_COUNT1: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_monitor_err_count1));

	OPTIC_DEBUG_WRN("RX AFECTRL: 0x%08X",
			pma_r32(gpon_rx_slice_pdi_afectrl));

	return OPTIC_STATUS_OK;

}
#endif

/*! @} */
/*! @} */
