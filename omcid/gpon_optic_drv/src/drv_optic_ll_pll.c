/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, PMA PLL Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_PLL_INTERNAL PLL Module - Internal
   @{
*/

#include "drv_optic_ll_pll.h"
#include "drv_optic_register.h"
#include "drv_optic_reg_pma.h"

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_PLL == ACTIVE))
static enum optic_errorcode optic_ll_pll_dump ( void );
static enum optic_errorcode optic_ll_pll_dump_status ( void );
#endif

/**
   Calibrate PLL and wait for locking.

   \return
   - OPTIC_STATUS_PLL_LOCKED - PLL locked,
   - OPTIC_STATUS_PLL_NOTLOCKED - PLL not locked
   - OPTIC_STATUS_PLL_LOCKTIMEOUT - timeout while PLL calibration

      1. Activate the PLL
      tmp = (
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_PWD(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_PWD_BIAS(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_PWD_CP(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_PWD_DIV(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_PWD_DIV2(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_PWD_DIV8(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_PWD_DIV5(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_PWD_FIX_PH_CORE_F(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_PWD_FD_IN_BUFFER(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_PWD_LDO_VCO(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_PWD_LF(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_PWD_VREFS(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_REF_CLK_O_MTR_EN(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_REFCLK_O_EN(1) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_REFCLK_SEL(1) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_TEST_EXT_FD_IN_EN(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_VCO_VCTRL_WHEN_CT(0) |
         ELEM_GPON_PLL_SLICE_PDI_A_CTRL3_MMD(46));
      io_write(ADR_GPON_PLL_SLICE_PDI_A_CTRL3, tmp);

      2. Wait 5 us

      3. Release the PLL reset
      tmp = (
         ELEM_GPON_PLL_SLICE_PDI_CTRL2_CONST_SDM(0x83) |
         ELEM_GPON_PLL_SLICE_PDI_CTRL2_EN_CONST_SDM_REG(0) |
         ELEM_GPON_PLL_SLICE_PDI_CTRL2_EN_CONST_SDM(1) |
         ELEM_GPON_PLL_SLICE_PDI_CTRL2_PLL_ENSDM(1) |
         ELEM_GPON_PLL_SLICE_PDI_CTRL2_PLL_ENWAVEGEN(0) |
         ELEM_GPON_PLL_SLICE_PDI_CTRL2_PLLDIGTEST(0) |
         ELEM_GPON_PLL_SLICE_PDI_CTRL2_PLL_RESETN(1));
      io_write(ADR_GPON_PLL_SLICE_PDI_CTRL2, tmp);

      4. Wait for PLL lock, check GPON_PLL_SLICE_PDI.STATUS.LOCK 0 --> 1

*/
enum optic_errorcode optic_ll_pll_calibrate ( void )
{
	enum optic_errorcode ret;
	uint32_t reg;
	uint32_t cnt = 100;

/* try PLL start like in phyton scrip
 * is however only slightly different to "original"
 * implementation by Henrik
 * Commented because stuck on boot seen in rarely occasions
 */
#if 0
	/*write reset values to HW*/
	pma_w32 ( 0x00000AB6, gpon_pll_slice_pdi_pmd_resetcontrol );
	pma_w32 ( 0x00008e39, gpon_pll_slice_pdi_ctrl1 );
	pma_w32 ( 0x00000283, gpon_pll_slice_pdi_ctrl2 );
	pma_w32 ( 0x00000041, gpon_pll_slice_pdi_ctrl3 );
	pma_w32 ( 0x00000000, gpon_pll_slice_pdi_ctrl4 );
	pma_w32 ( 0x00000000, gpon_pll_slice_pdi_ctrl5 );
	pma_w32 ( 0x00000000, gpon_pll_slice_pdi_ctrl6 );
	pma_w32 ( 0x00000000, gpon_pll_slice_pdi_ctrl7 );
	pma_w32 ( 0x00000000, gpon_pll_slice_pdi_a_ctrl1 );
	pma_w32 ( 0x00018000, gpon_pll_slice_pdi_a_ctrl2 );
	pma_w32 ( 0x00B86001, gpon_pll_slice_pdi_a_ctrl3 );
	pma_w32 ( 0x00000000, gpon_pll_slice_pdi_status );
	pma_w32 ( 0x00000000, gpon_pll_slice_pdi_pma_top_ctrl );
	/* OPTIC_DEBUG_ERR("PLL reset"); */

	/* PD PLL*/
	reg = ((0x2E << PMA_A_CTRL3_MMD_OFFSET) & PMA_A_CTRL3_MMD_MASK) |
          ((1 << PMA_A_CTRL3_VCO_VCTRL_WHEN_CT_OFFSET) & PMA_A_CTRL3_VCO_VCTRL_WHEN_CT_MASK) |
	      PMA_A_CTRL3_REFCLK_SEL |
	      PMA_A_CTRL3_REFCLK_O_EN |
	      PMA_A_CTRL3_PWD;
	pma_w32 ( reg, gpon_pll_slice_pdi_a_ctrl3 );

	/* supply adjust */
	reg = ((0x5 << PMA_A_CTRL2_LDO_VREF_SEL_OFFSET) & PMA_A_CTRL2_LDO_VREF_SEL_MASK) |
	      ((0x3 << PMA_A_CTRL2_CURR_SEL_PI_OFFSET) & PMA_A_CTRL2_CURR_SEL_PI_MASK) |
	      ((0x3 << PMA_A_CTRL2_CURR_SEL_DIV2_OFFSET) & PMA_A_CTRL2_CURR_SEL_DIV2_MASK);
	pma_w32 ( reg, gpon_pll_slice_pdi_a_ctrl2 );

	reg = PMA_CTRL2_PLL_ENSDM |
	      PMA_CTRL2_EN_CONST_SDM_EN |
	      ((0x83 << PMA_CTRL2_CONST_SDM_OFFSET) & PMA_CTRL2_CONST_SDM_MASK);
	pma_w32 ( reg, gpon_pll_slice_pdi_ctrl2 );

	optic_udelay(100);

	/* release PLL powerdown */
	reg = ((0x2E << PMA_A_CTRL3_MMD_OFFSET) & PMA_A_CTRL3_MMD_MASK) |
          ((1 << PMA_A_CTRL3_VCO_VCTRL_WHEN_CT_OFFSET) & PMA_A_CTRL3_VCO_VCTRL_WHEN_CT_MASK) |
	      PMA_A_CTRL3_REFCLK_SEL |
	      PMA_A_CTRL3_REFCLK_O_EN;
	pma_w32 ( reg, gpon_pll_slice_pdi_a_ctrl3 );

	optic_udelay(100);

	/* release digital PLL reset */
	reg = PMA_CTRL2_PLL_RESETN |
		  PMA_CTRL2_EN_CONST_SDM_EN |
		  PMA_CTRL2_PLL_ENSDM |
	      ((0x83 << PMA_CTRL2_CONST_SDM_OFFSET) & PMA_CTRL2_CONST_SDM_MASK);
	pma_w32 ( reg, gpon_pll_slice_pdi_ctrl2 );

	reg = ((0x0D << PMA_CTRL3_EXT_SELVCO_OFFSET) &
	                PMA_CTRL3_EXT_SELVCO_MASK) |
	      ((4 << PMA_CTRL3_EXT_MMD_DIV_RATIO_OFFSET) &
	             PMA_CTRL3_EXT_MMD_DIV_RATIO_MASK) |
	      PMA_CTRL3_EN_BIN_CAL_EN;
	pma_w32 ( reg, gpon_pll_slice_pdi_ctrl3 );

	optic_udelay(100);
	/* OPTIC_DEBUG_ERR("PLL wait lock"); */
#endif
#if 1
	/* manually tune the vco */
	optic_ll_pll_vco_set ();

	/* reset to digital PLL */
	reg = PMA_CTRL2_PLL_ENSDM |
	      PMA_CTRL2_EN_CONST_SDM_EN |
	      ((0x83 << PMA_CTRL2_CONST_SDM_OFFSET) & PMA_CTRL2_CONST_SDM_MASK);
	pma_w32 ( reg, gpon_pll_slice_pdi_ctrl2 );

	/* deactivate analog power down, activate PLL */
	reg = ((46 << PMA_A_CTRL3_MMD_OFFSET) & PMA_A_CTRL3_MMD_MASK) |
              ((1 << PMA_A_CTRL3_VCO_VCTRL_WHEN_CT_OFFSET) &
                     PMA_A_CTRL3_VCO_VCTRL_WHEN_CT_MASK) |
	      PMA_A_CTRL3_REFCLK_SEL |
	      PMA_A_CTRL3_REFCLK_O_EN |
	      PMA_A_CTRL3_PWD;
	pma_w32 ( reg, gpon_pll_slice_pdi_a_ctrl3 );



	ret = optic_ll_pll_start ( OPTIC_NOMODE );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_ll_pll_calibrate: %d",
				ret);
	}

	pma_w32_mask ( PMA_A_CTRL3_PWD, 0, gpon_pll_slice_pdi_a_ctrl3 );

	/* release reset to digital PLL */
	reg = PMA_CTRL2_PLL_RESETN |
	      PMA_CTRL2_PLL_ENSDM |
	      PMA_CTRL2_EN_CONST_SDM_EN |
	      ((0x83 << PMA_CTRL2_CONST_SDM_OFFSET) & PMA_CTRL2_CONST_SDM_MASK);
	pma_w32 ( reg, gpon_pll_slice_pdi_ctrl2 );

	/* release reset to digital PLL */
	reg = ((0x3 << PMA_A_CTRL2_LDO_VREF_SEL_OFFSET) &
	               PMA_A_CTRL2_LDO_VREF_SEL_MASK) |
	      ((0x3 << PMA_A_CTRL2_CURR_SEL_PI_OFFSET) &
	               PMA_A_CTRL2_CURR_SEL_PI_MASK) |
	      ((0x5 << PMA_A_CTRL2_CURR_SEL_DIV2_OFFSET) &
	               PMA_A_CTRL2_CURR_SEL_DIV2_MASK);
	pma_w32 ( reg, gpon_pll_slice_pdi_a_ctrl2 );

	/* wait to release reset to digital PLL */
	optic_udelay(100);
#endif
	/* wait until PLL locked */
	while ((cnt) && (((pma_r32(gpon_pll_slice_pdi_status) &
	       PMA_STATUS_STARTUP_RDY_MASK) >>
	       PMA_STATUS_STARTUP_RDY_OFFSET) != 1)) {
		cnt--;
#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_PLL == ACTIVE))
		optic_ll_pll_dump_status ();
#endif
		optic_udelay(10);
	}

	optic_udelay(100);


	/* try PLL start like in phyton scrip
	 * is however only slightly different to "original"
	 * implementation by Henrik
	 * Commented because stuck on boot seen in rarely occasions
	 */
#if 0
	/* no PD, but still reset */
	pma_w32 ( 0x0, gpon_pll_slice_pdi_pmd_resetcontrol );
#endif
	/* PLL calibration finished */
	if (cnt) {
		return optic_ll_pll_check ( );
	} else
		return OPTIC_STATUS_PLL_LOCKTIMEOUT;

}

enum optic_errorcode optic_ll_pll_vco_set ( void )
{
	uint32_t reg;

	reg = ((0x0D << PMA_CTRL3_EXT_SELVCO_OFFSET) &
	                PMA_CTRL3_EXT_SELVCO_MASK) |
	      ((4 << PMA_CTRL3_EXT_MMD_DIV_RATIO_OFFSET) &
	             PMA_CTRL3_EXT_MMD_DIV_RATIO_MASK) |
	      PMA_CTRL3_EN_BIN_CAL_EN;

	/* don't use external SEL VCO
	if (mode == OPTIC_ENABLE)
		reg |= PMA_CTRL3_EN_EXT_SELVCO_EN;
	*/

	pma_w32 ( reg, gpon_pll_slice_pdi_ctrl3 );

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_PLL == ACTIVE))
	OPTIC_DEBUG_WRN("PLL CTRL3: 0x%08X", reg);
#endif
	return OPTIC_STATUS_OK;
}



enum optic_errorcode optic_ll_pll_check ( void )
{
	if ((pma_r32(gpon_pll_slice_pdi_status) & PMA_STATUS_LOCK)
	    == PMA_STATUS_LOCK)
		return OPTIC_STATUS_PLL_LOCKED;
	else
		return OPTIC_STATUS_PLL_NOTLOCKED;
}


/**
   set omu/bosa mode, reset power down

   A) OMU:
      1. Select the OMU operation mode
      tmp = (
         ELEM_GPON_PLL_SLICE_PDI_PMA_TOP_CTRL_EXT_LASER_EN(0) |
         ELEM_GPON_PLL_SLICE_PDI_PMA_TOP_CTRL_TX_CLK_SEL(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMA_TOP_CTRL_RX_CLK_SEL(1) );
      io_write(ADR_GPON_PLL_SLICE_PDI_PMA_TOP_CTRL, tmp);

      2. Disable reset for TX(omu), RX(omu), MM, DLL
         Disable power down for RXOMU, TXOMU, MM, DLL
      tmp = (
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_TX_RSTN(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_TX_PD(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_TXOMU_PD(0) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_RX_RSTN(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_RX_PD(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_RXOMU_PD(0) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_BFD_RSTN(0) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_BFD_PD(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_MM_RSTN(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_MM_PD(0) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_DLL_RSTN(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_DLL_PD(0) );
      io_write(ADR_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL, tmp);

   B) BOSA:
      1. Select the OMU operation mode
      tmp = (
         ELEM_GPON_PLL_SLICE_PDI_PMA_TOP_CTRL_EXT_LASER_EN(0) |
         ELEM_GPON_PLL_SLICE_PDI_PMA_TOP_CTRL_TX_CLK_SEL(0) |
         ELEM_GPON_PLL_SLICE_PDI_PMA_TOP_CTRL_RX_CLK_SEL(0) );
      io_write(ADR_GPON_PLL_SLICE_PDI_PMA_TOP_CTRL, tmp);

      2. Disable reset for TX(omu), RX(omu), BFD, MM, DLL
         Disable power down for RX, TX, BFD, MM, DLL
      tmp = (
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_TX_RSTN(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_TX_PD(0) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_TXOMU_PD(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_RX_RSTN(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_RX_PD(0) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_RXOMU_PD(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_BFD_RSTN(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_BFD_PD(0) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_MM_RSTN(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_MM_PD(0) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_DLL_RSTN(1) |
         ELEM_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL_DLL_PD(0) );
      io_write(ADR_GPON_PLL_SLICE_PDI_PMD_RESETCONTROL, tmp);
*/
enum optic_errorcode optic_ll_pll_start ( const enum optic_manage_mode mode )
{
	uint32_t reg_top_ctrl = 0, reg_resetcontrol;

	/* keep voice pll as defined by voice driver if any */
	reg_resetcontrol = pma_r32 (gpon_pll_slice_pdi_pmd_resetcontrol) & 
		(PMA_PMD_RESETCONTROL_DLL_PD | PMA_PMD_RESETCONTROL_DLL_RSTN);
	switch (mode) {
	case OPTIC_NOMODE:
		/* OMU mode for TX + RX clock */
		reg_top_ctrl = (PMA_PMA_TOP_CTRL_TX_CLK_SEL |
	       			PMA_PMA_TOP_CTRL_RX_CLK_SEL);

		/* all power down + reset */
		reg_resetcontrol |= (PMA_PMD_RESETCONTROL_MM_PD |
		                    PMA_PMD_RESETCONTROL_BFD_PD |
		                    PMA_PMD_RESETCONTROL_TXOMU_PD |
		                    PMA_PMD_RESETCONTROL_TX_PD |
		                    PMA_PMD_RESETCONTROL_RXOMU_PD |
		                    PMA_PMD_RESETCONTROL_RX_PD);

		break;
	case OPTIC_OMU:
		/* OMU mode for TX + RX clock */
		reg_top_ctrl = (PMA_PMA_TOP_CTRL_TX_CLK_SEL |
	       			PMA_PMA_TOP_CTRL_RX_CLK_SEL|
	       			PMA_PMA_TOP_CTRL_EXT_LASER_EN);
		/* disable power down + no reset RX/TX OMU, DLL, MM */
		reg_resetcontrol |= (PMA_PMD_RESETCONTROL_MM_RSTN |
				    PMA_PMD_RESETCONTROL_BFD_PD |
				    PMA_PMD_RESETCONTROL_TX_PD |
				    PMA_PMD_RESETCONTROL_TX_RSTN |
				    PMA_PMD_RESETCONTROL_RX_PD |
				    PMA_PMD_RESETCONTROL_RX_RSTN);
		break;
	case OPTIC_BOSA:
		/* no OMU mode for TX + RX clock */
		reg_top_ctrl = 0;
		/* disable power down + no reset RX/TX, DLL, MM, BFD */
		reg_resetcontrol |= (PMA_PMD_RESETCONTROL_MM_RSTN |
		                    PMA_PMD_RESETCONTROL_BFD_RSTN |
		                    PMA_PMD_RESETCONTROL_TXOMU_PD |
		                    PMA_PMD_RESETCONTROL_TX_RSTN |
		                    PMA_PMD_RESETCONTROL_RXOMU_PD |
		                    PMA_PMD_RESETCONTROL_RX_RSTN);
		break;
	case OPTIC_BOSA_2:
		/* OMU mode for RX clock */
		reg_top_ctrl = (PMA_PMA_TOP_CTRL_RX_CLK_SEL|
	       			PMA_PMA_TOP_CTRL_EXT_LASER_EN);
		/* disable power down + no reset RX OMU/TX, DLL, MM, BFD */
		reg_resetcontrol |= (PMA_PMD_RESETCONTROL_MM_RSTN |
		                    PMA_PMD_RESETCONTROL_BFD_RSTN |
		                    PMA_PMD_RESETCONTROL_TXOMU_PD |
		                    PMA_PMD_RESETCONTROL_TX_RSTN |
		                    PMA_PMD_RESETCONTROL_RX_PD |
		                    PMA_PMD_RESETCONTROL_RX_RSTN);
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	pma_w32 ( reg_top_ctrl, gpon_pll_slice_pdi_pma_top_ctrl );
	pma_w32 ( reg_resetcontrol, gpon_pll_slice_pdi_pmd_resetcontrol );

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_PLL == ACTIVE))
	optic_ll_pll_dump ();
#endif

	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_ll_pll_laser_set ( const bool single_ended )
{
	pma_w32_mask ( PMA_PMA_TOP_CTRL_EXT_LASER_EN, (single_ended == true)?
		       PMA_PMA_TOP_CTRL_EXT_LASER_EN : 0,
		       gpon_pll_slice_pdi_pma_top_ctrl );

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_PLL == ACTIVE))
	OPTIC_DEBUG_WRN("PLL TOP_CTRL: 0x%08X",
			 pma_r32 ( gpon_pll_slice_pdi_pma_top_ctrl ));
#endif

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_pll_rogue (void)
{
	pma_w32_mask ( PMA_PMD_RESETCONTROL_TX_RSTN |
			PMA_PMD_RESETCONTROL_TX_PD |
			PMA_PMD_RESETCONTROL_BFD_RSTN |
			PMA_PMD_RESETCONTROL_BFD_PD,
			0,
		    gpon_pll_slice_pdi_pmd_resetcontrol );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_pll_module_set ( const enum optic_pll_module
					       module,
                                               const enum optic_activation
                                               mode )
{
	switch (module) {
	case OPTIC_PLL_TX:
		pma_w32_mask ( PMA_PMD_RESETCONTROL_TX_RSTN,
			       (mode == OPTIC_ENABLE)?
				PMA_PMD_RESETCONTROL_TX_RSTN : 0,
			       gpon_pll_slice_pdi_pmd_resetcontrol );
		break;
	case OPTIC_PLL_RX:
		pma_w32_mask ( PMA_PMD_RESETCONTROL_RX_RSTN,
			       (mode == OPTIC_ENABLE)?
				PMA_PMD_RESETCONTROL_RX_RSTN : 0,
			       gpon_pll_slice_pdi_pmd_resetcontrol );
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_pll_module_get ( const enum optic_pll_module
					       module,
                                               enum optic_activation *mode )
{
	uint32_t reg = pma_r32(gpon_pll_slice_pdi_pmd_resetcontrol);

	if (mode == NULL)
		return OPTIC_STATUS_ERR;

	switch (module) {
	case OPTIC_PLL_TX:
		*mode = (reg & PMA_PMD_RESETCONTROL_TX_RSTN) ?
		        OPTIC_ENABLE : OPTIC_DISABLE;
		break;
	case OPTIC_PLL_RX:
		*mode = (reg & PMA_PMD_RESETCONTROL_RX_RSTN) ?
		        OPTIC_ENABLE : OPTIC_DISABLE;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	return OPTIC_STATUS_OK;
}

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_PLL == ACTIVE))
static enum optic_errorcode optic_ll_pll_dump ( void )
{
	uint32_t reg;

	reg = pma_r32 ( gpon_pll_slice_pdi_pmd_resetcontrol );
	OPTIC_DEBUG_WRN("PLL RESETCONTROL: 0x%08X", reg);

	reg = pma_r32 ( gpon_pll_slice_pdi_ctrl1 );
	OPTIC_DEBUG_WRN("PLL CTRL1: 0x%08X", reg);

	reg = pma_r32 ( gpon_pll_slice_pdi_ctrl2 );
	OPTIC_DEBUG_WRN("PLL CTRL2: 0x%08X", reg);

	reg = pma_r32 ( gpon_pll_slice_pdi_ctrl3 );
	OPTIC_DEBUG_WRN("PLL CTRL3: 0x%08X", reg);

	reg = pma_r32 ( gpon_pll_slice_pdi_ctrl4 );
	OPTIC_DEBUG_WRN("PLL CTRL4: 0x%08X", reg);

	reg = pma_r32 ( gpon_pll_slice_pdi_ctrl5 );
	OPTIC_DEBUG_WRN("PLL CTRL5: 0x%08X", reg);

	reg = pma_r32 ( gpon_pll_slice_pdi_ctrl6 );
	OPTIC_DEBUG_WRN("PLL CTRL6: 0x%08X", reg);

	reg = pma_r32 ( gpon_pll_slice_pdi_ctrl7 );
	OPTIC_DEBUG_WRN("PLL CTRL7: 0x%08X", reg);

	reg = pma_r32 ( gpon_pll_slice_pdi_a_ctrl1 );
	OPTIC_DEBUG_WRN("PLL A_CTRL1: 0x%08X", reg);

	reg = pma_r32 ( gpon_pll_slice_pdi_a_ctrl2 );
	OPTIC_DEBUG_WRN("PLL A_CTRL2: 0x%08X", reg);

	reg = pma_r32 ( gpon_pll_slice_pdi_a_ctrl3 );
	OPTIC_DEBUG_WRN("PLL A_CTRL3: 0x%08X", reg);

	reg = pma_r32 ( gpon_pll_slice_pdi_status );
	OPTIC_DEBUG_WRN("PLL STATUS: 0x%08X", reg);

	reg = pma_r32 ( gpon_pll_slice_pdi_pma_top_ctrl );
	OPTIC_DEBUG_WRN("PLL TOP_CTRL: 0x%08X", reg);

	return OPTIC_STATUS_OK;
}

static enum optic_errorcode optic_ll_pll_dump_status ( void )
{
	uint32_t reg;

	reg = pma_r32 ( gpon_pll_slice_pdi_status );
	OPTIC_DEBUG_WRN("PLL STATUS: 0x%08X", reg);

	return OPTIC_STATUS_OK;
}
#endif

/*! @} */
/*! @} */
