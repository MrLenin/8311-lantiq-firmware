/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, FCSI Interface - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_FCSI_INTERNAL FCSI Register Interface - Internal
   @{
*/
#include "drv_optic_api.h"
#include "drv_optic_ll_fcsi.h"
#include "drv_optic_calc.h"
#include "drv_optic_register.h"
#include "drv_optic_common.h"
#include "drv_optic_reg_fcsic.h"
#ifdef CONFIG_WITH_FALCON_A2X
	#include "drv_optic_ll_tx.h"
#endif

static enum optic_errorcode optic_ll_fcsi_mode_set(
		const struct fcsi_addr_val *fcsi_init,
		uint16_t fcsi_len) {

	uint8_t i;

	for (i=0; i<fcsi_len; i++) {
		if (optic_ll_fcsi_write ( fcsi_init[i].addr, fcsi_init[i].val ) !=
		    OPTIC_STATUS_OK)
			return OPTIC_STATUS_INIT_FAIL;
	}

	return OPTIC_STATUS_OK;
}

/**
	Initialize the FCSI registers.

	This function writes meaningful values to the FCSI registers, because
	the hardware reset leaves all registers at 0x0000.
	The order of accesses must not be changed, otherwise the device
	might be damaged!

	\param p_ctrl - control context

	\return
	- OPTIC_STATUS_OK - success,
	- FCSIC_INIT_FAIL - initialization failed
*/
enum optic_errorcode optic_ll_fcsi_init ( const enum optic_manage_mode mode )
{
	/* !!! changing this setting/order can cause hardware damage !!! */
	enum optic_errorcode ret = OPTIC_STATUS_OK;

#ifdef CONFIG_WITH_FALCON_A1X
	static const struct fcsi_addr_val fcsi_init[] =
	{
		/* TXBOSA */
		{ FCSI_TXBOSA_DDC0, OPTIC_FCSI_TXBOSA_DDC0_RESET },
		{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET },
		{ FCSI_TXBOSA_BDC0, OPTIC_FCSI_TXBOSA_BDC0_RESET },
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET },
		{ FCSI_TXBOSA_CTRL, OPTIC_FCSI_TXBOSA_CTRL_RESET },
		{ FCSI_TXBOSA_CC, OPTIC_FCSI_TXBOSA_CC_RESET },
		{ FCSI_TXBOSA_PH, OPTIC_FCSI_TXBOSA_PH_RESET },
		{ FCSI_TXBOSA_PDS, OPTIC_FCSI_TXBOSA_PDS_RESET },
		/* activate TXBOSA */
		{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET |
				    TXBOSA_DDC1_ENPD},
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET |
				    TXBOSA_BDC1_ENPD},
		/* TXOMU */
		{ FCSI_TXOMU_TXEC, OPTIC_FCSI_TXOMU_TXEC_RESET },
		{ FCSI_TXOMU_TXDC, OPTIC_FCSI_TXOMU_TXDC_RESET },
		{ FCSI_TXOMU_CTRL, OPTIC_FCSI_TXOMU_CTRL_RESET },
		/* RXBOSA */
		{ FCSI_RXBOSA_CTRL, OPTIC_FCSI_RXBOSA_CTRL_RESET },
		/* RXOMU */
		{ FCSI_RXOMU_CTRL, OPTIC_FCSI_RXOMU_CTRL_RESET },
		/* MM */
		{ FCSI_MM_CTRL, OPTIC_FCSI_MM_CTRL_RESET },
		/* VDAC */
		{ FCSI_VDAC_CTRL, OPTIC_FCSI_VDAC_CTRL_RESET },
		/* BFD */
		{ FCSI_BFD_GVS, OPTIC_FCSI_BFD_GVS_RESET },
		{ FCSI_BFD_CTRL0, OPTIC_FCSI_BFD_CTRL0_RESET },
		{ FCSI_BFD_CTRL1, OPTIC_FCSI_BFD_CTRL1_RESET },
		/* PI */
		{ FCSI_PI_CTRL, OPTIC_FCSI_PI_CTRL_RESET },
		/* CBIAS */
		{ FCSI_CBIAS_CTRL0, OPTIC_FCSI_CBIAS_CTRL0_RESET },
		{ FCSI_CBIAS_CTRL1, OPTIC_FCSI_CBIAS_CTRL1_RESET },
		/* VDLL */
		{ FCSI_VDLL_CTRL, OPTIC_FCSI_VDLL_CTRL_RESET }
	};

	static const struct fcsi_addr_val fcsi_init_omu[] =
	{
		/* TXBOSA */
		{ FCSI_TXBOSA_DDC0, OPTIC_FCSI_TXBOSA_DDC0_RESET_OMU },
		{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET_OMU },
		{ FCSI_TXBOSA_BDC0, OPTIC_FCSI_TXBOSA_BDC0_RESET_OMU },
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET_OMU },
		{ FCSI_TXBOSA_CTRL, OPTIC_FCSI_TXBOSA_CTRL_RESET_OMU },
		{ FCSI_TXBOSA_CC, OPTIC_FCSI_TXBOSA_CC_RESET_OMU },
		{ FCSI_TXBOSA_PH, OPTIC_FCSI_TXBOSA_PH_RESET_OMU },
		{ FCSI_TXBOSA_PDS, OPTIC_FCSI_TXBOSA_PDS_RESET_OMU },
		/* TXOMU */
		{ FCSI_TXOMU_TXEC, OPTIC_FCSI_TXOMU_TXEC_RESET_OMU },
		{ FCSI_TXOMU_TXDC, OPTIC_FCSI_TXOMU_TXDC_RESET_OMU },
		{ FCSI_TXOMU_CTRL, OPTIC_FCSI_TXOMU_CTRL_RESET_OMU },
		/* RXBOSA */
		{ FCSI_RXBOSA_CTRL, OPTIC_FCSI_RXBOSA_CTRL_RESET_OMU },
		/* RXOMU */
		{ FCSI_RXOMU_CTRL, OPTIC_FCSI_RXOMU_CTRL_RESET_OMU },
		/* MM */
		{ FCSI_MM_CTRL, OPTIC_FCSI_MM_CTRL_RESET_OMU },
		/* VDAC */
		{ FCSI_VDAC_CTRL, OPTIC_FCSI_VDAC_CTRL_RESET_OMU },
		/* BFD */
		{ FCSI_BFD_GVS, OPTIC_FCSI_BFD_GVS_RESET_OMU },
		{ FCSI_BFD_CTRL0, OPTIC_FCSI_BFD_CTRL0_RESET_OMU },
		{ FCSI_BFD_CTRL1, OPTIC_FCSI_BFD_CTRL1_RESET_OMU },
		/* PI */
		{ FCSI_PI_CTRL, OPTIC_FCSI_PI_CTRL_RESET_OMU },
		/* CBIAS */
		{ FCSI_CBIAS_CTRL0, OPTIC_FCSI_CBIAS_CTRL0_RESET_OMU },
		{ FCSI_CBIAS_CTRL1, OPTIC_FCSI_CBIAS_CTRL1_RESET_OMU },
		/* VDLL */
		{ FCSI_VDLL_CTRL, OPTIC_FCSI_VDLL_CTRL_RESET_OMU }
	};

	static const struct fcsi_addr_val fcsi_init_bosa[] =
	{
		/* TXBOSA */
		{ FCSI_TXBOSA_DDC0, OPTIC_FCSI_TXBOSA_DDC0_RESET_BOSA },
		{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET_BOSA },
		{ FCSI_TXBOSA_BDC0, OPTIC_FCSI_TXBOSA_BDC0_RESET_BOSA },
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET_BOSA },
		{ FCSI_TXBOSA_CTRL, OPTIC_FCSI_TXBOSA_CTRL_RESET_BOSA },
		{ FCSI_TXBOSA_CC, OPTIC_FCSI_TXBOSA_CC_RESET_BOSA },
		{ FCSI_TXBOSA_PH, OPTIC_FCSI_TXBOSA_PH_RESET_BOSA },
		{ FCSI_TXBOSA_PDS, OPTIC_FCSI_TXBOSA_PDS_RESET_BOSA },
		/* activate TXBOSA */
		{ FCSI_TXBOSA_CTRL, OPTIC_FCSI_TXBOSA_CTRL_RESET_BOSA |
		                    TXBOSA_CTRL_FFR },
		{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET_BOSA |
				    TXBOSA_DDC1_ENPD},
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET_BOSA |
				    TXBOSA_BDC1_ENPD},
		/* TXOMU */
		{ FCSI_TXOMU_TXEC, OPTIC_FCSI_TXOMU_TXEC_RESET_BOSA },
		{ FCSI_TXOMU_TXDC, OPTIC_FCSI_TXOMU_TXDC_RESET_BOSA },
		{ FCSI_TXOMU_CTRL, OPTIC_FCSI_TXOMU_CTRL_RESET_BOSA },
		/* RXBOSA */
		{ FCSI_RXBOSA_CTRL, OPTIC_FCSI_RXBOSA_CTRL_RESET_BOSA },
		/* RXOMU */
		{ FCSI_RXOMU_CTRL, OPTIC_FCSI_RXOMU_CTRL_RESET_BOSA },
		/* MM */
		{ FCSI_MM_CTRL, OPTIC_FCSI_MM_CTRL_RESET_BOSA },
		/* VDAC */
		{ FCSI_VDAC_CTRL, OPTIC_FCSI_VDAC_CTRL_RESET_BOSA },
		/* BFD */
		{ FCSI_BFD_GVS, OPTIC_FCSI_BFD_GVS_RESET_BOSA },
		{ FCSI_BFD_CTRL0, OPTIC_FCSI_BFD_CTRL0_RESET_BOSA },
		{ FCSI_BFD_CTRL1, OPTIC_FCSI_BFD_CTRL1_RESET_BOSA },
		/* PI */
		{ FCSI_PI_CTRL, OPTIC_FCSI_PI_CTRL_RESET_BOSA },
		/* CBIAS */
		{ FCSI_CBIAS_CTRL0, OPTIC_FCSI_CBIAS_CTRL0_RESET_BOSA },
		{ FCSI_CBIAS_CTRL1, OPTIC_FCSI_CBIAS_CTRL1_RESET_BOSA },
		/* VDLL */
		{ FCSI_VDLL_CTRL, OPTIC_FCSI_VDLL_CTRL_RESET_BOSA }
	};

	static const struct fcsi_addr_val fcsi_init_bosa_2[] =
	{
		/* TXBOSA */
		{ FCSI_TXBOSA_DDC0, OPTIC_FCSI_TXBOSA_DDC0_RESET_BOSA },
		{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET_BOSA },
		{ FCSI_TXBOSA_BDC0, OPTIC_FCSI_TXBOSA_BDC0_RESET_BOSA },
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET_BOSA },
		{ FCSI_TXBOSA_CTRL, OPTIC_FCSI_TXBOSA_CTRL_RESET_BOSA },
		{ FCSI_TXBOSA_CC, OPTIC_FCSI_TXBOSA_CC_RESET_BOSA },
		{ FCSI_TXBOSA_PH, OPTIC_FCSI_TXBOSA_PH_RESET_BOSA },
		{ FCSI_TXBOSA_PDS, OPTIC_FCSI_TXBOSA_PDS_RESET_BOSA },
		/* activate TXBOSA */
		{ FCSI_TXBOSA_CTRL, OPTIC_FCSI_TXBOSA_CTRL_RESET_BOSA |
		                    TXBOSA_CTRL_FFR },
		{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET_BOSA |
				    TXBOSA_DDC1_ENPD},
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET_BOSA |
				    TXBOSA_BDC1_ENPD},
		/* TXOMU */
		{ FCSI_TXOMU_TXEC, OPTIC_FCSI_TXOMU_TXEC_RESET_BOSA },
		{ FCSI_TXOMU_TXDC, OPTIC_FCSI_TXOMU_TXDC_RESET_BOSA },
		{ FCSI_TXOMU_CTRL, OPTIC_FCSI_TXOMU_CTRL_RESET_BOSA },
		/* RXBOSA */
		{ FCSI_RXBOSA_CTRL, OPTIC_FCSI_RXBOSA_CTRL_RESET_BOSA },
		/* RXOMU */
		{ FCSI_RXOMU_CTRL, OPTIC_FCSI_RXOMU_CTRL_RESET_BOSA_2 },
		/* MM */
		{ FCSI_MM_CTRL, OPTIC_FCSI_MM_CTRL_RESET_BOSA },
		/* VDAC */
		{ FCSI_VDAC_CTRL, OPTIC_FCSI_VDAC_CTRL_RESET_BOSA },
		/* BFD */
		{ FCSI_BFD_GVS, OPTIC_FCSI_BFD_GVS_RESET_BOSA },
		{ FCSI_BFD_CTRL0, OPTIC_FCSI_BFD_CTRL0_RESET_BOSA },
		{ FCSI_BFD_CTRL1, OPTIC_FCSI_BFD_CTRL1_RESET_BOSA },
		/* PI */
		{ FCSI_PI_CTRL, OPTIC_FCSI_PI_CTRL_RESET_BOSA },
		/* CBIAS */
		{ FCSI_CBIAS_CTRL0, OPTIC_FCSI_CBIAS_CTRL0_RESET_BOSA },
		{ FCSI_CBIAS_CTRL1, OPTIC_FCSI_CBIAS_CTRL1_RESET_BOSA },
		/* VDLL */
		{ FCSI_VDLL_CTRL, OPTIC_FCSI_VDLL_CTRL_RESET_BOSA }
	};
#endif

#ifdef CONFIG_WITH_FALCON_A2X
	static const struct fcsi_addr_val fcsi_init_a21[] =
	{
		/* TXBOSA */
		{ FCSI_TXBOSA_DDC0, OPTIC_FCSI_TXBOSA_DDC0_RESET_A21 },
		{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET_A21 },
		{ FCSI_TXBOSA_BDC0, OPTIC_FCSI_TXBOSA_BDC0_RESET_A21 },
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET_A21 },
		{ FCSI_TXBOSA_CTRL, OPTIC_FCSI_TXBOSA_CTRL_RESET_A21 },
		{ FCSI_TXBOSA_CC, OPTIC_FCSI_TXBOSA_CC_RESET_A21 },
		{ FCSI_TXBOSA_PH, OPTIC_FCSI_TXBOSA_PH_RESET_A21 },
		{ FCSI_TXBOSA_PDS, OPTIC_FCSI_TXBOSA_PDS_RESET_A21 },
		/* activate TXBOSA -
		 * GPONSW-1035 activation will be done at the end of init */
		/*{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET_A21 |
				    TXBOSA_DDC1_ENPD},
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET_A21 |
				    TXBOSA_BDC1_ENPD},*/
		/* TXOMU */
		{ FCSI_TXOMU_TXEC, OPTIC_FCSI_TXOMU_TXEC_RESET },
		{ FCSI_TXOMU_TXDC, OPTIC_FCSI_TXOMU_TXDC_RESET },
		{ FCSI_TXOMU_CTRL, OPTIC_FCSI_TXOMU_CTRL_RESET },
		/* RXBOSA */
		{ FCSI_RXBOSA_CTRL, OPTIC_FCSI_RXBOSA_CTRL_RESET },
		/* RXOMU */
		{ FCSI_RXOMU_CTRL, OPTIC_FCSI_RXOMU_CTRL_RESET },
		/* MM */
		{ FCSI_MM_CTRL, OPTIC_FCSI_MM_CTRL_RESET },
		/* VDAC */
		{ FCSI_VDAC_CTRL, OPTIC_FCSI_VDAC_CTRL_RESET },
		/* BFD */
		{ FCSI_BFD_GVS, OPTIC_FCSI_BFD_GVS_RESET },
		{ FCSI_BFD_CTRL0, OPTIC_FCSI_BFD_CTRL0_RESET },
		{ FCSI_BFD_CTRL1, OPTIC_FCSI_BFD_CTRL1_RESET },
		/* PI */
		{ FCSI_PI_CTRL, OPTIC_FCSI_PI_CTRL_RESET },
		/* CBIAS */
		{ FCSI_CBIAS_CTRL0, OPTIC_FCSI_CBIAS_CTRL0_RESET },
		{ FCSI_CBIAS_CTRL1, OPTIC_FCSI_CBIAS_CTRL1_RESET },
		/* VDLL */
		{ FCSI_VDLL_CTRL, OPTIC_FCSI_VDLL_CTRL_RESET }
	};

	static const struct fcsi_addr_val fcsi_init_omu_a21[] =
	{
		/* TXBOSA */
		{ FCSI_TXBOSA_DDC0, OPTIC_FCSI_TXBOSA_DDC0_RESET_OMU_A21 },
		{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET_OMU_A21 },
		{ FCSI_TXBOSA_BDC0, OPTIC_FCSI_TXBOSA_BDC0_RESET_OMU_A21 },
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET_OMU_A21 },
		{ FCSI_TXBOSA_CTRL, OPTIC_FCSI_TXBOSA_CTRL_RESET_OMU_A21 },
		{ FCSI_TXBOSA_CC, OPTIC_FCSI_TXBOSA_CC_RESET_OMU_A21 },
		{ FCSI_TXBOSA_PH, OPTIC_FCSI_TXBOSA_PH_RESET_OMU_A21 },
		{ FCSI_TXBOSA_PDS, OPTIC_FCSI_TXBOSA_PDS_RESET_OMU_A21 },
		/* TXOMU */
		{ FCSI_TXOMU_TXEC, OPTIC_FCSI_TXOMU_TXEC_RESET_OMU },
		{ FCSI_TXOMU_TXDC, OPTIC_FCSI_TXOMU_TXDC_RESET_OMU },
		{ FCSI_TXOMU_CTRL, OPTIC_FCSI_TXOMU_CTRL_RESET_OMU },
		/* RXBOSA */
		{ FCSI_RXBOSA_CTRL, OPTIC_FCSI_RXBOSA_CTRL_RESET_OMU },
		/* RXOMU */
		{ FCSI_RXOMU_CTRL, OPTIC_FCSI_RXOMU_CTRL_RESET_OMU },
		/* MM */
		{ FCSI_MM_CTRL, OPTIC_FCSI_MM_CTRL_RESET_OMU },
		/* VDAC */
		{ FCSI_VDAC_CTRL, OPTIC_FCSI_VDAC_CTRL_RESET_OMU },
		/* BFD */
		{ FCSI_BFD_GVS, OPTIC_FCSI_BFD_GVS_RESET_OMU },
		{ FCSI_BFD_CTRL0, OPTIC_FCSI_BFD_CTRL0_RESET_OMU },
		{ FCSI_BFD_CTRL1, OPTIC_FCSI_BFD_CTRL1_RESET_OMU },
		/* PI */
		{ FCSI_PI_CTRL, OPTIC_FCSI_PI_CTRL_RESET_OMU },
		/* CBIAS */
		{ FCSI_CBIAS_CTRL0, OPTIC_FCSI_CBIAS_CTRL0_RESET_OMU },
		{ FCSI_CBIAS_CTRL1, OPTIC_FCSI_CBIAS_CTRL1_RESET_OMU },
		/* VDLL */
		{ FCSI_VDLL_CTRL, OPTIC_FCSI_VDLL_CTRL_RESET_OMU }
	};

	static const struct fcsi_addr_val fcsi_init_bosa_a21[] =
	{
		/* TXBOSA */
		{ FCSI_TXBOSA_DDC0, OPTIC_FCSI_TXBOSA_DDC0_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_BDC0, OPTIC_FCSI_TXBOSA_BDC0_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_CTRL, OPTIC_FCSI_TXBOSA_CTRL_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_CC, OPTIC_FCSI_TXBOSA_CC_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_PH, OPTIC_FCSI_TXBOSA_PH_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_PDS, OPTIC_FCSI_TXBOSA_PDS_RESET_BOSA_A21 },
		/* activate TXBOSA */
		{ FCSI_TXBOSA_CTRL, OPTIC_FCSI_TXBOSA_CTRL_RESET_BOSA_A21 |
		                    TXBOSA_CTRL_FFR },
		/* GPONSW-1035 activation will be done at the end of init */
		/*{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET_BOSA_A21 |
		    	    	    TXBOSA_DDC1_ENPD},
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET_BOSA_A21 |
				    TXBOSA_BDC1_ENPD},*/
		/* TXOMU */
		{ FCSI_TXOMU_TXEC, OPTIC_FCSI_TXOMU_TXEC_RESET_BOSA },
		{ FCSI_TXOMU_TXDC, OPTIC_FCSI_TXOMU_TXDC_RESET_BOSA },
		{ FCSI_TXOMU_CTRL, OPTIC_FCSI_TXOMU_CTRL_RESET_BOSA },
		/* RXBOSA */
		{ FCSI_RXBOSA_CTRL, OPTIC_FCSI_RXBOSA_CTRL_RESET_BOSA },
		/* RXOMU */
		{ FCSI_RXOMU_CTRL, OPTIC_FCSI_RXOMU_CTRL_RESET_BOSA },
		/* MM */
		{ FCSI_MM_CTRL, OPTIC_FCSI_MM_CTRL_RESET_BOSA },
		/* VDAC */
		{ FCSI_VDAC_CTRL, OPTIC_FCSI_VDAC_CTRL_RESET_BOSA },
		/* BFD */
		{ FCSI_BFD_GVS, OPTIC_FCSI_BFD_GVS_RESET_BOSA },
		{ FCSI_BFD_CTRL0, OPTIC_FCSI_BFD_CTRL0_RESET_BOSA },
		{ FCSI_BFD_CTRL1, OPTIC_FCSI_BFD_CTRL1_RESET_BOSA },
		/* PI */
		{ FCSI_PI_CTRL, OPTIC_FCSI_PI_CTRL_RESET_BOSA },
		/* CBIAS */
		{ FCSI_CBIAS_CTRL0, OPTIC_FCSI_CBIAS_CTRL0_RESET_BOSA },
		{ FCSI_CBIAS_CTRL1, OPTIC_FCSI_CBIAS_CTRL1_RESET_BOSA },
		/* VDLL */
		{ FCSI_VDLL_CTRL, OPTIC_FCSI_VDLL_CTRL_RESET_BOSA }
	};

	static const struct fcsi_addr_val fcsi_init_bosa_2_a21[] =
	{
		/* TXBOSA */
		{ FCSI_TXBOSA_DDC0, OPTIC_FCSI_TXBOSA_DDC0_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_BDC0, OPTIC_FCSI_TXBOSA_BDC0_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_CTRL, OPTIC_FCSI_TXBOSA_CTRL_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_CC, OPTIC_FCSI_TXBOSA_CC_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_PH, OPTIC_FCSI_TXBOSA_PH_RESET_BOSA_A21 },
		{ FCSI_TXBOSA_PDS, OPTIC_FCSI_TXBOSA_PDS_RESET_BOSA_A21 },
		/* activate TXBOSA */
		{ FCSI_TXBOSA_CTRL, OPTIC_FCSI_TXBOSA_CTRL_RESET_BOSA_A21 |
		                    TXBOSA_CTRL_FFR },
		{ FCSI_TXBOSA_DDC1, OPTIC_FCSI_TXBOSA_DDC1_RESET_BOSA_A21 |
				    TXBOSA_DDC1_ENPD},
		{ FCSI_TXBOSA_BDC1, OPTIC_FCSI_TXBOSA_BDC1_RESET_BOSA_A21 |
				    TXBOSA_BDC1_ENPD},
		/* TXOMU */
		{ FCSI_TXOMU_TXEC, OPTIC_FCSI_TXOMU_TXEC_RESET_BOSA },
		{ FCSI_TXOMU_TXDC, OPTIC_FCSI_TXOMU_TXDC_RESET_BOSA },
		{ FCSI_TXOMU_CTRL, OPTIC_FCSI_TXOMU_CTRL_RESET_BOSA },
		/* RXBOSA */
		{ FCSI_RXBOSA_CTRL, OPTIC_FCSI_RXBOSA_CTRL_RESET_BOSA },
		/* RXOMU */
		{ FCSI_RXOMU_CTRL, OPTIC_FCSI_RXOMU_CTRL_RESET_BOSA_2 },
		/* MM */
		{ FCSI_MM_CTRL, OPTIC_FCSI_MM_CTRL_RESET_BOSA },
		/* VDAC */
		{ FCSI_VDAC_CTRL, OPTIC_FCSI_VDAC_CTRL_RESET_BOSA },
		/* BFD */
		{ FCSI_BFD_GVS, OPTIC_FCSI_BFD_GVS_RESET_BOSA },
		{ FCSI_BFD_CTRL0, OPTIC_FCSI_BFD_CTRL0_RESET_BOSA },
		{ FCSI_BFD_CTRL1, OPTIC_FCSI_BFD_CTRL1_RESET_BOSA },
		/* PI */
		{ FCSI_PI_CTRL, OPTIC_FCSI_PI_CTRL_RESET_BOSA },
		/* CBIAS */
		{ FCSI_CBIAS_CTRL0, OPTIC_FCSI_CBIAS_CTRL0_RESET_BOSA },
		{ FCSI_CBIAS_CTRL1, OPTIC_FCSI_CBIAS_CTRL1_RESET_BOSA },
		/* VDLL */
		{ FCSI_VDLL_CTRL, OPTIC_FCSI_VDLL_CTRL_RESET_BOSA }
	};
#endif

	if (is_falcon_chip_a2x()) { /* A21 */

#ifdef CONFIG_WITH_FALCON_A2X
		//optic_ll_tx_pd_latchoverride_set(OPTIC_ENABLE);

		switch (mode) {
		case OPTIC_NOMODE:
			ret = optic_ll_fcsi_mode_set(fcsi_init_a21, ARRAY_SIZE(fcsi_init_a21));
			break;
		case OPTIC_OMU:
			ret = optic_ll_fcsi_mode_set(fcsi_init_omu_a21, ARRAY_SIZE(fcsi_init_omu_a21));
			break;
		case OPTIC_BOSA:
			ret = optic_ll_fcsi_mode_set(fcsi_init_bosa_a21, ARRAY_SIZE(fcsi_init_bosa_a21));
			break;
		case OPTIC_BOSA_2:
			ret = optic_ll_fcsi_mode_set(fcsi_init_bosa_2_a21, ARRAY_SIZE(fcsi_init_bosa_2_a21));
			break;
		default:
			return OPTIC_STATUS_POOR;
		}

		//optic_ll_tx_pd_latchoverride_set(OPTIC_DISABLE);
#else
		OPTIC_DEBUG_ERR("optic_ll_fcsi_init: wrong chip version!");
		return OPTIC_STATUS_ERR;
#endif
	}

	if (is_falcon_chip_a1x()) { /* A12 */

#ifdef CONFIG_WITH_FALCON_A1X
		switch (mode) {
		case OPTIC_NOMODE:
			ret = optic_ll_fcsi_mode_set(fcsi_init, ARRAY_SIZE(fcsi_init));
			break;
		case OPTIC_OMU:
			ret = optic_ll_fcsi_mode_set(fcsi_init_omu, ARRAY_SIZE(fcsi_init_omu));
			break;
		case OPTIC_BOSA:
			ret = optic_ll_fcsi_mode_set(fcsi_init_bosa, ARRAY_SIZE(fcsi_init_bosa));
			break;
		case OPTIC_BOSA_2:
			ret = optic_ll_fcsi_mode_set(fcsi_init_bosa_2, ARRAY_SIZE(fcsi_init_bosa_2));
			break;
		default:
			return OPTIC_STATUS_POOR;
		}
#else
		OPTIC_DEBUG_ERR("optic_ll_fcsi_init: wrong chip version!");
		return OPTIC_STATUS_ERR;
#endif
	}

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_FCSI == ACTIVE))
	optic_ll_fcsi_dump ();
#endif
	return ret;
}

enum optic_errorcode optic_ll_fcsi_init_bosa_2nd ( void )
{
	/* !!! changing this setting/order can cause hardware damage !!! */
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	uint32_t data;

	if (optic_ll_fcsi_read ( FCSI_TXBOSA_CTRL, &data) != OPTIC_STATUS_OK)
		return OPTIC_STATUS_INIT_FAIL;

	if ((data & TXBOSA_CTRL_FFR) != TXBOSA_CTRL_FFR)
		ret = optic_ll_fcsi_write ( FCSI_TXBOSA_CTRL,
		                                  data | TXBOSA_CTRL_FFR );

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_FCSI == ACTIVE))
	optic_ll_fcsi_dump ();
#endif
	return ret;
}

enum optic_errorcode optic_ll_fcsi_bfd_cfg ( const struct optic_config_fcsi
                                             *config_fcsi )
{
#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_FCSI == ACTIVE))
	uint32_t reg;
#endif

	/* BFD */
	if (config_fcsi == NULL)
		return OPTIC_STATUS_ERR;

	if (optic_ll_fcsi_write ( FCSI_BFD_GVS, config_fcsi->gvs )
	    != OPTIC_STATUS_OK)
		return OPTIC_STATUS_INIT_FAIL;


#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_FCSI == ACTIVE))
	optic_ll_fcsi_read ( FCSI_BFD_GVS, &reg );
	OPTIC_DEBUG_MSG("FCSI #%d: 0x%04X", FCSI_BFD_GVS, reg);
#endif
	return OPTIC_STATUS_OK;
}

/**
	Write a FCSI register.

	\param addr 8 bit fcsi register address
	\param data 16 bit register value to write

	\return
	- OPTIC_STATUS_OK - success,
	- OPTIC_STATUS_FCSI_WRITETIMEOUT - write failed
*/
enum optic_errorcode optic_ll_fcsi_write ( const vuint16_t *addr,
                                           const uint32_t data )
{
	enum optic_errorcode ret;
	uint32_t cnt = 100, data_;
	uint8_t cycle = 4;
	ulong_t reg = (ulong_t) addr;

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP == ACTIVE))
	OPTIC_DEBUG_MSG("FCSI #%d: w 0x%04X", reg, data);
#endif
#ifdef EVENT_LOGGER_DEBUG
	EL_LOG_EVENT_REG_WR (1, 0, 0, (uint32_t)addr, &data, 1);
#endif

	while (cycle) {
		/* wait until command fifo is empty and transmitter ready */
		while ((cnt) && (( fcsic_r32 (stat) &
		       (FCSIC_STAT_XR | FCSIC_STAT_XE)) !=
		       (FCSIC_STAT_XR_FRDY | FCSIC_STAT_XE_FEMP)))
			cnt--;

		if (cnt) {
			fcsic_w32 ( FCSIC_CMD_CMD_WRITE |
				    ((0 << FCSIC_CMD_LEN_OFFSET) &
				           FCSIC_CMD_LEN_MASK) |
				    ((reg << FCSIC_CMD_ADDR_OFFSET) &
					     FCSIC_CMD_ADDR_MASK), cmd );

			fcsic_w32 ( (data << FCSIC_DATA_DATA_OFFSET) &
					     FCSIC_DATA_DATA_MASK, data );

		} else
			return OPTIC_STATUS_FCSI_WRITETIMEOUT;

		/* double check written value */
		ret = optic_ll_fcsi_read ( addr, &data_ );
		if (ret != OPTIC_STATUS_OK)
			return ret;

		if (data_ != data) {
			OPTIC_DEBUG_MSG("FCSI #%d: w 0x%04X, r 0x%04X",
					reg, data, data_);
			cycle --;
		} else
			break;
	}

	return OPTIC_STATUS_OK;
}

/**
	Read a FCSI register.

	\param addr 8 bit fcsi register address
	\param data 16 bit register value to write

	\return
	- OPTIC_STATUS_OK - success,
	- OPTIC_STATUS_FCSI_READTIMEOUT - read failed
*/
enum optic_errorcode optic_ll_fcsi_read ( const vuint16_t *addr,
                                          uint32_t *data )
{
	uint32_t cnt = 100;
	ulong_t reg = (ulong_t) addr;

	if (data == NULL)
		return OPTIC_STATUS_ERR;

	/* wait until command fifo is empty and transmitter ready */
	while ((cnt) && (( fcsic_r32 (stat) &
	       (FCSIC_STAT_XR | FCSIC_STAT_XE)) !=
	       (FCSIC_STAT_XR_FRDY | FCSIC_STAT_XE_FEMP)))
		cnt--;

	if (cnt) {
		fcsic_w32 ( FCSIC_CMD_CMD_READ |
			    ((0 << FCSIC_CMD_LEN_OFFSET) & FCSIC_CMD_LEN_MASK) |
			    ((reg << FCSIC_CMD_ADDR_OFFSET) &
				     FCSIC_CMD_ADDR_MASK), cmd );
	} else {
		return OPTIC_STATUS_FCSI_READTIMEOUT;
	}

	cnt = 100;
	/* wait until receiver is ready, result fifo provides new data */
	while ((cnt) && ((fcsic_r32(stat) & FCSIC_STAT_RR) !=
                                                  	FCSIC_STAT_RR_FRDY))
		cnt--;

	if (cnt) {
		*data = ( fcsic_r32 (data) &
			  FCSIC_DATA_DATA_MASK ) >> FCSIC_DATA_DATA_OFFSET;
	} else {
		return OPTIC_STATUS_FCSI_READTIMEOUT;
	}


#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP == ACTIVE))
	OPTIC_DEBUG_WRN("FCSI #%d: r 0x%04X", reg, *data);
#endif
#ifdef EVENT_LOGGER_DEBUG
	EL_LOG_EVENT_REG_RD (1, 1, 0, (uint32_t)addr, data, 1);
#endif

	return OPTIC_STATUS_OK;
}

/**
	Store fusing information in FCSI CBIAS CTRL1 register

	\param tbgp 3 bit nFuseTbgp, to store in FCSI.CBIAS.CTRL1.BGPT
	\param vbgp 3 bit nFuseVbgp, to store in FCSI.CBIAS.CTRL1.BGPV
	\param irefbpg 4 bit nFuseIREFbgp, to store in FCSI.CBIAS.CTRL1.UICT

	\return
	- OPTIC_STATUS_OK - success,
	- OPTIC_STATUS_FCSI_READTIMEOUT - read failed
	- OPTIC_STATUS_FCSI_WRITETIMEOUT - write failed
*/
enum optic_errorcode optic_ll_fcsi_fuses_set ( const uint8_t tbgp,
                                               const uint8_t vbgp,
                                               const uint8_t irefbpg )
{
	enum optic_errorcode ret;
	uint32_t reg, set, clear;

	if ((tbgp > 0x7) || (vbgp > 0x7) || (irefbpg > 0xF))
		return OPTIC_STATUS_POOR;

	clear = CBIAS_CTRL1_UICT_MASK | CBIAS_CTRL1_BGPT_MASK |
		CBIAS_CTRL1_BGPV_MASK;

	/* TBGP is fused in a wrong way - just ignore it (value 0) */
	set = /*((tbgp << CBIAS_CTRL1_BGPT_OFFSET) & CBIAS_CTRL1_BGPT_MASK) |*/
	      ((vbgp << CBIAS_CTRL1_BGPV_OFFSET) & CBIAS_CTRL1_BGPV_MASK) |
	      ((irefbpg << CBIAS_CTRL1_UICT_OFFSET) & CBIAS_CTRL1_UICT_MASK);

	ret = optic_ll_fcsi_read (FCSI_CBIAS_CTRL1, &reg);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	reg &= ~clear;
	reg |= set;

	ret = optic_ll_fcsi_write (FCSI_CBIAS_CTRL1, reg);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

enum optic_errorcode optic_ll_fcsi_powersave_set ( const enum optic_activation
                                                   powersave )
{
	enum optic_errorcode ret;
	uint32_t reg;

	ret = optic_ll_fcsi_read (FCSI_TXBOSA_PDS, &reg);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (powersave == OPTIC_ENABLE &&
		!is_falcon_chip_a2x() ) /* GPONSW-905 */
		reg |= TXBOSA_PDS_PSPRE;
	else
		reg &= ~TXBOSA_PDS_PSPRE;

	ret = optic_ll_fcsi_write (FCSI_TXBOSA_PDS, reg);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

/**
	Store predriver configuration in FCSI DDC0,1 BDC0,1 register.

	\param dd_loadn - DDC0.RTN
	\param dd_bias_en - DDC0.FT
	\param dd_loadp - DDC1.RTP
	\param dd_cm_load - DDC1.CMR
	\param bd_loadn - BDC0.RTN
	\param bd_bias_en - BDC0.FT
	\param bd_loadp - BDC1.RTP
	\param bd_cm_load - BDC1.CMR

	- disable predriver: DDC1.en_predrv, BDC1.en_predrv
	- configure predriver settings: DDC0, DDC1, BDC0, BDC1
	- enable predriver: DDC1.en_predrv, BDC1.en_predrv

	\return
	- OPTIC_STATUS_OK - success,
	- OPTIC_STATUS_FCSI_READTIMEOUT - read failed
	- OPTIC_STATUS_FCSI_WRITETIMEOUT - write failed
*/
enum optic_errorcode optic_ll_fcsi_predriver_set ( uint8_t dd_loadn,
						   uint8_t dd_bias_en,
						   uint8_t dd_loadp,
						   uint8_t dd_cm_load,
						   uint8_t bd_loadn,
						   uint8_t bd_bias_en,
						   uint8_t bd_loadp,
						   uint8_t bd_cm_load )
{
	uint32_t reg_ddc0, reg_bdc0, reg_ddc1, reg_bdc1;
	enum optic_errorcode ret;

	ret = optic_ll_fcsi_read (FCSI_TXBOSA_DDC0, &reg_ddc0);
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_fcsi_read (FCSI_TXBOSA_DDC1, &reg_ddc1);
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_fcsi_read (FCSI_TXBOSA_BDC0, &reg_bdc0);
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_fcsi_read (FCSI_TXBOSA_BDC1, &reg_bdc1);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/** disable pre driver */
	reg_ddc1 &= ~TXBOSA_DDC1_ENPD;
	reg_bdc1 &= ~TXBOSA_BDC1_ENPD;

	ret = optic_ll_fcsi_write ( FCSI_TXBOSA_DDC1, reg_ddc1 );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_fcsi_write ( FCSI_TXBOSA_BDC1, reg_bdc1 );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/** configure DDC0, DDC1, BDC0, BDC1 */
	reg_ddc0 &= ~(TXBOSA_DDC0_RTN_MASK | TXBOSA_DDC0_FT_MASK);
	reg_ddc0 |= (((dd_loadn << TXBOSA_DDC0_RTN_OFFSET) &
	                           TXBOSA_DDC0_RTN_MASK) |
		     ((dd_bias_en << TXBOSA_DDC0_FT_OFFSET) &
		                     TXBOSA_DDC0_FT_MASK));
	reg_ddc1 &= ~(TXBOSA_DDC1_RTP_MASK | TXBOSA_DDC1_CMR_MASK);
	reg_ddc1 |= (((dd_loadp << TXBOSA_DDC1_RTP_OFFSET) &
	                           TXBOSA_DDC1_RTP_MASK) |
		     ((dd_cm_load << TXBOSA_DDC1_CMR_OFFSET) &
		                    TXBOSA_DDC1_CMR_MASK));
	reg_bdc0 &= ~(TXBOSA_BDC0_RTN_MASK | TXBOSA_BDC0_FT_MASK);
	reg_bdc0 |= (((bd_loadn << TXBOSA_BDC0_RTN_OFFSET) &
	                           TXBOSA_BDC0_RTN_MASK) |
		     ((bd_bias_en << TXBOSA_BDC0_FT_OFFSET) &
		                     TXBOSA_BDC0_FT_MASK));
	reg_bdc1 &= ~(TXBOSA_BDC1_RTP_MASK | TXBOSA_BDC1_CMR_MASK);
	reg_bdc1 |= (((bd_loadp << TXBOSA_BDC1_RTP_OFFSET) &
	                           TXBOSA_BDC1_RTP_MASK) |
		     ((bd_cm_load << TXBOSA_BDC1_CMR_OFFSET) &
		                     TXBOSA_BDC1_CMR_MASK));

	ret = optic_ll_fcsi_write ( FCSI_TXBOSA_DDC0, reg_ddc0 );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_fcsi_write ( FCSI_TXBOSA_DDC1, reg_ddc1 );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_fcsi_write ( FCSI_TXBOSA_BDC0, reg_bdc0 );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_fcsi_write ( FCSI_TXBOSA_BDC1, reg_bdc1 );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	/** enable pre driver */
	reg_ddc1 |= TXBOSA_DDC1_ENPD;
	reg_bdc1 |= TXBOSA_BDC1_ENPD;

	ret = optic_ll_fcsi_write ( FCSI_TXBOSA_DDC1, reg_ddc1 );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_fcsi_write ( FCSI_TXBOSA_BDC1, reg_bdc1 );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

/**
	Reads back predriver configuration of FCSI DDC0,1 BDC0,1 register.

	\param dd_loadn - DDC0.RTN
	\param dd_bias_en - DDC0.FT
	\param dd_loadp - DDC1.RTP
	\param dd_cm_load - DDC1.CMR
	\param bd_loadn - BDC0.RTN
	\param bd_bias_en - BDC0.FT
	\param bd_loadp - BDC1.RTP
	\param bd_cm_load - BDC1.CMR

	\return
	- OPTIC_STATUS_OK - success,
	- OPTIC_STATUS_FCSI_READTIMEOUT - read failed
*/
enum optic_errorcode optic_ll_fcsi_predriver_get ( uint8_t *dd_loadn,
						   uint8_t *dd_bias_en,
						   uint8_t *dd_loadp,
						   uint8_t *dd_cm_load,
						   uint8_t *bd_loadn,
						   uint8_t *bd_bias_en,
						   uint8_t *bd_loadp,
						   uint8_t *bd_cm_load )
{
	uint32_t reg_ddc0, reg_bdc0, reg_ddc1, reg_bdc1;
	enum optic_errorcode ret;

	ret = optic_ll_fcsi_read (FCSI_TXBOSA_DDC0, &reg_ddc0);
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_fcsi_read (FCSI_TXBOSA_DDC1, &reg_ddc1);
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_fcsi_read (FCSI_TXBOSA_BDC0, &reg_bdc0);
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_fcsi_read (FCSI_TXBOSA_BDC1, &reg_bdc1);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (dd_loadn != NULL)
		*dd_loadn = ((reg_ddc0 & TXBOSA_DDC0_RTN_MASK) >>
				         TXBOSA_DDC0_RTN_OFFSET);
	if (dd_bias_en != NULL)
		*dd_bias_en = ((reg_ddc0 & TXBOSA_DDC0_FT_MASK) >>
				           TXBOSA_DDC0_FT_OFFSET);
	if (dd_loadp != NULL)
		*dd_loadp = ((reg_ddc1 & TXBOSA_DDC1_RTP_MASK) >>
				         TXBOSA_DDC1_RTP_OFFSET);
	if (dd_cm_load != NULL)
		*dd_cm_load = ((reg_ddc1 & TXBOSA_DDC1_CMR_MASK) >>
				           TXBOSA_DDC1_CMR_OFFSET);

	if (bd_loadn != NULL)
		*bd_loadn = ((reg_bdc0 & TXBOSA_BDC0_RTN_MASK) >>
				         TXBOSA_BDC0_RTN_OFFSET);
	if (bd_bias_en != NULL)
		*bd_bias_en = ((reg_bdc0 & TXBOSA_BDC0_FT_MASK) >>
				           TXBOSA_BDC0_FT_OFFSET);
	if (bd_loadp != NULL)
		*bd_loadp = ((reg_bdc1 & TXBOSA_BDC1_RTP_MASK) >>
				         TXBOSA_BDC1_RTP_OFFSET);
	if (bd_cm_load != NULL)
		*bd_cm_load = ((reg_bdc1 & TXBOSA_BDC1_CMR_MASK) >>
				           TXBOSA_BDC1_CMR_OFFSET);

	return ret;
}

/* Be careful with using predriver_switch as it can cause HW damage.
 * Only enable predriver if the configuration was done before properly!
 */
enum optic_errorcode optic_ll_fcsi_predriver_switch (
		const enum optic_activation mode  )
{
	uint32_t reg_ddc1, reg_bdc1;
	enum optic_errorcode ret;

	ret = optic_ll_fcsi_read (FCSI_TXBOSA_DDC1, &reg_ddc1);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_fcsi_read (FCSI_TXBOSA_BDC1, &reg_bdc1);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if(mode == OPTIC_ENABLE) {
		/* enable pre driver */
		/* ATTENTION: never switch on pre driver,
		 * having set configuration before !!!!
		 * Otherwise this can produce HW damage !!!! */
		reg_ddc1 |= TXBOSA_DDC1_ENPD;
		reg_bdc1 |= TXBOSA_BDC1_ENPD;
	}
	else {
		/* disable pre driver */
		reg_ddc1 &= ~TXBOSA_DDC1_ENPD;
		reg_bdc1 &= ~TXBOSA_BDC1_ENPD;
	}

	ret = optic_ll_fcsi_write ( FCSI_TXBOSA_DDC1, reg_ddc1 );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	ret = optic_ll_fcsi_write ( FCSI_TXBOSA_BDC1, reg_bdc1 );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_fcsi_predriver_switch_get (enum optic_activation *mode)
{
	uint32_t reg_ddc1, reg_bdc1;
	enum optic_errorcode ret;

	ret = optic_ll_fcsi_read (FCSI_TXBOSA_DDC1, &reg_ddc1);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_fcsi_read (FCSI_TXBOSA_BDC1, &reg_bdc1);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (reg_ddc1 & TXBOSA_DDC1_ENPD && 
		reg_bdc1 & TXBOSA_BDC1_ENPD)
		*mode = OPTIC_ENABLE;
	else
		*mode = OPTIC_DISABLE;

	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_ll_fcsi_video_cfg_set ( const uint16_t video_word,
					           const bool video_range_low )
{
	uint32_t reg;
	enum optic_errorcode ret;

	ret = optic_ll_fcsi_read ( FCSI_VDAC_CTRL, &reg );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	reg &= ~(VDAC_CTRL_VWD_MASK | VDAC_CTRL_LREN);

	reg |= (((video_word << VDAC_CTRL_VWD_OFFSET) & VDAC_CTRL_VWD_MASK) |
	        ((video_range_low == true)? VDAC_CTRL_LREN_EN :
	         			    VDAC_CTRL_LREN_DIS));

	ret = optic_ll_fcsi_write ( FCSI_VDAC_CTRL, reg );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_fcsi_video_cfg_get ( uint16_t *video_word,
					           bool *video_range_low )
{
	uint32_t reg;
	enum optic_errorcode ret;

	ret = optic_ll_fcsi_read ( FCSI_VDAC_CTRL, &reg );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (video_word != NULL)
		*video_word = (reg & VDAC_CTRL_VWD_MASK) >>
				     VDAC_CTRL_VWD_OFFSET;

	if (video_range_low != NULL)
		*video_range_low = ((reg & VDAC_CTRL_LREN) ==
		                    	   VDAC_CTRL_LREN_EN)? true : false;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_fcsi_video_set ( const enum optic_activation
					       mode )
{
	uint32_t reg;
	enum optic_errorcode ret;

	ret = optic_ll_fcsi_read ( FCSI_VDAC_CTRL, &reg );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	switch (mode) {
	case OPTIC_ENABLE:
		reg &= ~(VDAC_CTRL_OM_PD);
		break;
	case OPTIC_DISABLE:
		reg |= VDAC_CTRL_OM_PD;
		break;
	default:
		return OPTIC_STATUS_POOR;
	}

	ret = optic_ll_fcsi_write ( FCSI_VDAC_CTRL, reg );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_fcsi_bfd_get ( struct optic_bfd *bfd )
{
	uint32_t reg;
	enum optic_errorcode ret;

	ret = optic_ll_fcsi_read ( FCSI_BFD_CTRL0, &reg );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	bfd->ctrl0 = reg;

	ret = optic_ll_fcsi_read ( FCSI_BFD_GVS, &reg );
	if (ret != OPTIC_STATUS_OK)
		return ret;
	bfd->gvs = reg;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_fcsi_video_get ( enum optic_activation *mode )
{
	uint32_t reg;
	enum optic_errorcode ret;

	ret = optic_ll_fcsi_read ( FCSI_VDAC_CTRL, &reg );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	if (mode != NULL)
		*mode = ((reg & VDAC_CTRL_OM_PD) == VDAC_CTRL_OM_PD)?
			OPTIC_DISABLE : OPTIC_ENABLE;

	return OPTIC_STATUS_OK;
}

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_FCSI == ACTIVE))
enum optic_errorcode  optic_ll_fcsi_dump ( void )
{
	vuint16_t *addr[] = {
		FCSI_TXBOSA_DDC0, FCSI_TXBOSA_DDC1, FCSI_TXBOSA_BDC0,
		FCSI_TXBOSA_BDC1, FCSI_TXBOSA_CTRL, FCSI_TXBOSA_CC,
		FCSI_TXBOSA_PH, FCSI_TXBOSA_PDS,
		FCSI_TXOMU_TXEC, FCSI_TXOMU_TXDC, FCSI_TXOMU_CTRL,
		FCSI_RXBOSA_CTRL,
		FCSI_RXOMU_CTRL,
		FCSI_MM_CTRL,
		FCSI_VDAC_CTRL,
		FCSI_BFD_GVS, FCSI_BFD_CTRL0, FCSI_BFD_CTRL1,
		FCSI_CBIAS_CTRL0, FCSI_CBIAS_CTRL1,
		FCSI_VDLL_CTRL };
	uint32_t reg;
	uint8_t i;

	for (i=0; i<(sizeof(addr)/sizeof(addr[0])); i++) {
		optic_ll_fcsi_read ( addr[i], &reg );
		OPTIC_DEBUG_MSG("FCSI #%d: 0x%04X", addr[i], reg);
	}

	return OPTIC_STATUS_OK;
}
#endif

/*! @} */
/*! @} */
