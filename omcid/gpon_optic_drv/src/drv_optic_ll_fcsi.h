/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_fcsi.h
*/
#ifndef _drv_optic_ll_fcsi_h
#define _drv_optic_ll_fcsi_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"
#include "drv_optic_common.h"
#include "drv_optic_reg_fcsi_base.h"
#include "drv_optic_reg_fcsi_txbosa.h"
#include "drv_optic_reg_fcsi_txomu.h"
#include "drv_optic_reg_fcsi_rxbosa.h"
#include "drv_optic_reg_fcsi_rxomu.h"
#include "drv_optic_reg_fcsi_mm.h"
#include "drv_optic_reg_fcsi_vdac.h"
#include "drv_optic_reg_fcsi_bfd.h"
#include "drv_optic_reg_fcsi_vdac.h"
#include "drv_optic_reg_fcsi_cbias.h"
#include "drv_optic_reg_fcsi_vdll.h"

struct fcsi_addr_val {
		vuint16_t *addr;
		uint32_t val;
};

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_FCSI_INTERNAL FCSI Register Interface - Internal
   @{
*/

#define OPTIC_FCSI_BASE    FCSI_TXBOSA_BASE
#define OPTIC_FCSI_END     FCSI_VDLL_END
#define OPTIC_FCSI_SIZE    (FCSI_TXBOSA_BASE - FCSI_VDLL_END)

/* Power level dependent DDC0, DDC1, BDC0, BDC1 settings */
/* "0x1F" # [-] FCSI DDC0.RTN setting for reference transmit power */
#define DD_LOADN_0 0x1F
#define DD_LOADN_0_A21 0x1F
/* "0x7" # [-] FCSI DDC0.FT setting for reference transmit power */
#define DD_BIAS_EN_0 0x7
#define DD_BIAS_EN_0_A21 0xF
/* "0x1F" # [-] FCSI DDC1.RTP setting for reference transmit power */
#define DD_LOADP_0 0x1F
#define DD_LOADP_0_A21 0x1F
/* "0x7" # [-] FCSI DDC1.CMR setting for reference transmit power */
#define DD_CM_LOAD_0 0x6
#define DD_CM_LOAD_0_A21 0x8
/* "0x1F" # [-] FCSI BDC0.RTN setting for reference transmit power */
#define BD_LOADN_0 0x1F
#define BD_LOADN_0_A21 0x05
/* "0xF" # [-] FCSI BDC0.FT setting for reference transmit power */
#define BD_BIAS_EN_0 0xF
#define BD_BIAS_EN_0_A21 0x3
/* "0x1F" # [-] FCSI BDC1.RTP setting for reference transmit power */
#define BD_LOADP_0 0x1F
#define BD_LOADP_0_A21 0x3
/* "0x3" # [-] FCSI BDC1.CMR setting for reference transmit power */
#define BD_CM_LOAD_0 0x3
#define BD_CM_LOAD_0_A21 0x6

/* "0x1F" # [-] FCSI DDC0.RTN setting for reference -3 dB transmit power */
#define DD_LOADN_1 0x1F
#define DD_LOADN_1_A21 0x1F
/* "0x7" # [-] FCSI DDC0.FT setting for reference -3 dB transmit power */
#define DD_BIAS_EN_1 0x7
#define DD_BIAS_EN_1_A21 0xF
/* "0x1F" # [-] FCSI DDC1.RTP setting for reference -3 dB transmit power */
#define DD_LOADP_1 0x1F
#define DD_LOADP_1_A21 0x1F
/* "0x7" # [-] FCSI DDC1.CMR setting for reference -3 dB transmit power */
#define DD_CM_LOAD_1 0x6
#define DD_CM_LOAD_1_A21 0x8
/* "0x1F" # [-] FCSI BDC0.RTN setting for reference -3 dB transmit power */
#define BD_LOADN_1 0x1F
#define BD_LOADN_1_A21 0x05
/* "0xF" # [-] FCSI BDC0.FT setting for reference -3 dB transmit power */
#define BD_BIAS_EN_1 0xF
#define BD_BIAS_EN_1_A21 0x3
/* "0x1F" # [-] FCSI BDC1.RTP setting for reference -3 dB transmit power */
#define BD_LOADP_1 0x1F
#define BD_LOADP_1_A21 0x3
/* "0x3" # [-] FCSI BDC1.CMR setting for reference -3 dB transmit power */
#define BD_CM_LOAD_1 0x3
#define BD_CM_LOAD_1_A21 0x6

/* "0x1F" # [-] FCSI DDC0.RTN setting for reference -6 dB transmit power */
#define DD_LOADN_2 0x1F
#define DD_LOADN_2_A21 0x1F
/* "0x7" # [-] FCSI DDC0.FT setting for reference -6 dB transmit power */
#define DD_BIAS_EN_2 0x7
#define DD_BIAS_EN_2_A21 0xF
/* "0x1F" # [-] FCSI DDC1.RTP setting for reference -6 dB transmit power */
#define DD_LOADP_2 0x1F
#define DD_LOADP_2_A21 0x1F
/* "0x7" # [-] FCSI DDC1.CMR setting for reference -6 dB transmit power */
#define DD_CM_LOAD_2 0x6
#define DD_CM_LOAD_2_A21 0x8
/* "0x1F" # [-] FCSI BDC0.RTN setting for reference -6 dB transmit power */
#define BD_LOADN_2 0x1F
#define BD_LOADN_2_A21 0x05
/* "0xF" # [-] FCSI BDC0.FT setting for reference -6 dB transmit power */
#define BD_BIAS_EN_2 0xF
#define BD_BIAS_EN_2_A21 0x3
/* "0x1F" # [-] FCSI BDC1.RTP setting for reference -6 dB transmit power */
#define BD_LOADP_2 0x1F
#define BD_LOADP_2_A21 0x3
/* "0x3" # [-] FCSI BDC1.CMR setting for reference -6 dB transmit power */
#define BD_CM_LOAD_2 0x3
#define BD_CM_LOAD_2_A21 0x6

struct optic_reg_fcsi {
   struct fcsi_reg_txbosa txbosa;   /* 0 .. 7 */
   struct fcsi_reg_txomu txomu;     /* 8 .. 10 */
   struct fcsi_reg_rxbosa rxbosa;   /* 11 */
   uint16_t reg_12;
   struct fcsi_reg_rxomu rxomu;     /* 13 */
   struct fcsi_reg_mm mm;           /* 14 */
   struct fcsi_reg_vdac vdac;       /* 15 */
   struct fcsi_reg_bfd bfd;         /* 16 .. 18 */
   uint16_t reg_19;
   struct fcsi_reg_cbias cbias;     /* 20, 21 */
   uint16_t reg_22;
   uint16_t reg_23;
   struct fcsi_reg_vdll vdll;       /* 24 */
};
/*
#define txbosa &(fcsi->txbosa)
#define rxbosa &(fcsi->rxbosa)
#define txomu &(fcsi->rxomu)
#define rxomu &(fcsi->rxomu)
#define bfd &(fcsi->bfd)
#define mm &(fcsi->mm)
*/
/* These are the FCSI register default values, used by OPTIC_IO_FCSI_Init */

/* !!! changing this setting can cause hardware damage !!! */

/** reg #0:
 fcsi_w(TXBOSA_Base + TXBOSA_DDC0 , 0x1B << TXBOSA_DDC0_RTN  |
				    0x0 << TXBOSA_DDC0_BLCD |
			            0x8 << TXBOSA_DDC0_FT   ); */
/*
#define OPTIC_FCSI_TXBOSA_DDC0_RESET 0x801B
*/
#define OPTIC_FCSI_TXBOSA_DDC0_RESET      0x8010
#define OPTIC_FCSI_TXBOSA_DDC0_RESET_BOSA 0x701F
#define OPTIC_FCSI_TXBOSA_DDC0_RESET_OMU  0x0000

#define OPTIC_FCSI_TXBOSA_DDC0_RESET_A21  	  0xF0BF
#define OPTIC_FCSI_TXBOSA_DDC0_RESET_BOSA_A21 0xF0BF
#define OPTIC_FCSI_TXBOSA_DDC0_RESET_OMU_A21  0x0000

/** reg #1:
 fcsi_w(TXBOSA_Base + TXBOSA_DDC1 , 0x1B << TXBOSA_DDC1_RTP  |
			            0x7 << TXBOSA_DDC1_CMR  |
			            0x0 << TXBOSA_DDC1_ENPD ); */
/*
#define OPTIC_FCSI_TXBOSA_DDC1_RESET_1 0x1C1B
*/
#define OPTIC_FCSI_TXBOSA_DDC1_RESET      0x4010
#define OPTIC_FCSI_TXBOSA_DDC1_RESET_BOSA 0x181F
#define OPTIC_FCSI_TXBOSA_DDC1_RESET_OMU  0x0000

#define OPTIC_FCSI_TXBOSA_DDC1_RESET_A21      0x207F
#define OPTIC_FCSI_TXBOSA_DDC1_RESET_BOSA_A21 0x207F
#define OPTIC_FCSI_TXBOSA_DDC1_RESET_OMU_A21  0x0000


/** reg #2:
 fcsi_w(TXBOSA_Base + TXBOSA_BDC0 , 0x10 << TXBOSA_BDC0_RTN  |
			            0x0 << TXBOSA_BDC0_BLCD |
                                    0x8 << TXBOSA_BDC0_FT   ); */
/*
#define OPTIC_FCSI_TXBOSA_BDC0_RESET 0x8010
*/
#define OPTIC_FCSI_TXBOSA_BDC0_RESET      0x8008
#define OPTIC_FCSI_TXBOSA_BDC0_RESET_BOSA 0xF01F
#define OPTIC_FCSI_TXBOSA_BDC0_RESET_OMU  0x0000

#define OPTIC_FCSI_TXBOSA_BDC0_RESET_A21      0x3005
#define OPTIC_FCSI_TXBOSA_BDC0_RESET_BOSA_A21 0x3005
#define OPTIC_FCSI_TXBOSA_BDC0_RESET_OMU_A21  0x0000

/** reg #3:
 fcsi_w(TXBOSA_Base + TXBOSA_BDC1 , 0x10 << TXBOSA_BDC1_RTP  |
			            0x0 << TXBOSA_BDC1_CMR  |
                                    0x0 << TXBOSA_BDC1_ENPD ); */
/*
#define OPTIC_FCSI_TXBOSA_BDC1_RESET_1 0x0010
*/
#define OPTIC_FCSI_TXBOSA_BDC1_RESET      0x0008
#define OPTIC_FCSI_TXBOSA_BDC1_RESET_BOSA 0x0C1F
#define OPTIC_FCSI_TXBOSA_BDC1_RESET_OMU  0x0000

#define OPTIC_FCSI_TXBOSA_BDC1_RESET_A21      0x1803
#define OPTIC_FCSI_TXBOSA_BDC1_RESET_BOSA_A21 0x1803
#define OPTIC_FCSI_TXBOSA_BDC1_RESET_OMU_A21  0x0000

/** reg #4:
 fcsi_w(TXBOSA_Base + TXBOSA_CTRL , 0x1 << TXBOSA_CTRL_FFR  |
                                    0x0 << TXBOSA_CTRL_SE   |
                                    0x0 << TXBOSA_CTRL_OP   |
                                    0x0 << TXBOSA_CTRL_CE   |
                                    0x0 << TXBOSA_CTRL_CED   |
                                    0x1 << TXBOSA_CTRL_PDB   |
                                    0x1 << TXBOSA_CTRL_PDD   |
                                    0x0 << TXBOSA_CTRL_PRE   ); */
#define OPTIC_FCSI_TXBOSA_CTRL_RESET      0x0001
#define OPTIC_FCSI_TXBOSA_CTRL_RESET_BOSA 0x0081
#define OPTIC_FCSI_TXBOSA_CTRL_RESET_OMU  0x0060

#define OPTIC_FCSI_TXBOSA_CTRL_RESET_A21      0x0081
#define OPTIC_FCSI_TXBOSA_CTRL_RESET_BOSA_A21 0x0081
#define OPTIC_FCSI_TXBOSA_CTRL_RESET_OMU_A21  0x0060

/** reg #5:
 fcsi_w(TXBOSA_Base + TXBOSA_CC  , 0x0 << TXBOSA_CC_CINV  |
                                   0x1B << TXBOSA_CC_PRTN  |
                                   0x1B << TXBOSA_CC_PRTP  |
                                   0x6 << TXBOSA_CC_PCM   ); */
#define OPTIC_FCSI_TXBOSA_CC_RESET      0x0000
#define OPTIC_FCSI_TXBOSA_CC_RESET_BOSA 0x3000
#define OPTIC_FCSI_TXBOSA_CC_RESET_OMU  0x0000

#define OPTIC_FCSI_TXBOSA_CC_RESET_A21      0x4000
#define OPTIC_FCSI_TXBOSA_CC_RESET_BOSA_A21 0x4000
#define OPTIC_FCSI_TXBOSA_CC_RESET_OMU_A21  0x0000


/** reg #6:
 fcsi_w(TXBOSA_Base + TXBOSA_PH ,   0x0 << TXBOSA_PH_RD   |
			            0x0 << TXBOSA_PH_RST  |
                                    0x10 << TXBOSA_PH_PRTNB|
                                    0x10 << TXBOSA_PH_PRTPB|
                                    0x8 << TXBOSA_PH_PBEN); */
#define OPTIC_FCSI_TXBOSA_PH_RESET      0x0000
#define OPTIC_FCSI_TXBOSA_PH_RESET_BOSA 0x1000
#define OPTIC_FCSI_TXBOSA_PH_RESET_OMU  0x0000

#define OPTIC_FCSI_TXBOSA_PH_RESET_A21      0x2000
#define OPTIC_FCSI_TXBOSA_PH_RESET_BOSA_A21 0x2000
#define OPTIC_FCSI_TXBOSA_PH_RESET_OMU_A21  0x0000


/** reg #7:
 fcsi_w(TXBOSA_Base + TXBOSA_PDS ,  0x7 << TXBOSA_PDS_PBENDD    |
			            0x6 << TXBOSA_PDS_PCMD      |
                                    0x0 << TXBOSA_PDS_PSPRE     ); */
#define OPTIC_FCSI_TXBOSA_PDS_RESET      0x0000
#define OPTIC_FCSI_TXBOSA_PDS_RESET_BOSA 0x0233
#define OPTIC_FCSI_TXBOSA_PDS_RESET_OMU  0x0000

#define OPTIC_FCSI_TXBOSA_PDS_RESET_A21      0x0067
#define OPTIC_FCSI_TXBOSA_PDS_RESET_BOSA_A21 0x0067
#define OPTIC_FCSI_TXBOSA_PDS_RESET_OMU_A21  0x0000

/** reg #8:
 fcsi_w(TXOMU_Base + TXOMU_TXEC   , 0x3 << TXOMU_TXEC_BEN   |
                                    0x7 << TXOMU_TXEC_PCSE  |
                                    0x0 << TXOMU_TXEC_BYPST |
                                    0x0 << TXOMU_TXEC_STE   |
                                    0xF << TXOMU_TXEC_SCSEL ); */
#define OPTIC_FCSI_TXOMU_TXEC_RESET      0xF707
#define OPTIC_FCSI_TXOMU_TXEC_RESET_BOSA 0x0000
#define OPTIC_FCSI_TXOMU_TXEC_RESET_OMU  0xF707

/** reg #9:
 fcsi_w(TXOMU_Base + TXOMU_TXDC   , 0x3 << TXOMU_TXDC_BEN   |
                                    0x7 << TXOMU_TXDC_PCSE  |
                                    0x0 << TXOMU_TXDC_BYPST |
                                    0x0 << TXOMU_TXDC_STE   |
                                    0xF << TXOMU_TXDC_SCSEL ); */
#define OPTIC_FCSI_TXOMU_TXDC_RESET      0xF707
#define OPTIC_FCSI_TXOMU_TXDC_RESET_BOSA 0x0000
#define OPTIC_FCSI_TXOMU_TXDC_RESET_OMU  0xF707


/** reg #10:
 fcsi_w(TXOMU_Base + TXOMU_CTRL   , 0x0 << TXOMU_CTRL_CMEN  |
                                    0x0 << TXOMU_CTRL_CLKM  |
                                    0x0 << TXOMU_CTRL_DEM   |
                                    0x0 << TXOMU_CTRL_CINV  |
                                    0x0 << TXOMU_CTRL_SOVD  |
                                    0x0 << TXOMU_CTRL_SOEN  |
                                    0x1 << TXOMU_CTRL_SE    |
                                    0x0 << TXOMU_CTRL_TBED  |
                                    0x0 << TXOMU_CTRL_TBEE  |
                                    0x0 << TXOMU_CTRL_CINV8  ); */
#define OPTIC_FCSI_TXOMU_CTRL_RESET      0x0040
#define OPTIC_FCSI_TXOMU_CTRL_RESET_BOSA 0x0000
#define OPTIC_FCSI_TXOMU_CTRL_RESET_OMU  0x0040


/** reg #11:
 fcsi_w(RXBOSA_Base + RXBOSA_CTRL , 0x0 <<  RXBOSA_CTRL_BLCM  |
                                    0x0 <<  RXBOSA_CTRL_BLCL  |
                                    0x0 <<  RXBOSA_CTRL_BLCH  |
                                    0x0 <<  RXBOSA_CTRL_ISOM  |
                                    0x0 <<  RXBOSA_CTRL_CDRR  |
                                    0x0 <<  RXBOSA_CTRL_CDRF  |
                                    0x0 <<  RXBOSA_CTRL_CDRD  |
                                    0x0 <<  RXBOSA_CTRL_CDRM  |
                                    0x0 <<  RXBOSA_CTRL_TDS   |
                                    0x0 <<  RXBOSA_CTRL_RST   |
                                    0x0 <<  RXBOSA_CTRL_CINV  |
                                    0x0 <<  RXBOSA_CTRL_DLCOM |
                                    0x0 <<  RXBOSA_CTRL_C3OM  ); */
/* \todo check for A21 */
#define OPTIC_FCSI_RXBOSA_CTRL_RESET      0x0000
#define OPTIC_FCSI_RXBOSA_CTRL_RESET_BOSA 0x0184
#define OPTIC_FCSI_RXBOSA_CTRL_RESET_OMU  0x0000


/** reg #13:
fcsi_w(RXOMU_Base + RXOMU_CTRL   ,  0x0 <<  RXOMU_CTRL_ISOM |
                                    0x0 <<  RXOMU_CTRL_BLOC |
                                    0x0 <<  RXOMU_CTRL_CDR  |
                                    0x0 <<  RXOMU_CTRL_CINV |
                                    0x0 <<  RXOMU_CTRL_TDS  ); */
#define OPTIC_FCSI_RXOMU_CTRL_RESET        0x0000
#define OPTIC_FCSI_RXOMU_CTRL_RESET_OMU    0x0000
#define OPTIC_FCSI_RXOMU_CTRL_RESET_BOSA   0x0000
#define OPTIC_FCSI_RXOMU_CTRL_RESET_BOSA_2 0x0002

/** reg #14:
fcsi_w(MM_Base + MM_CTRL ,          0x0 << MM_CTRL_TINP   |
                                    0x0 << MM_CTRL_TINN   |
                                    0x1 << MM_CTRL_RVS    |
                                    0x1 << MM_CTRL_FBSEL  |
                                    0x1 << MM_CTRL_REFEN  |
                                    0x0 << MM_CTRL_OPBIAS |
                                    0x0 << MM_CTRL_CINV   ); */
#define OPTIC_FCSI_MM_CTRL_RESET      0x0024
#define OPTIC_FCSI_MM_CTRL_RESET_BOSA 0x0024
#define OPTIC_FCSI_MM_CTRL_RESET_OMU  0x0024

/** reg #15:
fcsi_w(VDAC_Base + VDAC_CTRL   ,    0x00 << VDAC_CTRL_VWD  |
                                    0x0 << VDAC_CTRL_LREN |
                                    0x1 << VDAC_CTRL_OM   ); */
#define OPTIC_FCSI_VDAC_CTRL_RESET      0x0400
#define OPTIC_FCSI_VDAC_CTRL_RESET_BOSA 0x0400
#define OPTIC_FCSI_VDAC_CTRL_RESET_OMU  0x0400

/** reg #16:
fcsi_w(BFD_Base + BFD_GVS ,         0x0 <<  BFD_GVS_GAIN0 |
                                    0x5 <<  BFD_GVS_GAIN1 |
                                    0x6 <<  BFD_GVS_GAIN2 |
                                    0xA <<  BFD_GVS_GAIN3 ); */
#define OPTIC_FCSI_BFD_GVS_RESET      0xEEA5
#define OPTIC_FCSI_BFD_GVS_RESET_BOSA 0xEEA5
#define OPTIC_FCSI_BFD_GVS_RESET_OMU  0x0000

/** reg #17:
fcsi_w(BFD_Base + BFD_CTRL0  ,      0x4 << BFD_CTRL0_CMSEL  |
                                    0x0 << BFD_CTRL0_BLCD   |
                                    0x7 << BFD_CTRL0_RTSEL  |
                                    0x0 << BFD_CTRL0_CDRO   |
                                    0x0 << BFD_CTRL0_VCM0V6 |
                                    0x0 << BFD_CTRL0_VCM0V5 |
                                    0x0 << BFD_CTRL0_BLLD   ); */
#define OPTIC_FCSI_BFD_CTRL0_RESET      0x0074
#define OPTIC_FCSI_BFD_CTRL0_RESET_BOSA 0x0074
#define OPTIC_FCSI_BFD_CTRL0_RESET_OMU  0x0000

/** reg #18:
fcsi_w(BFD_Base + BFD_CTRL1  ,      0x0 <<  BFD_CTRL1_TDSEL |
                                    0x0 <<  BFD_CTRL1_BLAP0 |
                                    0x0 <<  BFD_CTRL1_BLAP1 |
                                    0x0 <<  BFD_CTRL1_RST   |
                                    0x0 <<  BFD_CTRL1_CINV  |
                                    0x0 <<  BFD_CTRL1_RINV  |
                                    0x0 <<  BFD_CTRL1_LDO   |
                                    0x0 <<  BFD_CTRL1_IRED  |
                                    0x0 <<  BFD_CTRL1_PDLS  ); */
#define OPTIC_FCSI_BFD_CTRL1_RESET      0x0200
#define OPTIC_FCSI_BFD_CTRL1_RESET_BOSA 0x0200
#define OPTIC_FCSI_BFD_CTRL1_RESET_OMU  0x0000

/** reg #19:
*/
#define OPTIC_FCSI_PI_CTRL_RESET      0x0000
#define OPTIC_FCSI_PI_CTRL_RESET_BOSA 0x00BC
#define OPTIC_FCSI_PI_CTRL_RESET_OMU  0x00F6



/** reg #20:
fcsi_w(CBIAS_Base + CBIAS_CTRL0  ,  0x0 << CBIAS_CTRL0_IBFD     |
                                    0x0 << CBIAS_CTRL0_IVCM0V5  |
                                    0x0 << CBIAS_CTRL0_IVCM0V6  |
                                    0x0 << CBIAS_CTRL0_ITXBOSA  |
                                    0x0 << CBIAS_CTRL0_IDAC1550 |
                                    0x0 << CBIAS_CTRL0_IMVCM    ); */
#define OPTIC_FCSI_CBIAS_CTRL0_RESET      0x0000
#define OPTIC_FCSI_CBIAS_CTRL0_RESET_BOSA 0x0000
#define OPTIC_FCSI_CBIAS_CTRL0_RESET_OMU  0x0000

/** reg #21:
fcsi_w(CBIAS_Base + CBIAS_CTRL1  ,  0x0 << CBIAS_CTRL1_BGPV  |
                                    0x0 << CBIAS_CTRL1_PD    |
                                    0x0 << CBIAS_CTRL1_BGPT  |
                                    0x0 << CBIAS_CTRL1_MCAL  |
                                    0x0 << CBIAS_CTRL1_UICT  |
                                    0x0 << CBIAS_CTRL1_UIRT  ); */
#define OPTIC_FCSI_CBIAS_CTRL1_RESET      0x0000
#define OPTIC_FCSI_CBIAS_CTRL1_RESET_BOSA 0x0000
#define OPTIC_FCSI_CBIAS_CTRL1_RESET_OMU  0x0000

/** reg #24:
fcsi_w(VDLL_Base + VDLL_CTRL      , 0x0 << VDLL_CTRL_VREF  |
                                    0x0 << VDLL_CTRL_ICP   |
                                    0x0 << VDLL_CTRL_IBIAS |
                                    0x0 << VDLL_CTRL_MCLK  ); */
#define OPTIC_FCSI_VDLL_CTRL_RESET      0x0000
#define OPTIC_FCSI_VDLL_CTRL_RESET_BOSA 0x0000
#define OPTIC_FCSI_VDLL_CTRL_RESET_OMU  0x0000


enum optic_errorcode optic_ll_fcsi_init ( const enum optic_manage_mode mode );
enum optic_errorcode optic_ll_fcsi_init_bosa_2nd ( void );
enum optic_errorcode optic_ll_fcsi_bfd_cfg ( const struct optic_config_fcsi
                                             *fcsi );
enum optic_errorcode optic_ll_fcsi_write ( const vuint16_t *addr,
                                           const uint32_t data );
enum optic_errorcode optic_ll_fcsi_read ( const vuint16_t *addr,
                                          uint32_t *data );
enum optic_errorcode optic_ll_fcsi_fuses_set ( const uint8_t tbgp,
                                               const uint8_t vbgp,
                                               const uint8_t irefbpg );
enum optic_errorcode optic_ll_fcsi_powersave_set ( const enum optic_activation
                                                   powerdown );
enum optic_errorcode optic_ll_fcsi_predriver_set ( uint8_t dd_loadn,
						   uint8_t dd_bias_en,
						   uint8_t dd_loadp,
						   uint8_t dd_cm_load,
						   uint8_t bd_loadn,
						   uint8_t bd_bias_en,
						   uint8_t bd_loadp,
						   uint8_t bd_cm_load );
enum optic_errorcode optic_ll_fcsi_predriver_get ( uint8_t *dd_loadn,
						   uint8_t *dd_bias_en,
						   uint8_t *dd_loadp,
						   uint8_t *dd_cm_load,
						   uint8_t *bd_loadn,
						   uint8_t *bd_bias_en,
						   uint8_t *bd_loadp,
						   uint8_t *bd_cm_load );
enum optic_errorcode optic_ll_fcsi_predriver_switch (
		const enum optic_activation mode  );
enum optic_errorcode optic_ll_fcsi_predriver_switch_get (enum optic_activation *mode);
enum optic_errorcode optic_ll_fcsi_video_cfg_set ( const uint16_t video_word,
					           const bool video_range_low );
enum optic_errorcode optic_ll_fcsi_video_cfg_get ( uint16_t *video_word,
					            bool *video_range_low );
enum optic_errorcode optic_ll_fcsi_video_set ( const enum optic_activation
					       mode );
enum optic_errorcode optic_ll_fcsi_video_get ( enum optic_activation *mode );

enum optic_errorcode optic_ll_fcsi_bfd_get ( struct optic_bfd *bfd );

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_FCSI == ACTIVE))
enum optic_errorcode optic_ll_fcsi_dump ( void );
#endif

/*! @} */

/*! @} */

EXTERN_C_END

#endif
