/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_reg_base_h
#define _drv_onu_reg_base_h

/** \addtogroup ONU_BASE
   @{
*/

#ifndef KSEG1
#define KSEG1 0xA0000000
#endif

/** address range for gpearb
    0x1D400100--0x1D4001FF */
#define ONU_GPEARB_BASE		(KSEG1 | 0x1D400100)
#define ONU_GPEARB_END		(KSEG1 | 0x1D4001FF)
#define ONU_GPEARB_SIZE		0x00000100
/** address range for tmu
    0x1D404000--0x1D404FFF */
#define ONU_TMU_BASE		(KSEG1 | 0x1D404000)
#define ONU_TMU_END		(KSEG1 | 0x1D404FFF)
#define ONU_TMU_SIZE		0x00001000
/** address range for iqm
    0x1D410000--0x1D41FFFF */
#define ONU_IQM_BASE		(KSEG1 | 0x1D410000)
#define ONU_IQM_END		(KSEG1 | 0x1D41FFFF)
#define ONU_IQM_SIZE		0x00010000
/** address range for octrlg
    0x1D420000--0x1D42FFFF */
#define ONU_OCTRLG_BASE		(KSEG1 | 0x1D420000)
#define ONU_OCTRLG_END		(KSEG1 | 0x1D42FFFF)
#define ONU_OCTRLG_SIZE		0x00010000
/** address range for octrll0
    0x1D440000--0x1D4400FF */
#define ONU_OCTRLL0_BASE		(KSEG1 | 0x1D440000)
#define ONU_OCTRLL0_END		(KSEG1 | 0x1D4400FF)
#define ONU_OCTRLL0_SIZE		0x00000100
/** address range for octrll1
    0x1D440100--0x1D4401FF */
#define ONU_OCTRLL1_BASE		(KSEG1 | 0x1D440100)
#define ONU_OCTRLL1_END		(KSEG1 | 0x1D4401FF)
#define ONU_OCTRLL1_SIZE		0x00000100
/** address range for octrll2
    0x1D440200--0x1D4402FF */
#define ONU_OCTRLL2_BASE		(KSEG1 | 0x1D440200)
#define ONU_OCTRLL2_END		(KSEG1 | 0x1D4402FF)
#define ONU_OCTRLL2_SIZE		0x00000100
/** address range for octrll3
    0x1D440300--0x1D4403FF */
#define ONU_OCTRLL3_BASE		(KSEG1 | 0x1D440300)
#define ONU_OCTRLL3_END		(KSEG1 | 0x1D4403FF)
#define ONU_OCTRLL3_SIZE		0x00000100
/** address range for octrlc
    0x1D441000--0x1D4410FF */
#define ONU_OCTRLC_BASE		(KSEG1 | 0x1D441000)
#define ONU_OCTRLC_END		(KSEG1 | 0x1D4410FF)
#define ONU_OCTRLC_SIZE		0x00000100
/** address range for ictrlg
    0x1D450000--0x1D45FFFF */
#define ONU_ICTRLG_BASE		(KSEG1 | 0x1D450000)
#define ONU_ICTRLG_END		(KSEG1 | 0x1D45FFFF)
#define ONU_ICTRLG_SIZE		0x00010000
/** address range for ictrll0
    0x1D460000--0x1D4601FF */
#define ONU_ICTRLL0_BASE		(KSEG1 | 0x1D460000)
#define ONU_ICTRLL0_END		(KSEG1 | 0x1D4601FF)
#define ONU_ICTRLL0_SIZE		0x00000200
/** address range for ictrll1
    0x1D460200--0x1D4603FF */
#define ONU_ICTRLL1_BASE		(KSEG1 | 0x1D460200)
#define ONU_ICTRLL1_END		(KSEG1 | 0x1D4603FF)
#define ONU_ICTRLL1_SIZE		0x00000200
/** address range for ictrll2
    0x1D460400--0x1D4605FF */
#define ONU_ICTRLL2_BASE		(KSEG1 | 0x1D460400)
#define ONU_ICTRLL2_END		(KSEG1 | 0x1D4605FF)
#define ONU_ICTRLL2_SIZE		0x00000200
/** address range for ictrll3
    0x1D460600--0x1D4607FF */
#define ONU_ICTRLL3_BASE		(KSEG1 | 0x1D460600)
#define ONU_ICTRLL3_END		(KSEG1 | 0x1D4607FF)
#define ONU_ICTRLL3_SIZE		0x00000200
/** address range for ictrlc0
    0x1D461000--0x1D4610FF */
#define ONU_ICTRLC0_BASE		(KSEG1 | 0x1D461000)
#define ONU_ICTRLC0_END		(KSEG1 | 0x1D4610FF)
#define ONU_ICTRLC0_SIZE		0x00000100
/** address range for ictrlc1
    0x1D461100--0x1D4611FF */
#define ONU_ICTRLC1_BASE		(KSEG1 | 0x1D461100)
#define ONU_ICTRLC1_END		(KSEG1 | 0x1D4611FF)
#define ONU_ICTRLC1_SIZE		0x00000100
/** address range for fsqm
    0x1D500000--0x1D5FFFFF */
#define ONU_FSQM_BASE		(KSEG1 | 0x1D500000)
#define ONU_FSQM_END		(KSEG1 | 0x1D5FFFFF)
#define ONU_FSQM_SIZE		0x00100000
/** address range for pctrl
    0x1D600000--0x1D6001FF */
#define ONU_PCTRL_BASE		(KSEG1 | 0x1D600000)
#define ONU_PCTRL_END		(KSEG1 | 0x1D6001FF)
#define ONU_PCTRL_SIZE		0x00000200
/** address range for link0
    0x1D600200--0x1D6002FF */
#define ONU_LINK0_BASE		(KSEG1 | 0x1D600200)
#define ONU_LINK0_END		(KSEG1 | 0x1D6002FF)
#define ONU_LINK0_SIZE		0x00000100
/** address range for link1
    0x1D600300--0x1D6003FF */
#define ONU_LINK1_BASE		(KSEG1 | 0x1D600300)
#define ONU_LINK1_END		(KSEG1 | 0x1D6003FF)
#define ONU_LINK1_SIZE		0x00000100
/** address range for link2
    0x1D600400--0x1D6004FF */
#define ONU_LINK2_BASE		(KSEG1 | 0x1D600400)
#define ONU_LINK2_END		(KSEG1 | 0x1D6004FF)
#define ONU_LINK2_SIZE		0x00000100
/** address range for disp
    0x1D600500--0x1D6005FF */
#define ONU_DISP_BASE		(KSEG1 | 0x1D600500)
#define ONU_DISP_END		(KSEG1 | 0x1D6005FF)
#define ONU_DISP_SIZE		0x00000100
/** address range for merge
    0x1D600600--0x1D6006FF */
#define ONU_MERGE_BASE		(KSEG1 | 0x1D600600)
#define ONU_MERGE_END		(KSEG1 | 0x1D6006FF)
#define ONU_MERGE_SIZE		0x00000100
/** address range for tbm
    0x1D600700--0x1D6007FF */
#define ONU_TBM_BASE		(KSEG1 | 0x1D600700)
#define ONU_TBM_END		(KSEG1 | 0x1D6007FF)
#define ONU_TBM_SIZE		0x00000100
/** address range for pe0
    0x1D610000--0x1D61FFFF */
#define ONU_PE0_BASE		(KSEG1 | 0x1D610000)
#define ONU_PE0_END		(KSEG1 | 0x1D61FFFF)
#define ONU_PE0_SIZE		0x00010000
/** address range for pe1
    0x1D620000--0x1D62FFFF */
#define ONU_PE1_BASE		(KSEG1 | 0x1D620000)
#define ONU_PE1_END		(KSEG1 | 0x1D62FFFF)
#define ONU_PE1_SIZE		0x00010000
/** address range for pe2
    0x1D630000--0x1D63FFFF */
#define ONU_PE2_BASE		(KSEG1 | 0x1D630000)
#define ONU_PE2_END		(KSEG1 | 0x1D63FFFF)
#define ONU_PE2_SIZE		0x00010000
/** address range for pe3
    0x1D640000--0x1D64FFFF */
#define ONU_PE3_BASE		(KSEG1 | 0x1D640000)
#define ONU_PE3_END		(KSEG1 | 0x1D64FFFF)
#define ONU_PE3_SIZE		0x00010000
/** address range for pe4
    0x1D650000--0x1D65FFFF */
#define ONU_PE4_BASE		(KSEG1 | 0x1D650000)
#define ONU_PE4_END		(KSEG1 | 0x1D65FFFF)
#define ONU_PE4_SIZE		0x00010000
/** address range for pe5
    0x1D660000--0x1D66FFFF */
#define ONU_PE5_BASE		(KSEG1 | 0x1D660000)
#define ONU_PE5_END		(KSEG1 | 0x1D66FFFF)
#define ONU_PE5_SIZE		0x00010000
/** address range for sys_gpe
    0x1D700000--0x1D7000FF */
#define ONU_SYS_GPE_BASE		(KSEG1 | 0x1D700000)
#define ONU_SYS_GPE_END		(KSEG1 | 0x1D7000FF)
#define ONU_SYS_GPE_SIZE		0x00000100
/** address range for eim
    0x1D800000--0x1D800FFF */
#define ONU_EIM_BASE		(KSEG1 | 0x1D800000)
#define ONU_EIM_END		(KSEG1 | 0x1D800FFF)
#define ONU_EIM_SIZE		0x00001000
/** address range for sxgmii
    0x1D808800--0x1D8088FF */
#define ONU_SXGMII_BASE		(KSEG1 | 0x1D808800)
#define ONU_SXGMII_END		(KSEG1 | 0x1D8088FF)
#define ONU_SXGMII_SIZE		0x00000100
/** address range for sgmii
    0x1D808C00--0x1D808CFF */
#define ONU_SGMII_BASE		(KSEG1 | 0x1D808C00)
#define ONU_SGMII_END		(KSEG1 | 0x1D808CFF)
#define ONU_SGMII_SIZE		0x00000100
/** address range for sys_eth
    0x1DB00000--0x1DB000FF */
#define ONU_SYS_ETH_BASE		(KSEG1 | 0x1DB00000)
#define ONU_SYS_ETH_END		(KSEG1 | 0x1DB000FF)
#define ONU_SYS_ETH_SIZE		0x00000100
/** address range for gtc
    0x1DC05000--0x1DC052D4 */
#define ONU_GTC_BASE		(KSEG1 | 0x1DC00000)
#define ONU_GTC_END		(KSEG1 | 0x1DC002D4)
#define ONU_GTC_SIZE		0x000002D5
/** address range for tod
    0x1DEFFE00--0x1DEFFEFC */
#define ONU_TOD_BASE		(KSEG1 | 0x1DEFFE00)
#define ONU_TOD_END		(KSEG1 | 0x1DEFFEFF)
#define ONU_TOD_SIZE		0x00000100
/** address range for sbs0ctrl
    0x1F080000--0x1F0801FF */
#define ONU_SBS0CTRL_BASE		(KSEG1 | 0x1F080000)
#define ONU_SBS0CTRL_END		(KSEG1 | 0x1F0801FF)
#define ONU_SBS0CTRL_SIZE		0x00000200
/** address range for sbs0ram
    0x1F200000--0x1F32FFFF */
#define ONU_SBS0RAM_BASE		(KSEG1 | 0x1F200000)
#define ONU_SBS0RAM_END		(KSEG1 | 0x1F32FFFF)
#define ONU_SBS0RAM_SIZE		0x00130000

/** address range for status
    0x1E802000--0x1E80207F */
#define ONU_STATUS_BASE		(KSEG1 | 0x1E802000)
#define ONU_STATUS_END		(KSEG1 | 0x1E80207F)
#define ONU_STATUS_SIZE		0x00000080

/** address range for sys1
    0x1EF00000--0x1EF000FF */
#define ONU_SYS1_BASE		(KSEG1 | 0x1EF00000)
#define ONU_SYS1_END		(KSEG1 | 0x1EF000FF)
#define ONU_SYS1_SIZE		0x00000100

/*! @} */ /* ONU_BASE */

#endif /* _drv_onu_reg_base_h */

