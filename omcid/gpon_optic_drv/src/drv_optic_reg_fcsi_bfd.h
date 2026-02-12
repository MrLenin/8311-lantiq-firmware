/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_fcsi_bfd_h
#define _drv_optic_reg_fcsi_bfd_h

/** \addtogroup BFD_REGISTER
   @{
*/

#ifndef __ASSEMBLY__

/* access macros */
#define bfd_r16(reg) reg_r16(&bfd->reg)
#define bfd_w16(val, reg) reg_w16(val, &bfd->reg)
#define bfd_w16_mask(clear, set, reg) reg_w16_mask(clear, set, &bfd->reg)
#define bfd_r16_table(reg, idx) reg_r16_table(bfd->reg, idx)
#define bfd_w16_table(val, reg, idx) reg_w16_table(val, bfd->reg, idx)
#define bfd_w16_table_mask(clear, set, reg, idx) reg_w16_table_mask(clear, set, bfd->reg, idx)
#define bfd_adr_table(reg, idx) adr_table(bfd->reg, idx)


/** BFD register structure */
struct fcsi_reg_bfd
{
   /** Gain Values Register; #16
       This Register serves as shadow register for the gain_tia(2:0) signal controlled from the PMA. gain_tia selects one field from this register: */
   unsigned short gvs; /* 0x00 */
   /** Control Register 0; #17 */
   unsigned short ctrl0; /* 0x01 */
   /** Control Register 1; #18 */
   unsigned short ctrl1; /* 0x02 */
};

#define FCSI_BFD_GVS   ((volatile unsigned short*)(FCSI_BFD_BASE + 0x00))
#define FCSI_BFD_CTRL0   ((volatile unsigned short*)(FCSI_BFD_BASE + 0x01))
#define FCSI_BFD_CTRL1   ((volatile unsigned short*)(FCSI_BFD_BASE + 0x02))

#define FCSI_PI_CTRL   ((volatile unsigned short*)(FCSI_PI_BASE + 0x00))

#else /* __ASSEMBLY__ */

#define FCSI_BFD_GVS   (FCSI_BFD_BASE + 0x00)
#define FCSI_BFD_CTRL0   (FCSI_BFD_BASE + 0x01)
#define FCSI_BFD_CTRL1   (FCSI_BFD_BASE + 0x02)

#define FCSI_PI_CTRL   (FCSI_BFD_BASE + 0x00)

#endif /* __ASSEMBLY__ */

/* Fields of "Gain Values Register; #16" */
/** FCSI Gain (bfd_fcsi_gain) 3
    See field GAIN0 for the coding details. */
#define BFD_GVS_GAIN3_MASK 0xF000
/** field offset */
#define BFD_GVS_GAIN3_OFFSET 12
/** FCSI Gain (bfd_fcsi_gain) 2
    See field GAIN0 for the coding details. */
#define BFD_GVS_GAIN2_MASK 0x0F00
/** field offset */
#define BFD_GVS_GAIN2_OFFSET 8
/** FCSI Gain (bfd_fcsi_gain) 1
    See field GAIN0 for the coding details. */
#define BFD_GVS_GAIN1_MASK 0x00F0
/** field offset */
#define BFD_GVS_GAIN1_OFFSET 4
/** FCSI Gain (bfd_fcsi_gain) 0
    The gain coding is not described here. */
#define BFD_GVS_GAIN0_MASK 0x000F
/** field offset */
#define BFD_GVS_GAIN0_OFFSET 0

/* Fields of "Control Register 0; #17" */
/** Bypass Leakage Compensation LD (bfd_ld_leak_bypass) */
#define BFD_CTRL0_BLLD 0x4000
/** No bypass */
#define BFD_CTRL0_BLLD_NBYP 0x0000
/** Bypass */
#define BFD_CTRL0_BLLD_BYP 0x4000
/** Common Mode Select (bfd_prog_vcm0v5)
    Select the output common mode voltage of the limiting amplifier. The common mode voltage calculates as 0.45 + 25mV*this-field-value */
#define BFD_CTRL0_VCM0V5_MASK 0x3000
/** field offset */
#define BFD_CTRL0_VCM0V5_OFFSET 12
/** Common Mode Select (bfd_prog_vcm0v6)
    Select the output common mode voltage of the limiting amplifier. */
#define BFD_CTRL0_VCM0V6_MASK 0x0C00
/** field offset */
#define BFD_CTRL0_VCM0V6_OFFSET 10
/** 0.60 Volts */
#define BFD_CTRL0_VCM0V6_V060 0x0000
/** 0.55 Volts */
#define BFD_CTRL0_VCM0V6_V055 0x0400
/** 0.65 Volts */
#define BFD_CTRL0_VCM0V6_V065 0x0800
/** 0.70 Volts */
#define BFD_CTRL0_VCM0V6_V070 0x0C00
/** CDR Off (bfd_cdr_dis) */
#define BFD_CTRL0_CDRO 0x0200
/** Default Operation. */
#define BFD_CTRL0_CDRO_DEF 0x0000
/** Clock generation outputs (div2, div4) are 0. */
#define BFD_CTRL0_CDRO_OFF 0x0200
/** Input Termination Select (bfd_rterm_sel)
    The termination resistor */
#define BFD_CTRL0_RTSEL_MASK 0x01F0
/** field offset */
#define BFD_CTRL0_RTSEL_OFFSET 4
/** Bypass Leakage Compensation DAC (bfd_offdac_leak_bypass) */
#define BFD_CTRL0_BLCD 0x0008
/** No bypass */
#define BFD_CTRL0_BLCD_NBYP 0x0000
/** Bypass */
#define BFD_CTRL0_BLCD_BYP 0x0008
/** Common Mode Select (bfd_output_cm_sel)
    Select the output common mode voltage of the bfd levelshiftblock. The common mode voltage calculates as VDD - 60mV*(this-field-value + 1) */
#define BFD_CTRL0_CMSEL_MASK 0x0007
/** field offset */
#define BFD_CTRL0_CMSEL_OFFSET 0

/* Fields of "Control Register 1; #18" */
/** PD LDO (pd_ldo)
    powerdown of the internal linear regulator. */
#define BFD_CTRL1_PDLS 0x0800
/** red bias curr(ired)
    Reduce bias current of the opamp of the linreg block. */
#define BFD_CTRL1_IRED 0x0400
/** VLDO_SEL (vldo_sel)
    The output voltage of the internal bfd linreg is not described here. */
#define BFD_CTRL1_LDO_MASK 0x0300
/** field offset */
#define BFD_CTRL1_LDO_OFFSET 8
/** Clock Inversion Reset (bfd_rst_inv)
    Invert the clock edge of the sync. clock for the reset. */
#define BFD_CTRL1_RINV 0x0080
/** non-inverted clk is used */
#define BFD_CTRL1_RINV_NINV 0x0000
/** inverted clk is used */
#define BFD_CTRL1_RINV_INV 0x0080
/** Clock Inversion (bfd_clk_edge_sel)
    Inverts the divide by eight clock coming from the bfd block. */
#define BFD_CTRL1_CINV 0x0040
/** non-inverted clk is used */
#define BFD_CTRL1_CINV_NINV 0x0000
/** inverted clk is used */
#define BFD_CTRL1_CINV_INV 0x0040
/** Reset (bfd_rst)
    Apply reset for all the DAC flipoflops and for the serializer block. */
#define BFD_CTRL1_RST 0x0020
/** No Reset */
#define BFD_CTRL1_RST_NRST 0x0000
/** Bypass Limiting Amplifier for P (byp_limit)1 */
#define BFD_CTRL1_BLAP1 0x0010
/** No bypass */
#define BFD_CTRL1_BLAP1_NBYP 0x0000
/** Bypass */
#define BFD_CTRL1_BLAP1_BYP 0x0010
/** Bypass Limiting Amplifier for P (byp_limit)0 */
#define BFD_CTRL1_BLAP0 0x0008
/** No bypass */
#define BFD_CTRL1_BLAP0_NBYP 0x0000
/** Bypass */
#define BFD_CTRL1_BLAP0_BYP 0x0008
/** Test DAC Select (bfd_test_dac_sel)
    Select the DAC output voltages, used inside the measurement module */
#define BFD_CTRL1_TDSEL_MASK 0x0007
/** field offset */
#define BFD_CTRL1_TDSEL_OFFSET 0
/** leveldac for p0 */
#define BFD_CTRL1_TDSEL_LDP0 0x0000
/** leveldac for p1 */
#define BFD_CTRL1_TDSEL_LDP1 0x0000
/** fine offset DAC */
#define BFD_CTRL1_TDSEL_FOD 0x0000
/** coarse offset DAC */
#define BFD_CTRL1_TDSEL_COD 0x0000
/** None */
#define BFD_CTRL1_TDSEL_NONE 0x0000

/*! @} */ /* BFD_REGISTER */

#endif /* _drv_optic_reg_fcsi_bfd_h */
