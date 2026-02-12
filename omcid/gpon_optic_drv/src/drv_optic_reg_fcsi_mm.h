/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_fcsi_mm_h
#define _drv_optic_reg_fcsi_mm_h

/** \addtogroup MM_REGISTER
   @{
*/

#ifndef __ASSEMBLY__

/* access macros */
#define mm_r16(reg) reg_r16(&mm->reg)
#define mm_w16(val, reg) reg_w16(val, &mm->reg)
#define mm_w16_mask(clear, set, reg) reg_w16_mask(clear, set, &mm->reg)
#define mm_r16_table(reg, idx) reg_r16_table(mm->reg, idx)
#define mm_w16_table(val, reg, idx) reg_w16_table(val, mm->reg, idx)
#define mm_w16_table_mask(clear, set, reg, idx) reg_w16_table_mask(clear, set, mm->reg, idx)
#define mm_adr_table(reg, idx) adr_table(mm->reg, idx)


/** MM register structure */
struct fcsi_reg_mm
{
   /** Measurement Module Control Register; #14 */
   unsigned short ctrl; /* 0x00 */
};

#define FCSI_MM_CTRL   ((volatile unsigned short*)(FCSI_MM_BASE + 0x00))

#else /* __ASSEMBLY__ */

#define FCSI_MM_CTRL   (FCSI_MM_BASE + 0x00)

#endif /* __ASSEMBLY__ */

/* Fields of "Measurement Module Control Register; #14" */
/** Invert clock (cap_clk_sel)
    invert sample clock of sc buffer () */
#define MM_CTRL_CINV 0x0080
/** NOT inverted clk for sc buffer. */
#define MM_CTRL_CINV_NINV_sc 0x0000
/** inverted clk for sc buffer. */
#define MM_CTRL_CINV_INV_sc 0x0080
/** OPAMP Bias Current Select (mm_iref_red) */
#define MM_CTRL_OPBIAS 0x0040
/** Default Operation. */
#define MM_CTRL_OPBIAS_DEF 0x0000
/** Reduce bias current of the opamp. */
#define MM_CTRL_OPBIAS_RED 0x0040
/** Reference Voltage Block Enable (mm_en_ref1v0)
    Enables the reference voltage block. */
#define MM_CTRL_REFEN 0x0020
/** Disable */
#define MM_CTRL_REFEN_DIS 0x0000
/** Enable */
#define MM_CTRL_REFEN_EN 0x0020
/** Feedback Point Select (mm_sel_fb) */
#define MM_CTRL_FBSEL 0x0010
/** Feedback is taken at the pad. */
#define MM_CTRL_FBSEL_PAD 0x0000
/** Feedback is taken at the output of the opamp. */
#define MM_CTRL_FBSEL_OPAMP 0x0010
/** Reference Voltage Select (mm_vsel)
    Select the reference voltage of the external thermistor. */
#define MM_CTRL_RVS_MASK 0x000C
/** field offset */
#define MM_CTRL_RVS_OFFSET 2
/** 0.93 Volt */
#define MM_CTRL_RVS_V093 0x0000
/** 0.99 Volt */
#define MM_CTRL_RVS_V099 0x0004
/** 1.05 Volt */
#define MM_CTRL_RVS_V105 0x0008
/** 1.175 Volt */
#define MM_CTRL_RVS_V1175 0x000C
/** Test Input N (mm_test_inn)
    Enables the positive test input */
#define MM_CTRL_TINN 0x0002
/** Disable */
#define MM_CTRL_TINN_DIS 0x0000
/** Enable */
#define MM_CTRL_TINN_EN 0x0002
/** Test Input P (mm_test_inp)
    Enables the positive test input */
#define MM_CTRL_TINP 0x0001
/** Disable */
#define MM_CTRL_TINP_DIS 0x0000
/** Enable */
#define MM_CTRL_TINP_EN 0x0001

/*! @} */ /* MM_REGISTER */

#endif /* _drv_optic_reg_fcsi_mm_h */
