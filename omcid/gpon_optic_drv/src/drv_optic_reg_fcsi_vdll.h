/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_fcsi_vdll_h
#define _drv_optic_reg_fcsi_vdll_h

/** \addtogroup VDLL_REGISTER
   @{
*/

#ifndef __ASSEMBLY__

/* access macros */
#define vdll_r16(reg) reg_r16(&vdll->reg)
#define vdll_w16(val, reg) reg_w16(val, &vdll->reg)
#define vdll_w16_mask(clear, set, reg) reg_w16_mask(clear, set, &vdll->reg)
#define vdll_r16_table(reg, idx) reg_r16_table(vdll->reg, idx)
#define vdll_w16_table(val, reg, idx) reg_w16_table(val, vdll->reg, idx)
#define vdll_w16_table_mask(clear, set, reg, idx) reg_w16_table_mask(clear, set, vdll->reg, idx)
#define vdll_adr_table(reg, idx) adr_table(vdll->reg, idx)


/** VDLL register structure */
struct fcsi_reg_vdll
{
   /** Voice DLL Control Register 0; #24 */
   unsigned short ctrl; /* 0x00 */
};

#define FCSI_VDLL_CTRL   ((volatile unsigned short*)(FCSI_VDLL_BASE + 0x00))

#else /* __ASSEMBLY__ */

#define FCSI_VDLL_CTRL   (FCSI_VDLL_BASE + 0x00)

#endif /* __ASSEMBLY__ */

/* Fields of "Voice DLL Control Register 0; #24" */
/** clock for the adc (mm_clk_sel)
    The select the iteration clock for the adc is not described here. */
#define VDLL_CTRL_MCLK 0x0080
/** Bias Current (dll_bias_cur_sel_lf_i) */
#define VDLL_CTRL_IBIAS_MASK 0x0060
/** field offset */
#define VDLL_CTRL_IBIAS_OFFSET 5
/** 25 uA */
#define VDLL_CTRL_IBIAS_UA25 0x0000
/** 20 uA */
#define VDLL_CTRL_IBIAS_UA20 0x0020
/** 35 uA */
#define VDLL_CTRL_IBIAS_UA35 0x0040
/** 30 uA */
#define VDLL_CTRL_IBIAS_UA30 0x0060
/** Charge Pump Current (dll_cp_cur_sel_i) */
#define VDLL_CTRL_ICP_MASK 0x001C
/** field offset */
#define VDLL_CTRL_ICP_OFFSET 2
/** 100 uA */
#define VDLL_CTRL_ICP_UA100 0x0000
/** 110 uA */
#define VDLL_CTRL_ICP_UA110 0x0004
/** 80 uA */
#define VDLL_CTRL_ICP_UA80 0x0008
/** 90 uA */
#define VDLL_CTRL_ICP_UA90 0x000C
/** 60 uA */
#define VDLL_CTRL_ICP_UA60 0x0010
/** 70 uA */
#define VDLL_CTRL_ICP_UA70 0x0014
/** 40 uA */
#define VDLL_CTRL_ICP_UA40 0x0018
/** 50 uA */
#define VDLL_CTRL_ICP_UA50 0x001C
/** Reference Voltage (dll_vref_sel_i)
    Reference voltage of the of the loop filter. */
#define VDLL_CTRL_VREF_MASK 0x0003
/** field offset */
#define VDLL_CTRL_VREF_OFFSET 0
/** 500 mV */
#define VDLL_CTRL_VREF_MV500 0x0000
/** 550 mV */
#define VDLL_CTRL_VREF_MV550 0x0001
/** 400 mV */
#define VDLL_CTRL_VREF_MV400 0x0002
/** 450 mV */
#define VDLL_CTRL_VREF_MV450 0x0003

/*! @} */ /* VDLL_REGISTER */

#endif /* _drv_optic_reg_fcsi_vdll_h */
