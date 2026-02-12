/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_fcsi_txbosa_h
#define _drv_optic_reg_fcsi_txbosa_h

/** \addtogroup TXBOSA_REGISTER
   @{
*/

#ifndef __ASSEMBLY__

/* access macros */
#define txbosa_r16(reg) reg_r16(&txbosa->reg)
#define txbosa_w16(val, reg) reg_w16(val, &txbosa->reg)
#define txbosa_w16_mask(clear, set, reg) reg_w16_mask(clear, set, &txbosa->reg)
#define txbosa_r16_table(reg, idx) reg_r16_table(txbosa->reg, idx)
#define txbosa_w16_table(val, reg, idx) reg_w16_table(val, txbosa->reg, idx)
#define txbosa_w16_table_mask(clear, set, reg, idx) reg_w16_table_mask(clear, set, txbosa->reg, idx)
#define txbosa_adr_table(reg, idx) adr_table(txbosa->reg, idx)


/** TXBOSA register structure */
struct fcsi_reg_txbosa
{
   /** Data Driver Control Register 0; #0 */
   unsigned short ddc0; /* 0x00 */
   /** Data Driver Control Register 1; #1 */
   unsigned short ddc1; /* 0x01 */
   /** Bias Driver Control Register 0; #2 */
   unsigned short bdc0; /* 0x02 */
   /** Bias Driver Control Register 1; #3 */
   unsigned short bdc1; /* 0x03 */
   /** TX Bosa Module Control Register; #4 */
   unsigned short ctrl; /* 0x04 */
   /** Clock Control Register; #5
       inverts the divide by eight clock of the bosa */
   unsigned short cc; /* 0x05 */
   /** Phase Control Register; #6 */
   unsigned short ph; /* 0x06 */
   /** Powerdown setting; #7 */
   unsigned short pds; /* 0x07 */
   /** Reserved */
   unsigned short res_0; /* 0x09 */
};

#define FCSI_TXBOSA_DDC0   ((volatile unsigned short*)(FCSI_TXBOSA_BASE + 0x00))
#define FCSI_TXBOSA_DDC1   ((volatile unsigned short*)(FCSI_TXBOSA_BASE + 0x01))
#define FCSI_TXBOSA_BDC0   ((volatile unsigned short*)(FCSI_TXBOSA_BASE + 0x02))
#define FCSI_TXBOSA_BDC1   ((volatile unsigned short*)(FCSI_TXBOSA_BASE + 0x03))
#define FCSI_TXBOSA_CTRL   ((volatile unsigned short*)(FCSI_TXBOSA_BASE + 0x04))
#define FCSI_TXBOSA_CC   ((volatile unsigned short*)(FCSI_TXBOSA_BASE + 0x05))
#define FCSI_TXBOSA_PH   ((volatile unsigned short*)(FCSI_TXBOSA_BASE + 0x06))
#define FCSI_TXBOSA_PDS   ((volatile unsigned short*)(FCSI_TXBOSA_BASE + 0x07))

#else /* __ASSEMBLY__ */

#define FCSI_TXBOSA_DDC0   (FCSI_TXBOSA_BASE + 0x00)
#define FCSI_TXBOSA_DDC1   (FCSI_TXBOSA_BASE + 0x01)
#define FCSI_TXBOSA_BDC0   (FCSI_TXBOSA_BASE + 0x02)
#define FCSI_TXBOSA_BDC1   (FCSI_TXBOSA_BASE + 0x03)
#define FCSI_TXBOSA_CTRL   (FCSI_TXBOSA_BASE + 0x04)
#define FCSI_TXBOSA_CC   (FCSI_TXBOSA_BASE + 0x05)
#define FCSI_TXBOSA_PH   (FCSI_TXBOSA_BASE + 0x06)
#define FCSI_TXBOSA_PDS   (FCSI_TXBOSA_BASE + 0x07)

#endif /* __ASSEMBLY__ */

/* Fields of "Data Driver Control Register 0; #0" */
/** Fall Time (tx_bosa_dd_bias_en)
    Controls the fall time of the pre driver of the TX BOSA data driver output circuits. The higher this value is, the more bias current is enabled through the pre-drivers speeding up the fall time of the outputs. */
#define TXBOSA_DDC0_FT_MASK 0xF000
/** field offset */
#define TXBOSA_DDC0_FT_OFFSET 12
/** Bypass Leakage Compensation DAC (tx_bosa_dd_byp_leak_ota) */
#define TXBOSA_DDC0_BLCD 0x0800
/** No bypass */
#define TXBOSA_DDC0_BLCD_NBYP 0x0000
/** Bypass */
#define TXBOSA_DDC0_BLCD_BYP 0x0800
/** Rise Time N-output (tx_bosa_dd_loadn)
    Controls the rise time of the pre driver of the TX BOSA data driver n-output circuit. The higher this value is, the more transistors get disabled slowing down the rise time. */
#define TXBOSA_DDC0_RTN_MASK 0x001F
/** field offset */
#define TXBOSA_DDC0_RTN_OFFSET 0

/* Fields of "Data Driver Control Register 1; #1" */
/** Enable pre driver (tx_bosa_dd_en_predrv) */
#define TXBOSA_DDC1_ENPD 0x8000
/** tri state () */
#define TXBOSA_DDC1_ENPD_TRI 0x0000
/** Enable (load resistors are connected to the supply) */
#define TXBOSA_DDC1_ENPD_EN 0x8000
/** common mode load resistor (tx_bosa_cm_load)
    these bits control the value of the common mode load resistor; the voltage drop over this resistor is defined by its value (tx_bosa_cm_load) and the amount of current through it (tx_boas_bias_dd) */
#define TXBOSA_DDC1_CMR_MASK 0x7C00
/** field offset */
#define TXBOSA_DDC1_CMR_OFFSET 10
/** Rise Time preD P-output (tx_bosa_dd_loadp)
    Controls the rise time of the pre driver of the TX BOSA data driver p-output circuit. */
#define TXBOSA_DDC1_RTP_MASK 0x001F
/** field offset */
#define TXBOSA_DDC1_RTP_OFFSET 0

/* Fields of "Bias Driver Control Register 0; #2" */
/** Fall Time Bias Driver (tx_bosa_bd_bias_en)
    Controls the fall time of the pre driver of the TX BOSA bias driver output circuits. The higher this value is, the more bias current is enabled through the pre-drivers speeding up the fall time of the outputs. */
#define TXBOSA_BDC0_FT_MASK 0xF000
/** field offset */
#define TXBOSA_BDC0_FT_OFFSET 12
/** Bypass Leakage Compensation DAC (tx_bosa_bd_byp_leak_ota) */
#define TXBOSA_BDC0_BLCD 0x0800
/** No bypass */
#define TXBOSA_BDC0_BLCD_NBYP 0x0000
/** Bypass */
#define TXBOSA_BDC0_BLCD_BYP 0x0800
/** Rise Time N-output (tx_bosa_bd_loadn)
    Controls the rise time of the pre driver of the TX BOSA bias driver n-output circuit. The higher this value is, the more transistors get disabled slowing down the rise time. */
#define TXBOSA_BDC0_RTN_MASK 0x001F
/** field offset */
#define TXBOSA_BDC0_RTN_OFFSET 0

/* Fields of "Bias Driver Control Register 1; #3" */
/** Enable pre driver (tx_bosa_bd_en_predrv) */
#define TXBOSA_BDC1_ENPD 0x8000
/** tri state () */
#define TXBOSA_BDC1_ENPD_TRI 0x0000
/** Enable (load resistors are connected to the supply) */
#define TXBOSA_BDC1_ENPD_EN 0x8000
/** common mode load resistor (tx_bosa_bd_cm_load)
    these bits control the value of the common mode load resistor; the voltage drop over this resistor is defined by its value (tx_bosa_cm_load) and the amount of current through it (tx_boas_bias_dd) */
#define TXBOSA_BDC1_CMR_MASK 0x7C00
/** field offset */
#define TXBOSA_BDC1_CMR_OFFSET 10
/** Rise Time preD P-output (tx_bosa_bd_loadp)
    Controls the rise time of the pre driver of the TX BOSA data driver p-output circuit. */
#define TXBOSA_BDC1_RTP_MASK 0x001F
/** field offset */
#define TXBOSA_BDC1_RTP_OFFSET 0

/* Fields of "TX Bosa Module Control Register; #4" */
/** enable the predistortion (pulsedvar_en_i)
    enable the predistortion circuit; '1' the falling edhe of the data are triggered with the distorted clock; if '0' the data is controlloed with the data clock (rising and falling). */
#define TXBOSA_CTRL_PRE 0x0080
/** pd drive (tx_pd_dd)
    powerdown of the drive dacs */
#define TXBOSA_CTRL_PDD 0x0040
/** pd bias (tx_pd_bd)
    powerdown of the bias dacs */
#define TXBOSA_CTRL_PDB 0x0020
/** clock edge (tx_clkedge_sel)
    sel clk used for writing out the data */
#define TXBOSA_CTRL_CED 0x0010
/** inverted clk is used. */
#define TXBOSA_CTRL_CED_NINV 0x0000
/** clk is used. */
#define TXBOSA_CTRL_CED_INV 0x0010
/** clock enable (tx_clkmode_en) */
#define TXBOSA_CTRL_CE 0x0008
/** normal operation. */
#define TXBOSA_CTRL_CE_ECLK 0x0000
/** data output generate clk (even bits are '1', odd bits are '0'). */
#define TXBOSA_CTRL_CE_ECLKn 0x0008
/** pot power down (tx_ei_sign_sel)
    define the output when block is in powerdown. */
#define TXBOSA_CTRL_OP 0x0004
/** en_ser_out (tx_ei_en)
    enable or disable serializer output. */
#define TXBOSA_CTRL_SE 0x0002
/** reset FF (tx_ser_en)
    reset the FF. */
#define TXBOSA_CTRL_FFR 0x0001
/** flops are in reset. */
#define TXBOSA_CTRL_FFR_RST 0x0000
/** normal operation. */
#define TXBOSA_CTRL_FFR_NOR 0x0001

/* Fields of "Clock Control Register; #5" */
/** tx_pd_vcm
    Powerdown setting for vcm; resistor value like in register1 (bits 14:10); */
#define TXBOSA_CC_PCM_MASK 0xF800
/** field offset */
#define TXBOSA_CC_PCM_OFFSET 11
/** tx_pd_dd_loadp
    Powerdown setting for loadp; resistor value like in register1 (bits 4:0); */
#define TXBOSA_CC_PRTP_MASK 0x07C0
/** field offset */
#define TXBOSA_CC_PRTP_OFFSET 6
/** tx_pd_dd_loadn
    Powerdown setting for loadn; resistor value like in register0 (bits 4:0); */
#define TXBOSA_CC_PRTN_MASK 0x003E
/** field offset */
#define TXBOSA_CC_PRTN_OFFSET 1
/** Clock Inversion inside the timing shell (tx_bosa_ctrl_div8_clk_edge)
    Inverts the divided by eight clock of the bosa. */
#define TXBOSA_CC_CINV 0x0001
/** inverted clk is used. */
#define TXBOSA_CC_CINV_NINV 0x0000
/** clk is used. */
#define TXBOSA_CC_CINV_INV 0x0001

/* Fields of "Phase Control Register; #6" */
/** tx_pd_bias_bd_en
    Powerdown setting for the bias current of the predrivers */
#define TXBOSA_PH_PBEN_MASK 0xF000
/** field offset */
#define TXBOSA_PH_PBEN_OFFSET 12
/** tx_pd_bd_loadp
    Powerdown setting for loadp; resistor value like in register1 (bits 4:0); */
#define TXBOSA_PH_PRTPB_MASK 0x0F80
/** field offset */
#define TXBOSA_PH_PRTPB_OFFSET 7
/** tx_pd_bd_loadn
    Powerdown setting for loadn; resistor value like in register0 (bits 4:0); */
#define TXBOSA_PH_PRTNB_MASK 0x007C
/** field offset */
#define TXBOSA_PH_PRTNB_OFFSET 2
/** tx_bosa_rst_phd (tx_bosa_rst_phd)
    reset the flipflop for detecting the phase between the data clock and the distorted clock. */
#define TXBOSA_PH_RST 0x0002
/** tx_bosa_phd_data_distort (tx_bosa_phd_data_distort)
    read back the phase relation between distorted and data clock. */
#define TXBOSA_PH_RD 0x0001

/* Fields of "Powerdown setting; #7" */
/** tx_pd_smart_pre
    if '1' the enable bit of the bias and drive predriver is controlled with the inverted pd_smart bit (this signal is controlled directly from the pma) */
#define TXBOSA_PDS_PSPRE 0x0200
/** tx_pd_cm_dd_load
    Powerdown setting for common mode voltage of the bias of the predrivers */
#define TXBOSA_PDS_PCMD_MASK 0x01F0
/** field offset */
#define TXBOSA_PDS_PCMD_OFFSET 4
/** tx_pd_bias_bd_en
    Powerdown setting for the bias current of the predrivers */
#define TXBOSA_PDS_PBENDD_MASK 0x000F
/** field offset */
#define TXBOSA_PDS_PBENDD_OFFSET 0

/*! @} */ /* TXBOSA_REGISTER */

#endif /* _drv_optic_reg_fcsi_txbosa_h */
