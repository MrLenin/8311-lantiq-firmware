/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_fcsi_cbias_h
#define _drv_optic_reg_fcsi_cbias_h

/** \addtogroup CBIAS_REGISTER
   @{
*/

#ifndef __ASSEMBLY__

/* access macros */
#define cbias_r16(reg) reg_r16(&cbias->reg)
#define cbias_w16(val, reg) reg_w16(val, &cbias->reg)
#define cbias_w16_mask(clear, set, reg) reg_w16_mask(clear, set, &cbias->reg)
#define cbias_r16_table(reg, idx) reg_r16_table(cbias->reg, idx)
#define cbias_w16_table(val, reg, idx) reg_w16_table(val, cbias->reg, idx)
#define cbias_w16_table_mask(clear, set, reg, idx) reg_w16_table_mask(clear, set, cbias->reg, idx)
#define cbias_adr_table(reg, idx) adr_table(cbias->reg, idx)


/** CBIAS register structure */
struct fcsi_reg_cbias
{
   /** Central Bias Register 0; #20 */
   unsigned short ctrl0; /* 0x00 */
   /** Central Bias Register 1; #21 */
   unsigned short ctrl1; /* 0x01 */
   /** Reserved */
   unsigned short res_0; /* 0x03 */
};

#define FCSI_CBIAS_CTRL0   ((volatile unsigned short*)(FCSI_CBIAS_BASE + 0x00))
#define FCSI_CBIAS_CTRL1   ((volatile unsigned short*)(FCSI_CBIAS_BASE + 0x01))

#else /* __ASSEMBLY__ */

#define FCSI_CBIAS_CTRL0   (FCSI_CBIAS_BASE + 0x00)
#define FCSI_CBIAS_CTRL1   (FCSI_CBIAS_BASE + 0x01)

#endif /* __ASSEMBLY__ */

/* Fields of "Central Bias Register 0; #20" */
/** Measurement VCM Reference Current (cb_imeasvcm_50u)
    Reference current for the output common mode voltage of the measurement switched cap buffer. Nominal Value 50uA */
#define CBIAS_CTRL0_IMVCM_MASK 0x0C00
/** field offset */
#define CBIAS_CTRL0_IMVCM_OFFSET 10
/** 100 % */
#define CBIAS_CTRL0_IMVCM_P100 0x0000
/** 80 % */
#define CBIAS_CTRL0_IMVCM_P80 0x0400
/** 90 % */
#define CBIAS_CTRL0_IMVCM_P90 0x0800
/** 110 % */
#define CBIAS_CTRL0_IMVCM_P110 0x0C00
/** 1550nm DAC Reference Current (cb_idac1550_50u)
    Reference current input of the 1550nm R2R DAC Nominal Value 50uA */
#define CBIAS_CTRL0_IDAC1550_MASK 0x0300
/** field offset */
#define CBIAS_CTRL0_IDAC1550_OFFSET 8
/** 100 % */
#define CBIAS_CTRL0_IDAC1550_P100 0x0000
/** 80 % */
#define CBIAS_CTRL0_IDAC1550_P80 0x0100
/** 90 % */
#define CBIAS_CTRL0_IDAC1550_P90 0x0200
/** 110 % */
#define CBIAS_CTRL0_IDAC1550_P110 0x0300
/** TXBOSA Bias Current (cb_itxbosa_50u)
    Bias current of the tx bosa block and reference current for the bias and modulation dac. Nominal Value 50uA */
#define CBIAS_CTRL0_ITXBOSA_MASK 0x00C0
/** field offset */
#define CBIAS_CTRL0_ITXBOSA_OFFSET 6
/** 100 % */
#define CBIAS_CTRL0_ITXBOSA_P100 0x0000
/** 50 % */
#define CBIAS_CTRL0_ITXBOSA_P50 0x0040
/** 75 % */
#define CBIAS_CTRL0_ITXBOSA_P75 0x0080
/** 125 % */
#define CBIAS_CTRL0_ITXBOSA_P125 0x00C0
/** VCM0V6 Bias Current (cb_i_bfdvcm0v6_50u)
    Bias current for the common mode voltage generation, derived from the 1.0V supply Nominal Value 50uA */
#define CBIAS_CTRL0_IVCM0V6_MASK 0x0030
/** field offset */
#define CBIAS_CTRL0_IVCM0V6_OFFSET 4
/** 100 % */
#define CBIAS_CTRL0_IVCM0V6_P100 0x0000
/** 50 % */
#define CBIAS_CTRL0_IVCM0V6_P50 0x0010
/** 75 % */
#define CBIAS_CTRL0_IVCM0V6_P75 0x0020
/** 125 % */
#define CBIAS_CTRL0_IVCM0V6_P125 0x0030
/** VCM0V5 Bias Current (cb_ibfd_vcm0v5_25u)
    Bias current for the common mode voltage generation, derived from the 1.0V supply Nominal Value 25uA */
#define CBIAS_CTRL0_IVCM0V5_MASK 0x000C
/** field offset */
#define CBIAS_CTRL0_IVCM0V5_OFFSET 2
/** 100 % */
#define CBIAS_CTRL0_IVCM0V5_P100 0x0000
/** 50 % */
#define CBIAS_CTRL0_IVCM0V5_P50 0x0004
/** 75 % */
#define CBIAS_CTRL0_IVCM0V5_P75 0x0008
/** 125 % */
#define CBIAS_CTRL0_IVCM0V5_P125 0x000C
/** BFD Bias Current (cb_ibfd_50u)
    Bias current for the bfd block and for the offset and level DACs inside the bfd module. Nominal Value 50uA */
#define CBIAS_CTRL0_IBFD_MASK 0x0003
/** field offset */
#define CBIAS_CTRL0_IBFD_OFFSET 0
/** 100 % */
#define CBIAS_CTRL0_IBFD_P100 0x0000
/** 50 % */
#define CBIAS_CTRL0_IBFD_P50 0x0001
/** 75 % */
#define CBIAS_CTRL0_IBFD_P75 0x0002
/** 125 % */
#define CBIAS_CTRL0_IBFD_P125 0x0003

/* Fields of "Central Bias Register 1; #21" */
/** Reference Current Trimming (cb_ui_ref_trimm)
    Change the reference currents for the dacs and adc reference. */
#define CBIAS_CTRL1_UIRT_MASK 0xF000
/** field offset */
#define CBIAS_CTRL1_UIRT_OFFSET 12
/** 100.0 % */
#define CBIAS_CTRL1_UIRT_P100D0 0x0000
/** 102.4 % */
#define CBIAS_CTRL1_UIRT_P102D4 0x1000
/** 105.6 % */
#define CBIAS_CTRL1_UIRT_P105D6 0x2000
/** 108.8 % */
#define CBIAS_CTRL1_UIRT_P108D8 0x3000
/** 111.2 % */
#define CBIAS_CTRL1_UIRT_P111D2 0x4000
/** 115.2 % */
#define CBIAS_CTRL1_UIRT_P115D2 0x5000
/** 118.4 % */
#define CBIAS_CTRL1_UIRT_P118D4 0x6000
/** 122.4 % */
#define CBIAS_CTRL1_UIRT_P122D4 0x7000
/** 97.6 % */
#define CBIAS_CTRL1_UIRT_P97D6 0x8000
/** 95.2 % */
#define CBIAS_CTRL1_UIRT_P95D2 0x9000
/** 92.0 % */
#define CBIAS_CTRL1_UIRT_P92D0 0xA000
/** 88.8 % */
#define CBIAS_CTRL1_UIRT_P88D8 0xB000
/** 85.6 % */
#define CBIAS_CTRL1_UIRT_P85D6 0xC000
/** 83.2 % */
#define CBIAS_CTRL1_UIRT_P83D2 0xD000
/** 80.0 % */
#define CBIAS_CTRL1_UIRT_P80D0 0xE000
/** 78.0 % */
#define CBIAS_CTRL1_UIRT_P78D0 0xF000
/** Bias and Calibration Current Trimming (cb_ui_conv_trimm)
    Change the bias currents and the calibration currents. */
#define CBIAS_CTRL1_UICT_MASK 0x0F00
/** field offset */
#define CBIAS_CTRL1_UICT_OFFSET 8
/** 100.0 % */
#define CBIAS_CTRL1_UICT_P100D0 0x0000
/** 102.4 % */
#define CBIAS_CTRL1_UICT_P102D4 0x0100
/** 105.6 % */
#define CBIAS_CTRL1_UICT_P105D6 0x0200
/** 108.8 % */
#define CBIAS_CTRL1_UICT_P108D8 0x0300
/** 111.2 % */
#define CBIAS_CTRL1_UICT_P111D2 0x0400
/** 115.2 % */
#define CBIAS_CTRL1_UICT_P115D2 0x0500
/** 118.4 % */
#define CBIAS_CTRL1_UICT_P118D4 0x0600
/** 122.4 % */
#define CBIAS_CTRL1_UICT_P122D4 0x0700
/** 97.6 % */
#define CBIAS_CTRL1_UICT_P97D6 0x0800
/** 95.2 % */
#define CBIAS_CTRL1_UICT_P95D2 0x0900
/** 92.0 % */
#define CBIAS_CTRL1_UICT_P92D0 0x0A00
/** 88.8 % */
#define CBIAS_CTRL1_UICT_P88D8 0x0B00
/** 85.6 % */
#define CBIAS_CTRL1_UICT_P85D6 0x0C00
/** 83.2 % */
#define CBIAS_CTRL1_UICT_P83D2 0x0D00
/** 80.0 % */
#define CBIAS_CTRL1_UICT_P80D0 0x0E00
/** 78.0 % */
#define CBIAS_CTRL1_UICT_P78D0 0x0F00
/** MM bias prog (cb_prog_300u)
    . */
#define CBIAS_CTRL1_MCAL 0x0080
/** Bandgap Temperature Coefficient (cb_bgp_temp)
    This value is represented as 2s-complement. So, it reaches from 111 (negative maximum) via 000 (neutral=default) to 011 (positive maximum). */
#define CBIAS_CTRL1_BGPT_MASK 0x0070
/** field offset */
#define CBIAS_CTRL1_BGPT_OFFSET 4
/** Central Biasing operating mode (cb_pd) */
#define CBIAS_CTRL1_PD 0x0008
/** Powerup. */
#define CBIAS_CTRL1_PD_PU 0x0000
/** Bandgap Reference Voltage (cb_bgp_abs)
    Reference voltage of the bandgap. */
#define CBIAS_CTRL1_BGPV_MASK 0x0007
/** field offset */
#define CBIAS_CTRL1_BGPV_OFFSET 0
/** 502 mV */
#define CBIAS_CTRL1_BGPV_MV502 0x0000
/** 515 mV */
#define CBIAS_CTRL1_BGPV_MV515 0x0001
/** 528 mV */
#define CBIAS_CTRL1_BGPV_MV528 0x0002
/** 541 mV */
#define CBIAS_CTRL1_BGPV_MV541 0x0003
/** 489 mV */
#define CBIAS_CTRL1_BGPV_MV489 0x0004
/** 476 mV */
#define CBIAS_CTRL1_BGPV_MV476 0x0005
/** 463 mV */
#define CBIAS_CTRL1_BGPV_MV463 0x0006
/** 450 mV */
#define CBIAS_CTRL1_BGPV_MV450 0x0007

/*! @} */ /* CBIAS_REGISTER */

#endif /* _drv_optic_reg_fcsi_cbias_h */
