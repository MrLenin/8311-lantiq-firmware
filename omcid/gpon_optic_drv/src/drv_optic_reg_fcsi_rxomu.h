/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_fcsi_rxomu_h
#define _drv_optic_reg_fcsi_rxomu_h

/** \addtogroup RXOMU_REGISTER
   @{
*/

#ifndef __ASSEMBLY__

/* access macros */
#define rxomu_r16(reg) reg_r16(&rxomu->reg)
#define rxomu_w16(val, reg) reg_w16(val, &rxomu->reg)
#define rxomu_w16_mask(clear, set, reg) reg_w16_mask(clear, set, &rxomu->reg)
#define rxomu_r16_table(reg, idx) reg_r16_table(rxomu->reg, idx)
#define rxomu_w16_table(val, reg, idx) reg_w16_table(val, rxomu->reg, idx)
#define rxomu_w16_table_mask(clear, set, reg, idx) reg_w16_table_mask(clear, set, rxomu->reg, idx)
#define rxomu_adr_table(reg, idx) adr_table(rxomu->reg, idx)


/** RXOMU register structure */
struct fcsi_reg_rxomu
{
   /** RX Omu Module Control Register; #13 */
   unsigned short ctrl; /* 0x00 */
};

#define FCSI_RXOMU_CTRL   ((volatile unsigned short*)(FCSI_RXOMU_BASE + 0x00))

#else /* __ASSEMBLY__ */

#define FCSI_RXOMU_CTRL   (FCSI_RXOMU_BASE + 0x00)

#endif /* __ASSEMBLY__ */

/* Fields of "RX Omu Module Control Register; #13" */
/** Test DAC Select (rx_omu_test_dac)
    select whether the DAC output is fed to the measurement module. */
#define RXOMU_CTRL_TDS 0x0010
/** No DAC is selected. */
#define RXOMU_CTRL_TDS_NONE 0x0000
/** DAC is selected. */
#define RXOMU_CTRL_TDS_DAC 0x0010
/** Clock Inversion (rx_omu_clk_edge_sel)
    Inverts the divide by eight clock of the timingshell. */
#define RXOMU_CTRL_CINV 0x0008
/** rising edge used inside the timing shell. */
#define RXOMU_CTRL_CINV_NINV 0x0000
/** inverted clk is used inside the timing shell. */
#define RXOMU_CTRL_CINV_INV 0x0008
/** Clock/Data Recovery (rx_omu_cdr_off) */
#define RXOMU_CTRL_CDR 0x0004
/** Default Operation. */
#define RXOMU_CTRL_CDR_DEF 0x0000
/** Clock generation outputs (div2, div4) are 0. */
#define RXOMU_CTRL_CDR_OFF 0x0004
/** Bypass Leakage Compensation OTA (rx_omu_byp_leak_ota) */
#define RXOMU_CTRL_BLOC 0x0002
/** No bypass */
#define RXOMU_CTRL_BLOC_NBYP 0x0000
/** Bypass */
#define RXOMU_CTRL_BLOC_BYP 0x0002
/** Input Stage Operating Mode (rx_omu_sgmii_pd)
    Disabling is done via cascode transistors. */
#define RXOMU_CTRL_ISOM 0x0001
/** Powerup. */
#define RXOMU_CTRL_ISOM_PU 0x0000
/** Powerdown. */
#define RXOMU_CTRL_ISOM_PD 0x0001

/*! @} */ /* RXOMU_REGISTER */

#endif /* _drv_optic_reg_fcsi_rxomu_h */
