/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_fcsi_rxbosa_h
#define _drv_optic_reg_fcsi_rxbosa_h

/** \addtogroup RXBOSA_REGISTER
   @{
*/

#ifndef __ASSEMBLY__

/* access macros */
#define rxbosa_r16(reg) reg_r16(&rxbosa->reg)
#define rxbosa_w16(val, reg) reg_w16(val, &rxbosa->reg)
#define rxbosa_w16_mask(clear, set, reg) reg_w16_mask(clear, set, &rxbosa->reg)
#define rxbosa_r16_table(reg, idx) reg_r16_table(rxbosa->reg, idx)
#define rxbosa_w16_table(val, reg, idx) reg_w16_table(val, rxbosa->reg, idx)
#define rxbosa_w16_table_mask(clear, set, reg, idx) reg_w16_table_mask(clear, set, rxbosa->reg, idx)
#define rxbosa_adr_table(reg, idx) adr_table(rxbosa->reg, idx)


/** RXBOSA register structure */
struct fcsi_reg_rxbosa
{
   /** RX Bosa Module Control Register; #11 */
   unsigned short ctrl; /* 0x00 */
};

#define FCSI_RXBOSA_CTRL   ((volatile unsigned short*)(FCSI_RXBOSA_BASE + 0x00))

#else /* __ASSEMBLY__ */

#define FCSI_RXBOSA_CTRL   (FCSI_RXBOSA_BASE + 0x00)

#endif /* __ASSEMBLY__ */

/* Fields of "RX Bosa Module Control Register; #11" */
/** Comparator 3 Operating Mode (rx_pd_comp3) */
#define RXBOSA_CTRL_C3OM 0x4000
/** Powerup */
#define RXBOSA_CTRL_C3OM_PU 0x0000
/** Powerdown */
#define RXBOSA_CTRL_C3OM_PD 0x4000
/** Data Lo Comparator Operating Mode (rx_pd_comp_data_lo)
     */
#define RXBOSA_CTRL_DLCOM 0x2000
/** Powerup */
#define RXBOSA_CTRL_DLCOM_PU 0x0000
/** Powerdown */
#define RXBOSA_CTRL_DLCOM_PD 0x2000
/** Timing Shell Clock Inversion (rx_bosa_clk_edge_sel)
    Inverts the divide by eight clock of the timingshell. */
#define RXBOSA_CTRL_CINV 0x1000
/** rising edge used inside the timing shell. */
#define RXBOSA_CTRL_CINV_NINV 0x0000
/** inverted clk is used inside the timing shell. */
#define RXBOSA_CTRL_CINV_INV 0x1000
/** Reset (rx_bosa_rst)
    Apply reset to demultiplexers. */
#define RXBOSA_CTRL_RST 0x0800
/** No Reset */
#define RXBOSA_CTRL_RST_NRST 0x0000
/** Test DAC Select (rx_bosa_testdacx)
    select the DAC output, which is fed to the measurement module. */
#define RXBOSA_CTRL_TDS_MASK 0x0700
/** field offset */
#define RXBOSA_CTRL_TDS_OFFSET 8
/** No DAC is selected. */
#define RXBOSA_CTRL_TDS_NONE 0x0000
/** Monitor DAC is selected. */
#define RXBOSA_CTRL_TDS_MON 0x0100
/** Datalo DAC is selected. */
#define RXBOSA_CTRL_TDS_DLO 0x0200
/** Datahi DAC is selected. */
#define RXBOSA_CTRL_TDS_DHI 0x0300
/** Zero DAC is selected. */
#define RXBOSA_CTRL_TDS_ZERO 0x0400
/** CDR Monitor (rx_bosa_cdr_off_monitor) */
#define RXBOSA_CTRL_CDRM 0x0080
/** Default Operation. */
#define RXBOSA_CTRL_CDRM_DEF 0x0000
/** Clock generation outputs (div2, div4) are 0. */
#define RXBOSA_CTRL_CDRM_OFF 0x0080
/** CDR DFE (rx_bosa_cdr_off_dfe) */
#define RXBOSA_CTRL_CDRD 0x0040
/** Default Operation. */
#define RXBOSA_CTRL_CDRD_DEF 0x0000
/** Clock generation outputs (div2, div4) are 0. */
#define RXBOSA_CTRL_CDRD_OFF 0x0040
/** CDR Fall (rx_bosa_cdr_off_fall) */
#define RXBOSA_CTRL_CDRF 0x0020
/** Default Operation. */
#define RXBOSA_CTRL_CDRF_DEF 0x0000
/** Clock generation outputs (div2, div4) are 0. */
#define RXBOSA_CTRL_CDRF_OFF 0x0020
/** CDR Rise (rx_bosa_cdr_off_rise) */
#define RXBOSA_CTRL_CDRR 0x0010
/** Default Operation. */
#define RXBOSA_CTRL_CDRR_DEF 0x0000
/** Clock generation outputs (div2, div4) are 0. */
#define RXBOSA_CTRL_CDRR_OFF 0x0010
/** Input Stage Operating Mode
    Disabling is done via cascode transistors (rx_bosa_sgmii_pd_i). */
#define RXBOSA_CTRL_ISOM 0x0008
/** Powerup */
#define RXBOSA_CTRL_ISOM_PU 0x0000
/** Powerdown */
#define RXBOSA_CTRL_ISOM_PD 0x0008
/** Bypass Leakage Compensation OTA Datahi (rx_bosabyp_leak_ota_datahi) */
#define RXBOSA_CTRL_BLCH 0x0004
/** No bypass */
#define RXBOSA_CTRL_BLCH_NBYP 0x0000
/** Bypass */
#define RXBOSA_CTRL_BLCH_BYP 0x0004
/** Bypass Leakage Compensation OTA Datalo (rx_bosa_byp_leak_ota_datalo) */
#define RXBOSA_CTRL_BLCL 0x0002
/** No bypass */
#define RXBOSA_CTRL_BLCL_NBYP 0x0000
/** Bypass */
#define RXBOSA_CTRL_BLCL_BYP 0x0002
/** Bypass Leakage Compensation OTA Monitor (rx_bosa_byp_leak_ota_monitor) */
#define RXBOSA_CTRL_BLCM 0x0001
/** No bypass */
#define RXBOSA_CTRL_BLCM_NBYP 0x0000
/** Bypass */
#define RXBOSA_CTRL_BLCM_BYP 0x0001

/*! @} */ /* RXBOSA_REGISTER */

#endif /* _drv_optic_reg_fcsi_rxbosa_h */
