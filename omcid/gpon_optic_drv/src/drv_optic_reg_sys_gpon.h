/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_sys_gpon_h
#define _drv_optic_reg_sys_gpon_h

/** \addtogroup SYS_GPON_REGISTER
   @{
*/
/* access macros */
#define sys_gpon_r32(reg) reg_r32(&sys_gpon->reg)
#define sys_gpon_w32(val, reg) reg_w32(val, &sys_gpon->reg)
#define sys_gpon_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &sys_gpon->reg)
#define sys_gpon_r32_table(reg, idx) reg_r32_table(sys_gpon->reg, idx)
#define sys_gpon_w32_table(val, reg, idx) reg_w32_table(val, sys_gpon->reg, idx)
#define sys_gpon_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, sys_gpon->reg, idx)
#define sys_gpon_adr_table(reg, idx) adr_table(sys_gpon->reg, idx)


/** SYS_GPON register structure */
struct optic_reg_sys_gpon
{
   /** Clock Status Register */
   unsigned int clks; /* 0x00000000 */
   /** Clock Enable Register
       Via this register the clocks for the domains can be enabled. */
   unsigned int clken; /* 0x00000004 */
   /** Clock Clear Register
       Via this register the clocks for the domains can be disabled. */
   unsigned int clkclr; /* 0x00000008 */
   /** Reserved */
   unsigned int res_0[5]; /* 0x0000000C */
   /** Activation Status Register */
   unsigned int acts; /* 0x00000020 */
   /** Activation Register
       Via this register the domains can be activated. */
   unsigned int act; /* 0x00000024 */
   /** Deactivation Register
       Via this register the domains can be deactivated. */
   unsigned int deact; /* 0x00000028 */
   /** Reboot Trigger Register
       Via this register the domains can be rebooted (sent through reset). */
   unsigned int rbt; /* 0x0000002C */
   /** Reserved */
   unsigned int res_1[33]; /* 0x00000030 */
   /** Power Down Configuration Register
       Via this register the configuration is done whether in case of deactivation the power supply of the domain shall be removed. */
   unsigned int pdcfg; /* 0x000000B4 */
   /** Reserved */
   unsigned int res_2; /* 0x000000B8 */
   /** Voice Clock Control Register
       Controls the clock outputs NTR and SIF_CLK. The contents of the writeable fields of this register shall not be changed during operation. */
   unsigned int vcc; /* 0x000000BC */
   /** Reserved */
   unsigned int res_3[16]; /* 0x000000C0 */
};


/* Fields of "Clock Status Register" */
/** PMATX Clock Enable
    Shows the clock enable bit for the PMATX domain. This domain contains the TX (upstream) parts of the PMA, the GTCPMAIF block and the tx-clk CDC. However, a reset to this domain resets the RX (downstream) parts of the PMA too, but not the PLL and FCSI related parts of the PMA. Note: This domain must be enabled/activated to access any register in the tx-clk domain (PMA, GTCPMAIF, TOD, ...) as the CDC is part of this domain. */
#define SYS_GPON_CLKS_PMATX 0x00010000
/** Disable */
#define SYS_GPON_CLKS_PMATX_DIS 0x00000000
/** Enable */
#define SYS_GPON_CLKS_PMATX_EN 0x00010000
/** TOD Clock Enable
    Shows the clock enable bit for the TOD domain. This domain contains the Time-of-Day block. */
#define SYS_GPON_CLKS_TOD 0x00001000
/** Disable */
#define SYS_GPON_CLKS_TOD_DIS 0x00000000
/** Enable */
#define SYS_GPON_CLKS_TOD_EN 0x00001000
/** GPEIF Clock Enable
    Shows the clock enable bit for the GPEIF domain. This domain contains all parts of the GTC related to the GPE interface. */
#define SYS_GPON_CLKS_GPEIF 0x00000100
/** Disable */
#define SYS_GPON_CLKS_GPEIF_DIS 0x00000000
/** Enable */
#define SYS_GPON_CLKS_GPEIF_EN 0x00000100
/** GTCRXPDI Clock Enable
    Shows the clock enable bit for the GTCRXPDI domain. This domain contains the PDI registers of the RX (downstream) related parts of the GTC. */
#define SYS_GPON_CLKS_GTCRXPDI 0x00000008
/** Disable */
#define SYS_GPON_CLKS_GTCRXPDI_DIS 0x00000000
/** Enable */
#define SYS_GPON_CLKS_GTCRXPDI_EN 0x00000008
/** GTCRX Clock Enable
    Shows the clock enable bit for the GTCRX domain. This domain contains all RX (downstream) related parts of the GTC. */
#define SYS_GPON_CLKS_GTCRX 0x00000004
/** Disable */
#define SYS_GPON_CLKS_GTCRX_DIS 0x00000000
/** Enable */
#define SYS_GPON_CLKS_GTCRX_EN 0x00000004
/** GTCTXPDI Clock Enable
    Shows the clock enable bit for the GTCTXPDI domain. This domain contains the PDI registers of the TX (upstream) related parts of the GTC. */
#define SYS_GPON_CLKS_GTCTXPDI 0x00000002
/** Disable */
#define SYS_GPON_CLKS_GTCTXPDI_DIS 0x00000000
/** Enable */
#define SYS_GPON_CLKS_GTCTXPDI_EN 0x00000002
/** GTCTX Clock Enable
    Shows the clock enable bit for the GTCTX domain. This domain contains all TX (upstream) related parts of the GTC. */
#define SYS_GPON_CLKS_GTCTX 0x00000001
/** Disable */
#define SYS_GPON_CLKS_GTCTX_DIS 0x00000000
/** Enable */
#define SYS_GPON_CLKS_GTCTX_EN 0x00000001

/* Fields of "Clock Enable Register" */
/** Set Clock Enable PMATX
    Sets the clock enable bit of the PMATX domain. This domain contains the TX (upstream) parts of the PMA, the GTCPMAIF block and the tx-clk CDC. However, a reset to this domain resets the RX (downstream) parts of the PMA too, but not the PLL and FCSI related parts of the PMA. Note: This domain must be enabled/activated to access any register in the tx-clk domain (PMA, GTCPMAIF, TOD, ...) as the CDC is part of this domain. */
#define SYS_GPON_CLKEN_PMATX 0x00010000
/** No-Operation */
#define SYS_GPON_CLKEN_PMATX_NOP 0x00000000
/** Set */
#define SYS_GPON_CLKEN_PMATX_SET 0x00010000
/** Set Clock Enable TOD
    Sets the clock enable bit of the TOD domain. This domain contains the Time-of-Day block. */
#define SYS_GPON_CLKEN_TOD 0x00001000
/** No-Operation */
#define SYS_GPON_CLKEN_TOD_NOP 0x00000000
/** Set */
#define SYS_GPON_CLKEN_TOD_SET 0x00001000
/** Set Clock Enable GPEIF
    Sets the clock enable bit of the GPEIF domain. This domain contains all parts of the GTC related to the GPE interface. */
#define SYS_GPON_CLKEN_GPEIF 0x00000100
/** No-Operation */
#define SYS_GPON_CLKEN_GPEIF_NOP 0x00000000
/** Set */
#define SYS_GPON_CLKEN_GPEIF_SET 0x00000100
/** Set Clock Enable GTCRXPDI
    Sets the clock enable bit of the GTCRXPDI domain. This domain contains the PDI registers of the RX (downstream) related parts of the GTC. */
#define SYS_GPON_CLKEN_GTCRXPDI 0x00000008
/** No-Operation */
#define SYS_GPON_CLKEN_GTCRXPDI_NOP 0x00000000
/** Set */
#define SYS_GPON_CLKEN_GTCRXPDI_SET 0x00000008
/** Set Clock Enable GTCRX
    Sets the clock enable bit of the GTCRX domain. This domain contains all RX (downstream) related parts of the GTC. */
#define SYS_GPON_CLKEN_GTCRX 0x00000004
/** No-Operation */
#define SYS_GPON_CLKEN_GTCRX_NOP 0x00000000
/** Set */
#define SYS_GPON_CLKEN_GTCRX_SET 0x00000004
/** Set Clock Enable GTCTXPDI
    Sets the clock enable bit of the GTCTXPDI domain. This domain contains the PDI registers of the TX (upstream) related parts of the GTC. */
#define SYS_GPON_CLKEN_GTCTXPDI 0x00000002
/** No-Operation */
#define SYS_GPON_CLKEN_GTCTXPDI_NOP 0x00000000
/** Set */
#define SYS_GPON_CLKEN_GTCTXPDI_SET 0x00000002
/** Set Clock Enable GTCTX
    Sets the clock enable bit of the GTCTX domain. This domain contains all TX (upstream) related parts of the GTC. */
#define SYS_GPON_CLKEN_GTCTX 0x00000001
/** No-Operation */
#define SYS_GPON_CLKEN_GTCTX_NOP 0x00000000
/** Set */
#define SYS_GPON_CLKEN_GTCTX_SET 0x00000001

/* Fields of "Clock Clear Register" */
/** Clear Clock Enable PMATX
    Clears the clock enable bit of the PMATX domain. This domain contains the TX (upstream) parts of the PMA, the GTCPMAIF block and the tx-clk CDC. However, a reset to this domain resets the RX (downstream) parts of the PMA too, but not the PLL and FCSI related parts of the PMA. Note: This domain must be enabled/activated to access any register in the tx-clk domain (PMA, GTCPMAIF, TOD, ...) as the CDC is part of this domain. */
#define SYS_GPON_CLKCLR_PMATX 0x00010000
/** No-Operation */
#define SYS_GPON_CLKCLR_PMATX_NOP 0x00000000
/** Clear */
#define SYS_GPON_CLKCLR_PMATX_CLR 0x00010000
/** Clear Clock Enable TOD
    Clears the clock enable bit of the TOD domain. This domain contains the Time-of-Day block. */
#define SYS_GPON_CLKCLR_TOD 0x00001000
/** No-Operation */
#define SYS_GPON_CLKCLR_TOD_NOP 0x00000000
/** Clear */
#define SYS_GPON_CLKCLR_TOD_CLR 0x00001000
/** Clear Clock Enable GPEIF
    Clears the clock enable bit of the GPEIF domain. This domain contains all parts of the GTC related to the GPE interface. */
#define SYS_GPON_CLKCLR_GPEIF 0x00000100
/** No-Operation */
#define SYS_GPON_CLKCLR_GPEIF_NOP 0x00000000
/** Clear */
#define SYS_GPON_CLKCLR_GPEIF_CLR 0x00000100
/** Clear Clock Enable GTCRXPDI
    Clears the clock enable bit of the GTCRXPDI domain. This domain contains the PDI registers of the RX (downstream) related parts of the GTC. */
#define SYS_GPON_CLKCLR_GTCRXPDI 0x00000008
/** No-Operation */
#define SYS_GPON_CLKCLR_GTCRXPDI_NOP 0x00000000
/** Clear */
#define SYS_GPON_CLKCLR_GTCRXPDI_CLR 0x00000008
/** Clear Clock Enable GTCRX
    Clears the clock enable bit of the GTCRX domain. This domain contains all RX (downstream) related parts of the GTC. */
#define SYS_GPON_CLKCLR_GTCRX 0x00000004
/** No-Operation */
#define SYS_GPON_CLKCLR_GTCRX_NOP 0x00000000
/** Clear */
#define SYS_GPON_CLKCLR_GTCRX_CLR 0x00000004
/** Clear Clock Enable GTCTXPDI
    Clears the clock enable bit of the GTCTXPDI domain. This domain contains the PDI registers of the TX (upstream) related parts of the GTC. */
#define SYS_GPON_CLKCLR_GTCTXPDI 0x00000002
/** No-Operation */
#define SYS_GPON_CLKCLR_GTCTXPDI_NOP 0x00000000
/** Clear */
#define SYS_GPON_CLKCLR_GTCTXPDI_CLR 0x00000002
/** Clear Clock Enable GTCTX
    Clears the clock enable bit of the GTCTX domain. This domain contains all TX (upstream) related parts of the GTC. */
#define SYS_GPON_CLKCLR_GTCTX 0x00000001
/** No-Operation */
#define SYS_GPON_CLKCLR_GTCTX_NOP 0x00000000
/** Clear */
#define SYS_GPON_CLKCLR_GTCTX_CLR 0x00000001

/* Fields of "Activation Status Register" */
/** PMATX Status
    Shows the activation status of the PMATX domain. This domain contains the TX (upstream) parts of the PMA, the GTCPMAIF block and the tx-clk CDC. However, a reset to this domain resets the RX (downstream) parts of the PMA too, but not the PLL and FCSI related parts of the PMA. Note: This domain must be enabled/activated to access any register in the tx-clk domain (PMA, GTCPMAIF, TOD, ...) as the CDC is part of this domain. */
#define SYS_GPON_ACTS_PMATX 0x00010000
/** The block is inactive. */
#define SYS_GPON_ACTS_PMATX_INACT 0x00000000
/** The block is active. */
#define SYS_GPON_ACTS_PMATX_ACT 0x00010000
/** TOD Status
    Shows the activation status of the TOD domain. This domain contains the Time-of-Day block. */
#define SYS_GPON_ACTS_TOD 0x00001000
/** The block is inactive. */
#define SYS_GPON_ACTS_TOD_INACT 0x00000000
/** The block is active. */
#define SYS_GPON_ACTS_TOD_ACT 0x00001000
/** GPEIF Status
    Shows the activation status of the GPEIF domain. This domain contains all parts of the GTC related to the GPE interface. */
#define SYS_GPON_ACTS_GPEIF 0x00000100
/** The block is inactive. */
#define SYS_GPON_ACTS_GPEIF_INACT 0x00000000
/** The block is active. */
#define SYS_GPON_ACTS_GPEIF_ACT 0x00000100
/** GTCRXPDI Status
    Shows the activation status of the GTCRXPDI domain. This domain contains the PDI registers of the RX (downstream) related parts of the GTC. */
#define SYS_GPON_ACTS_GTCRXPDI 0x00000008
/** The block is inactive. */
#define SYS_GPON_ACTS_GTCRXPDI_INACT 0x00000000
/** The block is active. */
#define SYS_GPON_ACTS_GTCRXPDI_ACT 0x00000008
/** GTCRX Status
    Shows the activation status of the GTCRX domain. This domain contains all RX (downstream) related parts of the GTC. */
#define SYS_GPON_ACTS_GTCRX 0x00000004
/** The block is inactive. */
#define SYS_GPON_ACTS_GTCRX_INACT 0x00000000
/** The block is active. */
#define SYS_GPON_ACTS_GTCRX_ACT 0x00000004
/** GTCTXPDI Status
    Shows the activation status of the GTCTXPDI domain. This domain contains the PDI registers of the TX (upstream) related parts of the GTC. */
#define SYS_GPON_ACTS_GTCTXPDI 0x00000002
/** The block is inactive. */
#define SYS_GPON_ACTS_GTCTXPDI_INACT 0x00000000
/** The block is active. */
#define SYS_GPON_ACTS_GTCTXPDI_ACT 0x00000002
/** GTCTX Status
    Shows the activation status of the GTCTX domain. This domain contains all TX (upstream) related parts of the GTC. */
#define SYS_GPON_ACTS_GTCTX 0x00000001
/** The block is inactive. */
#define SYS_GPON_ACTS_GTCTX_INACT 0x00000000
/** The block is active. */
#define SYS_GPON_ACTS_GTCTX_ACT 0x00000001

/* Fields of "Activation Register" */
/** Activate PMATX
    Sets the activation flag of the PMATX domain. This domain contains the TX (upstream) parts of the PMA, the GTCPMAIF block and the tx-clk CDC. However, a reset to this domain resets the RX (downstream) parts of the PMA too, but not the PLL and FCSI related parts of the PMA. Note: This domain must be enabled/activated to access any register in the tx-clk domain (PMA, GTCPMAIF, TOD, ...) as the CDC is part of this domain. */
#define SYS_GPON_ACT_PMATX 0x00010000
/** No-Operation */
#define SYS_GPON_ACT_PMATX_NOP 0x00000000
/** Set */
#define SYS_GPON_ACT_PMATX_SET 0x00010000
/** Activate TOD
    Sets the activation flag of the TOD domain. This domain contains the Time-of-Day block. */
#define SYS_GPON_ACT_TOD 0x00001000
/** No-Operation */
#define SYS_GPON_ACT_TOD_NOP 0x00000000
/** Set */
#define SYS_GPON_ACT_TOD_SET 0x00001000
/** Activate GPEIF
    Sets the activation flag of the GPEIF domain. This domain contains all parts of the GTC related to the GPE interface. */
#define SYS_GPON_ACT_GPEIF 0x00000100
/** No-Operation */
#define SYS_GPON_ACT_GPEIF_NOP 0x00000000
/** Set */
#define SYS_GPON_ACT_GPEIF_SET 0x00000100
/** Activate GTCRXPDI
    Sets the activation flag of the GTCRXPDI domain. This domain contains the PDI registers of the RX (downstream) related parts of the GTC. */
#define SYS_GPON_ACT_GTCRXPDI 0x00000008
/** No-Operation */
#define SYS_GPON_ACT_GTCRXPDI_NOP 0x00000000
/** Set */
#define SYS_GPON_ACT_GTCRXPDI_SET 0x00000008
/** Activate GTCRX
    Sets the activation flag of the GTCRX domain. This domain contains all RX (downstream) related parts of the GTC. */
#define SYS_GPON_ACT_GTCRX 0x00000004
/** No-Operation */
#define SYS_GPON_ACT_GTCRX_NOP 0x00000000
/** Set */
#define SYS_GPON_ACT_GTCRX_SET 0x00000004
/** Activate GTCTXPDI
    Sets the activation flag of the GTCTXPDI domain. This domain contains the PDI registers of the TX (upstream) related parts of the GTC. */
#define SYS_GPON_ACT_GTCTXPDI 0x00000002
/** No-Operation */
#define SYS_GPON_ACT_GTCTXPDI_NOP 0x00000000
/** Set */
#define SYS_GPON_ACT_GTCTXPDI_SET 0x00000002
/** Activate GTCTX
    Sets the activation flag of the GTCTX domain. This domain contains all TX (upstream) related parts of the GTC. */
#define SYS_GPON_ACT_GTCTX 0x00000001
/** No-Operation */
#define SYS_GPON_ACT_GTCTX_NOP 0x00000000
/** Set */
#define SYS_GPON_ACT_GTCTX_SET 0x00000001

/* Fields of "Deactivation Register" */
/** Deactivate PMATX
    Clears the activation flag of the PMATX domain. This domain contains the TX (upstream) parts of the PMA, the GTCPMAIF block and the tx-clk CDC. However, a reset to this domain resets the RX (downstream) parts of the PMA too, but not the PLL and FCSI related parts of the PMA. Note: This domain must be enabled/activated to access any register in the tx-clk domain (PMA, GTCPMAIF, TOD, ...) as the CDC is part of this domain. */
#define SYS_GPON_DEACT_PMATX 0x00010000
/** No-Operation */
#define SYS_GPON_DEACT_PMATX_NOP 0x00000000
/** Clear */
#define SYS_GPON_DEACT_PMATX_CLR 0x00010000
/** Deactivate TOD
    Clears the activation flag of the TOD domain. This domain contains the Time-of-Day block. */
#define SYS_GPON_DEACT_TOD 0x00001000
/** No-Operation */
#define SYS_GPON_DEACT_TOD_NOP 0x00000000
/** Clear */
#define SYS_GPON_DEACT_TOD_CLR 0x00001000
/** Deactivate GPEIF
    Clears the activation flag of the GPEIF domain. This domain contains all parts of the GTC related to the GPE interface. */
#define SYS_GPON_DEACT_GPEIF 0x00000100
/** No-Operation */
#define SYS_GPON_DEACT_GPEIF_NOP 0x00000000
/** Clear */
#define SYS_GPON_DEACT_GPEIF_CLR 0x00000100
/** Deactivate GTCRXPDI
    Clears the activation flag of the GTCRXPDI domain. This domain contains the PDI registers of the RX (downstream) related parts of the GTC. */
#define SYS_GPON_DEACT_GTCRXPDI 0x00000008
/** No-Operation */
#define SYS_GPON_DEACT_GTCRXPDI_NOP 0x00000000
/** Clear */
#define SYS_GPON_DEACT_GTCRXPDI_CLR 0x00000008
/** Deactivate GTCRX
    Clears the activation flag of the GTCRX domain. This domain contains all RX (downstream) related parts of the GTC. */
#define SYS_GPON_DEACT_GTCRX 0x00000004
/** No-Operation */
#define SYS_GPON_DEACT_GTCRX_NOP 0x00000000
/** Clear */
#define SYS_GPON_DEACT_GTCRX_CLR 0x00000004
/** Deactivate GTCTXPDI
    Clears the activation flag of the GTCTXPDI domain. This domain contains the PDI registers of the TX (upstream) related parts of the GTC. */
#define SYS_GPON_DEACT_GTCTXPDI 0x00000002
/** No-Operation */
#define SYS_GPON_DEACT_GTCTXPDI_NOP 0x00000000
/** Clear */
#define SYS_GPON_DEACT_GTCTXPDI_CLR 0x00000002
/** Deactivate GTCTX
    Clears the activation flag of the GTCTX domain. This domain contains all TX (upstream) related parts of the GTC. */
#define SYS_GPON_DEACT_GTCTX 0x00000001
/** No-Operation */
#define SYS_GPON_DEACT_GTCTX_NOP 0x00000000
/** Clear */
#define SYS_GPON_DEACT_GTCTX_CLR 0x00000001

/* Fields of "Reboot Trigger Register" */
/** Reboot PMATX
    Triggers a reboot of the PMATX domain. This domain contains the TX (upstream) parts of the PMA, the GTCPMAIF block and the tx-clk CDC. However, a reset to this domain resets the RX (downstream) parts of the PMA too, but not the PLL and FCSI related parts of the PMA. Note: This domain must be enabled/activated to access any register in the tx-clk domain (PMA, GTCPMAIF, TOD, ...) as the CDC is part of this domain. */
#define SYS_GPON_RBT_PMATX 0x00010000
/** No-Operation */
#define SYS_GPON_RBT_PMATX_NOP 0x00000000
/** Trigger */
#define SYS_GPON_RBT_PMATX_TRIG 0x00010000
/** Reboot TOD
    Triggers a reboot of the TOD domain. This domain contains the Time-of-Day block. */
#define SYS_GPON_RBT_TOD 0x00001000
/** No-Operation */
#define SYS_GPON_RBT_TOD_NOP 0x00000000
/** Trigger */
#define SYS_GPON_RBT_TOD_TRIG 0x00001000
/** Reboot GPEIF
    Triggers a reboot of the GPEIF domain. This domain contains all parts of the GTC related to the GPE interface. */
#define SYS_GPON_RBT_GPEIF 0x00000100
/** No-Operation */
#define SYS_GPON_RBT_GPEIF_NOP 0x00000000
/** Trigger */
#define SYS_GPON_RBT_GPEIF_TRIG 0x00000100
/** Reboot GTCRXPDI
    Triggers a reboot of the GTCRXPDI domain. This domain contains the PDI registers of the RX (downstream) related parts of the GTC. */
#define SYS_GPON_RBT_GTCRXPDI 0x00000008
/** No-Operation */
#define SYS_GPON_RBT_GTCRXPDI_NOP 0x00000000
/** Trigger */
#define SYS_GPON_RBT_GTCRXPDI_TRIG 0x00000008
/** Reboot GTCRX
    Triggers a reboot of the GTCRX domain. This domain contains all RX (downstream) related parts of the GTC. */
#define SYS_GPON_RBT_GTCRX 0x00000004
/** No-Operation */
#define SYS_GPON_RBT_GTCRX_NOP 0x00000000
/** Trigger */
#define SYS_GPON_RBT_GTCRX_TRIG 0x00000004
/** Reboot GTCTXPDI
    Triggers a reboot of the GTCTXPDI domain. This domain contains the PDI registers of the TX (upstream) related parts of the GTC. */
#define SYS_GPON_RBT_GTCTXPDI 0x00000002
/** No-Operation */
#define SYS_GPON_RBT_GTCTXPDI_NOP 0x00000000
/** Trigger */
#define SYS_GPON_RBT_GTCTXPDI_TRIG 0x00000002
/** Reboot GTCTX
    Triggers a reboot of the GTCTX domain. This domain contains all TX (upstream) related parts of the GTC. */
#define SYS_GPON_RBT_GTCTX 0x00000001
/** No-Operation */
#define SYS_GPON_RBT_GTCTX_NOP 0x00000000
/** Trigger */
#define SYS_GPON_RBT_GTCTX_TRIG 0x00000001

/* Fields of "Power Down Configuration Register" */
/** Enable Power Down PMATX
    Ignore this bit as power-gating is not supported for this chip. */
#define SYS_GPON_PDCFG_PMATX 0x00010000
/** Disable */
#define SYS_GPON_PDCFG_PMATX_DIS 0x00000000
/** Enable */
#define SYS_GPON_PDCFG_PMATX_EN 0x00010000
/** Enable Power Down TOD
    Ignore this bit as power-gating is not supported for this chip. */
#define SYS_GPON_PDCFG_TOD 0x00001000
/** Disable */
#define SYS_GPON_PDCFG_TOD_DIS 0x00000000
/** Enable */
#define SYS_GPON_PDCFG_TOD_EN 0x00001000
/** Enable Power Down GPEIF
    Ignore this bit as power-gating is not supported for this chip. */
#define SYS_GPON_PDCFG_GPEIF 0x00000100
/** Disable */
#define SYS_GPON_PDCFG_GPEIF_DIS 0x00000000
/** Enable */
#define SYS_GPON_PDCFG_GPEIF_EN 0x00000100
/** Enable Power Down GTCRXPDI
    Ignore this bit as power-gating is not supported for this chip. */
#define SYS_GPON_PDCFG_GTCRXPDI 0x00000008
/** Disable */
#define SYS_GPON_PDCFG_GTCRXPDI_DIS 0x00000000
/** Enable */
#define SYS_GPON_PDCFG_GTCRXPDI_EN 0x00000008
/** Enable Power Down GTCRX
    Ignore this bit as power-gating is not supported for this chip. */
#define SYS_GPON_PDCFG_GTCRX 0x00000004
/** Disable */
#define SYS_GPON_PDCFG_GTCRX_DIS 0x00000000
/** Enable */
#define SYS_GPON_PDCFG_GTCRX_EN 0x00000004
/** Enable Power Down GTCTXPDI
    Ignore this bit as power-gating is not supported for this chip. */
#define SYS_GPON_PDCFG_GTCTXPDI 0x00000002
/** Disable */
#define SYS_GPON_PDCFG_GTCTXPDI_DIS 0x00000000
/** Enable */
#define SYS_GPON_PDCFG_GTCTXPDI_EN 0x00000002
/** Enable Power Down GTCTX
    Ignore this bit as power-gating is not supported for this chip. */
#define SYS_GPON_PDCFG_GTCTX 0x00000001
/** Disable */
#define SYS_GPON_PDCFG_GTCTX_DIS 0x00000000
/** Enable */
#define SYS_GPON_PDCFG_GTCTX_EN 0x00000001

/* Fields of "Voice Clock Control Register" */
/** SmartSlic Interface Clock Enable
    En-/Disables the SmartSLIC interface clock to realise the SIF power-down feature. This bit is only useful in case of internally generated SIF clock. */
#define SYS_GPON_VCC_SIFCEN 0x00020000
/** Disable */
#define SYS_GPON_VCC_SIFCEN_DIS 0x00000000
/** Enable */
#define SYS_GPON_VCC_SIFCEN_EN 0x00020000
/** SmartSlic Interface Clock Select
    Selects the source for the SIF Clock. */
#define SYS_GPON_VCC_SIFCS 0x00010000
/** Use the clock generated by the SmartSlic on the SmartSlic Interface. */
#define SYS_GPON_VCC_SIFCS_EXT 0x00000000
/** Use the internally generated clock on the SmartSlic Interface. */
#define SYS_GPON_VCC_SIFCS_INT 0x00010000
/** NTR8K Output Enable
    Enables the output driver of the NTR8K pin. */
#define SYS_GPON_VCC_NTR8KEN 0x00000100
/** Disable */
#define SYS_GPON_VCC_NTR8KEN_DIS 0x00000000
/** Enable */
#define SYS_GPON_VCC_NTR8KEN_EN 0x00000100
/** NTR Output Enable
    Enables the output driver of the NTR pin. */
#define SYS_GPON_VCC_NTREN 0x00000080
/** Disable */
#define SYS_GPON_VCC_NTREN_DIS 0x00000000
/** Enable */
#define SYS_GPON_VCC_NTREN_EN 0x00000080
/** NTR Frequency Select
    Selects the frequency of the NTR Pad. */
#define SYS_GPON_VCC_NTRFS_MASK 0x00000007
/** field offset */
#define SYS_GPON_VCC_NTRFS_OFFSET 0
/** 8 kHz. */
#define SYS_GPON_VCC_NTRFS_8k 0x00000000
/** 512 kHz. */
#define SYS_GPON_VCC_NTRFS_512k 0x00000001
/** 1024 kHz. */
#define SYS_GPON_VCC_NTRFS_1024k 0x00000002
/** 1536 kHz. */
#define SYS_GPON_VCC_NTRFS_1536k 0x00000003
/** 2048 kHz. */
#define SYS_GPON_VCC_NTRFS_2048k 0x00000004
/** 4096 kHz. */
#define SYS_GPON_VCC_NTRFS_4096k 0x00000005
/** 8192 kHz. */
#define SYS_GPON_VCC_NTRFS_8192k 0x00000006

/*! @} */ /* SYS_GPON_REGISTER */

#endif /* _drv_optic_reg_sys_gpon_h */
