/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_fcsi_txomu_h
#define _drv_optic_reg_fcsi_txomu_h

/** \addtogroup TXOMU_REGISTER
   @{
*/

#ifndef __ASSEMBLY__

/* access macros */
#define txomu_r16(reg) reg_r16(&txomu->reg)
#define txomu_w16(val, reg) reg_w16(val, &txomu->reg)
#define txomu_w16_mask(clear, set, reg) reg_w16_mask(clear, set, &txomu->reg)
#define txomu_r16_table(reg, idx) reg_r16_table(txomu->reg, idx)
#define txomu_w16_table(val, reg, idx) reg_w16_table(val, txomu->reg, idx)
#define txomu_w16_table_mask(clear, set, reg, idx) reg_w16_table_mask(clear, set, txomu->reg, idx)
#define txomu_adr_table(reg, idx) adr_table(txomu->reg, idx)


/** TXOMU register structure */
struct fcsi_reg_txomu
{
   /** TXEN Control Register; #8
       This register controls the omu_txen pecl driver. */
   unsigned short txec; /* 0x00 */
   /** TXD Control Register; #9
       This register controls the omu_tx data pecl driver. */
   unsigned short txdc; /* 0x01 */
   /** Control Register; #10 */
   unsigned short ctrl; /* 0x02 */
};

#define FCSI_TXOMU_TXEC   ((volatile unsigned short*)(FCSI_TXOMU_BASE + 0x00))
#define FCSI_TXOMU_TXDC   ((volatile unsigned short*)(FCSI_TXOMU_BASE + 0x01))
#define FCSI_TXOMU_CTRL   ((volatile unsigned short*)(FCSI_TXOMU_BASE + 0x02))

#else /* __ASSEMBLY__ */

#define FCSI_TXOMU_TXEC   (FCSI_TXOMU_BASE + 0x00)
#define FCSI_TXOMU_TXDC   (FCSI_TXOMU_BASE + 0x01)
#define FCSI_TXOMU_CTRL   (FCSI_TXOMU_BASE + 0x02)

#endif /* __ASSEMBLY__ */

/* Fields of "TXEN Control Register; #8" */
/** Sink Current Select
    Selects the amount of current that can be sinked. */
#define TXOMU_TXEC_SCSEL_MASK 0xF000
/** field offset */
#define TXOMU_TXEC_SCSEL_OFFSET 12
/** appr. 2mA + 0mA current sink is enabled. */
#define TXOMU_TXEC_SCSEL_P0MA 0x0000
/** appr. 2mA + 1mA current sink is enabled. */
#define TXOMU_TXEC_SCSEL_P1MA 0x1000
/** appr. 2mA + 2mA current sink is enabled. */
#define TXOMU_TXEC_SCSEL_P2MA 0x2000
/** appr. 2mA + 6mA current sink is enabled. */
#define TXOMU_TXEC_SCSEL_P6MA 0x4000
/** appr. 2mA + 10mA current sink is enabled. */
#define TXOMU_TXEC_SCSEL_P10MA 0x8000
/** all current sinks are enabled (appr. 21mA). */
#define TXOMU_TXEC_SCSEL_ALLS 0xF000
/** Serial Transistor Enable
    Selects additional series transistors from the output to VSS */
#define TXOMU_TXEC_STE_MASK 0x0700
/** field offset */
#define TXOMU_TXEC_STE_OFFSET 8
/** no branch to VSS enabled. */
#define TXOMU_TXEC_STE_NOBR 0x0000
/** smallest series transistor enabled . */
#define TXOMU_TXEC_STE_SMALL 0x0100
/** 2 times smallest series transistor enabled. */
#define TXOMU_TXEC_STE_DOUB 0x0200
/** 4 times smallest series transistor enabled. */
#define TXOMU_TXEC_STE_QUAD 0x0300
/** all series transistors enabled. */
#define TXOMU_TXEC_STE_ALLTR 0x0700
/** Bypass Serial Transistors
    Controls whether the transistors defined in STE are shorted or not. */
#define TXOMU_TXEC_BYPST 0x0080
/** Working. */
#define TXOMU_TXEC_BYPST_WORK 0x0000
/** Shorted, fastest fall time possible and level down to VSS. */
#define TXOMU_TXEC_BYPST_SHRT 0x0080
/** Parallel Current Sink Enable
    Controls the fall time for the pre driver signal. Enable of current sources in parallel to pmos inverter. */
#define TXOMU_TXEC_PCSE_MASK 0x0070
/** field offset */
#define TXOMU_TXEC_PCSE_OFFSET 4
/** No current source is enabled, output goes down to VSS. */
#define TXOMU_TXEC_PCSE_NONE 0x0000
/** A quarter current source is enabled, fall time is slower. */
#define TXOMU_TXEC_PCSE_QURT 0x0010
/** A half current source is enabled, fall time getting slower. */
#define TXOMU_TXEC_PCSE_HALF 0x0020
/** One current source is enabled. */
#define TXOMU_TXEC_PCSE_ONE 0x0030
/** All current sources are enabled. */
#define TXOMU_TXEC_PCSE_ALL 0x0070
/** Bank Enable
    Enables the predriver circuit. */
#define TXOMU_TXEC_BEN_MASK 0x0007
/** field offset */
#define TXOMU_TXEC_BEN_OFFSET 0
/** output is forced to 1. */
#define TXOMU_TXEC_BEN_C1 0x0000
/** output is toggling with the data. */
#define TXOMU_TXEC_BEN_TGL 0x0001

/* Fields of "TXD Control Register; #9" */
/** Sink Current Select
    Selects the amount of current that can be sinked. */
#define TXOMU_TXDC_SCSEL_MASK 0xF000
/** field offset */
#define TXOMU_TXDC_SCSEL_OFFSET 12
/** appr. 2mA + 0mA current sink is enabled. */
#define TXOMU_TXDC_SCSEL_P0MA 0x0000
/** appr. 2mA + 1mA current sink is enabled. */
#define TXOMU_TXDC_SCSEL_P1MA 0x1000
/** appr. 2mA + 2mA current sink is enabled. */
#define TXOMU_TXDC_SCSEL_P2MA 0x2000
/** appr. 2mA + 6mA current sink is enabled. */
#define TXOMU_TXDC_SCSEL_P6MA 0x4000
/** appr. 2mA + 10mA current sink is enabled. */
#define TXOMU_TXDC_SCSEL_P10MA 0x8000
/** all current sinks are enabled (appr. 21mA). */
#define TXOMU_TXDC_SCSEL_ALLS 0xF000
/** Serial Transistor Enable
    Selects additional series transistors from the output to VSS */
#define TXOMU_TXDC_STE_MASK 0x0700
/** field offset */
#define TXOMU_TXDC_STE_OFFSET 8
/** no branch to VSS enabled. */
#define TXOMU_TXDC_STE_NOBR 0x0000
/** smallest series transistor enabled . */
#define TXOMU_TXDC_STE_SMALL 0x0100
/** 2 times smallest series transistor enabled. */
#define TXOMU_TXDC_STE_DOUB 0x0200
/** 4 times smallest series transistor enabled. */
#define TXOMU_TXDC_STE_QUAD 0x0300
/** all series transistors enabled. */
#define TXOMU_TXDC_STE_ALLTR 0x0700
/** Bypass Serial Transistors
    Controls whether the transistors defined in STE are shorted or not. */
#define TXOMU_TXDC_BYPST 0x0080
/** Working. */
#define TXOMU_TXDC_BYPST_WORK 0x0000
/** Shorted, fastest fall time possible and level down to VSS. */
#define TXOMU_TXDC_BYPST_SHRT 0x0080
/** Parallel Current Sink Enable
    Controls the fall time for the pre driver signal. Enable of current sources in parallel to pmos inverter. */
#define TXOMU_TXDC_PCSE_MASK 0x0070
/** field offset */
#define TXOMU_TXDC_PCSE_OFFSET 4
/** No current source is enabled, output goes down to VSS. */
#define TXOMU_TXDC_PCSE_NONE 0x0000
/** A quarter current source is enabled, fall time is slower. */
#define TXOMU_TXDC_PCSE_QURT 0x0010
/** A half current source is enabled, fall time getting slower. */
#define TXOMU_TXDC_PCSE_HALF 0x0020
/** One current source is enabled. */
#define TXOMU_TXDC_PCSE_ONE 0x0030
/** All current sources are enabled. */
#define TXOMU_TXDC_PCSE_ALL 0x0070
/** Bank Enable
    Enables the predriver circuit. */
#define TXOMU_TXDC_BEN_MASK 0x0007
/** field offset */
#define TXOMU_TXDC_BEN_OFFSET 0
/** output is forced to 1. */
#define TXOMU_TXDC_BEN_C1 0x0000
/** output is toggling with the data. */
#define TXOMU_TXDC_BEN_TGL 0x0001

/* Fields of "Control Register; #10" */
/** (tx_omu_ctrl_div8_clk_edge)
    inverts the divide by eight clock of the omu. */
#define TXOMU_CTRL_CINV8 0x0200
/** rising edge used inside the timing shell. */
#define TXOMU_CTRL_CINV8_NINV8 0x0000
/** inverted clk is used inside the timing shell and for pma. */
#define TXOMU_CTRL_CINV8_INV8 0x0200
/** Testbus 2 Enable (tx_omu_testbus2_en)
    When enabled txen_p and txen_n are fed to the testbus. */
#define TXOMU_CTRL_TBEE 0x0100
/** Disable */
#define TXOMU_CTRL_TBEE_DIS 0x0000
/** Enable */
#define TXOMU_CTRL_TBEE_EN 0x0100
/** Testbus Enable TXD (tx_omu_testbus_en)
    When enabled txd_p and txd_n are fed to the testbus. */
#define TXOMU_CTRL_TBED 0x0080
/** Disable */
#define TXOMU_CTRL_TBED_DIS 0x0000
/** Enable */
#define TXOMU_CTRL_TBED_EN 0x0080
/** Serializer Enable (tx_omu_ser_en).
    When disabled all Flip-Flops are in reset. */
#define TXOMU_CTRL_SE 0x0040
/** Disable */
#define TXOMU_CTRL_SE_DIS 0x0000
/** Enable */
#define TXOMU_CTRL_SE_EN 0x0040
/** Serializer Output Enable (tx_omu_ei_en).
    enable or disable serializer output */
#define TXOMU_CTRL_SOEN 0x0020
/** Disable */
#define TXOMU_CTRL_SOEN_DIS 0x0000
/** Enable */
#define TXOMU_CTRL_SOEN_EN 0x0020
/** Serializer Output Value when Disabled (tx_omu_ei_sign_sel)
    Defines the output when serializer output is disabled. */
#define TXOMU_CTRL_SOVD 0x0010
/** Inverts the data write clock (tx_omu_clkdge_sel). */
#define TXOMU_CTRL_CINV 0x0008
/** inverted clk is used. */
#define TXOMU_CTRL_CINV_INV 0x0000
/** non inverted clk is used. */
#define TXOMU_CTRL_CINV_NINV 0x0008
/** Deemphasis Enable (tx_omu_deemph_en)
    If enabled, the lsb bit is delayed by 1 clock cycle with respect to the msb. */
#define TXOMU_CTRL_DEM 0x0004
/** Disable */
#define TXOMU_CTRL_DEM_DIS 0x0000
/** Enable */
#define TXOMU_CTRL_DEM_EN 0x0004
/** Clock Mode (tx_omu_clkmode_en) */
#define TXOMU_CTRL_CLKM 0x0002
/** Normal Operation Mode. */
#define TXOMU_CTRL_CLKM_NOM 0x0000
/** CMOS Enable (tx_omu_sel_cmos_stage_in)
    Enable CMOS inputs. Default is PECL. */
#define TXOMU_CTRL_CMEN 0x0001
/** Disable */
#define TXOMU_CTRL_CMEN_DIS 0x0000
/** Enable */
#define TXOMU_CTRL_CMEN_EN 0x0001

/*! @} */ /* TXOMU_REGISTER */

#endif /* _drv_optic_reg_fcsi_txomu_h */
