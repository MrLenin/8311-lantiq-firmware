/******************************************************************************

                               Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_reg_tbm_h
#define _drv_onu_reg_tbm_h

/** \addtogroup TBM_REGISTER
   @{
*/
/* access macros */
#define tbm_r32(reg) reg_r32(&tbm->reg)
#define tbm_w32(val, reg) reg_w32(val, &tbm->reg)
#define tbm_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &tbm->reg)
#define tbm_r32_table(reg, idx) reg_r32_table(tbm->reg, idx)
#define tbm_w32_table(val, reg, idx) reg_w32_table(val, tbm->reg, idx)
#define tbm_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, tbm->reg, idx)
#define tbm_adr_table(reg, idx) adr_table(tbm->reg, idx)


/** TBM register structure */
struct onu_reg_tbm
{
   /** Control Register
       This register provides the global TBM controls. */
   unsigned int ctrl; /* 0x00000000 */
   /** Reserved */
   unsigned int res_0[15]; /* 0x00000004 */
   /** Token Bucket Meter Table Register 0
       This register provides (indirect) access to the TBMT. */
   unsigned int tbmtr0; /* 0x00000040 */
   /** Token Bucket Meter Table Register 1
       This register provides (indirect) access to the TBMT. */
   unsigned int tbmtr1; /* 0x00000044 */
   /** Token Bucket Meter Table Register 2
       This register provides (indirect) access to the TBMT. */
   unsigned int tbmtr2; /* 0x00000048 */
   /** Token Bucket meter Table Register 3
       This register provides (indirect) access to the TBMT. */
   unsigned int tbmtr3; /* 0x0000004C */
   /** Token Bucket Meter Table Control Register
       This register provides the controls to the indirect access to TBMT(R0:R3) */
   unsigned int tbmtc; /* 0x00000050 */
   /** Command Handling Config Register
       This register provides configuration for command handling. */
   unsigned int chconf; /* 0x00000054 */
   /** Token Bucket Config Register
       This register provides configuration for token bucket handling. */
   unsigned int tbconf; /* 0x00000058 */
   /** Reserved */
   unsigned int res_1[9]; /* 0x0000005C */
   /** IRN Capture Register
       This register shows the currently active interrupt events masked with the corresponding enable bits of the IRNEN register. The interrupts can be acknowledged by a write operation. */
   unsigned int irncr; /* 0x00000080 */
   /** IRN Interrupt Control Register
       A write operation directly effects the interrupts. This can be used to trigger events under software control for testing purposes. A read operation returns the unmasked interrupt events. */
   unsigned int irnicr; /* 0x00000084 */
   /** IRN Interrupt Enable Register
       This register contains the enable (or mask) bits for the interrupts. Disabled interrupts are not visible in the IRNCR register and are not signalled via the interrupt line towards the controller. */
   unsigned int irnen; /* 0x00000088 */
   /** Reserved */
   unsigned int res_2[29]; /* 0x0000008C */
};


/* Fields of "Control Register" */
/** Activate Core State Machine
    This bit enables the TBM state machine. */
#define TBM_CTRL_ACT 0x80000000
/* Disable
#define TBM_CTRL_ACT_DIS 0x00000000 */
/** Enable */
#define TBM_CTRL_ACT_EN 0x80000000
/** Freeze Core State Machine
    This bit freezes the TBM state machine. */
#define TBM_CTRL_FRZ 0x40000000
/* Disable
#define TBM_CTRL_FRZ_DIS 0x00000000 */
/** Enable */
#define TBM_CTRL_FRZ_EN 0x40000000
/** TIMESTAMP PRESCALER
    This field defines the exponent of a clock divider used before the timestamp counter is incremented */
#define TBM_CTRL_TSPRESCALE_MASK 0x07000000
/** field offset */
#define TBM_CTRL_TSPRESCALE_OFFSET 24
/** DEACTIVATION OF TIMEOUT SORT INTERRUPT
    This bit deactivates the Timeout Interrupt in the sorter. */
#define TBM_CTRL_A1X_TIMEOUTDEACT 0x00100000
/** RAM INITIALIZATION DONE
    This bit gives the status of the RAM initialization for the sort RAM. */
#define TBM_CTRL_A1X_INITDONE 0x00010000
/** START RAM INITIALIZATION
    This bit starts the RAM initialzation for the sort RAM. */
#define TBM_CTRL_A1X_INITSTART 0x00001000
/* Disable
#define TBM_CTRL_A1X_INITSTART_DIS 0x00000000 */
/** Enable */
#define TBM_CTRL_A1X_INITSTART_EN 0x00001000
/** Crawler EPOC
    The EPOC is incremented with each CPERIOD expiration and revolves across the values 0, 1, 2, 3 */
#define TBM_CTRL_EPOC_MASK 0x00000300
/** field offset */
#define TBM_CTRL_EPOC_OFFSET 8
/** Crawler Period Exponent
    Specifies the 4 MSB of a 20 bit exponent of the crawler period expressed in clocks */
#define TBM_CTRL_CPERIOD_MASK 0x0000000F
/** field offset */
#define TBM_CTRL_CPERIOD_OFFSET 0

/* Fields of "Token Bucket Meter Table Register 0" */
/** Token Bucket Enable
    This bit indicates if the TB is enabled. Configured by SW. Value can be changed on an active meter with SELCFG = 1 in TBMTC. */
#define TBM_TBMTR0_TBE 0x80000000
/* Disable
#define TBM_TBMTR0_TBE_DIS 0x00000000 */
/** Enable */
#define TBM_TBMTR0_TBE_EN 0x80000000
/** Timestamp Selector
    This bit indicates if the Timestamp shall be taken from the Meter Request (default = 0) or from the internal timer (=1). Configured by SW. Value can be changed on an active meter with SELCFG = 1 in TBMTC. */
#define TBM_TBMTR0_TSS 0x40000000
/* Disable
#define TBM_TBMTR0_TSS_DIS 0x00000000 */
/** Enable */
#define TBM_TBMTR0_TSS_EN 0x40000000
/** Coupling Flag
    This bit selects an additional mode in the calculation of the TBC for MEF 10.2 compliance */
#define TBM_TBMTR0_CF 0x04000000
/* Disable
#define TBM_TBMTR0_CF_DIS 0x00000000 */
/** Enable */
#define TBM_TBMTR0_CF_EN 0x04000000
/** Token Bucket Meter Mode
    Selection of the Meter Mode and Color Awareness. Configured by SW. Value can be changed on an active meter with SELCFG = 1 in TBMTC. */
#define TBM_TBMTR0_MOD_MASK 0x03000000
/** field offset */
#define TBM_TBMTR0_MOD_OFFSET 24
/** RFC 4115 color blind */
#define TBM_TBMTR0_MOD_MOD_0 0x00000000
/** RFC 4115 color aware */
#define TBM_TBMTR0_MOD_MOD_1 0x01000000
/** RFC 2698 color blind */
#define TBM_TBMTR0_MOD_MOD_2 0x02000000
/** RFC 2698 color aware */
#define TBM_TBMTR0_MOD_MOD_3 0x03000000
/** Meter Rate Mantissa
    Mantissa of the desired Meter Rate. Dependent on core clock. Configured by SW. Value can be changed on an active meter with SELCFG = 1 in TBMTC. SW must calculate the internal representation from the desired PIR and CIR according to formula given in text */
#define TBM_TBMTR0_A1X_MRM_MASK 0x0000FFF0
#define TBM_TBMTR0_A2X_MRM_MASK 0x000FFF00
/** field offset */
#define TBM_TBMTR0_A1X_MRM_OFFSET 4
#define TBM_TBMTR0_A2X_MRM_OFFSET 8
/** Meter Rate Exponent
    Exponent of the desired Meter Rate. Dependent on core clock. Configured by SW. Value can be changed on an active meter with SELCFG = 1 in TBMTC. SW must calculate the internal representation from the desired PIR and CIR according to formula given in text */
#define TBM_TBMTR0_A1X_MRE_MASK 0x0000000F
#define TBM_TBMTR0_A2X_MRE_MASK 0x0000001F
/** field offset */
#define TBM_TBMTR0_MRE_OFFSET 0

/* Fields of "Token Bucket Meter Table Register 1" */
/** Maximum Bucket Size
    This field gives the Maximum Size of the Token Bucket in Bytes. Configured by SW. Value can be changed on an active meter with SELCFG = 1 in TBMTC. */
#define TBM_TBMTR1_A1X_MBS_MASK 0x00FFFFFF
#define TBM_TBMTR1_A2X_MBS_MASK 0x00FFFFF0
/** field offset */
#define TBM_TBMTR1_A1X_MBS_OFFSET 0
#define TBM_TBMTR1_A2X_MBS_OFFSET 4

/* Fields of "Token Bucket Meter Table Register 2" */
/** Token Bucket Counter
    This field gives the current Token Bucket Counter value in fractional Bytes (4 fractional bits). Status variable, default 0. Read only for SW when ACT = 1 and TBE = 1 */
#define TBM_TBMTR2_TBC_MASK 0x00FFFFFF
/** field offset */
#define TBM_TBMTR2_TBC_OFFSET 0

/* Fields of "Token Bucket meter Table Register 3" */
/** Valid Time Stamp
    Indicates if LTS is valid. Status variable, default 0. Read only for SW when ACT = 1 and TBE = 1 */
#define TBM_TBMTR3_VTS 0x80000000
/** Epoc Time Stamp
    Indicates crawler epoc when LTS was last updated. Status variable, default 0. Read only for SW when ACT = 1 and TBE = 1 */
#define TBM_TBMTR3_ETS_MASK 0x03000000
/** field offset */
#define TBM_TBMTR3_ETS_OFFSET 24
/** Last Time Stamp
    Holds the time stamp of the last meter request. Status variable, default 0. Read only for SW when ACT = 1 and TBE = 1 */
#define TBM_TBMTR3_LTS_MASK 0x00FFFFFF
/** field offset */
#define TBM_TBMTR3_LTS_OFFSET 0

/* Fields of "Token Bucket Meter Table Control Register" */
/** Read Write Status
    This bit defines the indirect access to all TBMT fields, including Status variables as read or write */
#define TBM_TBMTC_SEL 0x00020000
/* Only configuration fields of TBMT registers (i.e. TBMTR0 and TBMTR1) are written, status fields (TBMTR2 and TBMTR3) remain unchanged
#define TBM_TBMTC_SEL_SELCFG 0x00000000 */
/** All fields of TBMT registers are written */
#define TBM_TBMTC_SEL_SELALL 0x00020000
/** Read/Write Configuration
    This bit defines the indirect access to configuration fields of TBMT only, as read or write */
#define TBM_TBMTC_RW 0x00010000
/* Read access to TBMT registers
#define TBM_TBMTC_RW_R 0x00000000 */
/** Write access to TBMT registers */
#define TBM_TBMTC_RW_W 0x00010000
/** Token Bucket Identifier
    This field holds the TB identifier */
#define TBM_TBMTC_TBID_MASK 0x000001FF
/** field offset */
#define TBM_TBMTC_TBID_OFFSET 0

/* Fields of "Command Handling Config Register" (A2X) */
/** Commands Hold On Delay
    Determines an additional internal delay in number of clock cycles to hold on master from sending new commands (delay for avail signal).Do not use except in case of communication problems! */
#define TBM_CHCONF_A2X_CMDHDLY_MASK 0x000000FF
/** field offset */
#define TBM_CHCON_A2XF_CMDHDLY_OFFSET 0

/* Fields of "Token Bucket Config Register"(A2X) */
/** Maximum TBID
    This field specifies the Maximum Token Bucket ID that can be used for metering. Initially 511. */
#define TBM_TBCONF_A2X_MAXTB_MASK 0x000001FF
/** field offset */
#define TBM_TBCONF_A2X_MAXTB_OFFSET 0

/* Fields of "IRN Capture Register" */
/** TBM calendar not free
    This bit is set if calendar entry is not free) This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define TBM_IRNCR_A1X_CALNOTFREE 0x00000800
/* Nothing
#define TBM_IRNCR_A1X_CALNOTFREE_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define TBM_IRNCR_A1X_CALNOTFREE_INTACK 0x00000800
/** Read: Interrupt occurred. */
#define TBM_IRNCR_A1X_CALNOTFREE_INTOCC 0x00000800
/** Calendar8 timeout
    This bit is set if calendar 8 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT8 0x00000400
/* Nothing
#define TBM_IRNCR_A1X_TIMEOUT8_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT8_INTACK 0x00000400
/** Read: Interrupt occurred. */
#define TBM_IRNCR_A1X_TIMEOUT8_INTOCC 0x00000400
/** Calendar7 timeout
    This bit is set if calendar 7 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT7 0x00000200
/* Nothing
#define TBM_IRNCR_A1X_TIMEOUT7_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT7_INTACK 0x00000200
/** Read: Interrupt occurred. */
#define TBM_IRNCR_A1X_TIMEOUT7_INTOCC 0x00000200
/** Calendar6 timeout
    This bit is set if calendar 6 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT6 0x00000100
/* Nothing
#define TBM_IRNCR_A1X_TIMEOUT6_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT6_INTACK 0x00000100
/** Read: Interrupt occurred. */
#define TBM_IRNCR_A1X_TIMEOUT6_INTOCC 0x00000100
/** Calendar5 timeout
    This bit is set if calendar 5 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT5 0x00000080
/* Nothing
#define TBM_IRNCR_A1X_TIMEOUT5_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT5_INTACK 0x00000080
/** Read: Interrupt occurred. */
#define TBM_IRNCR_A1X_TIMEOUT5_INTOCC 0x00000080
/** Calendar4 timeout
    This bit is set if calendar 4 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT4 0x00000040
/* Nothing
#define TBM_IRNCR_A1X_TIMEOUT4_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT4_INTACK 0x00000040
/** Read: Interrupt occurred. */
#define TBM_IRNCR_A1X_TIMEOUT4_INTOCC 0x00000040
/** Calendar3 timeout
    This bit is set if calendar 3 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT3 0x00000020
/* Nothing
#define TBM_IRNCR_A1X_TIMEOUT3_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT3_INTACK 0x00000020
/** Read: Interrupt occurred. */
#define TBM_IRNCR_A1X_TIMEOUT3_INTOCC 0x00000020
/** Calendar2 timeout
    This bit is set if calendar 2 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT2 0x00000010
/* Nothing
#define TBM_IRNCR_A1X_TIMEOUT2_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT2_INTACK 0x00000010
/** Read: Interrupt occurred. */
#define TBM_IRNCR_A1X_TIMEOUT2_INTOCC 0x00000010
/** Calendar1 timeout
    This bit is set if calendar 1 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT1 0x00000008
/* Nothing
#define TBM_IRNCR_A1X_TIMEOUT1_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT1_INTACK 0x00000008
/** Read: Interrupt occurred. */
#define TBM_IRNCR_A1X_TIMEOUT1_INTOCC 0x00000008
/** Calendar0 timeout
    This bit is set if calendar 0 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT0 0x00000004
/* Nothing
#define TBM_IRNCR_A1X_TIMEOUT0_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define TBM_IRNCR_A1X_TIMEOUT0_INTACK 0x00000004
/** Read: Interrupt occurred. */
#define TBM_IRNCR_A1X_TIMEOUT0_INTOCC 0x00000004
/** TBM Ready
    This bit is set to one, if transfer from/to RAM is done == RESET VALUE OF READY IS 1 This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define TBM_IRNCR_READY 0x00000002
/* Nothing
#define TBM_IRNCR_READY_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define TBM_IRNCR_READY_INTACK 0x00000002
/** Read: Interrupt occurred. */
#define TBM_IRNCR_READY_INTOCC 0x00000002

/* Fields of "IRN Interrupt Control Register" */
/** TBM calendar not free
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNICR_A1X_CALNOTFREE 0x00000800
/** Calendar8 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNICR_A1X_TIMEOUT8 0x00000400
/** Calendar7 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNICR_A1X_TIMEOUT7 0x00000200
/** Calendar6 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNICR_A1X_TIMEOUT6 0x00000100
/** Calendar5 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNICR_A1X_TIMEOUT5 0x00000080
/** Calendar4 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNICR_A1X_TIMEOUT4 0x00000040
/** Calendar3 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNICR_A1X_TIMEOUT3 0x00000020
/** Calendar2 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNICR_A1X_TIMEOUT2 0x00000010
/** Calendar1 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNICR_A1X_TIMEOUT1 0x00000008
/** Calendar0 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNICR_A1X_TIMEOUT0 0x00000004
/** TBM Ready
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNICR_READY 0x00000002

/* Fields of "IRN Interrupt Enable Register" */
/** TBM calendar not free
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNEN_A1X_CALNOTFREE 0x00000800
/* Disable
#define TBM_IRNEN_A1X_CALNOTFREE_DIS 0x00000000 */
/** Enable */
#define TBM_IRNEN_A1X_CALNOTFREE_EN 0x00000800
/** Calendar8 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNEN_A1X_TIMEOUT8 0x00000400
/* Disable
#define TBM_IRNEN_A1X_TIMEOUT8_DIS 0x00000000 */
/** Enable */
#define TBM_IRNEN_A1X_TIMEOUT8_EN 0x00000400
/** Calendar7 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNEN_A1X_TIMEOUT7 0x00000200
/* Disable
#define TBM_IRNEN_A1X_TIMEOUT7_DIS 0x00000000 */
/** Enable */
#define TBM_IRNEN_A1X_TIMEOUT7_EN 0x00000200
/** Calendar6 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNEN_A1X_TIMEOUT6 0x00000100
/* Disable
#define TBM_IRNEN_A1X_TIMEOUT6_DIS 0x00000000 */
/** Enable */
#define TBM_IRNEN_A1X_TIMEOUT6_EN 0x00000100
/** Calendar5 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNEN_A1X_TIMEOUT5 0x00000080
/* Disable
#define TBM_IRNEN_A1X_TIMEOUT5_DIS 0x00000000 */
/** Enable */
#define TBM_IRNEN_A1X_TIMEOUT5_EN 0x00000080
/** Calendar4 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNEN_A1X_TIMEOUT4 0x00000040
/* Disable
#define TBM_IRNEN_A1X_TIMEOUT4_DIS 0x00000000 */
/** Enable */
#define TBM_IRNEN_A1X_TIMEOUT4_EN 0x00000040
/** Calendar3 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNEN_A1X_TIMEOUT3 0x00000020
/* Disable
#define TBM_IRNEN_A1X_TIMEOUT3_DIS 0x00000000 */
/** Enable */
#define TBM_IRNEN_A1X_TIMEOUT3_EN 0x00000020
/** Calendar2 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNEN_A1X_TIMEOUT2 0x00000010
/* Disable
#define TBM_IRNEN_A1X_TIMEOUT2_DIS 0x00000000 */
/** Enable */
#define TBM_IRNEN_A1X_TIMEOUT2_EN 0x00000010
/** Calendar1 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNEN_A1X_TIMEOUT1 0x00000008
/* Disable
#define TBM_IRNEN_A1X_TIMEOUT1_DIS 0x00000000 */
/** Enable */
#define TBM_IRNEN_A1X_TIMEOUT1_EN 0x00000008
/** Calendar0 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNEN_A1X_TIMEOUT0 0x00000004
/* Disable
#define TBM_IRNEN_A1X_TIMEOUT0_DIS 0x00000000 */
/** Enable */
#define TBM_IRNEN_A1X_TIMEOUT0_EN 0x00000004
/** TBM Ready
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define TBM_IRNEN_READY 0x00000002
/* Disable
#define TBM_IRNEN_READY_DIS 0x00000000 */
/** Enable */
#define TBM_IRNEN_READY_EN 0x00000002

/*! @} */ /* TBM_REGISTER */

#endif /* _drv_onu_reg_tbm_h */
