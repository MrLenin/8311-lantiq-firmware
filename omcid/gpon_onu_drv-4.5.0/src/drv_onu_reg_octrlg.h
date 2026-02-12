/******************************************************************************

                               Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_reg_octrlg_h
#define _drv_onu_reg_octrlg_h

/** \addtogroup OCTRLG_REGISTER
   @{
*/
/* access macros */
#define octrlg_r32(reg) reg_r32(&octrlg->reg)
#define octrlg_w32(val, reg) reg_w32(val, &octrlg->reg)
#define octrlg_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &octrlg->reg)
#define octrlg_r32_table(reg, idx) reg_r32_table(octrlg->reg, idx)
#define octrlg_w32_table(val, reg, idx) reg_w32_table(val, octrlg->reg, idx)
#define octrlg_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, octrlg->reg, idx)
#define octrlg_adr_table(reg, idx) adr_table(octrlg->reg, idx)


/** OCTRLG register structure */
struct onu_reg_octrlg
{
   /** Control Register */
   unsigned int ctrl; /* 0x00000000 */
   /** Configuration Register 0 */
   unsigned int cfg0; /* 0x00000004 */
   /** Configuration Register 1 */
   unsigned int cfg1; /* 0x00000008 */
   /** DMAR Control Register */
   unsigned int dctrl; /* 0x0000000C */
   /** DBRu Debug Register
       These DBRu values are transmitted when CFG1.DBRUDBG is enabled. */
   unsigned int dbrudbg; /* 0x00000010 */
   /** Reserved */
   unsigned int res_0[3]; /* 0x00000014 */
   /** IRN Capture Register
       This register shows the currently active interrupt events masked with the corresponding enable bits of the IRNEN register. The interrupts can be acknowledged by a write operation. */
   unsigned int irncr; /* 0x00000020 */
   /** IRN Interrupt Control Register
       A write operation directly effects the interrupts. This can be used to trigger events under software control for testing purposes. A read operation returns the unmasked interrupt events. */
   unsigned int irnicr; /* 0x00000024 */
   /** IRN Interrupt Enable Register
       This register contains the enable (or mask) bits for the interrupts. Disabled interrupts are not visible in the IRNCR register and are not signalled via the interrupt line towards the controller. */
   unsigned int irnen; /* 0x00000028 */
   /** Reserved */
   unsigned int res_1[5]; /* 0x0000002C */
   /** Idle Frame Pattern
       This Pattern is copied to GTC in case of Idle Frame Insertion. The length used for Idle Frame insertion is defined in CFG0.IDLELEN. The maximum length is 64. */
   unsigned int idleframe[16]; /* 0x00000040 */
   /** Reserved */
   unsigned int res_3[4064]; /* 0x00000080 */
   /** T-Cont Mapping Table
       The 4096 entries are binding zero, one or two Egress Port Numbers to a T-Cont Number. TCIX addresses the corresponding Egress Port in TCTABLE. */
   unsigned int tcmap[4096]; /* 0x00004000 */
   /** T-Cont Table
       The 32 entries are addressed by TCMAP.TCIX. */
   unsigned int tctable[32]; /* 0x00008000 */
   /** Reserved */
   unsigned int res_6[224]; /* 0x00008080 */
   /** GEM Port Index Table
       The 256 entries are mapping the 8 bit GPIX (from TMU) to the 12 bit GPID which must be inserted into the GEM Header. */
   unsigned int gpixtable[256]; /* 0x00008400 */
   /** Transmitted PDUs Counter for GEM Port Index
       The 256 counters are metering the transmitted PDUs for the assigned Port Index. Idle Frames are not counted. */
   unsigned int txpcnt[256]; /* 0x00008800 */
   /** Reserved */
   unsigned int res_9[256]; /* 0x00008C00 */
   /** Transmitted PDU Bytes Counter for GEM Port Index (Low Part)
       The 256 counters are metering the transmitted PDU Bytes for the assigned Port Index. Only GEM payload is counted. GEM Idles are not counted. */
   unsigned int txbcntl[256]; /* 0x00009000 */
  /** Transmitted PDU Bytes Counter for GEM Port Index (High Part)
       The 256 counters are metering the transmitted PDU Bytes for the assigned Port Index. Only GEM payload is counted. GEM Idles are not counted. */
   unsigned int txbcnth[256]; /* 0x00009400 */
   /** Total Transmitted PDUs Counter
       This counter is metering the transmitted PDUs for all GEM Port Indexes. Idle Frames are not counted */
   unsigned int txtpcnt; /* 0x00009800 */
   /** Total Transmitted PDU Bytes Counter (Low Part)
       This counter is metering the transmitted PDU Bytes for all GEM Port Indexes. Only GEM payload is counted. GEM Idles are not counted. */
   unsigned int txtbcntl; /* 0x00009804 */
   /** Total Transmitted PDU Bytes Counter (High Part)
       This counter is metering the transmitted PDU Bytes for all GEM Port Indexes. Only GEM payload is counted. GEM Idles are not counted. */
   unsigned int txtbcnth; /* 0x00009808 */
   /** Total Transmitted GEM Idle Frames Counter
       This counter is metering the transmitted GEM Idle Frames for all GEM Port Indexes. */
   unsigned int txticnt; /* 0x0000980C */
   /** Total Transmitted Bytes Counter
       This counter is metering the total number of transmitted Bytes for all GEM Port Indexes. All transmitted Bytes are counted, i.e. DBRu, GEM (header + payload), Idle Bytes. */
   unsigned int txtcnt; /* 0x00009810 */
   /** Total Transmitted T-Conts Counter
       This counter is metering the Total Transmitted T-Conts. */
   unsigned int txttcnt; /* 0x00009814 */
   /** Reserved */
   unsigned int res_12[58]; /* 0x00009818 */
   /** T-Cont Request
       This Register shows the current T-Cont Request. */
   unsigned int tcreq; /* 0x00009900 */
   /** T-Cont State Register
       This Register shows the internal T-Cont processing states. */
   unsigned int tcstate; /* 0x00009904 */
   /** Reserved */
   unsigned int res_13[446]; /* 0x00009908 */
   /** DMAR Pointer Register for EPN n
       This read only Register mirrors the DMAR.PTRn Register and may be used for debugging. */
   unsigned int dptr[64]; /* 0x0000A000 */
   /** DMAR Context Register for EPN n
       This read only Register mirrors the DMAR.CONTEXTn Register and may be used for debugging. */
   unsigned int dcontext[64]; /* 0x0000A100 */
   /** Reserved */
   unsigned int res_16[6016]; /* 0x0000A200 */
};


/* Fields of "Control Register" */
/** T-Cont Request Preprocessing
    Note: Don't touch, feature is not fully tested!This bit enables the preprocessing of the next T-Cont request when the current T-Cont is active. */
#define OCTRLG_CTRL_TCRP 0x00010000
/* Disable
#define OCTRLG_CTRL_TCRP_DIS 0x00000000 */
/** Enable */
#define OCTRLG_CTRL_TCRP_EN 0x00010000
/** Activate Core State Machine
    This bit enables the OCTRL state machine.When deactivating, the current T-Cont is finished and then the OCTRL is on hold.Note 1: All static configuration must be done before activation.Note 2: Deactivation is for debugging only. act - deact - act is prohibited! */
#define OCTRLG_CTRL_ACT 0x00000001
/* Disable
#define OCTRLG_CTRL_ACT_DIS 0x00000000 */
/** Enable */
#define OCTRLG_CTRL_ACT_EN 0x00000001

/* Fields of "Configuration Register 0" */
/** Upstream GTC Fifo Threshold
    Filling Level below or equal this threshold will cause Idle Frame insertion. The granularity is 1 Fifo entry, i.e. 4 Bytes.The IRN*.GTCFIFOTHRES interrupt can be used for reporting. */
#define OCTRLG_CFG0_GTCFIFOTHRES_MASK 0xFF000000
/** field offset */
#define OCTRLG_CFG0_GTCFIFOTHRES_OFFSET 24
/** Idle Frame Length
    Max number of Idle Frame Bytes used (0 = 1 Byte). */
#define OCTRLG_CFG0_IDLELEN_MASK 0x003F0000
/** field offset */
#define OCTRLG_CFG0_IDLELEN_OFFSET 16
/** Inverse Block Size
    To be programmed to (2^15)/B with B = DBR Block Size. */
#define OCTRLG_CFG0_IBS_MASK 0x00007FFF
/** field offset */
#define OCTRLG_CFG0_IBS_OFFSET 0

/* Fields of "Configuration Register 1" */
/** DBRu Debug
    This bit enables the debug mode for the DBRu reporting.When debug mode is enabled no backlog is executed. The DBRu values in DBRUDBG are transmitted instead. */
#define OCTRLG_CFG1_DBRUDBG 0x00040000
/* Disable
#define OCTRLG_CFG1_DBRUDBG_DIS 0x00000000 */
/** Enable */
#define OCTRLG_CFG1_DBRUDBG_EN 0x00040000
/** T-Cont 0 Upstream GTC Fifo Threshold
    Enable threshold for T-Cont 0 (1st T-Cont) of each BW-Map. */
#define OCTRLG_CFG1_TC0GTCFIFOTHRES 0x00020000
/* Disable
#define OCTRLG_CFG1_TC0GTCFIFOTHRES_DIS 0x00000000 */
/** Enable */
#define OCTRLG_CFG1_TC0GTCFIFOTHRES_EN 0x00020000
/** Per GEM Port Index Transmitted PDUs Counter Fragmentation
    Enable fragmented counting, i.e. PDUs that are fragmented across multiple GEM frames will result in the counter being incremented once for each GEM frame. */
#define OCTRLG_CFG1_TXPCNTFRAG 0x00010000
/* Disable
#define OCTRLG_CFG1_TXPCNTFRAG_DIS 0x00000000 */
/** Enable */
#define OCTRLG_CFG1_TXPCNTFRAG_EN 0x00010000
/** Maximum GEM Payload Size
    Lower Values are favorable for preemption, but increase transmission overhead. */
#define OCTRLG_CFG1_GEMPLSIZE_MASK 0x00000FFF
/** field offset */
#define OCTRLG_CFG1_GEMPLSIZE_OFFSET 0

/* Fields of "DMAR Control Register" */
/** Free Queue
    FSQM Queue selection for LSA freeing */
#define OCTRLG_DCTRL_FQ 0x00000001
/* Select Queue 0 (Note: Usage is prohibited!)
#define OCTRLG_DCTRL_FQ_Q0 0x00000000 */
/** Select Queue 1 (Default) */
#define OCTRLG_DCTRL_FQ_Q1 0x00000001

/* Fields of "DBRu Debug Register" */
/** DBRu Mode 2 Yellow Value */
#define OCTRLG_DBRUDBG_DBRU2Y_MASK 0x00FF0000
/** field offset */
#define OCTRLG_DBRUDBG_DBRU2Y_OFFSET 16
/** DBRu Mode 2 Green Value */
#define OCTRLG_DBRUDBG_DBRU2G_MASK 0x0000FF00
/** field offset */
#define OCTRLG_DBRUDBG_DBRU2G_OFFSET 8
/** DBRu Mode 1 Value */
#define OCTRLG_DBRUDBG_DBRU1_MASK 0x000000FF
/** field offset */
#define OCTRLG_DBRUDBG_DBRU1_OFFSET 0

/* Fields of "IRN Capture Register" */
/** T-Cont Length 0
    The T-cont Length is zero.The T-Cont Alloc-ID will be returned to the GTC.This bit contributes to the OCTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define OCTRLG_IRNCR_TCL0 0x00400000
/* Nothing
#define OCTRLG_IRNCR_TCL0_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define OCTRLG_IRNCR_TCL0_INTACK 0x00400000
/** Read: Interrupt occurred. */
#define OCTRLG_IRNCR_TCL0_INTOCC 0x00400000
/** Egress Port Number Not Valid
    The T-Cont Index points to an invalid EPN couple in the T-Cont Table, i.e. rEPN = 64 and pEPN = 64.The T-Cont will be filled with Idles.This bit contributes to the OCTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define OCTRLG_IRNCR_EPNNV 0x00200000
/* Nothing
#define OCTRLG_IRNCR_EPNNV_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define OCTRLG_IRNCR_EPNNV_INTACK 0x00200000
/** Read: Interrupt occurred. */
#define OCTRLG_IRNCR_EPNNV_INTOCC 0x00200000
/** T-Cont Index Not Valid
    The T-Cont Alloc-ID points to an invalid T-Cont Index in the T-Cont Mapping Table.The T-Cont will be filled with Idles.This bit contributes to the OCTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define OCTRLG_IRNCR_TCIXNV 0x00100000
/* Nothing
#define OCTRLG_IRNCR_TCIXNV_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define OCTRLG_IRNCR_TCIXNV_INTACK 0x00100000
/** Read: Interrupt occurred. */
#define OCTRLG_IRNCR_TCIXNV_INTOCC 0x00100000
/** PDU Length
    The PDU Length received from the TMU is zero, i.e. HDRL + BDYL = 0.The schedule response is discarded and the T-Cont will be filled with Idles.This bit contributes to the OCTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define OCTRLG_IRNCR_PLEN 0x00080000
/* Nothing
#define OCTRLG_IRNCR_PLEN_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define OCTRLG_IRNCR_PLEN_INTACK 0x00080000
/** Read: Interrupt occurred. */
#define OCTRLG_IRNCR_PLEN_INTOCC 0x00080000
/** OCTRL NIL LSA
    OCTRL has received a NIL LSA from TMU.The schedule response is discarded and the T-Cont will be filled with Idles.This bit contributes to the OCTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define OCTRLG_IRNCR_NIL 0x00040000
/* Nothing
#define OCTRLG_IRNCR_NIL_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define OCTRLG_IRNCR_NIL_INTACK 0x00040000
/** Read: Interrupt occurred. */
#define OCTRLG_IRNCR_NIL_INTOCC 0x00040000
/** DMAR NIL LSA
    DMAR has received a NIL LSA from FSQM, i.e. linked list in FSQM is corrupt.The PDU transmission is immediately stopped and the memory, allocated by the already transmitted bytes, is deallocated. The T-Cont is filled with Idles and the OCTRLwill be disabled, i.e. CTRL.ACT = 0.This bit contributes to the OCTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define OCTRLG_IRNCR_DNIL 0x00010000
/* Nothing
#define OCTRLG_IRNCR_DNIL_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define OCTRLG_IRNCR_DNIL_INTACK 0x00010000
/** Read: Interrupt occurred. */
#define OCTRLG_IRNCR_DNIL_INTOCC 0x00010000
/** Egress Port Number Empty
    The requested EPN is empty in the TMU.The T-Cont will be filled with Idles. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define OCTRLG_IRNCR_EPNEMP 0x00000008
/* Nothing
#define OCTRLG_IRNCR_EPNEMP_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define OCTRLG_IRNCR_EPNEMP_INTACK 0x00000008
/** Read: Interrupt occurred. */
#define OCTRLG_IRNCR_EPNEMP_INTOCC 0x00000008
/** Upstream GTC Fifo Threshold
    The Filling Level of the GTC Egress Fifo is below or equal the watermark defined in CFG0.GTCFIFOTHRES.The T-Cont will be filled with Idles. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define OCTRLG_IRNCR_GTCFIFOTHRES 0x00000004
/* Nothing
#define OCTRLG_IRNCR_GTCFIFOTHRES_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define OCTRLG_IRNCR_GTCFIFOTHRES_INTACK 0x00000004
/** Read: Interrupt occurred. */
#define OCTRLG_IRNCR_GTCFIFOTHRES_INTOCC 0x00000004
/** T-Cont Length GEM
    The T-Cont Length is to short to transmit the Header of the first GEM Frame.The T-Cont will be filled with Idles. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define OCTRLG_IRNCR_TCLGEM 0x00000002
/* Nothing
#define OCTRLG_IRNCR_TCLGEM_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define OCTRLG_IRNCR_TCLGEM_INTACK 0x00000002
/** Read: Interrupt occurred. */
#define OCTRLG_IRNCR_TCLGEM_INTOCC 0x00000002
/** T-Cont Length DBRu
    The T-Cont Length is to short to transmit the DBRu Report.The T-Cont will be filled with Idles. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define OCTRLG_IRNCR_TCLDBRU 0x00000001
/* Nothing
#define OCTRLG_IRNCR_TCLDBRU_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define OCTRLG_IRNCR_TCLDBRU_INTACK 0x00000001
/** Read: Interrupt occurred. */
#define OCTRLG_IRNCR_TCLDBRU_INTOCC 0x00000001

/* Fields of "IRN Interrupt Control Register" */
/** T-Cont Length 0
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNICR_TCL0 0x00400000
/** Egress Port Number Not Valid
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNICR_EPNNV 0x00200000
/** T-Cont Index Not Valid
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNICR_TCIXNV 0x00100000
/** PDU Length
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNICR_PLEN 0x00080000
/** OCTRL NIL LSA
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNICR_NIL 0x00040000
/** DMAR NIL LSA
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNICR_DNIL 0x00010000
/** Egress Port Number Empty
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNICR_EPNEMP 0x00000008
/** Upstream GTC Fifo Threshold
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNICR_GTCFIFOTHRES 0x00000004
/** T-Cont Length GEM
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNICR_TCLGEM 0x00000002
/** T-Cont Length DBRu
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNICR_TCLDBRU 0x00000001

/* Fields of "IRN Interrupt Enable Register" */
/** T-Cont Length 0
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNEN_TCL0 0x00400000
/* Disable
#define OCTRLG_IRNEN_TCL0_DIS 0x00000000 */
/** Enable */
#define OCTRLG_IRNEN_TCL0_EN 0x00400000
/** Egress Port Number Not Valid
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNEN_EPNNV 0x00200000
/* Disable
#define OCTRLG_IRNEN_EPNNV_DIS 0x00000000 */
/** Enable */
#define OCTRLG_IRNEN_EPNNV_EN 0x00200000
/** T-Cont Index Not Valid
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNEN_TCIXNV 0x00100000
/* Disable
#define OCTRLG_IRNEN_TCIXNV_DIS 0x00000000 */
/** Enable */
#define OCTRLG_IRNEN_TCIXNV_EN 0x00100000
/** PDU Length
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNEN_PLEN 0x00080000
/* Disable
#define OCTRLG_IRNEN_PLEN_DIS 0x00000000 */
/** Enable */
#define OCTRLG_IRNEN_PLEN_EN 0x00080000
/** OCTRL NIL LSA
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNEN_NIL 0x00040000
/* Disable
#define OCTRLG_IRNEN_NIL_DIS 0x00000000 */
/** Enable */
#define OCTRLG_IRNEN_NIL_EN 0x00040000
/** DMAR NIL LSA
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNEN_DNIL 0x00010000
/* Disable
#define OCTRLG_IRNEN_DNIL_DIS 0x00000000 */
/** Enable */
#define OCTRLG_IRNEN_DNIL_EN 0x00010000
/** Egress Port Number Empty
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNEN_EPNEMP 0x00000008
/* Disable
#define OCTRLG_IRNEN_EPNEMP_DIS 0x00000000 */
/** Enable */
#define OCTRLG_IRNEN_EPNEMP_EN 0x00000008
/** Upstream GTC Fifo Threshold
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNEN_GTCFIFOTHRES 0x00000004
/* Disable
#define OCTRLG_IRNEN_GTCFIFOTHRES_DIS 0x00000000 */
/** Enable */
#define OCTRLG_IRNEN_GTCFIFOTHRES_EN 0x00000004
/** T-Cont Length GEM
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNEN_TCLGEM 0x00000002
/* Disable
#define OCTRLG_IRNEN_TCLGEM_DIS 0x00000000 */
/** Enable */
#define OCTRLG_IRNEN_TCLGEM_EN 0x00000002
/** T-Cont Length DBRu
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define OCTRLG_IRNEN_TCLDBRU 0x00000001
/* Disable
#define OCTRLG_IRNEN_TCLDBRU_DIS 0x00000000 */
/** Enable */
#define OCTRLG_IRNEN_TCLDBRU_EN 0x00000001

/* Fields of "Idle Frame Pattern 0" */
/** Idle Frame Byte 0 */
#define OCTRLG_IDLEFRAME0_IFB0_MASK 0xFF000000
/** field offset */
#define OCTRLG_IDLEFRAME0_IFB0_OFFSET 24
/** Idle Frame Byte 1 */
#define OCTRLG_IDLEFRAME0_IFB1_MASK 0x00FF0000
/** field offset */
#define OCTRLG_IDLEFRAME0_IFB1_OFFSET 16
/** Idle Frame Byte 2 */
#define OCTRLG_IDLEFRAME0_IFB2_MASK 0x0000FF00
/** field offset */
#define OCTRLG_IDLEFRAME0_IFB2_OFFSET 8
/** Idle Frame Byte 3 */
#define OCTRLG_IDLEFRAME0_IFB3_MASK 0x000000FF
/** field offset */
#define OCTRLG_IDLEFRAME0_IFB3_OFFSET 0

/* Fields of "Idle Frame Pattern 1" */
/** Idle Frame Byte 4 */
#define OCTRLG_IDLEFRAME1_IFB4_MASK 0xFF000000
/** field offset */
#define OCTRLG_IDLEFRAME1_IFB4_OFFSET 24
/** Idle Frame Byte 5 */
#define OCTRLG_IDLEFRAME1_IFB5_MASK 0x00FF0000
/** field offset */
#define OCTRLG_IDLEFRAME1_IFB5_OFFSET 16
/** Idle Frame Byte 6 */
#define OCTRLG_IDLEFRAME1_IFB6_MASK 0x0000FF00
/** field offset */
#define OCTRLG_IDLEFRAME1_IFB6_OFFSET 8
/** Idle Frame Byte 7 */
#define OCTRLG_IDLEFRAME1_IFB7_MASK 0x000000FF
/** field offset */
#define OCTRLG_IDLEFRAME1_IFB7_OFFSET 0

/* Fields of "Idle Frame Pattern 15" */
/** Idle Frame Byte 60 */
#define OCTRLG_IDLEFRAME15_IFB60_MASK 0xFF000000
/** field offset */
#define OCTRLG_IDLEFRAME15_IFB60_OFFSET 24
/** Idle Frame Byte 61 */
#define OCTRLG_IDLEFRAME15_IFB61_MASK 0x00FF0000
/** field offset */
#define OCTRLG_IDLEFRAME15_IFB61_OFFSET 16
/** Idle Frame Byte 62 */
#define OCTRLG_IDLEFRAME15_IFB62_MASK 0x0000FF00
/** field offset */
#define OCTRLG_IDLEFRAME15_IFB62_OFFSET 8
/** Idle Frame Byte 63 */
#define OCTRLG_IDLEFRAME15_IFB63_MASK 0x000000FF
/** field offset */
#define OCTRLG_IDLEFRAME15_IFB63_OFFSET 0

/* Fields of "T-Cont Mapping Table 0" */
/** Valid 0
    Reduced Alloc-ID 0 Valid FlagNote: Reset not valid (RAM)! */
#define OCTRLG_TCMAP0_V0 0x00000020
/* Not Valid
#define OCTRLG_TCMAP0_V0_NV 0x00000000 */
/** Valid */
#define OCTRLG_TCMAP0_V0_V 0x00000020
/** T-Cont Index 0
    Reduced Alloc-ID 0Note: Reset not valid (RAM)! */
#define OCTRLG_TCMAP0_TCIX0_MASK 0x0000001F
/** field offset */
#define OCTRLG_TCMAP0_TCIX0_OFFSET 0

/* Fields of "T-Cont Mapping Table 4095" */
/** Valid 4095
    Reduced Alloc-ID 4095 Valid FlagNote: Reset not valid (RAM)! */
#define OCTRLG_TCMAP4095_V4095 0x00000020
/* Not Valid
#define OCTRLG_TCMAP4095_V4095_NV 0x00000000 */
/** Valid */
#define OCTRLG_TCMAP4095_V4095_V 0x00000020
/** T-Cont Index 4095
    Reduced Alloc-ID 4095Note: Reset not valid (RAM)! */
#define OCTRLG_TCMAP4095_TCIX4095_MASK 0x0000001F
/** field offset */
#define OCTRLG_TCMAP4095_TCIX4095_OFFSET 0

/* Fields of "T-Cont Table 0" */
/** Regular EPN 0
    This egress port handles the regular data for the T-Cont with TCMAP.TCIX = 0.0 to 63: Implemented EPN range 63: No EPN assigned */
#define OCTRLG_TCTABLE0_REPN0_MASK 0x00007F00
/** field offset */
#define OCTRLG_TCTABLE0_REPN0_OFFSET 8
/** Preempting EPN 0
    This egress port handles the preempting data for the T-Cont with TCMAP.TCIX = 0.0 to 63: Implemented EPN range 63: No EPN assigned */
#define OCTRLG_TCTABLE0_PEPN0_MASK 0x0000007F
/** field offset */
#define OCTRLG_TCTABLE0_PEPN0_OFFSET 0

/* Fields of "T-Cont Table 31" */
/** Regular EPN 31
    This egress port handles the regular data for the T-Cont with TCMAP.TCIX = 31.0 to 63: Implemented EPN range 63: No EPN assigned */
#define OCTRLG_TCTABLE31_REPN31_MASK 0x00007F00
/** field offset */
#define OCTRLG_TCTABLE31_REPN31_OFFSET 8
/** Preempting EPN 31
    This egress port handles the preempting data for the T-Cont with TCMAP.TCIX = 31.0 to 63: Implemented EPN range 63: No EPN assigned */
#define OCTRLG_TCTABLE31_PEPN31_MASK 0x0000007F
/** field offset */
#define OCTRLG_TCTABLE31_PEPN31_OFFSET 0

/* Fields of "GEM Port Index Table 0" */
/** GEM Port-ID 0
    GEM Port-ID 0 to be inserted into the GEM HeaderNote: Reset not valid (RAM)! */
#define OCTRLG_GPIXTABLE0_GPID0_MASK 0x00000FFF
/** field offset */
#define OCTRLG_GPIXTABLE0_GPID0_OFFSET 0

/* Fields of "GEM Port Index Table 255" */
/** GEM Port-ID 255
    GEM Port-ID 255 to be inserted into the GEM HeaderNote: Reset not valid (RAM)! */
#define OCTRLG_GPIXTABLE255_GPID255_MASK 0x00000FFF
/** field offset */
#define OCTRLG_GPIXTABLE255_GPID255_OFFSET 0

/* Fields of "Transmitted PDUs Counter for GEM Port Index 0" */
/** Counter Value0
    Packet Counter Value for GEM Port Index 0Note: Reset not valid (RAM)! */
#define OCTRLG_TXPCNT0_PCNT0_MASK 0xFFFFFFFF
/** field offset */
#define OCTRLG_TXPCNT0_PCNT0_OFFSET 0

/* Fields of "Transmitted PDUs Counter for GEM Port Index 255" */
/** Counter Value255
    Packet Counter Value for GEM Port Index 255Note: Reset not valid (RAM)! */
#define OCTRLG_TXPCNT255_PCNT255_MASK 0xFFFFFFFF
/** field offset */
#define OCTRLG_TXPCNT255_PCNT255_OFFSET 0

/* Fields of "Transmitted PDU Bytes Counter for GEM Port Index 0 (Low Part)" */
/** Counter Value 0 (Low)
    Byte Counter Value for GEM Port Index 0 (Low Part)Note 1: Reset not valid (RAM)!Note 2: First the Low and then the High Part has to be read.Note 3: First the High and then the Low Part has to be written. */
#define OCTRLG_TXBCNTL0_BCNTL0_MASK 0xFFFFFFFF
/** field offset */
#define OCTRLG_TXBCNTL0_BCNTL0_OFFSET 0

/* Fields of "Transmitted PDU Bytes Counter for GEM Port Index 255 (Low Part)" */
/** Counter Value 255 (Low)
    Byte Counter Value for GEM Port Index 255 (Low Part)Note 1: Reset not valid (RAM)!Note 2: First the Low and then the High Part has to be read.Note 3: First the High and then the Low Part has to be written. */
#define OCTRLG_TXBCNTL255_BCNTL255_MASK 0xFFFFFFFF
/** field offset */
#define OCTRLG_TXBCNTL255_BCNTL255_OFFSET 0

/* Fields of "Transmitted PDU Bytes Counter for GEM Port Index 0 (High Part)" */
/** Counter Value 0 (High)
    Byte Counter Value for GEM Port Index 0 (High Part)Note 1: Reset not valid (RAM)!Note 2: First the Low and then the High Part has to be read.Note 3: First the High and then the Low Part has to be written. */
#define OCTRLG_TXBCNTH0_BCNTH0_MASK 0x000000FF
/** field offset */
#define OCTRLG_TXBCNTH0_BCNTH0_OFFSET 0

/* Fields of "Transmitted PDU Bytes Counter for GEM Port Index 255 (High Part)" */
/** Counter Value 255 (High)
    Byte Counter Value for GEM Port Index 255 (High Part)Note 1: Reset not valid (RAM)!Note 2: First the Low and then the High Part has to be read.Note 3: First the High and then the Low Part has to be written. */
#define OCTRLG_TXBCNTH255_BCNTH255_MASK 0x000000FF
/** field offset */
#define OCTRLG_TXBCNTH255_BCNTH255_OFFSET 0

/* Fields of "Total Transmitted PDUs Counter" */
/** Counter Value
    Total Packet Counter Value */
#define OCTRLG_TXTPCNT_TPCNT_MASK 0xFFFFFFFF
/** field offset */
#define OCTRLG_TXTPCNT_TPCNT_OFFSET 0

/* Fields of "Total Transmitted PDU Bytes Counter (Low Part)" */
/** Counter Value (Low)
    Total Byte Counter Value (Low Part)Note: First the Low and then the High Part has to be read. */
#define OCTRLG_TXTBCNTL_TBCNTL_MASK 0xFFFFFFFF
/** field offset */
#define OCTRLG_TXTBCNTL_TBCNTL_OFFSET 0

/* Fields of "Total Transmitted PDU Bytes Counter (High Part)" */
/** Counter Value (High)
    Total Byte Counter Value (High Part)Note: First the Low and then the High Part has to be read. */
#define OCTRLG_TXTBCNTH_TBCNTH_MASK 0x0000FFFF
/** field offset */
#define OCTRLG_TXTBCNTH_TBCNTH_OFFSET 0

/* Fields of "Total Transmitted GEM Idle Frames Counter" */
/** Counter Value
    Total GEM Idle Frame Counter Value */
#define OCTRLG_TXTICNT_TICNT_MASK 0xFFFFFFFF
/** field offset */
#define OCTRLG_TXTICNT_TICNT_OFFSET 0

/* Fields of "Total Transmitted Bytes Counter" */
/** Counter Value
    Total Byte Counter Value */
#define OCTRLG_TXTCNT_TCNT_MASK 0xFFFFFFFF
/** field offset */
#define OCTRLG_TXTCNT_TCNT_OFFSET 0

/* Fields of "Total Transmitted T-Conts Counter" */
/** Counter Value
    Total T-Cont Counter Value */
#define OCTRLG_TXTTCNT_TTCNT_MASK 0xFFFFFFFF
/** field offset */
#define OCTRLG_TXTTCNT_TTCNT_OFFSET 0

/* Fields of "T-Cont Request" */
/** T-Cont ID
    T-Cont ID (Alloc-ID, T-Cont Number) */
#define OCTRLG_TCREQ_TCID_MASK 0x3FFC0000
/** field offset */
#define OCTRLG_TCREQ_TCID_OFFSET 18
/** DBRu Mode */
#define OCTRLG_TCREQ_DBRU_MASK 0x00030000
/** field offset */
#define OCTRLG_TCREQ_DBRU_OFFSET 16
/** T-Cont Length */
#define OCTRLG_TCREQ_TCL_MASK 0x0000FFFF
/** field offset */
#define OCTRLG_TCREQ_TCL_OFFSET 0

/* Fields of "T-Cont State Register" */
/** Egress Port Number
    Current Egress Port Number */
#define OCTRLG_TCSTATE_EPN_MASK 0x7F000000
/** field offset */
#define OCTRLG_TCSTATE_EPN_OFFSET 24
/** DMAR Data Ready
    Indicates whether DMAR Data is ready or not. */
#define OCTRLG_TCSTATE_DMARDRDY 0x00080000
/* Not Ready
#define OCTRLG_TCSTATE_DMARDRDY_NRDY 0x00000000 */
/** Ready */
#define OCTRLG_TCSTATE_DMARDRDY_RDY 0x00080000
/** TX-Data Fifo Threshold
    Indicates whether the TX-Data Fifo Threshold is exceeded or not. */
#define OCTRLG_TCSTATE_TXFIFOTHRES 0x00040000
/* Not Exceeded
#define OCTRLG_TCSTATE_TXFIFOTHRES_NEX 0x00000000 */
/** Exceeded */
#define OCTRLG_TCSTATE_TXFIFOTHRES_EX 0x00040000
/** TX-Data Fifo Full
    Indicates whether the TX-Data Fifo is full or not. */
#define OCTRLG_TCSTATE_TXFIFOFULL 0x00020000
/* FIFO not full: There is free space in the FIFO.
#define OCTRLG_TCSTATE_TXFIFOFULL_FNFULL 0x00000000 */
/** FIFO full: There is no space in the FIFO. */
#define OCTRLG_TCSTATE_TXFIFOFULL_FFULL 0x00020000
/** T-Cont Request Fifo Empty
    Indicates whether the T-Cont Request Fifo is empty or not. */
#define OCTRLG_TCSTATE_TCFIFOEMPTY 0x00010000
/* FIFO not empty: The FIFO contains data.
#define OCTRLG_TCSTATE_TCFIFOEMPTY_FNEMP 0x00000000 */
/** FIFO empty: The FIFO does not contain data. */
#define OCTRLG_TCSTATE_TCFIFOEMPTY_FEMP 0x00010000
/** T-Cont Transmission State
    Current state of the T-Cont transmission. */
#define OCTRLG_TCSTATE_TCTX_MASK 0x00000F00
/** field offset */
#define OCTRLG_TCSTATE_TCTX_OFFSET 8
/** Idle */
#define OCTRLG_TCSTATE_TCTX_IDLE 0x00000000
/** T-Cont Start */
#define OCTRLG_TCSTATE_TCTX_TCSTART 0x00000100
/** GEM Frame Start */
#define OCTRLG_TCSTATE_TCTX_GEMSTART 0x00000200
/** Schedule */
#define OCTRLG_TCSTATE_TCTX_SCHEDULE 0x00000300
/** DMAR open channel */
#define OCTRLG_TCSTATE_TCTX_DMAROPEN 0x00000400
/** GEM Header transmission */
#define OCTRLG_TCSTATE_TCTX_GEMHEADTX 0x00000500
/** DMAR data transmission */
#define OCTRLG_TCSTATE_TCTX_DMARTX 0x00000600
/** DMAR close channel */
#define OCTRLG_TCSTATE_TCTX_DMARCLOSE 0x00000700
/** DMAR delete channel (deallocate segments in SSB) */
#define OCTRLG_TCSTATE_TCTX_DMARDELETE 0x00000800
/** Ethernet zero padding */
#define OCTRLG_TCSTATE_TCTX_ZEROPAD 0x00000900
/** FCS/CRC transmission */
#define OCTRLG_TCSTATE_TCTX_FCSCRCTX 0x00000A00
/** Idle transmission */
#define OCTRLG_TCSTATE_TCTX_IDLETX 0x00000B00
/** T-Cont End */
#define OCTRLG_TCSTATE_TCTX_TCEND 0x00000C00
/** T-Cont Preparation State
    Current state of the T-Cont preparation. */
#define OCTRLG_TCSTATE_TCPREP_MASK 0x00000007
/** field offset */
#define OCTRLG_TCSTATE_TCPREP_OFFSET 0
/** Idle */
#define OCTRLG_TCSTATE_TCPREP_IDLE 0x00000000
/** Load TC-Request */
#define OCTRLG_TCSTATE_TCPREP_TCREQ 0x00000001
/** Backlog for rEPN */
#define OCTRLG_TCSTATE_TCPREP_BACKLOGREPN 0x00000002
/** Backlog for pEPN */
#define OCTRLG_TCSTATE_TCPREP_BACKLOGPEPN 0x00000003
/** TC-Request is ready */
#define OCTRLG_TCSTATE_TCPREP_TCREADY 0x00000004

/* Fields of "DMAR Pointer Register for EPN 0" */
/** Tail LSA
    Tail Logical Segment AddressNote: Reset not valid (RAM)! */
#define OCTRLG_DPTR0_TLSA_MASK 0x7FFF0000
/** field offset */
#define OCTRLG_DPTR0_TLSA_OFFSET 16
/** Head LSA
    Head Logical Segment AddressNote: Reset not valid (RAM)! */
#define OCTRLG_DPTR0_HLSA_MASK 0x00007FFF
/** field offset */
#define OCTRLG_DPTR0_HLSA_OFFSET 0

/* Fields of "DMAR Pointer Register for EPN 63" */
/** Tail LSA
    Tail Logical Segment AddressNote: Reset not valid (RAM)! */
#define OCTRLG_DPTR63_TLSA_MASK 0x7FFF0000
/** field offset */
#define OCTRLG_DPTR63_TLSA_OFFSET 16
/** Head LSA
    Head Logical Segment AddressNote: Reset not valid (RAM)! */
#define OCTRLG_DPTR63_HLSA_MASK 0x00007FFF
/** field offset */
#define OCTRLG_DPTR63_HLSA_OFFSET 0

/* Fields of "DMAR Context Register for EPN 0" */
/** Header Length
    Length of the Packet HeaderNote: Reset not valid (RAM)! */
#define OCTRLG_DCONTEXT0_HDRL_MASK 0xFF000000
/** field offset */
#define OCTRLG_DCONTEXT0_HDRL_OFFSET 24
/** Offset
    Offset into Frame Segment(s)Note: Reset not valid (RAM)! */
#define OCTRLG_DCONTEXT0_OFFS_MASK 0x00FF0000
/** field offset */
#define OCTRLG_DCONTEXT0_OFFS_OFFSET 16
/** Body Length
    Length of the Packet Body w/o FCSNote: Reset not valid (RAM)! */
#define OCTRLG_DCONTEXT0_BDYL_MASK 0x0000FFFF
/** field offset */
#define OCTRLG_DCONTEXT0_BDYL_OFFSET 0

/* Fields of "DMAR Context Register for EPN 63" */
/** Header Length
    Length of the Packet HeaderNote: Reset not valid (RAM)! */
#define OCTRLG_DCONTEXT63_HDRL_MASK 0xFF000000
/** field offset */
#define OCTRLG_DCONTEXT63_HDRL_OFFSET 24
/** Offset
    Offset into Frame Segment(s)Note: Reset not valid (RAM)! */
#define OCTRLG_DCONTEXT63_OFFS_MASK 0x00FF0000
/** field offset */
#define OCTRLG_DCONTEXT63_OFFS_OFFSET 16
/** Body Length
    Length of the Packet Body w/o FCSNote: Reset not valid (RAM)! */
#define OCTRLG_DCONTEXT63_BDYL_MASK 0x0000FFFF
/** field offset */
#define OCTRLG_DCONTEXT63_BDYL_OFFSET 0

/*! @} */ /* OCTRLG_REGISTER */

#endif /* _drv_onu_reg_octrlg_h */
