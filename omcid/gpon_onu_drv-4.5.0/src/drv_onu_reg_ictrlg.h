/******************************************************************************

                               Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_reg_ictrlg_h
#define _drv_onu_reg_ictrlg_h

/** \addtogroup ICTRLG_REGISTER
   @{
*/
/* access macros */
#define ictrlg_r32(reg) reg_r32(&ictrlg->reg)
#define ictrlg_w32(val, reg) reg_w32(val, &ictrlg->reg)
#define ictrlg_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &ictrlg->reg)
#define ictrlg_r32_table(reg, idx) reg_r32_table(ictrlg->reg, idx)
#define ictrlg_w32_table(val, reg, idx) reg_w32_table(val, ictrlg->reg, idx)
#define ictrlg_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, ictrlg->reg, idx)
#define ictrlg_adr_table(reg, idx) adr_table(ictrlg->reg, idx)


/** ICTRLG register structure */
struct onu_reg_ictrlg
{
   /** Control Register
       This register provides the global ICTRLG controls. */
   unsigned int ctrl; /* 0x00000000 */
   /** DMAW Configuration Register
       This register contains necessary configuration elements for the DMAW. */
   unsigned int dmaw_cfg; /* 0x00000004 */
   /** Reassembly Timeout Control Register
       This register provides the rassembly timeout control. */
   unsigned int timeout; /* 0x00000008 */
   /** Reserved */
   unsigned int res_0[9]; /* 0x0000000C */
   /** Maximum allowed Size for PDU Type 0..7
       This register contains the maximum allowed size for PDU type 0..7. */
   unsigned int maxsize[8]; /* 0x00000030 */
   /** Total Received Bytes Counter (Low Part)
       This counter is metering the total number of received bytes. */
   unsigned int rxbcntl; /* 0x00000050 */
   /** Total Received Bytes Counter (High Part)
       This counter is metering the total number of received bytes. */
   unsigned int rxbcnth; /* 0x00000054 */
   /** Oversized non-OMCI PDUs Counter
       This counter is metering the number of oversized non-OMCI PDUs:- Oversized non-OMCI PDU Error (IRN*.OVRSIZE) */
   unsigned int ovrsize; /* 0x00000058 */
   /** DMAW Error Counter
       This counter is metering the number of DMAW Errors:- DMAW Out of FIFO Error (IRN*.DMAWOOF)- DMAW Out Of Memory Error (IRN*.DMAWOOM)- DMAW Timeout Error (IRN*.DMAWTMO)Note: Due to the LSA prefetch, the DMAW errors Out of Memory and Timeout can also occur when no PDU is processed or pending. */
   unsigned int dmawerr; /* 0x0000005C */
   /** OMCI Message Discard Counter
       This counter is metering the number of OMCI Messages which have been discarded due to:- Bad OMCI Errors (IRN*.BADOMCI) */
   unsigned int badomci; /* 0x00000060 */
   /** Ethernet FCS Error Counter
       This counter is metering the total number of Ethernet PDUs where the FCS check has failed:- FCS Errors (IRN*.FCSERR) */
   unsigned int fcserr; /* 0x00000064 */
   /** Reassembly Error Counter
       This counter is metering the number of reassembly errors:- Reassembly Timeout Error (IRN*.REASSERR)- Active Channels Overflow (IRN*.ACTCHAN)- Invalid GPIX Error (IRN*.INVGPIX) */
   unsigned int reasserr; /* 0x00000068 */
   /** Undersized Ethernet Frames Counter
       This counter is metering the number of Ethernet frames which are smaller than 64 bytes. */
   unsigned int undsize; /* 0x0000006C */
   /** Non-OMCI Packet Discard Counter
       This counter is metering the total number of non-OMCI PDUs which have been discarded due to:- Oversize Errors- Minimum Size Under-run- FCS Errors- DMAW Errors- Reassembly Timeout Error- Active Channels Overflow- Invalid GPIX Error */
   unsigned int pdc; /* 0x00000070 */
   /** Total Received PDUs Counter
       This counter is metering the total number of received PDUs. */
   unsigned int rxtpcnt; /* 0x00000074 */
   /** Reserved */
   unsigned int res_1[34]; /* 0x00000078 */
   /** IRN Capture Register
       This register shows the currently active interrupt events masked with the corresponding enable bits of the IRNEN register. The interrupts can be acknowledged by a write operation. */
   unsigned int irncr; /* 0x00000100 */
   /** IRN Interrupt Control Register
       A write operation directly effects the interrupts. This can be used to trigger events under software control for testing purposes. A read operation returns the unmasked interrupt events. */
   unsigned int irnicr; /* 0x00000104 */
   /** IRN Interrupt Enable Register
       This register contains the enable (or mask) bits for the interrupts. Disabled interrupts are not visible in the IRNCR register and are not signalled via the interrupt line towards the controller. */
   unsigned int irnen; /* 0x00000108 */
   /** Reserved */
   unsigned int res_2[4029]; /* 0x0000010C */
   /** GEM Port Table
       The 4096 Entries are addressed by the GEM Port ID and providing the GPID to GPIX translation. */
   unsigned int gpt[4096]; /* 0x00004000 */
   /** GEM Port Index Configuration
       The 256 entries are addressed by GPT.GPIX. */
   unsigned int gpix_cfg[256]; /* 0x00008000 */
   /** GEM Port Index Received Frames Counter
       The 256 counters are metering the either the received GEM frames (CTRL.FRMCNT == 1) or PDUs (CTRL.FRMCNT == 0) for the corresponding GPIX. */
   unsigned int gpix_rxfcnt[256]; /* 0x00008400 */
   /** GEM Port Index Received Bytes Counter (Low Part)
       The 256 counters are metering the received bytes for the corresponding GPIX. */
   unsigned int gpix_rxbcntl[256]; /* 0x00008800 */
   /** GEM Port Index Received Bytes Counter (High Part)
       The 256 counters are metering the received bytes for the corresponding GPIX. */
   unsigned int gpix_rxbcnth[256]; /* 0x00008C00 */
   /** Reserved */
   unsigned int res_7[7168]; /* 0x00008D00 */
};


/* Fields of "Control Register" */
/** Activate Debug Mode of the ICTRL Module
    This bit enables the Debug Mode of the ICTRL.If enabled, ICTRL will always write out data to the IQM, regardless of IQM FIFO state. */
#define ICTRLG_CTRL_DBG 0x80000000
/* Disable
#define ICTRLG_CTRL_DBG_DIS 0x00000000 */
/** Enable */
#define ICTRLG_CTRL_DBG_EN 0x80000000
/** GPIX_RXFCNT Fragmentation
    If enabled, GPIX_RXFCNT is counting received GEM frames else PDUs. */
#define ICTRLG_CTRL_FRMCNT 0x00000020
/* Disable
#define ICTRLG_CTRL_FRMCNT_DIS 0x00000000 */
/** Enable */
#define ICTRLG_CTRL_FRMCNT_EN 0x00000020
/** Activate CRC Checking for OMCI and Ethernet Frames
    This bit enables the CRC checking for OMCI and Ethernet frames. */
#define ICTRLG_CTRL_CRC 0x00000010
/* Disable
#define ICTRLG_CTRL_CRC_DIS 0x00000000 */
/** Enable */
#define ICTRLG_CTRL_CRC_EN 0x00000010
/** Activate Core State Machine
    This bit enables the ICTRL state machine.When deactivating, the current GEM frame is finished and then the ICTRL is on hold.Note 1: All static configuration must be done before activation.Note 2: Deactivation is for debugging only. act - deact - act is prohibited! */
#define ICTRLG_CTRL_ACT 0x00000001
/* Disable
#define ICTRLG_CTRL_ACT_DIS 0x00000000 */
/** Enable */
#define ICTRLG_CTRL_ACT_EN 0x00000001

/* Fields of "DMAW Configuration Register" */
/** Synchronous Reset of DMAW */
#define ICTRLG_DMAW_CFG_SRET 0x80000000
/* NoReset
#define ICTRLG_DMAW_CFG_SRET_NoReset 0x00000000 */
/** Reset */
#define ICTRLG_DMAW_CFG_SRET_Reset 0x80000000
/** Alloc Queue Selection
    FSQM Queue selection for LSA allocation. */
#define ICTRLG_DMAW_CFG_ALLOCQ 0x00000200
/* Select Queue 0 (Note: Usage is prohibited!)
#define ICTRLG_DMAW_CFG_ALLOCQ_Q0 0x00000000 */
/** Select Queue 1 (Default) */
#define ICTRLG_DMAW_CFG_ALLOCQ_Q1 0x00000200
/** Free Queue Selection
    FSQM Queue selection for LSA freeing. */
#define ICTRLG_DMAW_CFG_FREEQ 0x00000100
/* Select Queue 0 (Note: Usage is prohibited!)
#define ICTRLG_DMAW_CFG_FREEQ_Q0 0x00000000 */
/** Select Queue 1 (Default) */
#define ICTRLG_DMAW_CFG_FREEQ_Q1 0x00000100
/** FSQM LSA Request Limitation
    This is the number of wait cycles until a LSA request to FSQM issues an error. */
#define ICTRLG_DMAW_CFG_LSARLMT_MASK 0x000000FF
/** field offset */
#define ICTRLG_DMAW_CFG_LSARLMT_OFFSET 0

/* Fields of "Reassembly Timeout Control Register" */
/** Limit for Reassembly Timeout Counter
    This value determines the time budget for a fragmented PDU.When the budged is consumed the packet is dropped.0x0: no check0x1: approx. 3.2ns0xFFFF_FFFF: approx. 13,7sNote: The values are based on 312.5MHz core clock frequency. */
#define ICTRLG_TIMEOUT_LIMIT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_TIMEOUT_LIMIT_OFFSET 0

/* Fields of "Maximum allowed Size for PDU Type 0" */
/** Size
    This register holds the size in bytes.0x0: no check */
#define ICTRLG_MAXSIZE0_SIZE_MASK 0x0000FFFF
/** field offset */
#define ICTRLG_MAXSIZE0_SIZE_OFFSET 0

/* Fields of "Maximum allowed Size for PDU Type 1" */
/** Size
    This register holds the size in bytes.0x0: no check */
#define ICTRLG_MAXSIZE1_SIZE_MASK 0x0000FFFF
/** field offset */
#define ICTRLG_MAXSIZE1_SIZE_OFFSET 0

/* Fields of "Maximum allowed Size for PDU Type 2" */
/** Size
    This register holds the size in bytes.0x0: no check */
#define ICTRLG_MAXSIZE2_SIZE_MASK 0x0000FFFF
/** field offset */
#define ICTRLG_MAXSIZE2_SIZE_OFFSET 0

/* Fields of "Maximum allowed Size for PDU Type 3" */
/** Size
    This register holds the size in bytes.0x0: no check */
#define ICTRLG_MAXSIZE3_SIZE_MASK 0x0000FFFF
/** field offset */
#define ICTRLG_MAXSIZE3_SIZE_OFFSET 0

/* Fields of "Maximum allowed Size for PDU Type 4" */
/** Size
    This register holds the size in bytes.0x0: no check */
#define ICTRLG_MAXSIZE4_SIZE_MASK 0x0000FFFF
/** field offset */
#define ICTRLG_MAXSIZE4_SIZE_OFFSET 0

/* Fields of "Maximum allowed Size for PDU Type 5" */
/** Size
    This register holds the size in bytes.0x0: no check */
#define ICTRLG_MAXSIZE5_SIZE_MASK 0x0000FFFF
/** field offset */
#define ICTRLG_MAXSIZE5_SIZE_OFFSET 0

/* Fields of "Maximum allowed Size for PDU Type 6" */
/** Size
    This register holds the size in bytes.0x0: no check */
#define ICTRLG_MAXSIZE6_SIZE_MASK 0x0000FFFF
/** field offset */
#define ICTRLG_MAXSIZE6_SIZE_OFFSET 0

/* Fields of "Maximum allowed Size for PDU Type 7" */
/** Size
    This register holds the size in bytes.0x0: no check */
#define ICTRLG_MAXSIZE7_SIZE_MASK 0x0000FFFF
/** field offset */
#define ICTRLG_MAXSIZE7_SIZE_OFFSET 0

/* Fields of "Total Received Bytes Counter (Low Part)" */
/** Counter
    Counter value (Low Part).Note: First the Low and then the High Part has to be read. */
#define ICTRLG_RXBCNTL_CNT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_RXBCNTL_CNT_OFFSET 0

/* Fields of "Total Received Bytes Counter (High Part)" */
/** Counter
    Counter value (High Part).Note: First the Low and then the High Part has to be read. */
#define ICTRLG_RXBCNTH_CNT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_RXBCNTH_CNT_OFFSET 0

/* Fields of "Oversized non-OMCI PDUs Counter" */
/** Counter
    This register holds the counter value. */
#define ICTRLG_OVRSIZE_CNT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_OVRSIZE_CNT_OFFSET 0

/* Fields of "DMAW Error Counter" */
/** Counter
    This register holds the counter value. */
#define ICTRLG_DMAWERR_CNT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_DMAWERR_CNT_OFFSET 0

/* Fields of "OMCI Message Discard Counter" */
/** Counter
    This register holds the counter value. */
#define ICTRLG_BADOMCI_CNT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_BADOMCI_CNT_OFFSET 0

/* Fields of "Ethernet FCS Error Counter" */
/** Counter
    This register holds the counter value. */
#define ICTRLG_FCSERR_CNT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_FCSERR_CNT_OFFSET 0

/* Fields of "Reassembly Error Counter" */
/** Counter
    This register holds the counter value. */
#define ICTRLG_REASSERR_CNT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_REASSERR_CNT_OFFSET 0

/* Fields of "Undersized Ethernet Frames Counter" */
/** Counter
    This register holds the counter value. */
#define ICTRLG_UNDSIZE_CNT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_UNDSIZE_CNT_OFFSET 0

/* Fields of "Non-OMCI Packet Discard Counter" */
/** Counter
    This register holds the counter value. */
#define ICTRLG_PDC_CNT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_PDC_CNT_OFFSET 0

/* Fields of "Total Received PDUs Counter" */
/** Counter
    This register holds the counter value. */
#define ICTRLG_RXTPCNT_CNT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_RXTPCNT_CNT_OFFSET 0

/* Fields of "IRN Capture Register" */
/** DMAW Out of FIFO Error
    Indicates that the IQM fifo was full when trying to enqueue the PDU.This bit contributes to the ICTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define ICTRLG_IRNCR_DMAWOOF 0x04000000
/* Nothing
#define ICTRLG_IRNCR_DMAWOOF_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define ICTRLG_IRNCR_DMAWOOF_INTACK 0x04000000
/** Read: Interrupt occurred. */
#define ICTRLG_IRNCR_DMAWOOF_INTOCC 0x04000000
/** DMAW Out Of Memory Error
    Indicates that the LSA request to FSQM returned NIL.This bit contributes to the ICTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define ICTRLG_IRNCR_DMAWOOM 0x02000000
/* Nothing
#define ICTRLG_IRNCR_DMAWOOM_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define ICTRLG_IRNCR_DMAWOOM_INTACK 0x02000000
/** Read: Interrupt occurred. */
#define ICTRLG_IRNCR_DMAWOOM_INTOCC 0x02000000
/** DMAW Timeout Error
    Indicates that the LSA request to FSQM went into timeout.This bit contributes to the ICTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define ICTRLG_IRNCR_DMAWTMO 0x01000000
/* Nothing
#define ICTRLG_IRNCR_DMAWTMO_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define ICTRLG_IRNCR_DMAWTMO_INTACK 0x01000000
/** Read: Interrupt occurred. */
#define ICTRLG_IRNCR_DMAWTMO_INTOCC 0x01000000
/** Minimum Size non-OMCI PDU Under-run
    Indicates that a non-OMCI PDU has under-run the minimum size of 5 bytes.This bit contributes to the ICTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define ICTRLG_IRNCR_MINSIZE 0x00400000
/* Nothing
#define ICTRLG_IRNCR_MINSIZE_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define ICTRLG_IRNCR_MINSIZE_INTACK 0x00400000
/** Read: Interrupt occurred. */
#define ICTRLG_IRNCR_MINSIZE_INTOCC 0x00400000
/** Reassembly Timeout Error
    Indicates that a reassembly timeout has occurred.This bit contributes to the ICTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define ICTRLG_IRNCR_REASSERR 0x00200000
/* Nothing
#define ICTRLG_IRNCR_REASSERR_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define ICTRLG_IRNCR_REASSERR_INTACK 0x00200000
/** Read: Interrupt occurred. */
#define ICTRLG_IRNCR_REASSERR_INTOCC 0x00200000
/** Invalid GPIX Error
    Indicates that the GPID has pointed to an invalid GPIX, i.e. GPT[GPID].VALID = 0.This bit contributes to the ICTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define ICTRLG_IRNCR_INVGPIX 0x00100000
/* Nothing
#define ICTRLG_IRNCR_INVGPIX_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define ICTRLG_IRNCR_INVGPIX_INTACK 0x00100000
/** Read: Interrupt occurred. */
#define ICTRLG_IRNCR_INVGPIX_INTOCC 0x00100000
/** Active Channels Overflow
    Indicates that the number of active channels has exceeded the maximum number of 2.This bit contributes to the ICTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define ICTRLG_IRNCR_ACTCHAN 0x00080000
/* Nothing
#define ICTRLG_IRNCR_ACTCHAN_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define ICTRLG_IRNCR_ACTCHAN_INTACK 0x00080000
/** Read: Interrupt occurred. */
#define ICTRLG_IRNCR_ACTCHAN_INTOCC 0x00080000
/** FCS Error
    Indicates that the Ethernet frame FCS check has failed.Note: There is no FCS check for oversized Ethernet frames.This bit contributes to the ICTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define ICTRLG_IRNCR_FCSERR 0x00040000
/* Nothing
#define ICTRLG_IRNCR_FCSERR_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define ICTRLG_IRNCR_FCSERR_INTACK 0x00040000
/** Read: Interrupt occurred. */
#define ICTRLG_IRNCR_FCSERR_INTOCC 0x00040000
/** Bad OMCI Error
    Indicates that one of the following OMCI errors has occurred:- Oversize Errors (PLI MAXSIZE && MAXSIZE 0 && PDUT == OMCI)- Minimum Size Under-run (PLI - CRC Errors- DMAW Errors- Reassembly Timeout ErrorThis bit contributes to the ICTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define ICTRLG_IRNCR_BADOMCI 0x00020000
/* Nothing
#define ICTRLG_IRNCR_BADOMCI_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define ICTRLG_IRNCR_BADOMCI_INTACK 0x00020000
/** Read: Interrupt occurred. */
#define ICTRLG_IRNCR_BADOMCI_INTOCC 0x00020000
/** Oversized non-OMCI PDU Error
    Indicates that a non-OMCI PDU has been oversized, i.e.sum(PLI) MAXSIZE && MAXSIZE 0 && PDUT != OMCIThis bit contributes to the ICTRLG_ERR interrupt. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define ICTRLG_IRNCR_OVRSIZE 0x00010000
/* Nothing
#define ICTRLG_IRNCR_OVRSIZE_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define ICTRLG_IRNCR_OVRSIZE_INTACK 0x00010000
/** Read: Interrupt occurred. */
#define ICTRLG_IRNCR_OVRSIZE_INTOCC 0x00010000

/* Fields of "IRN Interrupt Control Register" */
/** DMAW Out of FIFO Error
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNICR_DMAWOOF 0x04000000
/** DMAW Out Of Memory Error
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNICR_DMAWOOM 0x02000000
/** DMAW Timeout Error
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNICR_DMAWTMO 0x01000000
/** Minimum Size non-OMCI PDU Under-run
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNICR_MINSIZE 0x00400000
/** Reassembly Timeout Error
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNICR_REASSERR 0x00200000
/** Invalid GPIX Error
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNICR_INVGPIX 0x00100000
/** Active Channels Overflow
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNICR_ACTCHAN 0x00080000
/** FCS Error
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNICR_FCSERR 0x00040000
/** Bad OMCI Error
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNICR_BADOMCI 0x00020000
/** Oversized non-OMCI PDU Error
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNICR_OVRSIZE 0x00010000

/* Fields of "IRN Interrupt Enable Register" */
/** DMAW Out of FIFO Error
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNEN_DMAWOOF 0x04000000
/* Disable
#define ICTRLG_IRNEN_DMAWOOF_DIS 0x00000000 */
/** Enable */
#define ICTRLG_IRNEN_DMAWOOF_EN 0x04000000
/** DMAW Out Of Memory Error
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNEN_DMAWOOM 0x02000000
/* Disable
#define ICTRLG_IRNEN_DMAWOOM_DIS 0x00000000 */
/** Enable */
#define ICTRLG_IRNEN_DMAWOOM_EN 0x02000000
/** DMAW Timeout Error
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNEN_DMAWTMO 0x01000000
/* Disable
#define ICTRLG_IRNEN_DMAWTMO_DIS 0x00000000 */
/** Enable */
#define ICTRLG_IRNEN_DMAWTMO_EN 0x01000000
/** Minimum Size non-OMCI PDU Under-run
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNEN_MINSIZE 0x00400000
/* Disable
#define ICTRLG_IRNEN_MINSIZE_DIS 0x00000000 */
/** Enable */
#define ICTRLG_IRNEN_MINSIZE_EN 0x00400000
/** Reassembly Timeout Error
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNEN_REASSERR 0x00200000
/* Disable
#define ICTRLG_IRNEN_REASSERR_DIS 0x00000000 */
/** Enable */
#define ICTRLG_IRNEN_REASSERR_EN 0x00200000
/** Invalid GPIX Error
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNEN_INVGPIX 0x00100000
/* Disable
#define ICTRLG_IRNEN_INVGPIX_DIS 0x00000000 */
/** Enable */
#define ICTRLG_IRNEN_INVGPIX_EN 0x00100000
/** Active Channels Overflow
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNEN_ACTCHAN 0x00080000
/* Disable
#define ICTRLG_IRNEN_ACTCHAN_DIS 0x00000000 */
/** Enable */
#define ICTRLG_IRNEN_ACTCHAN_EN 0x00080000
/** FCS Error
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNEN_FCSERR 0x00040000
/* Disable
#define ICTRLG_IRNEN_FCSERR_DIS 0x00000000 */
/** Enable */
#define ICTRLG_IRNEN_FCSERR_EN 0x00040000
/** Bad OMCI Error
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNEN_BADOMCI 0x00020000
/* Disable
#define ICTRLG_IRNEN_BADOMCI_DIS 0x00000000 */
/** Enable */
#define ICTRLG_IRNEN_BADOMCI_EN 0x00020000
/** Oversized non-OMCI PDU Error
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define ICTRLG_IRNEN_OVRSIZE 0x00010000
/* Disable
#define ICTRLG_IRNEN_OVRSIZE_DIS 0x00000000 */
/** Enable */
#define ICTRLG_IRNEN_OVRSIZE_EN 0x00010000

/* Fields of "GEM Port Table" */
/** Valid Bit
    GEM Port Index valid flag.Note: Reset not valid (RAM)! */
#define ICTRLG_GPT_VALID 0x00000100
/* Not Valid
#define ICTRLG_GPT_VALID_NV 0x00000000 */
/** Valid */
#define ICTRLG_GPT_VALID_V 0x00000100
/** GEM Port Index
    The GPIX addresses the corresponding entry in GPIX_CFG.Note: Reset not valid (RAM)! */
#define ICTRLG_GPT_GPIX_MASK 0x000000FF
/** field offset */
#define ICTRLG_GPT_GPIX_OFFSET 0

/* Fields of "GEM Port Index Configuration" */
/** Ingress Queue Number
    Ingress queue number:0 - IQM queue 51 - IQM queue 62,3 - IQM queue 7Note: Reset not valid (RAM)! */
#define ICTRLG_GPIX_CFG_IQN_MASK 0x00000018
/** field offset */
#define ICTRLG_GPIX_CFG_IQN_OFFSET 3
/** PDU Type
    Indicates the base Protocol for each GEM portNote: Reset not valid (RAM)! */
#define ICTRLG_GPIX_CFG_PDUT_MASK 0x00000007
/** field offset */
#define ICTRLG_GPIX_CFG_PDUT_OFFSET 0

/* Fields of "GEM Port Index Received Frames Counter" */
/** Counter
    Counter value.Note: Reset not valid (RAM)! */
#define ICTRLG_GPIX_RXFCNT_CNT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_GPIX_RXFCNT_CNT_OFFSET 0

/* Fields of "GEM Port Index Received Bytes Counter (Low Part)" */
/** Counter
    Counter value (Low Part).Note 1: Reset not valid (RAM)!Note 2: First the Low and then the High Part has to be read. */
#define ICTRLG_GPIX_RXBCNTL_CNT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_GPIX_RXBCNTL_CNT_OFFSET 0

/* Fields of "GEM Port Index Received Bytes Counter (High Part)" */
/** Counter
    Counter value (High Part).Note 1: Reset not valid (RAM)!Note 2: First the Low and then the High Part has to be read. */
#define ICTRLG_GPIX_RXBCNTH_CNT_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLG_GPIX_RXBCNTH_CNT_OFFSET 0

/*! @} */ /* ICTRLG_REGISTER */

#endif /* _drv_onu_reg_ictrlg_h */
