/******************************************************************************

                               Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_reg_merge_h
#define _drv_onu_reg_merge_h

/** \addtogroup MERGE_REGISTER
   @{
*/
/* access macros */
#define merge_r32(reg) reg_r32(&merge->reg)
#define merge_w32(val, reg) reg_w32(val, &merge->reg)
#define merge_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &merge->reg)
#define merge_r32_table(reg, idx) reg_r32_table(merge->reg, idx)
#define merge_w32_table(val, reg, idx) reg_w32_table(val, merge->reg, idx)
#define merge_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, merge->reg, idx)
#define merge_adr_table(reg, idx) adr_table(merge->reg, idx)


/** MERGE register structure */
struct onu_reg_merge
{
   /** Control Register
       This register provides the global MERGE controls. */
   unsigned int ctrl; /* 0x00000000 */
   /** Thread Control Register 0
       This register controls wether a thread transmit data is served by the Merger unit.The register can be used to exclude threads from processing during regular operation.The control bits can be programmed any time, an ongoing transfer will not be effected. */
   unsigned int tctrl0; /* 0x00000004 */
   /** Thread Control Register 1
       This register controls wether a thread transmit data is served by the Merger unit.The register can be used to exclude threads from processing during regular operation.The control bits can be programmed any time, an ongoing transfer will not be effected. */
   unsigned int tctrl1; /* 0x00000008 */
   /** Thread Control Register 2
       This register controls wether a thread transmit data is served by the Merger unit.The register can be used to exclude threads from processing during regular operation.The control bits can be programmed any time, an ongoing transfer will not be effected. */
   unsigned int tctrl2; /* 0x0000000C */
   /** NIL Counter Register
       This register counts the generated nil interrupts. */
   unsigned int nilcounter; /* 0x00000010 */
   /** DISCARD Counter Register
       This register counts the generated discard interrupts. */
   unsigned int discardcounter; /* 0x00000014 */
   /** FSQM Queue
       This register selects the corresponding FSQM Queue for LSA Free commands. */
   unsigned int fsqmq; /* 0x00000018 */
   /** Reserved */
   unsigned int res_0; /* 0x0000001C */
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
   unsigned int res_1[17]; /* 0x0000002C */
   /** Address/Valid Register of LINK HOST
       This register controls the address of the read access for the link_host, and a valid signal if write or/and read of the LINK-Interface is activated. */
   unsigned int linkhost; /* 0x00000070 */
   /** Address/Valid Register of TMU LINK HOST
       This register controls the qid address of the read access for the link_host to the TMU, and a valid signal if write or/and read of the LINK-Interface is activated. */
   unsigned int tmulinkhost; /* 0x00000074 */
   /** Reserved */
   unsigned int res_2[2]; /* 0x00000078 */
   /** Control Register
       This register provides the global LINK Interface controls. The Link-Interface is an on-chip network which interconnects different on-chip modules. The CPU can use this interface to access this network. */
   unsigned int link_ctrl; /* 0x00000080 */
   /** Reserved */
   unsigned int res_3[3]; /* 0x00000084 */
   /** LINK_IRN Capture Register
       This register shows the currently active interrupt events masked with the corresponding enable bits of the LINK_IRNEN register. The interrupts can be acknowledged by a write operation. */
   unsigned int link_irncr; /* 0x00000090 */
   /** LINK_IRN Interrupt Control Register
       A write operation directly effects the interrupts. This can be used to trigger events under software control for testing purposes. A read operation returns the unmasked interrupt events. */
   unsigned int link_irnicr; /* 0x00000094 */
   /** LINK_IRN Interrupt Enable Register
       This register contains the enable (or mask) bits for the interrupts. Disabled interrupts are not visible in the LINK_IRNCR register and are not signalled via the interrupt line towards the controller. */
   unsigned int link_irnen; /* 0x00000098 */
   /** Reserved */
   unsigned int res_4; /* 0x0000009C */
   /** Length Register
       Holds the FIFO Lenght for the Receive FIFO */
   unsigned int link_len; /* 0x000000A0 */
   /** Data Register 0
       Receive data Register 0 */
   unsigned int link_data0; /* 0x000000A4 */
   /** Data Register 1
       Receive data Register 1 */
   unsigned int link_data1; /* 0x000000A8 */
   /** Reserved */
   unsigned int res_5[5]; /* 0x000000AC */
   /** Control Register
       This register provides the global LINK Interface controls. The Link-Interface is an on-chip network which interconnects different on-chip modules. The CPU can use this interface to access this network. */
   unsigned int tmu_link_ctrl; /* 0x000000C0 */
   /** Reserved */
   unsigned int res_6[3]; /* 0x000000C4 */
   /** TMU_LINK_IRN Capture Register
       This register shows the currently active interrupt events masked with the corresponding enable bits of the TMU_LINK_IRNEN register. The interrupts can be acknowledged by a write operation. */
   unsigned int tmu_link_irncr; /* 0x000000D0 */
   /** TMU_LINK_IRN Interrupt Control Register
       A write operation directly effects the interrupts. This can be used to trigger events under software control for testing purposes. A read operation returns the unmasked interrupt events. */
   unsigned int tmu_link_irnicr; /* 0x000000D4 */
   /** TMU_LINK_IRN Interrupt Enable Register
       This register contains the enable (or mask) bits for the interrupts. Disabled interrupts are not visible in the TMU_LINK_IRNCR register and are not signalled via the interrupt line towards the controller. */
   unsigned int tmu_link_irnen; /* 0x000000D8 */
   /** Reserved */
   unsigned int res_7; /* 0x000000DC */
   /** Length Register
       Holds the FIFO Lenght for the Receive FIFO */
   unsigned int tmu_link_len; /* 0x000000E0 */
   /** Data Register 0
       Receive data Register 0 */
   unsigned int tmu_link_data0; /* 0x000000E4 */
   /** Data Register 1
       Receive data Register 1 */
   unsigned int tmu_link_data1; /* 0x000000E8 */
   /** Reserved */
   unsigned int res_8[5]; /* 0x000000EC */
};


/* Fields of "Control Register" */
/** DEACTIVATION OF TIMEOUT SORT INTERRUPT
    This bit deactivates the Timeout Interrupt in the sorter. */
#define MERGE_CTRL_TIMEOUTDEACT 0x00001000
/** RAM INITIALIZATION DONE
    This bit gives the status of the RAM initialization for the sort RAM. */
#define MERGE_CTRL_INITDONE 0x00000100
/** START RAM INITIALIZATION
    This bit starts the RAM initialization for the sort RAM. */
#define MERGE_CTRL_INITSTART 0x00000010
/* Disable
#define MERGE_CTRL_INITSTART_DIS 0x00000000 */
/** Enable */
#define MERGE_CTRL_INITSTART_EN 0x00000010
/** Freeze Output Path
    This bit freezes the output path to the interfaces FSQM, SSB and TMU. */
#define MERGE_CTRL_FRZO 0x00000004
/* Disable
#define MERGE_CTRL_FRZO_DIS 0x00000000 */
/** Enable */
#define MERGE_CTRL_FRZO_EN 0x00000004
/** Freeze Input Path
    This bit freezes the input path from the PEs. */
#define MERGE_CTRL_FRZI 0x00000002
/* Disable
#define MERGE_CTRL_FRZI_DIS 0x00000000 */
/** Enable */
#define MERGE_CTRL_FRZI_EN 0x00000002
/** Activate Module
    This bit enables the dispatcher module. Only for startup scenarios sensfull (deactivation brings the module not in a defined state!) */
#define MERGE_CTRL_ACT 0x00000001
/* Disable
#define MERGE_CTRL_ACT_DIS 0x00000000 */
/** Enable */
#define MERGE_CTRL_ACT_EN 0x00000001

/* Fields of "Thread Control Register 0" */
/** Thread 2.1.3
    Enable packet header data from PE 2, Virtual Machine 1, Thread 3. */
#define MERGE_TCTRL0_T213 0x80000000
/* Disable
#define MERGE_TCTRL0_T213_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T213_EN 0x80000000
/** Thread 2.1.2
    Enable packet header data from PE 2, Virtual Machine 1, Thread 2. */
#define MERGE_TCTRL0_T212 0x40000000
/* Disable
#define MERGE_TCTRL0_T212_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T212_EN 0x40000000
/** Thread 2.1.1
    Enable packet header data from PE 2, Virtual Machine 1, Thread 1. */
#define MERGE_TCTRL0_T211 0x20000000
/* Disable
#define MERGE_TCTRL0_T211_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T211_EN 0x20000000
/** Thread 2.1.0
    Enable packet header data from PE 2, Virtual Machine 1, Thread 0. */
#define MERGE_TCTRL0_T210 0x10000000
/* Disable
#define MERGE_TCTRL0_T210_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T210_EN 0x10000000
/** Thread 2.0.3
    Enable packet header data from PE 2, Virtual Machine 0, Thread 3. */
#define MERGE_TCTRL0_T203 0x08000000
/* Disable
#define MERGE_TCTRL0_T203_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T203_EN 0x08000000
/** Thread 2.0.2
    Enable packet header data from PE 2, Virtual Machine 0, Thread 2. */
#define MERGE_TCTRL0_T202 0x04000000
/* Disable
#define MERGE_TCTRL0_T202_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T202_EN 0x04000000
/** Thread 2.0.1
    Enable packet header data from PE 2, Virtual Machine 0, Thread 1. */
#define MERGE_TCTRL0_T201 0x02000000
/* Disable
#define MERGE_TCTRL0_T201_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T201_EN 0x02000000
/** Thread 2.0.0
    Enable packet header data from PE 2, Virtual Machine 0, Thread 0. */
#define MERGE_TCTRL0_T200 0x01000000
/* Disable
#define MERGE_TCTRL0_T200_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T200_EN 0x01000000
/** Thread 1.2.3
    Enable packet header data from PE 1, Virtual Machine 2, Thread 3. */
#define MERGE_TCTRL0_T123 0x00800000
/* Disable
#define MERGE_TCTRL0_T123_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T123_EN 0x00800000
/** Thread 1.2.2
    Enable packet header data from PE 1, Virtual Machine 2, Thread 2. */
#define MERGE_TCTRL0_T122 0x00400000
/* Disable
#define MERGE_TCTRL0_T122_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T122_EN 0x00400000
/** Thread 1.2.1
    Enable packet header data from PE 1, Virtual Machine 2, Thread 1. */
#define MERGE_TCTRL0_T121 0x00200000
/* Disable
#define MERGE_TCTRL0_T121_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T121_EN 0x00200000
/** Thread 1.2.0
    Enable packet header data from PE 1, Virtual Machine 2, Thread 0. */
#define MERGE_TCTRL0_T120 0x00100000
/* Disable
#define MERGE_TCTRL0_T120_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T120_EN 0x00100000
/** Thread 1.1.3
    Enable packet header data from PE 1, Virtual Machine 1, Thread 3. */
#define MERGE_TCTRL0_T113 0x00080000
/* Disable
#define MERGE_TCTRL0_T113_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T113_EN 0x00080000
/** Thread 1.1.2
    Enable packet header data from PE 1, Virtual Machine 1, Thread 2. */
#define MERGE_TCTRL0_T112 0x00040000
/* Disable
#define MERGE_TCTRL0_T112_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T112_EN 0x00040000
/** Thread 1.1.1
    Enable packet header data from PE 1, Virtual Machine 1, Thread 1. */
#define MERGE_TCTRL0_T111 0x00020000
/* Disable
#define MERGE_TCTRL0_T111_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T111_EN 0x00020000
/** Thread 1.1.0
    Enable packet header data from PE 1, Virtual Machine 1, Thread 0. */
#define MERGE_TCTRL0_T110 0x00010000
/* Disable
#define MERGE_TCTRL0_T110_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T110_EN 0x00010000
/** Thread 1.0.3
    Enable packet header data from PE 1, Virtual Machine 0, Thread 3. */
#define MERGE_TCTRL0_T103 0x00008000
/* Disable
#define MERGE_TCTRL0_T103_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T103_EN 0x00008000
/** Thread 1.0.2
    Enable packet header data from PE 1, Virtual Machine 0, Thread 2. */
#define MERGE_TCTRL0_T102 0x00004000
/* Disable
#define MERGE_TCTRL0_T102_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T102_EN 0x00004000
/** Thread 1.0.1
    Enable packet header data from PE 1, Virtual Machine 0, Thread 1. */
#define MERGE_TCTRL0_T101 0x00002000
/* Disable
#define MERGE_TCTRL0_T101_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T101_EN 0x00002000
/** Thread 1.0.0
    Enable packet header data from PE 1, Virtual Machine 0, Thread 0. */
#define MERGE_TCTRL0_T100 0x00001000
/* Disable
#define MERGE_TCTRL0_T100_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T100_EN 0x00001000
/** Thread 0.2.3
    Enable packet header data from PE 0, Virtual Machine 2, Thread 3. */
#define MERGE_TCTRL0_T023 0x00000800
/* Disable
#define MERGE_TCTRL0_T023_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T023_EN 0x00000800
/** Thread 0.2.2
    Enable packet header data from PE 0, Virtual Machine 2, Thread 2. */
#define MERGE_TCTRL0_T022 0x00000400
/* Disable
#define MERGE_TCTRL0_T022_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T022_EN 0x00000400
/** Thread 0.2.1
    Enable packet header data from PE 0, Virtual Machine 2, Thread 1. */
#define MERGE_TCTRL0_T021 0x00000200
/* Disable
#define MERGE_TCTRL0_T021_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T021_EN 0x00000200
/** Thread 0.2.0
    Enable packet header data from PE 0, Virtual Machine 2, Thread 0. */
#define MERGE_TCTRL0_T020 0x00000100
/* Disable
#define MERGE_TCTRL0_T020_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T020_EN 0x00000100
/** Thread 0.1.3
    Enable packet header data from PE 0, Virtual Machine 1, Thread 3. */
#define MERGE_TCTRL0_T013 0x00000080
/* Disable
#define MERGE_TCTRL0_T013_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T013_EN 0x00000080
/** Thread 0.1.2
    Enable packet header data from PE 0, Virtual Machine 1, Thread 2. */
#define MERGE_TCTRL0_T012 0x00000040
/* Disable
#define MERGE_TCTRL0_T012_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T012_EN 0x00000040
/** Thread 0.1.1
    Enable packet header data from PE 0, Virtual Machine 1, Thread 1. */
#define MERGE_TCTRL0_T011 0x00000020
/* Disable
#define MERGE_TCTRL0_T011_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T011_EN 0x00000020
/** Thread 0.1.0
    Enable packet header data from PE 0, Virtual Machine 1, Thread 0. */
#define MERGE_TCTRL0_T010 0x00000010
/* Disable
#define MERGE_TCTRL0_T010_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T010_EN 0x00000010
/** Thread 0.0.3
    Enable packet header data from PE 0, Virtual Machine 0, Thread 3. */
#define MERGE_TCTRL0_T003 0x00000008
/* Disable
#define MERGE_TCTRL0_T003_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T003_EN 0x00000008
/** Thread 0.0.2
    Enable packet header data from PE 0, Virtual Machine 0, Thread 2. */
#define MERGE_TCTRL0_T002 0x00000004
/* Disable
#define MERGE_TCTRL0_T002_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T002_EN 0x00000004
/** Thread 0.0.1
    Enable packet header data from PE 0, Virtual Machine 0, Thread 1. */
#define MERGE_TCTRL0_T001 0x00000002
/* Disable
#define MERGE_TCTRL0_T001_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T001_EN 0x00000002
/** Thread 0.0.0
    Enable packet header data from PE 0, Virtual Machine 0, Thread 0. */
#define MERGE_TCTRL0_T000 0x00000001
/* Disable
#define MERGE_TCTRL0_T000_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL0_T000_EN 0x00000001

/* Fields of "Thread Control Register 1" */
/** Thread 5.0.3
    Enable packet header data from PE 5, Virtual Machine 0, Thread 3. */
#define MERGE_TCTRL1_T503 0x80000000
/* Disable
#define MERGE_TCTRL1_T503_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T503_EN 0x80000000
/** Thread 5.0.2
    Enable packet header data from PE 5, Virtual Machine 0, Thread 2. */
#define MERGE_TCTRL1_T502 0x40000000
/* Disable
#define MERGE_TCTRL1_T502_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T502_EN 0x40000000
/** Thread 5.0.1
    Enable packet header data from PE 5, Virtual Machine 0, Thread 1. */
#define MERGE_TCTRL1_T501 0x20000000
/* Disable
#define MERGE_TCTRL1_T501_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T501_EN 0x20000000
/** Thread 5.0.0
    Enable packet header data from PE 5, Virtual Machine 0, Thread 0. */
#define MERGE_TCTRL1_T500 0x10000000
/* Disable
#define MERGE_TCTRL1_T500_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T500_EN 0x10000000
/** Thread 4.2.3
    Enable packet header data from PE 4, Virtual Machine 2, Thread 3. */
#define MERGE_TCTRL1_T423 0x08000000
/* Disable
#define MERGE_TCTRL1_T423_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T423_EN 0x08000000
/** Thread 4.2.2
    Enable packet header data from PE 4, Virtual Machine 2, Thread 2. */
#define MERGE_TCTRL1_T422 0x04000000
/* Disable
#define MERGE_TCTRL1_T422_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T422_EN 0x04000000
/** Thread 4.2.1
    Enable packet header data from PE 4, Virtual Machine 2, Thread 1. */
#define MERGE_TCTRL1_T421 0x02000000
/* Disable
#define MERGE_TCTRL1_T421_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T421_EN 0x02000000
/** Thread 4.2.0
    Enable packet header data from PE 4, Virtual Machine 2, Thread 0. */
#define MERGE_TCTRL1_T420 0x01000000
/* Disable
#define MERGE_TCTRL1_T420_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T420_EN 0x01000000
/** Thread 4.1.3
    Enable packet header data from PE 4, Virtual Machine 1, Thread 3. */
#define MERGE_TCTRL1_T413 0x00800000
/* Disable
#define MERGE_TCTRL1_T413_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T413_EN 0x00800000
/** Thread 4.1.2
    Enable packet header data from PE 4, Virtual Machine 1, Thread 2. */
#define MERGE_TCTRL1_T412 0x00400000
/* Disable
#define MERGE_TCTRL1_T412_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T412_EN 0x00400000
/** Thread 4.1.1
    Enable packet header data from PE 4, Virtual Machine 1, Thread 1. */
#define MERGE_TCTRL1_T411 0x00200000
/* Disable
#define MERGE_TCTRL1_T411_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T411_EN 0x00200000
/** Thread 4.1.0
    Enable packet header data from PE 4, Virtual Machine 1, Thread 0. */
#define MERGE_TCTRL1_T410 0x00100000
/* Disable
#define MERGE_TCTRL1_T410_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T410_EN 0x00100000
/** Thread 4.0.3
    Enable packet header data from PE 4, Virtual Machine 0, Thread 3. */
#define MERGE_TCTRL1_T403 0x00080000
/* Disable
#define MERGE_TCTRL1_T403_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T403_EN 0x00080000
/** Thread 4.0.2
    Enable packet header data from PE 4, Virtual Machine 0, Thread 2. */
#define MERGE_TCTRL1_T402 0x00040000
/* Disable
#define MERGE_TCTRL1_T402_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T402_EN 0x00040000
/** Thread 4.0.1
    Enable packet header data from PE 4, Virtual Machine 0, Thread 1. */
#define MERGE_TCTRL1_T401 0x00020000
/* Disable
#define MERGE_TCTRL1_T401_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T401_EN 0x00020000
/** Thread 4.0.0
    Enable packet header data from PE 4, Virtual Machine 0, Thread 0. */
#define MERGE_TCTRL1_T400 0x00010000
/* Disable
#define MERGE_TCTRL1_T400_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T400_EN 0x00010000
/** Thread 3.2.3
    Enable packet header data from PE 3, Virtual Machine 2, Thread 3. */
#define MERGE_TCTRL1_T323 0x00008000
/* Disable
#define MERGE_TCTRL1_T323_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T323_EN 0x00008000
/** Thread 3.2.2
    Enable packet header data from PE 3, Virtual Machine 2, Thread 2. */
#define MERGE_TCTRL1_T322 0x00004000
/* Disable
#define MERGE_TCTRL1_T322_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T322_EN 0x00004000
/** Thread 3.2.1
    Enable packet header data from PE 3, Virtual Machine 2, Thread 1. */
#define MERGE_TCTRL1_T321 0x00002000
/* Disable
#define MERGE_TCTRL1_T321_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T321_EN 0x00002000
/** Thread 3.2.0
    Enable packet header data from PE 3, Virtual Machine 2, Thread 0. */
#define MERGE_TCTRL1_T320 0x00001000
/* Disable
#define MERGE_TCTRL1_T320_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T320_EN 0x00001000
/** Thread 3.1.3
    Enable packet header data from PE 3, Virtual Machine 1, Thread 3. */
#define MERGE_TCTRL1_T313 0x00000800
/* Disable
#define MERGE_TCTRL1_T313_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T313_EN 0x00000800
/** Thread 3.1.2
    Enable packet header data from PE 3, Virtual Machine 1, Thread 2. */
#define MERGE_TCTRL1_T312 0x00000400
/* Disable
#define MERGE_TCTRL1_T312_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T312_EN 0x00000400
/** Thread 3.1.1
    Enable packet header data from PE 3, Virtual Machine 1, Thread 1. */
#define MERGE_TCTRL1_T311 0x00000200
/* Disable
#define MERGE_TCTRL1_T311_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T311_EN 0x00000200
/** Thread 3.1.0
    Enable packet header data from PE 3, Virtual Machine 1, Thread 0. */
#define MERGE_TCTRL1_T310 0x00000100
/* Disable
#define MERGE_TCTRL1_T310_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T310_EN 0x00000100
/** Thread 3.0.3
    Enable packet header data from PE 3, Virtual Machine 0, Thread 3. */
#define MERGE_TCTRL1_T303 0x00000080
/* Disable
#define MERGE_TCTRL1_T303_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T303_EN 0x00000080
/** Thread 3.0.2
    Enable packet header data from PE 3, Virtual Machine 0, Thread 2. */
#define MERGE_TCTRL1_T302 0x00000040
/* Disable
#define MERGE_TCTRL1_T302_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T302_EN 0x00000040
/** Thread 3.0.1
    Enable packet header data from PE 3, Virtual Machine 0, Thread 1. */
#define MERGE_TCTRL1_T301 0x00000020
/* Disable
#define MERGE_TCTRL1_T301_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T301_EN 0x00000020
/** Thread 3.0.0
    Enable packet header data from PE 3, Virtual Machine 0, Thread 0. */
#define MERGE_TCTRL1_T300 0x00000010
/* Disable
#define MERGE_TCTRL1_T300_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T300_EN 0x00000010
/** Thread 2.2.3
    Enable packet header data from PE 2, Virtual Machine 2, Thread 3. */
#define MERGE_TCTRL1_T223 0x00000008
/* Disable
#define MERGE_TCTRL1_T223_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T223_EN 0x00000008
/** Thread 2.2.2
    Enable packet header data from PE 2, Virtual Machine 2, Thread 2. */
#define MERGE_TCTRL1_T222 0x00000004
/* Disable
#define MERGE_TCTRL1_T222_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T222_EN 0x00000004
/** Thread 2.2.1
    Enable packet header data from PE 2, Virtual Machine 2, Thread 1. */
#define MERGE_TCTRL1_T221 0x00000002
/* Disable
#define MERGE_TCTRL1_T221_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T221_EN 0x00000002
/** Thread 2.2.0
    Enable packet header data from PE 2, Virtual Machine 2, Thread 0. */
#define MERGE_TCTRL1_T220 0x00000001
/* Disable
#define MERGE_TCTRL1_T220_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL1_T220_EN 0x00000001

/* Fields of "Thread Control Register 2" */
/** CPU Link 1.3
    Enable packet header data from CPU Link 1, Channel 3 */
#define MERGE_TCTRL2_T613 0x00008000
/* Disable
#define MERGE_TCTRL2_T613_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T613_EN 0x00008000
/** CPU Link 1.2
    Enable packet header data from CPU Link 1, Channel 2 */
#define MERGE_TCTRL2_T612 0x00004000
/* Disable
#define MERGE_TCTRL2_T612_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T612_EN 0x00004000
/** CPU Link 1.1
    Enable packet header data from CPU Link 1, Channel 1 */
#define MERGE_TCTRL2_T611 0x00002000
/* Disable
#define MERGE_TCTRL2_T611_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T611_EN 0x00002000
/** CPU Link 1.0
    Enable packet header data from CPU Link 1, Channel 0 */
#define MERGE_TCTRL2_T610 0x00001000
/* Disable
#define MERGE_TCTRL2_T610_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T610_EN 0x00001000
/** CPU Link 0.3
    Enable packet header data from CPU Link 0, Channel 3 */
#define MERGE_TCTRL2_T603 0x00000800
/* Disable
#define MERGE_TCTRL2_T603_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T603_EN 0x00000800
/** CPU Link 0.2
    Enable packet header data from CPU Link 0, Channel 2 */
#define MERGE_TCTRL2_T602 0x00000400
/* Disable
#define MERGE_TCTRL2_T602_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T602_EN 0x00000400
/** CPU Link 0.1
    Enable packet header data from CPU Link 0, Channel 1 */
#define MERGE_TCTRL2_T601 0x00000200
/* Disable
#define MERGE_TCTRL2_T601_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T601_EN 0x00000200
/** CPU Link 0.0
    Enable packet header data from CPU Link 0, Channel 0 */
#define MERGE_TCTRL2_T600 0x00000100
/* Disable
#define MERGE_TCTRL2_T600_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T600_EN 0x00000100
/** Thread 5.2.3
    Enable packet header data from PE 5, Virtual Machine 2, Thread 3. */
#define MERGE_TCTRL2_T523 0x00000080
/* Disable
#define MERGE_TCTRL2_T523_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T523_EN 0x00000080
/** Thread 5.2.2
    Enable packet header data from PE 5, Virtual Machine 2, Thread 2. */
#define MERGE_TCTRL2_T522 0x00000040
/* Disable
#define MERGE_TCTRL2_T522_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T522_EN 0x00000040
/** Thread 5.2.1
    Enable packet header data from PE 5, Virtual Machine 2, Thread 1. */
#define MERGE_TCTRL2_T521 0x00000020
/* Disable
#define MERGE_TCTRL2_T521_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T521_EN 0x00000020
/** Thread 5.2.0
    Enable packet header data from PE 5, Virtual Machine 2, Thread 0. */
#define MERGE_TCTRL2_T520 0x00000010
/* Disable
#define MERGE_TCTRL2_T520_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T520_EN 0x00000010
/** Thread 5.1.3
    Enable packet header data from PE 5, Virtual Machine 1, Thread 3. */
#define MERGE_TCTRL2_T513 0x00000008
/* Disable
#define MERGE_TCTRL2_T513_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T513_EN 0x00000008
/** Thread 5.1.2
    Enable packet header data from PE 5, Virtual Machine 1, Thread 2. */
#define MERGE_TCTRL2_T512 0x00000004
/* Disable
#define MERGE_TCTRL2_T512_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T512_EN 0x00000004
/** Thread 5.1.1
    Enable packet header data from PE 5, Virtual Machine 1, Thread 1. */
#define MERGE_TCTRL2_T511 0x00000002
/* Disable
#define MERGE_TCTRL2_T511_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T511_EN 0x00000002
/** Thread 5.1.0
    Enable packet header data from PE 5, Virtual Machine 1, Thread 0. */
#define MERGE_TCTRL2_T510 0x00000001
/* Disable
#define MERGE_TCTRL2_T510_DIS 0x00000000 */
/** Enable */
#define MERGE_TCTRL2_T510_EN 0x00000001

/* Fields of "NIL Counter Register" */
/** NIL_Counter
    The counter of the NIL Interrupts */
#define MERGE_NILCOUNTER_NIL_MASK 0xFFFFFFFF
/** field offset */
#define MERGE_NILCOUNTER_NIL_OFFSET 0

/* Fields of "DISCARD Counter Register" */
/** DISCARD_Counter
    The counter of the Discard Interrupts */
#define MERGE_DISCARDCOUNTER_DISCARD_MASK 0xFFFFFFFF
/** field offset */
#define MERGE_DISCARDCOUNTER_DISCARD_OFFSET 0

/* Fields of "FSQM Queue" */
/** QUEUE SEL
    The bit switchs between the two queues in FSQM */
#define MERGE_FSQMQ_QUE 0x00000001

/* Fields of "IRN Capture Register" */
/** TDiscard
    This bit is set if discard) This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_IRNCR_DISCARD 0x00000800
/* Nothing
#define MERGE_IRNCR_DISCARD_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define MERGE_IRNCR_DISCARD_INTACK 0x00000800
/** Read: Interrupt occurred. */
#define MERGE_IRNCR_DISCARD_INTOCC 0x00000800
/** FSQM nil
    This bit is set if FSQM has no free segments) This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_IRNCR_NIL 0x00000400
/* Nothing
#define MERGE_IRNCR_NIL_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define MERGE_IRNCR_NIL_INTACK 0x00000400
/** Read: Interrupt occurred. */
#define MERGE_IRNCR_NIL_INTOCC 0x00000400
/** TBM calendar not free
    This bit is set if calendar entry is not free) This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_IRNCR_CALNOTFREE 0x00000200
/* Nothing
#define MERGE_IRNCR_CALNOTFREE_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define MERGE_IRNCR_CALNOTFREE_INTACK 0x00000200
/** Read: Interrupt occurred. */
#define MERGE_IRNCR_CALNOTFREE_INTOCC 0x00000200
/** Calendar8 timeout
    This bit is set if calendar 8 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_IRNCR_TIMEOUT8 0x00000100
/* Nothing
#define MERGE_IRNCR_TIMEOUT8_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define MERGE_IRNCR_TIMEOUT8_INTACK 0x00000100
/** Read: Interrupt occurred. */
#define MERGE_IRNCR_TIMEOUT8_INTOCC 0x00000100
/** Calendar7 timeout
    This bit is set if calendar 7 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_IRNCR_TIMEOUT7 0x00000080
/* Nothing
#define MERGE_IRNCR_TIMEOUT7_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define MERGE_IRNCR_TIMEOUT7_INTACK 0x00000080
/** Read: Interrupt occurred. */
#define MERGE_IRNCR_TIMEOUT7_INTOCC 0x00000080
/** Calendar6 timeout
    This bit is set if calendar 6 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_IRNCR_TIMEOUT6 0x00000040
/* Nothing
#define MERGE_IRNCR_TIMEOUT6_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define MERGE_IRNCR_TIMEOUT6_INTACK 0x00000040
/** Read: Interrupt occurred. */
#define MERGE_IRNCR_TIMEOUT6_INTOCC 0x00000040
/** Calendar5 timeout
    This bit is set if calendar 5 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_IRNCR_TIMEOUT5 0x00000020
/* Nothing
#define MERGE_IRNCR_TIMEOUT5_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define MERGE_IRNCR_TIMEOUT5_INTACK 0x00000020
/** Read: Interrupt occurred. */
#define MERGE_IRNCR_TIMEOUT5_INTOCC 0x00000020
/** Calendar4 timeout
    This bit is set if calendar 4 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_IRNCR_TIMEOUT4 0x00000010
/* Nothing
#define MERGE_IRNCR_TIMEOUT4_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define MERGE_IRNCR_TIMEOUT4_INTACK 0x00000010
/** Read: Interrupt occurred. */
#define MERGE_IRNCR_TIMEOUT4_INTOCC 0x00000010
/** Calendar3 timeout
    This bit is set if calendar 3 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_IRNCR_TIMEOUT3 0x00000008
/* Nothing
#define MERGE_IRNCR_TIMEOUT3_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define MERGE_IRNCR_TIMEOUT3_INTACK 0x00000008
/** Read: Interrupt occurred. */
#define MERGE_IRNCR_TIMEOUT3_INTOCC 0x00000008
/** Calendar2 timeout
    This bit is set if calendar 2 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_IRNCR_TIMEOUT2 0x00000004
/* Nothing
#define MERGE_IRNCR_TIMEOUT2_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define MERGE_IRNCR_TIMEOUT2_INTACK 0x00000004
/** Read: Interrupt occurred. */
#define MERGE_IRNCR_TIMEOUT2_INTOCC 0x00000004
/** Calendar1 timeout
    This bit is set if calendar 1 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_IRNCR_TIMEOUT1 0x00000002
/* Nothing
#define MERGE_IRNCR_TIMEOUT1_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define MERGE_IRNCR_TIMEOUT1_INTACK 0x00000002
/** Read: Interrupt occurred. */
#define MERGE_IRNCR_TIMEOUT1_INTOCC 0x00000002
/** Calendar0 timeout
    This bit is set if calendar 0 got a timeout This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_IRNCR_TIMEOUT0 0x00000001
/* Nothing
#define MERGE_IRNCR_TIMEOUT0_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define MERGE_IRNCR_TIMEOUT0_INTACK 0x00000001
/** Read: Interrupt occurred. */
#define MERGE_IRNCR_TIMEOUT0_INTOCC 0x00000001

/* Fields of "IRN Interrupt Control Register" */
/** TDiscard
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNICR_DISCARD 0x00000800
/** FSQM nil
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNICR_NIL 0x00000400
/** TBM calendar not free
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNICR_CALNOTFREE 0x00000200
/** Calendar8 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNICR_TIMEOUT8 0x00000100
/** Calendar7 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNICR_TIMEOUT7 0x00000080
/** Calendar6 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNICR_TIMEOUT6 0x00000040
/** Calendar5 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNICR_TIMEOUT5 0x00000020
/** Calendar4 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNICR_TIMEOUT4 0x00000010
/** Calendar3 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNICR_TIMEOUT3 0x00000008
/** Calendar2 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNICR_TIMEOUT2 0x00000004
/** Calendar1 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNICR_TIMEOUT1 0x00000002
/** Calendar0 timeout
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNICR_TIMEOUT0 0x00000001

/* Fields of "IRN Interrupt Enable Register" */
/** TDiscard
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNEN_DISCARD 0x00000800
/* Disable
#define MERGE_IRNEN_DISCARD_DIS 0x00000000 */
/** Enable */
#define MERGE_IRNEN_DISCARD_EN 0x00000800
/** FSQM nil
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNEN_NIL 0x00000400
/* Disable
#define MERGE_IRNEN_NIL_DIS 0x00000000 */
/** Enable */
#define MERGE_IRNEN_NIL_EN 0x00000400
/** TBM calendar not free
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNEN_CALNOTFREE 0x00000200
/* Disable
#define MERGE_IRNEN_CALNOTFREE_DIS 0x00000000 */
/** Enable */
#define MERGE_IRNEN_CALNOTFREE_EN 0x00000200
/** Calendar8 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNEN_TIMEOUT8 0x00000100
/* Disable
#define MERGE_IRNEN_TIMEOUT8_DIS 0x00000000 */
/** Enable */
#define MERGE_IRNEN_TIMEOUT8_EN 0x00000100
/** Calendar7 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNEN_TIMEOUT7 0x00000080
/* Disable
#define MERGE_IRNEN_TIMEOUT7_DIS 0x00000000 */
/** Enable */
#define MERGE_IRNEN_TIMEOUT7_EN 0x00000080
/** Calendar6 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNEN_TIMEOUT6 0x00000040
/* Disable
#define MERGE_IRNEN_TIMEOUT6_DIS 0x00000000 */
/** Enable */
#define MERGE_IRNEN_TIMEOUT6_EN 0x00000040
/** Calendar5 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNEN_TIMEOUT5 0x00000020
/* Disable
#define MERGE_IRNEN_TIMEOUT5_DIS 0x00000000 */
/** Enable */
#define MERGE_IRNEN_TIMEOUT5_EN 0x00000020
/** Calendar4 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNEN_TIMEOUT4 0x00000010
/* Disable
#define MERGE_IRNEN_TIMEOUT4_DIS 0x00000000 */
/** Enable */
#define MERGE_IRNEN_TIMEOUT4_EN 0x00000010
/** Calendar3 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNEN_TIMEOUT3 0x00000008
/* Disable
#define MERGE_IRNEN_TIMEOUT3_DIS 0x00000000 */
/** Enable */
#define MERGE_IRNEN_TIMEOUT3_EN 0x00000008
/** Calendar2 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNEN_TIMEOUT2 0x00000004
/* Disable
#define MERGE_IRNEN_TIMEOUT2_DIS 0x00000000 */
/** Enable */
#define MERGE_IRNEN_TIMEOUT2_EN 0x00000004
/** Calendar1 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNEN_TIMEOUT1 0x00000002
/* Disable
#define MERGE_IRNEN_TIMEOUT1_DIS 0x00000000 */
/** Enable */
#define MERGE_IRNEN_TIMEOUT1_EN 0x00000002
/** Calendar0 timeout
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define MERGE_IRNEN_TIMEOUT0 0x00000001
/* Disable
#define MERGE_IRNEN_TIMEOUT0_DIS 0x00000000 */
/** Enable */
#define MERGE_IRNEN_TIMEOUT0_EN 0x00000001

/* Fields of "Address/Valid Register of LINK HOST" */
/** Read valid
    This bit activates the LINK-Interface for reading. */
#define MERGE_LINKHOST_RVAL 0x00000100
/** Read address of LINK-Interface
    Stores the data of the choosed thread number if read is activated */
#define MERGE_LINKHOST_RADDR_MASK 0x0000007F
/** field offset */
#define MERGE_LINKHOST_RADDR_OFFSET 0

/* Fields of "Address/Valid Register of TMU LINK HOST" */
/** Read valid
    This bit activates the TMU LINK-Interface for reading. */
#define MERGE_TMULINKHOST_TMURVAL 0x01000000
/** activates all qids
    This bit activates all qid of the TMU LINK-Interface for reading. */
#define MERGE_TMULINKHOST_TMUALL 0x00010000
/** Read address of qid of TMU LINK-Interface
    Stores the data of the choosed qid number if read is activated */
#define MERGE_TMULINKHOST_TMURADDR_MASK 0x000001FF
/** field offset */
#define MERGE_TMULINKHOST_TMURADDR_OFFSET 0

/* Fields of "Control Register" */
/** Request pulse -- not supported for this instance
    When writing '1' to this bit, a request pulse is asserted. */
#define MERGE_LINK_CTRL_REQ 0x00000020
/** Reset Receiver
    When this bit is set the receiver is reseted */
#define MERGE_LINK_CTRL_RSR 0x00000008
/** Mark as Start-of-Packet
    On a read the information is returned whether the current 64bit word within DATA is signed as the first data packet (Start of Packet). */
#define MERGE_LINK_CTRL_SOP 0x00000002
/** Mark as End-of-Packet
    On a read the information is returned whether the current 64bit word within DATA is signed as the last data packet (End of Packet). */
#define MERGE_LINK_CTRL_EOP 0x00000001

/* Fields of "LINK_IRN Capture Register" */
/** Receive FIFO Ready
    This bit is set if the Recieve FIFO is not empty. This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_LINK_IRNCR_RXR 0x00000004
/* Nothing
#define MERGE_LINK_IRNCR_RXR_NULL 0x00000000 */
/** Read: Interrupt occurred. */
#define MERGE_LINK_IRNCR_RXR_INTOCC 0x00000004
/** Start-of-Packet
    This bit is set if the topmost receive FIFO entry is a start-of-packet This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_LINK_IRNCR_SOP 0x00000002
/* Nothing
#define MERGE_LINK_IRNCR_SOP_NULL 0x00000000 */
/** Read: Interrupt occurred. */
#define MERGE_LINK_IRNCR_SOP_INTOCC 0x00000002
/** End-of-Packet
    This bit is set if the topmost receive FIFO entry is a end-of-packet This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_LINK_IRNCR_EOP 0x00000001
/* Nothing
#define MERGE_LINK_IRNCR_EOP_NULL 0x00000000 */
/** Read: Interrupt occurred. */
#define MERGE_LINK_IRNCR_EOP_INTOCC 0x00000001

/* Fields of "LINK_IRN Interrupt Control Register" */
/** Receive FIFO Ready
    Interrupt control bit for the corresponding bit in the LINK_IRNCR register. */
#define MERGE_LINK_IRNICR_RXR 0x00000004
/** Start-of-Packet
    Interrupt control bit for the corresponding bit in the LINK_IRNCR register. */
#define MERGE_LINK_IRNICR_SOP 0x00000002
/** End-of-Packet
    Interrupt control bit for the corresponding bit in the LINK_IRNCR register. */
#define MERGE_LINK_IRNICR_EOP 0x00000001

/* Fields of "LINK_IRN Interrupt Enable Register" */
/** Receive FIFO Ready
    Interrupt enable bit for the corresponding bit in the LINK_IRNCR register. */
#define MERGE_LINK_IRNEN_RXR 0x00000004
/* Disable
#define MERGE_LINK_IRNEN_RXR_DIS 0x00000000 */
/** Enable */
#define MERGE_LINK_IRNEN_RXR_EN 0x00000004
/** Start-of-Packet
    Interrupt enable bit for the corresponding bit in the LINK_IRNCR register. */
#define MERGE_LINK_IRNEN_SOP 0x00000002
/* Disable
#define MERGE_LINK_IRNEN_SOP_DIS 0x00000000 */
/** Enable */
#define MERGE_LINK_IRNEN_SOP_EN 0x00000002
/** End-of-Packet
    Interrupt enable bit for the corresponding bit in the LINK_IRNCR register. */
#define MERGE_LINK_IRNEN_EOP 0x00000001
/* Disable
#define MERGE_LINK_IRNEN_EOP_DIS 0x00000000 */
/** Enable */
#define MERGE_LINK_IRNEN_EOP_EN 0x00000001

/* Fields of "Length Register" */
/** Receiver Packets
    Returns the number of complete packets which are curently stored in the receive FIFO. */
#define MERGE_LINK_LEN_PACR_MASK 0x1F000000
/** field offset */
#define MERGE_LINK_LEN_PACR_OFFSET 24
/** Receiver Length
    Returns the number of available complete entries in the receive FIFO.This value is decremented whenever a complete 64bit word is read from DATA (Data0+Data1).This value is incremented whenever a complete 64bit word is received (inserted into the DATA FIFO).The seqence of reads to Data0 and Data1 isn't of any matter. */
#define MERGE_LINK_LEN_LENR_MASK 0x001F0000
/** field offset */
#define MERGE_LINK_LEN_LENR_OFFSET 16

/* Fields of "Data Register 0" */
/** Receive/Transmit Data 0
    This register holds the lower 32bits of a 64bit word (bits 31:0) transferd via the LINK interface.On a read the lower 32bits from the receive fifo are returned. */
#define MERGE_LINK_DATA0_DATA0_MASK 0xFFFFFFFF
/** field offset */
#define MERGE_LINK_DATA0_DATA0_OFFSET 0

/* Fields of "Data Register 1" */
/** Receive/Transmit Data 1
    This register holds the higher 32bits of a 64bit word (bits 63:32) transferd via the LINK interface.On a read the higher 32bits from the receive fifo are returned. */
#define MERGE_LINK_DATA1_DATA1_MASK 0xFFFFFFFF
/** field offset */
#define MERGE_LINK_DATA1_DATA1_OFFSET 0

/* Fields of "Control Register" */
/** Request pulse -- not supported for this instance
    When writing '1' to this bit, a request pulse is asserted. */
#define MERGE_TMU_LINK_CTRL_REQ 0x00000020
/** Reset Receiver
    When this bit is set the receiver is reseted */
#define MERGE_TMU_LINK_CTRL_RSR 0x00000008
/** Mark as Start-of-Packet
    On a read the information is returned whether the current 64bit word within DATA is signed as the first data packet (Start of Packet). */
#define MERGE_TMU_LINK_CTRL_SOP 0x00000002
/** Mark as End-of-Packet
    On a read the information is returned whether the current 64bit word within DATA is signed as the last data packet (End of Packet). */
#define MERGE_TMU_LINK_CTRL_EOP 0x00000001

/* Fields of "TMU_LINK_IRN Capture Register" */
/** Receive FIFO Ready
    This bit is set if the Recieve FIFO is not empty. This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_TMU_LINK_IRNCR_RXR 0x00000004
/* Nothing
#define MERGE_TMU_LINK_IRNCR_RXR_NULL 0x00000000 */
/** Read: Interrupt occurred. */
#define MERGE_TMU_LINK_IRNCR_RXR_INTOCC 0x00000004
/** Start-of-Packet
    This bit is set if the topmost receive FIFO entry is a start-of-packet This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_TMU_LINK_IRNCR_SOP 0x00000002
/* Nothing
#define MERGE_TMU_LINK_IRNCR_SOP_NULL 0x00000000 */
/** Read: Interrupt occurred. */
#define MERGE_TMU_LINK_IRNCR_SOP_INTOCC 0x00000002
/** End-of-Packet
    This bit is set if the topmost receive FIFO entry is a end-of-packet This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define MERGE_TMU_LINK_IRNCR_EOP 0x00000001
/* Nothing
#define MERGE_TMU_LINK_IRNCR_EOP_NULL 0x00000000 */
/** Read: Interrupt occurred. */
#define MERGE_TMU_LINK_IRNCR_EOP_INTOCC 0x00000001

/* Fields of "TMU_LINK_IRN Interrupt Control Register" */
/** Receive FIFO Ready
    Interrupt control bit for the corresponding bit in the TMU_LINK_IRNCR register. */
#define MERGE_TMU_LINK_IRNICR_RXR 0x00000004
/** Start-of-Packet
    Interrupt control bit for the corresponding bit in the TMU_LINK_IRNCR register. */
#define MERGE_TMU_LINK_IRNICR_SOP 0x00000002
/** End-of-Packet
    Interrupt control bit for the corresponding bit in the TMU_LINK_IRNCR register. */
#define MERGE_TMU_LINK_IRNICR_EOP 0x00000001

/* Fields of "TMU_LINK_IRN Interrupt Enable Register" */
/** Receive FIFO Ready
    Interrupt enable bit for the corresponding bit in the TMU_LINK_IRNCR register. */
#define MERGE_TMU_LINK_IRNEN_RXR 0x00000004
/* Disable
#define MERGE_TMU_LINK_IRNEN_RXR_DIS 0x00000000 */
/** Enable */
#define MERGE_TMU_LINK_IRNEN_RXR_EN 0x00000004
/** Start-of-Packet
    Interrupt enable bit for the corresponding bit in the TMU_LINK_IRNCR register. */
#define MERGE_TMU_LINK_IRNEN_SOP 0x00000002
/* Disable
#define MERGE_TMU_LINK_IRNEN_SOP_DIS 0x00000000 */
/** Enable */
#define MERGE_TMU_LINK_IRNEN_SOP_EN 0x00000002
/** End-of-Packet
    Interrupt enable bit for the corresponding bit in the TMU_LINK_IRNCR register. */
#define MERGE_TMU_LINK_IRNEN_EOP 0x00000001
/* Disable
#define MERGE_TMU_LINK_IRNEN_EOP_DIS 0x00000000 */
/** Enable */
#define MERGE_TMU_LINK_IRNEN_EOP_EN 0x00000001

/* Fields of "Length Register" */
/** Receiver Packets
    Returns the number of complete packets which are curently stored in the receive FIFO. */
#define MERGE_TMU_LINK_LEN_PACR_MASK 0x1F000000
/** field offset */
#define MERGE_TMU_LINK_LEN_PACR_OFFSET 24
/** Receiver Length
    Returns the number of available complete entries in the receive FIFO.This value is decremented whenever a complete 64bit word is read from DATA (Data0+Data1).This value is incremented whenever a complete 64bit word is received (inserted into the DATA FIFO).The seqence of reads to Data0 and Data1 isn't of any matter. */
#define MERGE_TMU_LINK_LEN_LENR_MASK 0x001F0000
/** field offset */
#define MERGE_TMU_LINK_LEN_LENR_OFFSET 16

/* Fields of "Data Register 0" */
/** Receive/Transmit Data 0
    This register holds the lower 32bits of a 64bit word (bits 31:0) transferd via the LINK interface.On a read the lower 32bits from the receive fifo are returned. */
#define MERGE_TMU_LINK_DATA0_DATA0_MASK 0xFFFFFFFF
/** field offset */
#define MERGE_TMU_LINK_DATA0_DATA0_OFFSET 0

/* Fields of "Data Register 1" */
/** Receive/Transmit Data 1
    This register holds the higher 32bits of a 64bit word (bits 63:32) transferd via the LINK interface.On a read the higher 32bits from the receive fifo are returned. */
#define MERGE_TMU_LINK_DATA1_DATA1_MASK 0xFFFFFFFF
/** field offset */
#define MERGE_TMU_LINK_DATA1_DATA1_OFFSET 0

/*! @} */ /* MERGE_REGISTER */

#endif /* _drv_onu_reg_merge_h */
