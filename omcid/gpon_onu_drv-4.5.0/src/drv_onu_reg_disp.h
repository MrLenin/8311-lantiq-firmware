/******************************************************************************

                               Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_reg_disp_h
#define _drv_onu_reg_disp_h

/** \addtogroup DISP_REGISTER
   @{
*/
/* access macros */
#define disp_r32(reg) reg_r32(&disp->reg)
#define disp_w32(val, reg) reg_w32(val, &disp->reg)
#define disp_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &disp->reg)
#define disp_r32_table(reg, idx) reg_r32_table(disp->reg, idx)
#define disp_w32_table(val, reg, idx) reg_w32_table(val, disp->reg, idx)
#define disp_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, disp->reg, idx)
#define disp_adr_table(reg, idx) adr_table(disp->reg, idx)


/** DISP register structure */
struct onu_reg_disp
{
   /** Control Register
       This register provides the global DISP controls. */
   unsigned int ctrl; /* 0x00000000 */
   /** Thread Control Register 0
       This register controls wether a packet request signal from thread running on a Virtual Machine are served.The register can be used to exclude threads from processing during regular operation.The bits can be reprogrammed any time, ongoing packet transmissions are not effected. */
   unsigned int tctrl0; /* 0x00000004 */
   /** Thread Request Status Register
       This register represents the Request Status of all threads running on a Virtual Machine. Whenever one of the threads signal a request signal, then the corresponding virtual machine flag in the Dispatcher Unit is set. This flag signals the IQM module, if at least one of the threads for this virtual machine is ready to accept new data. This flags are represented in this register. */
   unsigned int tstat0; /* 0x00000008 */
   /** Link Control Register 0
       This register controls the link resets of all threads */
   unsigned int lctrl0; /* 0x0000000C */
   /** Link Status Register 0
       This register represents the Request LINK Status of all threads of one Virtual Machine. */
   unsigned int lstat0; /* 0x00000010 */
   /** SSB Control Register
       This register provides the SSB DISP control. */
   unsigned int ssbmax; /* 0x00000014 */
   /** Reserved */
   unsigned int res_0[2]; /* 0x00000018 */
   /** Link Data Register 0
       This register represents the data entry sent from the IQM. See the IQM documentation for more details. */
   unsigned int ldata0; /* 0x00000020 */
   /** Link Data Register 1
       This register represents the data entry sent from the IQM. See the IQM documentation for more details. */
   unsigned int ldata1; /* 0x00000024 */
   /** Link Data Register 2
       This register represents the data entry sent from the IQM. See the IQM documentation for more details. */
   unsigned int ldata2; /* 0x00000028 */
   /** Link Data Register 3
       This register represents the data entry sent from the IQM. See the IQM documentation for more details. */
   unsigned int ldata3; /* 0x0000002C */
   /** Reserved */
   unsigned int res_1[4]; /* 0x00000030 */
   /** Link FIFO Register 0
       This register represents the fill state of the link buffer FIFOs. Every logical link from the SSB to the Threads is buffered. This register represents the status of this buffers. */
   unsigned int lfifo0; /* 0x00000040 */
   /** Link FIFO Register 1
       This register represents the fill state of the link buffer FIFOs. Every logical link from the SSB to the Threads is buffered. This register represents the status of this buffers. */
   unsigned int lfifo1; /* 0x00000044 */
   /** Link FIFO Register 2
       This register represents the fill state of the link buffer FIFOs. Every logical link from the SSB to the Threads is buffered. This register represents the status of this buffers. */
   unsigned int lfifo2; /* 0x00000048 */
   /** Link FIFO Register 3
       This register represents the fill state of the link buffer FIFOs. Every logical link from the SSB to the Threads is buffered. This register represents the status of this buffers. */
   unsigned int lfifo3; /* 0x0000004C */
   /** Link FIFO Register 4
       This register represents the fill state of the link buffer FIFOs. Every logical link from the SSB to the Threads is buffered. This register represents the status of this buffers. */
   unsigned int lfifo4; /* 0x00000050 */
   /** Reserved */
   unsigned int res_2[7]; /* 0x00000054 */
   /** Address/Valid Register of LINK HOST
       This register controls the address of the read access for the link_host, and a valid signal if write or/and read of the LINK-Interface is activated. */
   unsigned int linkhost; /* 0x00000070 */
   /** Reserved */
   unsigned int res_3[3]; /* 0x00000074 */
   /** Control Register
       This register provides the global LINK Interface controls. The Link-Interface is an on-chip network which interconnects different on-chip modules. The CPU can use this interface to access this network. */
   unsigned int link_ctrl; /* 0x00000080 */
   /** Reserved */
   unsigned int res_4[3]; /* 0x00000084 */
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
   unsigned int res_5; /* 0x0000009C */
   /** Length Register
       Holds the FIFO Lenght for the Transmit and Receive FIFO */
   unsigned int link_len; /* 0x000000A0 */
   /** Data Register 0
       Transmit and Receive data Register 0 */
   unsigned int link_data0; /* 0x000000A4 */
   /** Data Register 1
       Transmit and Receive data Register 1 */
   unsigned int link_data1; /* 0x000000A8 */
   /** Reserved */
   unsigned int res_6[21]; /* 0x000000AC */
};


/* Fields of "Control Register" */
/** Freeze Output Path
    This bit freezes the output path to the processing elements (PEs). Currently ongoing transfers out of the link buffer are completed before freeze. */
#define DISP_CTRL_FRZO 0x00000004
/* Disable
#define DISP_CTRL_FRZO_DIS 0x00000000 */
/** Enable */
#define DISP_CTRL_FRZO_EN 0x00000004
/** Freeze Input Path
    This bit freezes the input path from the input queue manager (IQM). Currently ongoing transfers into the link buffer are completed before freeze. */
#define DISP_CTRL_FRZI 0x00000002
/* Disable
#define DISP_CTRL_FRZI_DIS 0x00000000 */
/** Enable */
#define DISP_CTRL_FRZI_EN 0x00000002
/** Activate Module
    This bit enables the dispatcher module. Whenever the module is deactivated an internal sychronous reset is performed. There for the module starts in a defined state after activation.. */
#define DISP_CTRL_ACT 0x00000001
/* Disable
#define DISP_CTRL_ACT_DIS 0x00000000 */
/** Enable */
#define DISP_CTRL_ACT_EN 0x00000001

/* Fields of "Thread Control Register 0" */
/** CPU Link 1
    Enable packet header requests from CPU Link 1. */
#define DISP_TCTRL0_T61 0x00080000
/* Disable
#define DISP_TCTRL0_T61_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T61_EN 0x00080000
/** CPU Link 0
    Enable packet header requests from CPU Link 0. */
#define DISP_TCTRL0_T60 0x00040000
/* Disable
#define DISP_TCTRL0_T60_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T60_EN 0x00040000
/** Threads 5.2.x
    Enable packet header requests from PE 5, Virtual machine 2, Threads 0-3. */
#define DISP_TCTRL0_T52 0x00020000
/* Disable
#define DISP_TCTRL0_T52_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T52_EN 0x00020000
/** Threads 5.1.x
    Enable packet header requests from PE 5, Virtual machine 1, Threads 0-3. */
#define DISP_TCTRL0_T51 0x00010000
/* Disable
#define DISP_TCTRL0_T51_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T51_EN 0x00010000
/** Threads 5.0.x
    Enable packet header requests from PE 5, Virtual machine 0, Threads 0-3. */
#define DISP_TCTRL0_T50 0x00008000
/* Disable
#define DISP_TCTRL0_T50_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T50_EN 0x00008000
/** Threads 4.2.x
    Enable packet header requests from PE 4, Virtual machine 2, Threads 0-3. */
#define DISP_TCTRL0_T42 0x00004000
/* Disable
#define DISP_TCTRL0_T42_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T42_EN 0x00004000
/** Threads 4.1.x
    Enable packet header requests from PE 4, Virtual machine 1, Threads 0-3. */
#define DISP_TCTRL0_T41 0x00002000
/* Disable
#define DISP_TCTRL0_T41_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T41_EN 0x00002000
/** Threads 4.0.x
    Enable packet header requests from PE 4, Virtual machine 0, Threads 0-3. */
#define DISP_TCTRL0_T40 0x00001000
/* Disable
#define DISP_TCTRL0_T40_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T40_EN 0x00001000
/** Threads 3.2.x
    Enable packet header requests from PE 3, Virtual machine 2, Threads 0-3. */
#define DISP_TCTRL0_T32 0x00000800
/* Disable
#define DISP_TCTRL0_T32_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T32_EN 0x00000800
/** Threads 3.1.x
    Enable packet header requests from PE 3, Virtual machine 1, Threads 0-3. */
#define DISP_TCTRL0_T31 0x00000400
/* Disable
#define DISP_TCTRL0_T31_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T31_EN 0x00000400
/** Threads 3.0.x
    Enable packet header requests from PE 3, Virtual machine 0, Threads 0-3. */
#define DISP_TCTRL0_T30 0x00000200
/* Disable
#define DISP_TCTRL0_T30_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T30_EN 0x00000200
/** Threads 2.2.x
    Enable packet header requests from PE 2, Virtual machine 2, Threads 0-3. */
#define DISP_TCTRL0_T22 0x00000100
/* Disable
#define DISP_TCTRL0_T22_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T22_EN 0x00000100
/** Threads 2.1.x
    Enable packet header requests from PE 2, Virtual machine 1, Threads 0-3. */
#define DISP_TCTRL0_T21 0x00000080
/* Disable
#define DISP_TCTRL0_T21_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T21_EN 0x00000080
/** Threads 2.0.x
    Enable packet header requests from PE 2, Virtual machine 0, Threads 0-3. */
#define DISP_TCTRL0_T20 0x00000040
/* Disable
#define DISP_TCTRL0_T20_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T20_EN 0x00000040
/** Threads 1.2.x
    Enable packet header requests from PE 1, Virtual machine 2, Threads 0-3. */
#define DISP_TCTRL0_T12 0x00000020
/* Disable
#define DISP_TCTRL0_T12_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T12_EN 0x00000020
/** Threads 1.1.x
    Enable packet header requests from PE 1, Virtual machine 1, Threads 0-3. */
#define DISP_TCTRL0_T11 0x00000010
/* Disable
#define DISP_TCTRL0_T11_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T11_EN 0x00000010
/** Threads 1.0.x
    Enable packet header requests from PE 1, Virtual machine 0, Threads 0-3. */
#define DISP_TCTRL0_T10 0x00000008
/* Disable
#define DISP_TCTRL0_T10_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T10_EN 0x00000008
/** Threads 0.2.x
    Enable packet header requests from PE 0, Virtual machine 2, Threads 0-3. */
#define DISP_TCTRL0_T02 0x00000004
/* Disable
#define DISP_TCTRL0_T02_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T02_EN 0x00000004
/** Threads 0.1.x
    Enable packet header requests from PE 0, Virtual machine 1, Threads 0-3. */
#define DISP_TCTRL0_T01 0x00000002
/* Disable
#define DISP_TCTRL0_T01_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T01_EN 0x00000002
/** Threads 0.0.x
    Enable packet header requests from PE 0, Virtual machine 0, Threads 0-3. */
#define DISP_TCTRL0_T00 0x00000001
/* Disable
#define DISP_TCTRL0_T00_DIS 0x00000000 */
/** Enable */
#define DISP_TCTRL0_T00_EN 0x00000001

/* Fields of "Thread Request Status Register" */
/** CPU Link 1
    This Flag represents the packet header request status of CPU Link 1.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T61 0x00080000
/* Not Ready
#define DISP_TSTAT0_T61_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T61_RDY 0x00080000
/** CPU Link 0
    This Flag represents the packet header request status of CPU Link 0.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T60 0x00040000
/* Not Ready
#define DISP_TSTAT0_T60_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T60_RDY 0x00040000
/** Threads 5.2.x
    This Flag represents the packet header request status of PE 5, Virtual Machine 2, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T52 0x00020000
/* Not Ready
#define DISP_TSTAT0_T52_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T52_RDY 0x00020000
/** Threads 5.1.x
    This Flag represents the packet header request status of PE 5, Virtual Machine 1, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T51 0x00010000
/* Not Ready
#define DISP_TSTAT0_T51_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T51_RDY 0x00010000
/** Threads 5.0.x
    This Flag represents the packet header request status of PE 5, Virtual Machine 0, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T50 0x00008000
/* Not Ready
#define DISP_TSTAT0_T50_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T50_RDY 0x00008000
/** Threads 4.2.x
    This Flag represents the packet header request status of PE 4, Virtual Machine 2, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T42 0x00004000
/* Not Ready
#define DISP_TSTAT0_T42_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T42_RDY 0x00004000
/** Threads 4.1.x
    This Flag represents the packet header request status of PE 4, Virtual Machine 1, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T41 0x00002000
/* Not Ready
#define DISP_TSTAT0_T41_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T41_RDY 0x00002000
/** Threads 4.0.x
    This Flag represents the packet header request status of PE 4, Virtual Machine 0, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T40 0x00001000
/* Not Ready
#define DISP_TSTAT0_T40_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T40_RDY 0x00001000
/** Threads 3.2.x
    This Flag represents the packet header request status of PE 3, Virtual Machine 2, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T32 0x00000800
/* Not Ready
#define DISP_TSTAT0_T32_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T32_RDY 0x00000800
/** Threads 3.1.x
    This Flag represents the packet header request status of PE 3, Virtual Machine 1, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T31 0x00000400
/* Not Ready
#define DISP_TSTAT0_T31_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T31_RDY 0x00000400
/** Threads 3.0.x
    This Flag represents the packet header request status of PE 3, Virtual Machine 0, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T30 0x00000200
/* Not Ready
#define DISP_TSTAT0_T30_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T30_RDY 0x00000200
/** Threads 2.2.x
    This Flag represents the packet header request status of PE 2, Virtual Machine 2, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T22 0x00000100
/* Not Ready
#define DISP_TSTAT0_T22_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T22_RDY 0x00000100
/** Threads 2.1.x
    This Flag represents the packet header request status of PE 2, Virtual Machine 1, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T21 0x00000080
/* Not Ready
#define DISP_TSTAT0_T21_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T21_RDY 0x00000080
/** Threads 2.0.x
    This Flag represents the packet header request status of PE 2, Virtual Machine 0, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T20 0x00000040
/* Not Ready
#define DISP_TSTAT0_T20_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T20_RDY 0x00000040
/** Threads 1.2.x
    This Flag represents the packet header request status of PE 1, Virtual Machine 2, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T12 0x00000020
/* Not Ready
#define DISP_TSTAT0_T12_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T12_RDY 0x00000020
/** Threads 1.1.x
    This Flag represents the packet header request status of PE 1, Virtual Machine 1, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T11 0x00000010
/* Not Ready
#define DISP_TSTAT0_T11_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T11_RDY 0x00000010
/** Threads 1.0.x
    This Flag represents the packet header request status of PE 1, Virtual Machine 0, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T10 0x00000008
/* Not Ready
#define DISP_TSTAT0_T10_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T10_RDY 0x00000008
/** Threads 0.2.x
    This Flag represents the packet header request status of PE 0, Virtual Machine 2, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T02 0x00000004
/* Not Ready
#define DISP_TSTAT0_T02_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T02_RDY 0x00000004
/** Threads 0.1.x
    This Flag represents the packet header request status of PE 0, Virtual Machine 1, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T01 0x00000002
/* Not Ready
#define DISP_TSTAT0_T01_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T01_RDY 0x00000002
/** Threads 0.0.x
    This Flag represents the packet header request status of PE 0, Virtual Machine 0, Threads 0-3. When at least one of the threads issues a request this bit is set.When this bit is written with a logical one the bit is reset to 0 (NRDY). */
#define DISP_TSTAT0_T00 0x00000001
/* Not Ready
#define DISP_TSTAT0_T00_NRDY 0x00000000 */
/** Ready */
#define DISP_TSTAT0_T00_RDY 0x00000001

/* Fields of "Link Control Register 0" */
/** Link Control Reset for CPU Link 1
    When written with a logical one the receive link for the CPU Link 1 is reseted. */
#define DISP_LCTRL0_T61 0x00080000
/* No-Operation
#define DISP_LCTRL0_T61_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T61_CLR 0x00080000
/** Link Control Reset for CPU Link 0
    When written with a logical one the receive link for the CPU Link 0 is reseted. */
#define DISP_LCTRL0_T60 0x00040000
/* No-Operation
#define DISP_LCTRL0_T60_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T60_CLR 0x00040000
/** Link Control Reset for Threads 5.2.x
    When written with a logical one the receive link for PE 5, Virutal Machine 2, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T52 0x00020000
/* No-Operation
#define DISP_LCTRL0_T52_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T52_CLR 0x00020000
/** Link Control Reset for Threads 5.1.x
    When written with a logical one the receive link for PE 5, Virutal Machine 1, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T51 0x00010000
/* No-Operation
#define DISP_LCTRL0_T51_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T51_CLR 0x00010000
/** Link Control Reset for Threads 5.0.x
    When written with a logical one the receive link for PE 5, Virutal Machine 0, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T50 0x00008000
/* No-Operation
#define DISP_LCTRL0_T50_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T50_CLR 0x00008000
/** Link Control Reset for Threads 4.2.x
    When written with a logical one the receive link for PE 4, Virutal Machine 2, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T42 0x00004000
/* No-Operation
#define DISP_LCTRL0_T42_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T42_CLR 0x00004000
/** Link Control Reset for Threads 4.1.x
    When written with a logical one the receive link for PE 4, Virutal Machine 1, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T41 0x00002000
/* No-Operation
#define DISP_LCTRL0_T41_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T41_CLR 0x00002000
/** Link Control Reset for Threads 4.0.x
    When written with a logical one the receive link for PE 4, Virutal Machine 0, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T40 0x00001000
/* No-Operation
#define DISP_LCTRL0_T40_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T40_CLR 0x00001000
/** Link Control Reset for Threads 3.2.x
    When written with a logical one the receive link for PE 3, Virutal Machine 2, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T32 0x00000800
/* No-Operation
#define DISP_LCTRL0_T32_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T32_CLR 0x00000800
/** Link Control Reset for Threads 3.1.x
    When written with a logical one the receive link for PE 3, Virutal Machine 1, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T31 0x00000400
/* No-Operation
#define DISP_LCTRL0_T31_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T31_CLR 0x00000400
/** Link Control Reset for Threads 3.0.x
    When written with a logical one the receive link for PE 3, Virutal Machine 0, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T30 0x00000200
/* No-Operation
#define DISP_LCTRL0_T30_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T30_CLR 0x00000200
/** Link Control Reset for Threads 2.2.x
    When written with a logical one the receive link for PE 2, Virutal Machine 2, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T22 0x00000100
/* No-Operation
#define DISP_LCTRL0_T22_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T22_CLR 0x00000100
/** Link Control Reset for Threads 2.1.x
    When written with a logical one the receive link for PE 2, Virutal Machine 1, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T21 0x00000080
/* No-Operation
#define DISP_LCTRL0_T21_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T21_CLR 0x00000080
/** Link Control Reset for Threads 2.0.x
    When written with a logical one the receive link for PE 2, Virutal Machine 0, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T20 0x00000040
/* No-Operation
#define DISP_LCTRL0_T20_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T20_CLR 0x00000040
/** Link Control Reset for Threads 1.2.x
    When written with a logical one the receive link for PE 1, Virutal Machine 2, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T12 0x00000020
/* No-Operation
#define DISP_LCTRL0_T12_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T12_CLR 0x00000020
/** Link Control Reset for Threads 1.1.x
    When written with a logical one the receive link for PE 1, Virutal Machine 1, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T11 0x00000010
/* No-Operation
#define DISP_LCTRL0_T11_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T11_CLR 0x00000010
/** Link Control Reset for Threads 1.0.x
    When written with a logical one the receive link for PE 1, Virutal Machine 0, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T10 0x00000008
/* No-Operation
#define DISP_LCTRL0_T10_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T10_CLR 0x00000008
/** Link Control Reset for Threads 0.2.x
    When written with a logical one the receive link for PE 0, Virutal Machine 2, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T02 0x00000004
/* No-Operation
#define DISP_LCTRL0_T02_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T02_CLR 0x00000004
/** Link Control Reset for Threads 0.1.x
    When written with a logical one the receive link for PE 0, Virutal Machine 1, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T01 0x00000002
/* No-Operation
#define DISP_LCTRL0_T01_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T01_CLR 0x00000002
/** Link Control Reset for Threads 0.0.x
    When written with a logical one the receive link for PE 0, Virutal Machine 0, Threads 0-3 is reseted. */
#define DISP_LCTRL0_T00 0x00000001
/* No-Operation
#define DISP_LCTRL0_T00_NOP 0x00000000 */
/** Clear */
#define DISP_LCTRL0_T00_CLR 0x00000001

/* Fields of "Link Status Register 0" */
/** Link Status of CPU Link 1.
    This Flag represents the link state of the CPU Link 1. */
#define DISP_LSTAT0_T61 0x00080000
/* Not Ready
#define DISP_LSTAT0_T61_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T61_RDY 0x00080000
/** Link Status of CPU Link 0.
    This Flag represents the link state of the CPU Link 0. */
#define DISP_LSTAT0_T60 0x00040000
/* Not Ready
#define DISP_LSTAT0_T60_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T60_RDY 0x00040000
/** Link Status of Threads 5.2.x
    This Flag represents the link state of PE 5, Virtual Machine 2, Threads 0-3. */
#define DISP_LSTAT0_T52 0x00020000
/* Not Ready
#define DISP_LSTAT0_T52_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T52_RDY 0x00020000
/** Link Status of Threads 5.1.x
    This Flag represents the link state of PE 5, Virtual Machine 1, Threads 0-3. */
#define DISP_LSTAT0_T51 0x00010000
/* Not Ready
#define DISP_LSTAT0_T51_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T51_RDY 0x00010000
/** Link Status of Threads 5.0.x
    This Flag represents the link state of PE 5, Virtual Machine 0, Threads 0-3. */
#define DISP_LSTAT0_T50 0x00008000
/* Not Ready
#define DISP_LSTAT0_T50_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T50_RDY 0x00008000
/** Link Status of Threads 4.2.x
    This Flag represents the link state of PE 4, Virtual Machine 2, Threads 0-3. */
#define DISP_LSTAT0_T42 0x00004000
/* Not Ready
#define DISP_LSTAT0_T42_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T42_RDY 0x00004000
/** Link Status of Threads 4.1.x
    This Flag represents the link state of PE 4, Virtual Machine 1, Threads 0-3. */
#define DISP_LSTAT0_T41 0x00002000
/* Not Ready
#define DISP_LSTAT0_T41_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T41_RDY 0x00002000
/** Link Status of Threads 4.0.x
    This Flag represents the link state of PE 4, Virtual Machine 0, Threads 0-3. */
#define DISP_LSTAT0_T40 0x00001000
/* Not Ready
#define DISP_LSTAT0_T40_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T40_RDY 0x00001000
/** Link Status of Threads 3.2.x
    This Flag represents the link state of PE 3, Virtual Machine 2, Threads 0-3. */
#define DISP_LSTAT0_T32 0x00000800
/* Not Ready
#define DISP_LSTAT0_T32_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T32_RDY 0x00000800
/** Link Status of Threads 3.1.x
    This Flag represents the link state of PE 3, Virtual Machine 1, Threads 0-3. */
#define DISP_LSTAT0_T31 0x00000400
/* Not Ready
#define DISP_LSTAT0_T31_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T31_RDY 0x00000400
/** Link Status of Threads 3.0.x
    This Flag represents the link state of PE 3, Virtual Machine 0, Threads 0-3. */
#define DISP_LSTAT0_T30 0x00000200
/* Not Ready
#define DISP_LSTAT0_T30_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T30_RDY 0x00000200
/** Link Status of Threads 2.2.x
    This Flag represents the link state of PE 2, Virtual Machine 2, Threads 0-3. */
#define DISP_LSTAT0_T22 0x00000100
/* Not Ready
#define DISP_LSTAT0_T22_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T22_RDY 0x00000100
/** Link Status of Threads 2.1.x
    This Flag represents the link state of PE 2, Virtual Machine 1, Threads 0-3. */
#define DISP_LSTAT0_T21 0x00000080
/* Not Ready
#define DISP_LSTAT0_T21_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T21_RDY 0x00000080
/** Link Status of Threads 2.0.x
    This Flag represents the link state of PE 2, Virtual Machine 0, Threads 0-3. */
#define DISP_LSTAT0_T20 0x00000040
/* Not Ready
#define DISP_LSTAT0_T20_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T20_RDY 0x00000040
/** Link Status of Threads 1.2.x
    This Flag represents the link state of PE 1, Virtual Machine 2, Threads 0-3. */
#define DISP_LSTAT0_T12 0x00000020
/* Not Ready
#define DISP_LSTAT0_T12_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T12_RDY 0x00000020
/** Link Status of Threads 1.1.x
    This Flag represents the link state of PE 1, Virtual Machine 1, Threads 0-3. */
#define DISP_LSTAT0_T11 0x00000010
/* Not Ready
#define DISP_LSTAT0_T11_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T11_RDY 0x00000010
/** Link Status of Threads 1.0.x
    This Flag represents the link state of PE 1, Virtual Machine 0, Threads 0-3. */
#define DISP_LSTAT0_T10 0x00000008
/* Not Ready
#define DISP_LSTAT0_T10_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T10_RDY 0x00000008
/** Link Status of Threads 0.2.x
    This Flag represents the link state of PE 0, Virtual Machine 2, Threads 0-3. */
#define DISP_LSTAT0_T02 0x00000004
/* Not Ready
#define DISP_LSTAT0_T02_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T02_RDY 0x00000004
/** Link Status of Threads 0.1.x
    This Flag represents the link state of PE 0, Virtual Machine 1, Threads 0-3. */
#define DISP_LSTAT0_T01 0x00000002
/* Not Ready
#define DISP_LSTAT0_T01_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T01_RDY 0x00000002
/** Link Status of Threads 0.0.x
    This Flag represents the link state of PE 0, Virtual Machine 0, Threads 0-3. */
#define DISP_LSTAT0_T00 0x00000001
/* Not Ready
#define DISP_LSTAT0_T00_NRDY 0x00000000 */
/** Ready */
#define DISP_LSTAT0_T00_RDY 0x00000001

/* Fields of "SSB Control Register" */
/** Maximum Packet Header Length
    This field represents the maximum header length which is dispatched to all threads. The value is given in multiples of 16 bytes. The maximum value is 8, which is equivalent to 8*16=128 bytes.If the packet length is less than the specified number of bytes, then only this number of bytes are transmitted to the thread. If the packet length is greater than the specified number of bytes, then only the first 128 bytes are transmitted to the thread. NOTE: The value specified limits the maximum number of SBB read accesses. */
#define DISP_SSBMAX_SSBMAX_MASK 0x0000000F
/** field offset */
#define DISP_SSBMAX_SSBMAX_OFFSET 0

/* Fields of "Link Data Register 0" */
/** Time Stamp */
#define DISP_LDATA0_TS_MASK 0x00FFFFFF
/** field offset */
#define DISP_LDATA0_TS_OFFSET 0

/* Fields of "Link Data Register 1" */
/** Tail LSA
    The logical SSB address of the stored PDU head */
#define DISP_LDATA1_NLSA_MASK 0x7FFF0000
/** field offset */
#define DISP_LDATA1_NLSA_OFFSET 16
/** PDU Type
    The PDU type is provided by SDMAx as a basic HW classification */
#define DISP_LDATA1_PDUT_MASK 0x00007000
/** field offset */
#define DISP_LDATA1_PDUT_OFFSET 12
/** Ingress Port Identifier
    Indentifies the ingress port. The assignment is done in hardware upon dequeue. */
#define DISP_LDATA1_IPN_MASK 0x00000700
/** field offset */
#define DISP_LDATA1_IPN_OFFSET 8
/** Ticket
    The Ticket is locally assigned from a ticket counter per queue. The assignment is done in hardware upon dequeue. */
#define DISP_LDATA1_TICK_MASK 0x000000FF
/** field offset */
#define DISP_LDATA1_TICK_OFFSET 0

/* Fields of "Link Data Register 2" */
/** GEM Port Index
    The GEM Port Index is mapped from the GEM Port Identifier in SDMAG */
#define DISP_LDATA2_GPIX_MASK 0x00FF0000
/** field offset */
#define DISP_LDATA2_GPIX_OFFSET 16
/** PDU Length
    The PDU Length in Bytes */
#define DISP_LDATA2_PLEN_MASK 0x0000FFFF
/** field offset */
#define DISP_LDATA2_PLEN_OFFSET 0

/* Fields of "Link Data Register 3" */
/** Tail LSA
    The logical SSB address of the stored PDU head */
#define DISP_LDATA3_TLSA_MASK 0x7FFF0000
/** field offset */
#define DISP_LDATA3_TLSA_OFFSET 16
/** Head LSA
    The logical SSB address of the stored PDU head */
#define DISP_LDATA3_HLSA_MASK 0x00007FFF
/** field offset */
#define DISP_LDATA3_HLSA_OFFSET 0

/* Fields of "Link FIFO Register 0" */
/** Link FIFO 0 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 0. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO0_OV0 0x80000000
/** Link FIFO 0 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 0. */
#define DISP_LFIFO0_LEN0_MASK 0x1F000000
/** field offset */
#define DISP_LFIFO0_LEN0_OFFSET 24
/** Link FIFO 1 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 1. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO0_OV1 0x00800000
/** Link FIFO 1 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 1. */
#define DISP_LFIFO0_LEN1_MASK 0x001F0000
/** field offset */
#define DISP_LFIFO0_LEN1_OFFSET 16
/** Link FIFO 2 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 2. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO0_OV2 0x00008000
/** Link FIFO 2 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 2. */
#define DISP_LFIFO0_LEN2_MASK 0x00001F00
/** field offset */
#define DISP_LFIFO0_LEN2_OFFSET 8
/** Link FIFO 3 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 3. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO0_OV3 0x00000080
/** Link FIFO 3 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 3. */
#define DISP_LFIFO0_LEN3_MASK 0x0000001F
/** field offset */
#define DISP_LFIFO0_LEN3_OFFSET 0

/* Fields of "Link FIFO Register 1" */
/** Link FIFO 4 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 4. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO1_OV4 0x80000000
/** Link FIFO 4 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 4. */
#define DISP_LFIFO1_LEN4_MASK 0x1F000000
/** field offset */
#define DISP_LFIFO1_LEN4_OFFSET 24
/** Link FIFO 5 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 5. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO1_OV5 0x00800000
/** Link FIFO 5 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 5. */
#define DISP_LFIFO1_LEN5_MASK 0x001F0000
/** field offset */
#define DISP_LFIFO1_LEN5_OFFSET 16
/** Link FIFO 6 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 6. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO1_OV6 0x00008000
/** Link FIFO 6 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 6. */
#define DISP_LFIFO1_LEN6_MASK 0x00001F00
/** field offset */
#define DISP_LFIFO1_LEN6_OFFSET 8
/** Link FIFO 7 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 7. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO1_OV7 0x00000080
/** Link FIFO 7 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 7. */
#define DISP_LFIFO1_LEN7_MASK 0x0000001F
/** field offset */
#define DISP_LFIFO1_LEN7_OFFSET 0

/* Fields of "Link FIFO Register 2" */
/** Link FIFO 8 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 8. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO2_OV8 0x80000000
/** Link FIFO 8 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 8. */
#define DISP_LFIFO2_LEN8_MASK 0x1F000000
/** field offset */
#define DISP_LFIFO2_LEN8_OFFSET 24
/** Link FIFO 9 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 9. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO2_OV9 0x00800000
/** Link FIFO 9 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 9. */
#define DISP_LFIFO2_LEN9_MASK 0x001F0000
/** field offset */
#define DISP_LFIFO2_LEN9_OFFSET 16
/** Link FIFO 10 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 10. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO2_OV10 0x00008000
/** Link FIFO 10 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 10. */
#define DISP_LFIFO2_LEN10_MASK 0x00001F00
/** field offset */
#define DISP_LFIFO2_LEN10_OFFSET 8
/** Link FIFO 11 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 11. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO2_OV11 0x00000080
/** Link FIFO 11 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 11. */
#define DISP_LFIFO2_LEN11_MASK 0x0000001F
/** field offset */
#define DISP_LFIFO2_LEN11_OFFSET 0

/* Fields of "Link FIFO Register 3" */
/** Link FIFO 12 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 12. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO3_OV12 0x80000000
/** Link FIFO 12 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 12. */
#define DISP_LFIFO3_LEN12_MASK 0x1F000000
/** field offset */
#define DISP_LFIFO3_LEN12_OFFSET 24
/** Link FIFO 13 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 13. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO3_OV13 0x00800000
/** Link FIFO 13 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 13. */
#define DISP_LFIFO3_LEN13_MASK 0x001F0000
/** field offset */
#define DISP_LFIFO3_LEN13_OFFSET 16
/** Link FIFO 14 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 14. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO3_OV14 0x00008000
/** Link FIFO 14 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 14. */
#define DISP_LFIFO3_LEN14_MASK 0x00001F00
/** field offset */
#define DISP_LFIFO3_LEN14_OFFSET 8
/** Link FIFO 15 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 15. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO3_OV15 0x00000080
/** Link FIFO 15 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 15. */
#define DISP_LFIFO3_LEN15_MASK 0x0000001F
/** field offset */
#define DISP_LFIFO3_LEN15_OFFSET 0

/* Fields of "Link FIFO Register 4" */
/** Link FIFO 16 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 16. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO4_OV16 0x80000000
/** Link FIFO 16 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 16. */
#define DISP_LFIFO4_LEN16_MASK 0x1F000000
/** field offset */
#define DISP_LFIFO4_LEN16_OFFSET 24
/** Link FIFO 17 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 17. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO4_OV17 0x00800000
/** Link FIFO 17 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 17. */
#define DISP_LFIFO4_LEN17_MASK 0x001F0000
/** field offset */
#define DISP_LFIFO4_LEN17_OFFSET 16
/** Link FIFO 18 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 18. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO4_OV18 0x00008000
/** Link FIFO 18 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 18. */
#define DISP_LFIFO4_LEN18_MASK 0x00001F00
/** field offset */
#define DISP_LFIFO4_LEN18_OFFSET 8
/** Link FIFO 19 overflow
    This Flag indicates that at a FIFO overflow has occured for the link buffer 19. The bit is reset when either a link reset is performed or the module ACT bit is deactivated. */
#define DISP_LFIFO4_OV19 0x00000080
/** Link FIFO 19 occupancy
    This Flag represents the number of 64-bit words which are currently buffered in thread link FIFO 19. */
#define DISP_LFIFO4_LEN19_MASK 0x0000001F
/** field offset */
#define DISP_LFIFO4_LEN19_OFFSET 0

/* Fields of "Address/Valid Register of LINK HOST" */
/** Write valid
    This bit activates the LINK-Interface for writing. */
#define DISP_LINKHOST_WVAL 0x00001000
/** Read valid
    This bit activates the LINK-Interface for reading. */
#define DISP_LINKHOST_RVAL 0x00000100
/** Read address of LINK-Interface
    Stores the data of the choosed thread number if read is activated.This field is limited to 19 by the hardware. */
#define DISP_LINKHOST_RADDR_MASK 0x0000001F
/** field offset */
#define DISP_LINKHOST_RADDR_OFFSET 0

/* Fields of "Control Register" */
/** Request pulse -- not supported for this instance
    When writing '1' to this bit, a request pulse is asserted. */
#define DISP_LINK_CTRL_REQ 0x00000020
/** Block Mode Transmitter
    When this bit is set (EN) transmitter operates in block mode. This means that at the output is send only if at least one complete packet is stored in the FIFO (thus at least one EOP has been applied). If the transmitter operates in regular mode, data is sent as soon as at least one data word is available in the trasnmit FIFO. */
#define DISP_LINK_CTRL_BMX 0x00000010
/* Disable
#define DISP_LINK_CTRL_BMX_DIS 0x00000000 */
/** Enable */
#define DISP_LINK_CTRL_BMX_EN 0x00000010
/** Reset Receiver
    When this bit is set the receiver is reseted */
#define DISP_LINK_CTRL_RSR 0x00000008
/** Reset Transmitter
    When this bit is set the transmitter is reseted */
#define DISP_LINK_CTRL_RSX 0x00000004
/** Mark as Start-of-Packet
    On a write the next data written to DATA is marked as the first data packet (Start of Packet).On a read the information is returned whether the current 64bit word within DATA is signed as the first data packet (Start of Packet). */
#define DISP_LINK_CTRL_SOP 0x00000002
/** Mark as End-of-Packet
    On a write the next data written to DATA is marked as the last data packet (End of Packet).On a read the information is returned whether the current 64bit word within DATA is signed as the last data packet (End of Packet). */
#define DISP_LINK_CTRL_EOP 0x00000001

/* Fields of "LINK_IRN Capture Register" */
/** Transmit FIFO Empty
    This bit is set if the Transmit FIFO is empty. This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define DISP_LINK_IRNCR_TXE 0x00000010
/* Nothing
#define DISP_LINK_IRNCR_TXE_NULL 0x00000000 */
/** Read: Interrupt occurred. */
#define DISP_LINK_IRNCR_TXE_INTOCC 0x00000010
/** Transmit FIFO Ready
    This bit is set if the Transmit FIFO is not full. This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define DISP_LINK_IRNCR_TXR 0x00000008
/* Nothing
#define DISP_LINK_IRNCR_TXR_NULL 0x00000000 */
/** Read: Interrupt occurred. */
#define DISP_LINK_IRNCR_TXR_INTOCC 0x00000008
/** Receive FIFO Ready
    This bit is set if the Recieve FIFO is not empty. This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define DISP_LINK_IRNCR_RXR 0x00000004
/* Nothing
#define DISP_LINK_IRNCR_RXR_NULL 0x00000000 */
/** Read: Interrupt occurred. */
#define DISP_LINK_IRNCR_RXR_INTOCC 0x00000004
/** Start-of-Packet
    This bit is set if the topmost receive FIFO entry is a start-of-packet This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define DISP_LINK_IRNCR_SOP 0x00000002
/* Nothing
#define DISP_LINK_IRNCR_SOP_NULL 0x00000000 */
/** Read: Interrupt occurred. */
#define DISP_LINK_IRNCR_SOP_INTOCC 0x00000002
/** End-of-Packet
    This bit is set if the topmost receive FIFO entry is a end-of-packet This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define DISP_LINK_IRNCR_EOP 0x00000001
/* Nothing
#define DISP_LINK_IRNCR_EOP_NULL 0x00000000 */
/** Read: Interrupt occurred. */
#define DISP_LINK_IRNCR_EOP_INTOCC 0x00000001

/* Fields of "LINK_IRN Interrupt Control Register" */
/** Transmit FIFO Empty
    Interrupt control bit for the corresponding bit in the LINK_IRNCR register. */
#define DISP_LINK_IRNICR_TXE 0x00000010
/** Transmit FIFO Ready
    Interrupt control bit for the corresponding bit in the LINK_IRNCR register. */
#define DISP_LINK_IRNICR_TXR 0x00000008
/** Receive FIFO Ready
    Interrupt control bit for the corresponding bit in the LINK_IRNCR register. */
#define DISP_LINK_IRNICR_RXR 0x00000004
/** Start-of-Packet
    Interrupt control bit for the corresponding bit in the LINK_IRNCR register. */
#define DISP_LINK_IRNICR_SOP 0x00000002
/** End-of-Packet
    Interrupt control bit for the corresponding bit in the LINK_IRNCR register. */
#define DISP_LINK_IRNICR_EOP 0x00000001

/* Fields of "LINK_IRN Interrupt Enable Register" */
/** Transmit FIFO Empty
    Interrupt enable bit for the corresponding bit in the LINK_IRNCR register. */
#define DISP_LINK_IRNEN_TXE 0x00000010
/* Disable
#define DISP_LINK_IRNEN_TXE_DIS 0x00000000 */
/** Enable */
#define DISP_LINK_IRNEN_TXE_EN 0x00000010
/** Transmit FIFO Ready
    Interrupt enable bit for the corresponding bit in the LINK_IRNCR register. */
#define DISP_LINK_IRNEN_TXR 0x00000008
/* Disable
#define DISP_LINK_IRNEN_TXR_DIS 0x00000000 */
/** Enable */
#define DISP_LINK_IRNEN_TXR_EN 0x00000008
/** Receive FIFO Ready
    Interrupt enable bit for the corresponding bit in the LINK_IRNCR register. */
#define DISP_LINK_IRNEN_RXR 0x00000004
/* Disable
#define DISP_LINK_IRNEN_RXR_DIS 0x00000000 */
/** Enable */
#define DISP_LINK_IRNEN_RXR_EN 0x00000004
/** Start-of-Packet
    Interrupt enable bit for the corresponding bit in the LINK_IRNCR register. */
#define DISP_LINK_IRNEN_SOP 0x00000002
/* Disable
#define DISP_LINK_IRNEN_SOP_DIS 0x00000000 */
/** Enable */
#define DISP_LINK_IRNEN_SOP_EN 0x00000002
/** End-of-Packet
    Interrupt enable bit for the corresponding bit in the LINK_IRNCR register. */
#define DISP_LINK_IRNEN_EOP 0x00000001
/* Disable
#define DISP_LINK_IRNEN_EOP_DIS 0x00000000 */
/** Enable */
#define DISP_LINK_IRNEN_EOP_EN 0x00000001

/* Fields of "Length Register" */
/** Receiver Packets
    Returns the number of complete packets which are curently stored in the receive FIFO. */
#define DISP_LINK_LEN_PACR_MASK 0x03000000
/** field offset */
#define DISP_LINK_LEN_PACR_OFFSET 24
/** Receiver Length
    Returns the number of available complete entries in the receive FIFO.This value is decremented whenever a complete 64bit word is read from DATA (Data0+Data1).This value is incremented whenever a complete 64bit word is received (inserted into the DATA FIFO).The seqence of reads to Data0 and Data1 isn't of any matter. */
#define DISP_LINK_LEN_LENR_MASK 0x00030000
/** field offset */
#define DISP_LINK_LEN_LENR_OFFSET 16
/** Transmitter Packets
    Returns the number of complete packets which are currently stored in the transmit FIFO. */
#define DISP_LINK_LEN_PACX_MASK 0x00000300
/** field offset */
#define DISP_LINK_LEN_PACX_OFFSET 8
/** Transmitter Length
    Returns the number of available free entries in the transmit FIFO.This value is decremented whenever a complete 64bit word is written to DATA (Data0+Data1).This value is incremented whenever a complete 64bit word is transmitted (evicted from the DATA FIFO).The seqence of writes to Data0 and Data1 isn't of any matter. */
#define DISP_LINK_LEN_LENX_MASK 0x00000003
/** field offset */
#define DISP_LINK_LEN_LENX_OFFSET 0

/* Fields of "Data Register 0" */
/** Receive/Transmit Data 0
    This register holds the lower 32bits of a 64bit word (bits 31:0) transferd via the LINK interface.On a read the lower 32bits from the receive fifo are returned.On a write the lower 32bits are written to the transmit fifo. */
#define DISP_LINK_DATA0_DATA0_MASK 0xFFFFFFFF
/** field offset */
#define DISP_LINK_DATA0_DATA0_OFFSET 0

/* Fields of "Data Register 1" */
/** Receive/Transmit Data 1
    This register holds the higher 32bits of a 64bit word (bits 63:32) transferd via the LINK interface.On a read the higher 32bits from the receive fifo are returned.On a write the higher 32bits are written to the transmit fifo. */
#define DISP_LINK_DATA1_DATA1_MASK 0xFFFFFFFF
/** field offset */
#define DISP_LINK_DATA1_DATA1_OFFSET 0

/*! @} */ /* DISP_REGISTER */

#endif /* _drv_onu_reg_disp_h */
