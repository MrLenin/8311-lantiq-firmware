/******************************************************************************

                               Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_reg_ictrlc_h
#define _drv_onu_reg_ictrlc_h

/** \addtogroup ICTRLC_REGISTER
   @{
*/
/* access macros */
#define ictrlc_r32(reg) reg_r32(&ictrlc->reg)
#define ictrlc_w32(val, reg) reg_w32(val, &ictrlc->reg)
#define ictrlc_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &ictrlc->reg)
#define ictrlc_r32_table(reg, idx) reg_r32_table(ictrlc->reg, idx)
#define ictrlc_w32_table(val, reg, idx) reg_w32_table(val, ictrlc->reg, idx)
#define ictrlc_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, ictrlc->reg, idx)
#define ictrlc_adr_table(reg, idx) adr_table(ictrlc->reg, idx)

/** ICTRLC register structure */
struct onu_reg_ictrlc
{
   /** Control Register
       This register provides the global LINK Interface controls. The Link-Interface is an on-chip network which interconnects different on-chip modules. The CPU can use this interface to access this network. */
   unsigned int ctrl; /* 0x00000000 */
   /** Reserved */
   unsigned int res_0[3]; /* 0x00000004 */
   /** IRN Capture Register
       This register shows the currently active interrupt events masked with the corresponding enable bits of the IRNEN register. The interrupts can be acknowledged by a write operation. */
   unsigned int irncr; /* 0x00000010 */
   /** IRN Interrupt Control Register
       A write operation directly effects the interrupts. This can be used to trigger events under software control for testing purposes. A read operation returns the unmasked interrupt events. */
   unsigned int irnicr; /* 0x00000014 */
   /** IRN Interrupt Enable Register
       This register contains the enable (or mask) bits for the interrupts. Disabled interrupts are not visible in the IRNCR register and are not signalled via the interrupt line towards the controller. */
   unsigned int irnen; /* 0x00000018 */
   /** Reserved */
   unsigned int res_1; /* 0x0000001C */
   /** Length Register
       Holds the FIFO Lenght for the Transmit FIFO */
   unsigned int len; /* 0x00000020 */
   /** Data Register 0
       Transmit data Register 0 */
   unsigned int data0; /* 0x00000024 */
   /** Data Register 1
       Transmit data Register 1 */
   unsigned int data1; /* 0x00000028 */
   /** Reserved */
   unsigned int res_2[53]; /* 0x0000002C */
};


/* Fields of "Control Register" */
/** Request pulse
    When writing '1' to this bit, a request pulse is asserted. */
#define ICTRLC_CTRL_REQ 0x00000020
/** Block Mode Transmitter
    When this bit is set (EN) transmitter operates in block mode. This means that at the output is send only if at least one complete packet is stored in the FIFO (thus at least one EOP has been applied). If the transmitter operates in regular mode, data is sent as soon as at least one data word is available in the trasnmit FIFO. */
#define ICTRLC_CTRL_BMX 0x00000010
/* Disable
#define ICTRLC_CTRL_BMX_DIS 0x00000000 */
/** Enable */
#define ICTRLC_CTRL_BMX_EN 0x00000010
/** Reset Transmitter
    When this bit is set the transmitter is reseted */
#define ICTRLC_CTRL_RSX 0x00000004
/** Mark as Start-of-Packet
    On a write the next data written to DATA is marked as the first data packet (Start of Packet). */
#define ICTRLC_CTRL_SOP 0x00000002
/** Mark as End-of-Packet
    On a write the next data written to DATA is marked as the last data packet (End of Packet). */
#define ICTRLC_CTRL_EOP 0x00000001

/* Fields of "IRN Capture Register" */
/** Transmit FIFO Empty
    This bit is set if the Transmit FIFO is empty. This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define ICTRLC_IRNCR_TXE 0x00000010
/* Nothing
#define ICTRLC_IRNCR_TXE_NULL 0x00000000 */
/** Read: Interrupt occurred. */
#define ICTRLC_IRNCR_TXE_INTOCC 0x00000010
/** Transmit FIFO Ready
    This bit is set if the Transmit FIFO is not full. This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define ICTRLC_IRNCR_TXR 0x00000008
/* Nothing
#define ICTRLC_IRNCR_TXR_NULL 0x00000000 */
/** Read: Interrupt occurred. */
#define ICTRLC_IRNCR_TXR_INTOCC 0x00000008

/* Fields of "IRN Interrupt Control Register" */
/** Transmit FIFO Empty
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define ICTRLC_IRNICR_TXE 0x00000010
/** Transmit FIFO Ready
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define ICTRLC_IRNICR_TXR 0x00000008

/* Fields of "IRN Interrupt Enable Register" */
/** Transmit FIFO Empty
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define ICTRLC_IRNEN_TXE 0x00000010
/* Disable
#define ICTRLC_IRNEN_TXE_DIS 0x00000000 */
/** Enable */
#define ICTRLC_IRNEN_TXE_EN 0x00000010
/** Transmit FIFO Ready
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define ICTRLC_IRNEN_TXR 0x00000008
/* Disable
#define ICTRLC_IRNEN_TXR_DIS 0x00000000 */
/** Enable */
#define ICTRLC_IRNEN_TXR_EN 0x00000008

/* Fields of "Length Register" */
/** Transmitter Packets
    Returns the number of complete packets which are currently stored in the transmit FIFO. */
#define ICTRLC_LEN_PACX_MASK 0x00000F00
/** field offset */
#define ICTRLC_LEN_PACX_OFFSET 8
/** Transmitter Length
    Returns the number of available free entries in the transmit FIFO.This value is decremented whenever a complete 64bit word is written to DATA (Data0+Data1).This value is incremented whenever a complete 64bit word is transmitted (evicted from the DATA FIFO).The seqence of writes to Data0 and Data1 isn't of any matter. */
#define ICTRLC_LEN_LENX_MASK 0x0000000F
/** field offset */
#define ICTRLC_LEN_LENX_OFFSET 0

/* Fields of "Data Register 0" */
/** Receive/Transmit Data 0
    This register holds the lower 32bits of a 64bit word (bits 31:0) transferd via the LINK interface.On a write the lower 32bits are written to the transmit fifo. */
#define ICTRLC_DATA0_DATA0_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLC_DATA0_DATA0_OFFSET 0

/* Fields of "Data Register 1" */
/** Receive/Transmit Data 1
    This register holds the higher 32bits of a 64bit word (bits 63:32) transferd via the LINK interface.On a write the higher 32bits are written to the transmit fifo. */
#define ICTRLC_DATA1_DATA1_MASK 0xFFFFFFFF
/** field offset */
#define ICTRLC_DATA1_DATA1_OFFSET 0

/*! @} */ /* ICTRLC_REGISTER */

#endif /* _drv_onu_reg_ictrlc_h */
