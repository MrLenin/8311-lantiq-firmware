/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_fcsic_h
#define _drv_optic_reg_fcsic_h

/** \addtogroup FCSIC_REGISTER
   @{
*/
/* access macros */
#define fcsic_r32(reg) reg_r32(&fcsic->reg)
#define fcsic_w32(val, reg) reg_w32(val, &fcsic->reg)
#define fcsic_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &fcsic->reg)
#define fcsic_r32_table(reg, idx) reg_r32_table(fcsic->reg, idx)
#define fcsic_w32_table(val, reg, idx) reg_w32_table(val, fcsic->reg, idx)
#define fcsic_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, fcsic->reg, idx)
#define fcsic_adr_table(reg, idx) adr_table(fcsic->reg, idx)


/** FCSIC register structure */
struct optic_reg_fcsic
{
   /** Control Register
       The FCSI Control Register controls all interrupt sources of the FCSI interface. */
   unsigned int ctrl; /* 0x00000000 */
   /** Status Register
       The FCSI Status Register holds the current state of the FCSI controller and the state of the FCSI interrupt request lines. */
   unsigned int stat; /* 0x00000004 */
   /** Interrupt Register
       The FCSI Interrupt Register holds all pending interrupt events of the FCSI controller and the FCSI bus. */
   unsigned int intr; /* 0x00000008 */
   /** Command Register
       The FCSI command register controls the address and transfer type for FCSI bus accesses. */
   unsigned int cmd; /* 0x0000000C */
   /** Data Register
       The FCSI Data Register represents the data interface to the FCSI bus. */
   unsigned int data; /* 0x00000010 */
   /** Reserved */
   unsigned int res_0[3]; /* 0x00000014 */
};


/* Fields of "Control Register" */
/** ERR Interrupt Enable
    Enables interrupt ERR. */
#define FCSIC_CTRL_ERR 0x00000008
/** Disable */
#define FCSIC_CTRL_ERR_DIS 0x00000000
/** Enable */
#define FCSIC_CTRL_ERR_EN 0x00000008
/** RR Interrupt Enable
    Enables interrupt RR. */
#define FCSIC_CTRL_RR 0x00000004
/** Disable */
#define FCSIC_CTRL_RR_DIS 0x00000000
/** Enable */
#define FCSIC_CTRL_RR_EN 0x00000004
/** XE Interrupt Enable
    Enables interrupt XE. */
#define FCSIC_CTRL_XE 0x00000002
/** Disable */
#define FCSIC_CTRL_XE_DIS 0x00000000
/** Enable */
#define FCSIC_CTRL_XE_EN 0x00000002
/** XR Interrupt Enable
    Enables interrupt XR. */
#define FCSIC_CTRL_XR 0x00000001
/** Disable */
#define FCSIC_CTRL_XR_DIS 0x00000000
/** Enable */
#define FCSIC_CTRL_XR_EN 0x00000001

/* Fields of "Status Register" */
/** Error
    The ERR bit is set when the Command-FIFO is full and another read or write command is issued or if there is an overflow condition of the Result-Queue. The bit reflects the corresponding bit in the FCSI_INT register. */
#define FCSIC_STAT_ERR 0x00000008
/** Nothing */
#define FCSIC_STAT_ERR_NULL 0x00000000
/** Read: Event occurred. */
#define FCSIC_STAT_ERR_EVOCC 0x00000008
/** Receiver Ready
    Indicates that at least one new data word is available in the FCSI Result-FIFO. The bit is directly derived from the fifo counters. */
#define FCSIC_STAT_RR 0x00000004
/** Nothing */
#define FCSIC_STAT_RR_NULL 0x00000000
/** Ready: The FIFO is ready to be accessed. */
#define FCSIC_STAT_RR_FRDY 0x00000004
/** Transmitter Empty
    Indicates that Command-FIFO is empty AND that there are no FCSI operations running. The bit is directly derived from the fifo counters. */
#define FCSIC_STAT_XE 0x00000002
/** Nothing */
#define FCSIC_STAT_XE_NULL 0x00000000
/** FIFO empty: The FIFO does not contain data. */
#define FCSIC_STAT_XE_FEMP 0x00000002
/** Transmitter Ready
    Indicates that a new data word can be written to the Command-FIFO. The bit is directly derived from the fifo counters. */
#define FCSIC_STAT_XR 0x00000001
/** Nothing */
#define FCSIC_STAT_XR_NULL 0x00000000
/** Ready: The FIFO is ready to be accessed. */
#define FCSIC_STAT_XR_FRDY 0x00000001

/* Fields of "Interrupt Register" */
/** ERR Interrupt
    Interrupt ERR occurred. The bit is cleard on read. */
#define FCSIC_INTR_ERR 0x00000008
/** Nothing */
#define FCSIC_INTR_ERR_NULL 0x00000000
/** Read: Interrupt occurred. */
#define FCSIC_INTR_ERR_INTOCC 0x00000008
/** RR Interrupt
    Interrupt RR occurred. Since this interrupt is level sensitive this bit is identical to the corresponding status register bit. */
#define FCSIC_INTR_RR 0x00000004
/** Nothing */
#define FCSIC_INTR_RR_NULL 0x00000000
/** Read: Interrupt occurred. */
#define FCSIC_INTR_RR_INTOCC 0x00000004
/** XE Interrupt
    Interrupt XE occurred. Since this interrupt is level sensitive this bit is identical to the corresponding status register bit. */
#define FCSIC_INTR_XE 0x00000002
/** Nothing */
#define FCSIC_INTR_XE_NULL 0x00000000
/** Read: Interrupt occurred. */
#define FCSIC_INTR_XE_INTOCC 0x00000002
/** XR Interrupt
    Interrupt XR occurred. Since this interrupt is level sensitive this bit is identical to the corresponding status register bit. */
#define FCSIC_INTR_XR 0x00000001
/** Nothing */
#define FCSIC_INTR_XR_NULL 0x00000000
/** Read: Interrupt occurred. */
#define FCSIC_INTR_XR_INTOCC 0x00000001

/* Fields of "Command Register" */
/** FCSI Command */
#define FCSIC_CMD_CMD_MASK 0x0000E000
/** field offset */
#define FCSIC_CMD_CMD_OFFSET 13
/** In this case the ADDR field and the AI field is written to a temporary address register. A following data write to the FCSI_DATA register is required and writes the content of the temporary address register together with the data written to FCSI_DATA into the Command-FIFO. If the AI field was programmed to a logical one, then the ADDR field in the temporary address register is incremented by one. For further consecutive writes only the data register has to be written (optional). */
#define FCSIC_CMD_CMD_WRITE 0x00000000
/** In this case a read operation is inserted into the Command-FIFO together with the effective read address. The effective read-address is defined by the ADDR field (AI=0) or the contents of the temporary address register (AI=1). If AI is equal to one also the temporary address register is incremented by one. As long as there is space available in the Result FIFO and the number of FCSI reads is less than then reads requested in the LEN field the Read Command reads the next word from the FCSI address. The Result-FIFO and can be read later by reading from the FCSI_DATA address. Please note, that the order of operations is maintained, e.g. the read command is executed always after previous read and/or write commands. */
#define FCSIC_CMD_CMD_READ 0x00002000
/** Reset FCSI Controller and Bus. The Reset line of the FCSI bus is pulsed low. Additionally the FCSI Interface itself is resetted. Two additonal parameters define the reset low time and reset recovery time 2**n cylces (n=0...7). */
#define FCSIC_CMD_CMD_RST 0x00004000
/** Reset FCSI Bus. The Reset line of the FCSI bus is pulsed low. The FCSI Interface itself is not resetted. The reset recovery time is 16 clock cycles. Please note, that the command following the RST command is executed after the reset sequence has been finished, therefore it is valid to write any other command into the command FIFO before the RST command is executed. */
#define FCSIC_CMD_CMD_BUS_RST 0x00006000
/** Reset Command-In FIFO. The Command-In FIFO is reset. The current bus transaction is not aborted. */
#define FCSIC_CMD_CMD_CMD_RST 0x00008000
/** Reset Result-FIFO. The Result-FIFO is reset. The current bus transaction is not aborted. */
#define FCSIC_CMD_CMD_RES_RST 0x0000A000
/** Auto Increment
    Enables the autoincrement mode. If enabled the address is incrementet for each access of a block access (LEN field greater than 1). This bit is only valid for WRITE and READ commands, ignored for other commands. */
#define FCSIC_CMD_AI 0x00001000
/** Disable */
#define FCSIC_CMD_AI_DIS 0x00000000
/** Enable */
#define FCSIC_CMD_AI_EN 0x00001000
/** Length
    Number of words that should be read. This field is only valid for READ commands, ignored for other commands. */
#define FCSIC_CMD_LEN_MASK 0x00000F00
/** field offset */
#define FCSIC_CMD_LEN_OFFSET 8
/** Address
    Holds the address for FCSI accesses. For write operations this field is written to the temporary address register. For read operations this field is written to the Command-FIFO and temporary address register, if the AI field is set to zero. If the AI field is set to one the ADDR field is ignored and the value of the temporary address register is written to the Command-FIFO. This field is only valid for WRITE and READ commands, ignored for other commands. */
#define FCSIC_CMD_ADDR_MASK 0x000000FF
/** field offset */
#define FCSIC_CMD_ADDR_OFFSET 0

/* Fields of "Data Register" */
/** FCSI Data
    The FCSI Data register is physically connected to the Command-FIFO for write operations and to the Result-FIFO for read operations. For a detailed description of read and write operations see the CMD register. */
#define FCSIC_DATA_DATA_MASK 0x0000FFFF
/** field offset */
#define FCSIC_DATA_DATA_OFFSET 0

/*! @} */ /* FCSIC_REGISTER */

#endif /* _drv_optic_reg_fcsic_h */
