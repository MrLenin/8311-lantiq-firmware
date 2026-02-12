/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_pma_int200_h
#define _drv_optic_reg_pma_int200_h

/** \addtogroup PMA_INT200_REGISTER
   @{
*/
/* access macros */
#define pma_int200_r32(reg) reg_r32(&pma_int200->reg)
#define pma_int200_w32(val, reg) reg_w32(val, &pma_int200->reg)
#define pma_int200_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &pma_int200->reg)
#define pma_int200_r32_table(reg, idx) reg_r32_table(pma_int200->reg, idx)
#define pma_int200_w32_table(val, reg, idx) reg_w32_table(val, pma_int200->reg, idx)
#define pma_int200_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, pma_int200->reg, idx)
#define pma_int200_adr_table(reg, idx) adr_table(pma_int200->reg, idx)


/** PMA_INT200 register structure */
struct optic_reg_pma_int200
{
   /** IRN Capture Register
       This register shows the currently active interrupt events masked with the corresponding enable bits of the IRNEN register. The interrupts can be acknowledged by a write operation. */
   unsigned int irncr; /* 0x00000000 */
   /** IRN Interrupt Control Register
       A write operation directly effects the interrupts. This can be used to trigger events under software control for testing purposes. A read operation returns the unmasked interrupt events. */
   unsigned int irnicr; /* 0x00000004 */
   /** IRN Interrupt Enable Register
       This register contains the enable (or mask) bits for the interrupts. Disabled interrupts are not visible in the IRNCR register and are not signalled via the interrupt line towards the controller. */
   unsigned int irnen; /* 0x00000008 */
   /** Reserved */
   unsigned int res_0; /* 0x0000000C */
};


/* Fields of "IRN Capture Register" */
/** Overload of Signal
    SSI Level above upper limit. Senseful only as result of measurement on channel 9. This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define PMA_INT200_IRNCR_OVL 0x00000004
/** Nothing */
#define PMA_INT200_IRNCR_OVL_NULL 0x00000000
/** Read: Interrupt occurred. */
#define PMA_INT200_IRNCR_OVL_INTOCC 0x00000004
/** Signal has become Valid
    This is the edge-sensitive inverted signal LOS. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define PMA_INT200_IRNCR_SIGDET 0x00000002
/** Nothing */
#define PMA_INT200_IRNCR_SIGDET_NULL 0x00000000
/** Write: Acknowledge the interrupt. */
#define PMA_INT200_IRNCR_SIGDET_INTACK 0x00000002
/** Read: Interrupt occurred. */
#define PMA_INT200_IRNCR_SIGDET_INTOCC 0x00000002
/** Loss of Signal
    SSI Level below lower limit. Senseful only as result of measurement on channel 9. This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define PMA_INT200_IRNCR_LOS 0x00000001
/** Nothing */
#define PMA_INT200_IRNCR_LOS_NULL 0x00000000
/** Read: Interrupt occurred. */
#define PMA_INT200_IRNCR_LOS_INTOCC 0x00000001

/* Fields of "IRN Interrupt Control Register" */
/** Overload of Signal
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define PMA_INT200_IRNICR_OVL 0x00000004
/** Signal has become Valid
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define PMA_INT200_IRNICR_SIGDET 0x00000002
/** Loss of Signal
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define PMA_INT200_IRNICR_LOS 0x00000001

/* Fields of "IRN Interrupt Enable Register" */
/** Overload of Signal
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define PMA_INT200_IRNEN_OVL 0x00000004
/** Disable */
#define PMA_INT200_IRNEN_OVL_DIS 0x00000000
/** Enable */
#define PMA_INT200_IRNEN_OVL_EN 0x00000004
/** Signal has become Valid
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define PMA_INT200_IRNEN_SIGDET 0x00000002
/** Disable */
#define PMA_INT200_IRNEN_SIGDET_DIS 0x00000000
/** Enable */
#define PMA_INT200_IRNEN_SIGDET_EN 0x00000002
/** Loss of Signal
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define PMA_INT200_IRNEN_LOS 0x00000001
/** Disable */
#define PMA_INT200_IRNEN_LOS_DIS 0x00000000
/** Enable */
#define PMA_INT200_IRNEN_LOS_EN 0x00000001

/*! @} */ /* PMA_INT200_REGISTER */

#endif /* _drv_optic_reg_pma_int200_h */
