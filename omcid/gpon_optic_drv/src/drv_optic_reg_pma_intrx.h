/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_pma_intrx_h
#define _drv_optic_reg_pma_intrx_h

/** \addtogroup PMA_INTRX_REGISTER
   @{
*/
/* access macros */
#define pma_intrx_r32(reg) reg_r32(&pma_intrx->reg)
#define pma_intrx_w32(val, reg) reg_w32(val, &pma_intrx->reg)
#define pma_intrx_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &pma_intrx->reg)
#define pma_intrx_r32_table(reg, idx) reg_r32_table(pma_intrx->reg, idx)
#define pma_intrx_w32_table(val, reg, idx) reg_w32_table(val, pma_intrx->reg, idx)
#define pma_intrx_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, pma_intrx->reg, idx)
#define pma_intrx_adr_table(reg, idx) adr_table(pma_intrx->reg, idx)


/** PMA_INTRX register structure */
struct optic_reg_pma_intrx
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
/** Loss of Lock
    RX data frequency != PLL+/-xppm This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define PMA_INTRX_IRNCR_LOL 0x00000001
/** Nothing */
#define PMA_INTRX_IRNCR_LOL_NULL 0x00000000
/** Read: Interrupt occurred. */
#define PMA_INTRX_IRNCR_LOL_INTOCC 0x00000001

/* Fields of "IRN Interrupt Control Register" */
/** Loss of Lock
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define PMA_INTRX_IRNICR_LOL 0x00000001

/* Fields of "IRN Interrupt Enable Register" */
/** Loss of Lock
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define PMA_INTRX_IRNEN_LOL 0x00000001
/** Disable */
#define PMA_INTRX_IRNEN_LOL_DIS 0x00000000
/** Enable */
#define PMA_INTRX_IRNEN_LOL_EN 0x00000001

/*! @} */ /* PMA_INTRX_REGISTER */

#endif /* _drv_optic_reg_pma_intrx_h */
