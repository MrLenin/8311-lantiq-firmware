/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_pma_inttx_h
#define _drv_optic_reg_pma_inttx_h

/** \addtogroup PMA_INTTX_REGISTER
   @{
*/
/* access macros */
#define pma_inttx_r32(reg) reg_r32(&pma_inttx->reg)
#define pma_inttx_w32(val, reg) reg_w32(val, &pma_inttx->reg)
#define pma_inttx_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &pma_inttx->reg)
#define pma_inttx_r32_table(reg, idx) reg_r32_table(pma_inttx->reg, idx)
#define pma_inttx_w32_table(val, reg, idx) reg_w32_table(val, pma_inttx->reg, idx)
#define pma_inttx_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, pma_inttx->reg, idx)
#define pma_inttx_adr_table(reg, idx) adr_table(pma_inttx->reg, idx)


/** PMA_INTTX register structure */
struct optic_reg_pma_inttx
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
/** Overcurrent
    Modulation + bias current above programmable threshold. This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define PMA_INTTX_IRNCR_OV 0x00000040
/** Nothing */
#define PMA_INTTX_IRNCR_OV_NULL 0x00000000
/** Read: Interrupt occurred. */
#define PMA_INTTX_IRNCR_OV_INTOCC 0x00000040
/** BFD P1 Inter-Burst Alarm
    p1_alarm[6:0] nibbles P1 limit. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define PMA_INTTX_IRNCR_BP1IBA 0x00000020
/** Nothing */
#define PMA_INTTX_IRNCR_BP1IBA_NULL 0x00000000
/** Write: Acknowledge the interrupt. */
#define PMA_INTTX_IRNCR_BP1IBA_INTACK 0x00000020
/** Read: Interrupt occurred. */
#define PMA_INTTX_IRNCR_BP1IBA_INTOCC 0x00000020
/** BFD P0 Inter-Burst Alarm
    p0_alarm[6:0] nibbles P0 limit. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define PMA_INTTX_IRNCR_BP0IBA 0x00000010
/** Nothing */
#define PMA_INTTX_IRNCR_BP0IBA_NULL 0x00000000
/** Write: Acknowledge the interrupt. */
#define PMA_INTTX_IRNCR_BP0IBA_INTACK 0x00000010
/** Read: Interrupt occurred. */
#define PMA_INTTX_IRNCR_BP0IBA_INTOCC 0x00000010
/** BFD P1 Intra-Burst Alarm
    p1_alarm[6:0] nibbles P1 limit. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define PMA_INTTX_IRNCR_BP1BA 0x00000008
/** Nothing */
#define PMA_INTTX_IRNCR_BP1BA_NULL 0x00000000
/** Write: Acknowledge the interrupt. */
#define PMA_INTTX_IRNCR_BP1BA_INTACK 0x00000008
/** Read: Interrupt occurred. */
#define PMA_INTTX_IRNCR_BP1BA_INTOCC 0x00000008
/** BFD P0 Intra-Burst Alarm
    p0_alarm[6:0] nibbles This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define PMA_INTTX_IRNCR_BP0BA 0x00000004
/** Nothing */
#define PMA_INTTX_IRNCR_BP0BA_NULL 0x00000000
/** Write: Acknowledge the interrupt. */
#define PMA_INTTX_IRNCR_BP0BA_INTACK 0x00000004
/** Read: Interrupt occurred. */
#define PMA_INTTX_IRNCR_BP0BA_INTOCC 0x00000004
/** Bias Limit
    Bias current above programmable threshold. This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define PMA_INTTX_IRNCR_BIASL 0x00000002
/** Nothing */
#define PMA_INTTX_IRNCR_BIASL_NULL 0x00000000
/** Read: Interrupt occurred. */
#define PMA_INTTX_IRNCR_BIASL_INTOCC 0x00000002
/** Modulation Limit
    Modulation current above programmable threshold. This bit is level-sensitive. This bit contributes to the indirect interrupt. */
#define PMA_INTTX_IRNCR_MODL 0x00000001
/** Nothing */
#define PMA_INTTX_IRNCR_MODL_NULL 0x00000000
/** Read: Interrupt occurred. */
#define PMA_INTTX_IRNCR_MODL_INTOCC 0x00000001

/* Fields of "IRN Interrupt Control Register" */
/** Overcurrent
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNICR_OV 0x00000040
/** BFD P1 Inter-Burst Alarm
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNICR_BP1IBA 0x00000020
/** BFD P0 Inter-Burst Alarm
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNICR_BP0IBA 0x00000010
/** BFD P1 Intra-Burst Alarm
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNICR_BP1BA 0x00000008
/** BFD P0 Intra-Burst Alarm
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNICR_BP0BA 0x00000004
/** Bias Limit
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNICR_BIASL 0x00000002
/** Modulation Limit
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNICR_MODL 0x00000001

/* Fields of "IRN Interrupt Enable Register" */
/** Overcurrent
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNEN_OV 0x00000040
/** Disable */
#define PMA_INTTX_IRNEN_OV_DIS 0x00000000
/** Enable */
#define PMA_INTTX_IRNEN_OV_EN 0x00000040
/** BFD P1 Inter-Burst Alarm
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNEN_BP1IBA 0x00000020
/** Disable */
#define PMA_INTTX_IRNEN_BP1IBA_DIS 0x00000000
/** Enable */
#define PMA_INTTX_IRNEN_BP1IBA_EN 0x00000020
/** BFD P0 Inter-Burst Alarm
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNEN_BP0IBA 0x00000010
/** Disable */
#define PMA_INTTX_IRNEN_BP0IBA_DIS 0x00000000
/** Enable */
#define PMA_INTTX_IRNEN_BP0IBA_EN 0x00000010
/** BFD P1 Intra-Burst Alarm
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNEN_BP1BA 0x00000008
/** Disable */
#define PMA_INTTX_IRNEN_BP1BA_DIS 0x00000000
/** Enable */
#define PMA_INTTX_IRNEN_BP1BA_EN 0x00000008
/** BFD P0 Intra-Burst Alarm
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNEN_BP0BA 0x00000004
/** Disable */
#define PMA_INTTX_IRNEN_BP0BA_DIS 0x00000000
/** Enable */
#define PMA_INTTX_IRNEN_BP0BA_EN 0x00000004
/** Bias Limit
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNEN_BIASL 0x00000002
/** Disable */
#define PMA_INTTX_IRNEN_BIASL_DIS 0x00000000
/** Enable */
#define PMA_INTTX_IRNEN_BIASL_EN 0x00000002
/** Modulation Limit
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define PMA_INTTX_IRNEN_MODL 0x00000001
/** Disable */
#define PMA_INTTX_IRNEN_MODL_DIS 0x00000000
/** Enable */
#define PMA_INTTX_IRNEN_MODL_EN 0x00000001

/*! @} */ /* PMA_INTTX_REGISTER */

#endif /* _drv_optic_reg_pma_inttx_h */
