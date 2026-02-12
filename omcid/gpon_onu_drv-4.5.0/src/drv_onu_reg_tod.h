/******************************************************************************

                               Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_reg_tod_h
#define _drv_onu_reg_tod_h

/** \addtogroup TOD_REGISTER
   @{
*/
/* access macros */
#define tod_r32(reg) reg_r32(&tod->reg)
#define tod_w32(val, reg) reg_w32(val, &tod->reg)
#define tod_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &tod->reg)
#define tod_r32_table(reg, idx) reg_r32_table(tod->reg, idx)
#define tod_w32_table(val, reg, idx) reg_w32_table(val, tod->reg, idx)
#define tod_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, tod->reg, idx)
#define tod_adr_table(reg, idx) adr_table(tod->reg, idx)


/** TOD register structure */
struct onu_reg_tod
{
   /** Configuration Register
       Configures the module. */
   unsigned int cfg; /* 0x00000000 */
   /** Reserved */
   unsigned int res_0[3]; /* 0x00000004 */
   /** Nanoseconds Reload Register
       Holds the nanoseconds parts of the reload value of the ToD counter. */
   unsigned int rldns; /* 0x00000010 */
   /** Seconds Reload Register
       Holds the seconds part of the reload value of the ToD counter. */
   unsigned int rlds; /* 0x00000014 */
   /** Superframe Counter Compare Register */
   unsigned int sfcc; /* 0x00000018 */
   /** Reserved */
   unsigned int res_1; /* 0x0000001C */
   /** Nanoseconds ToD Counter Register
       Shows the actual nanoseconds part of the ToD counter. */
   unsigned int tcns; /* 0x00000020 */
   /** Seconds ToD Counter Register
       Shows the actual seconds part of the ToD counter. */
   unsigned int tcs; /* 0x00000024 */
   /** Reserved */
   unsigned int res_2[2]; /* 0x00000028 */
   /** Nanoseconds Waveform Counter Register
       Shows the actual nanoseconds part of the waveform counter. */
   unsigned int wcns; /* 0x00000030 */
   /** Reserved */
   unsigned int res_3[3]; /* 0x00000034 */
   /** PPS Seconds Register
       Shows the seconds part of the ToD counter at the time of the rising edge of the pps-signal. */
   unsigned int ppssec; /* 0x00000040 */
   /** Reserved */
   unsigned int res_4[43]; /* 0x00000044 */
   /** IRN Capture Register
       This register shows the currently active interrupt events masked with the corresponding enable bits of the IRNEN register. The interrupts can be acknowledged by a write operation. */
   unsigned int irncr; /* 0x000000F0 */
   /** IRN Interrupt Control Register
       A write operation directly effects the interrupts. This can be used to trigger events under software control for testing purposes. A read operation returns the unmasked interrupt events. */
   unsigned int irnicr; /* 0x000000F4 */
   /** IRN Interrupt Enable Register
       This register contains the enable (or mask) bits for the interrupts. Disabled interrupts are not visible in the IRNCR register and are not signalled via the interrupt line towards the controller. */
   unsigned int irnen; /* 0x000000F8 */
   /** Reserved */
   unsigned int res_5; /* 0x000000FC */
};


/* Fields of "Configuration Register" */
/** Free Running Mode
    When this bit is enabled, the load pulses for the ToD counters are suppressed. Furthermore the ToD counter starts regardless of a programmed SFCC-value. */
#define TOD_CFG_FRM 0x80000000
/* Disable
#define TOD_CFG_FRM_DIS 0x00000000 */
/** Enable */
#define TOD_CFG_FRM_EN 0x80000000
/** Interrupt Delay
    Selects the delay of the delayable interrupt with respect to the rising edge of the pps signal in multiples of 100us. */
#define TOD_CFG_INTDEL_MASK 0x0FFF0000
/** field offset */
#define TOD_CFG_INTDEL_OFFSET 16
/** Pulsewidth
    Selects the pulsewidth of the pps-signal in multiples of 100us. */
#define TOD_CFG_PW_MASK 0x00000FFF
/** field offset */
#define TOD_CFG_PW_OFFSET 0

/* Fields of "Nanoseconds Reload Register" */
/** Higher Nanoseconds Part
    Holds the higher nanoseconds part of the reload value. It corresponds to the higher 4 decimal digits of the nanoseconds part received via PLOAM/OMCI message. One LSB of this field counts 100 us. */
#define TOD_RLDNS_RLDNSHI_MASK 0x3FFF0000
/** field offset */
#define TOD_RLDNS_RLDNSHI_OFFSET 16
/** Lower Nanoseconds Part
    Holds the lower nanoseconds part of the reload value. It corresponds to the lowest 5 decimal digits of the nanoseconds part received via PLOAM/OMCI message. One LSB of this field counts 100000/31104 ns as the counting frequency is 311.04 MHz. */
#define TOD_RLDNS_RLDNSLO_MASK 0x00007FFF
/** field offset */
#define TOD_RLDNS_RLDNSLO_OFFSET 0

/* Fields of "Seconds Reload Register" */
/** Seconds Part
    Holds the seconds part of the reload value. It corresponds to the lowest 31 bit of the seconds part received via PLOAM/OMCI message. */
#define TOD_RLDS_SEC_MASK 0x7FFFFFFF
/** field offset */
#define TOD_RLDS_SEC_OFFSET 0

/* Fields of "Superframe Counter Compare Register" */
/** Superframe Counter Compare Value
    When the superframe counter (within GTC) reaches this value, the content of the reload registers is loaded into the ToD counter registers. The ToD counter starts counting when this field is programmed for the first time unless free-running mode is enabled. */
#define TOD_SFCC_SFCC_MASK 0x3FFFFFFF
/** field offset */
#define TOD_SFCC_SFCC_OFFSET 0

/* Fields of "Nanoseconds ToD Counter Register" */
/** Higher Nanoseconds Part
    Shows the actual higher nanoseconds part of the ToD counter. It corresponds to the higher 4 decimal digits of the nanoseconds part. One LSB of this field counts 100 us. */
#define TOD_TCNS_NSHI_MASK 0x3FFF0000
/** field offset */
#define TOD_TCNS_NSHI_OFFSET 16
/** Lower Nanoseconds Part
    Shows the actual lower nanoseconds part of the ToD counter. It correspons to the lowest 5 decimal digits of the nanoseconds part. One LSB of this field counts 100000/31104 ns as the counting frequency is 311.04 MHz. */
#define TOD_TCNS_NSLO_MASK 0x00007FFF
/** field offset */
#define TOD_TCNS_NSLO_OFFSET 0

/* Fields of "Seconds ToD Counter Register" */
/** Tcseconds Part
    Shows the actual seconds part of the ToD counter. */
#define TOD_TCS_SEC_MASK 0x7FFFFFFF
/** field offset */
#define TOD_TCS_SEC_OFFSET 0

/* Fields of "Nanoseconds Waveform Counter Register" */
/** Higher Nanoseconds Part
    Shows the actual higher nanoseconds part of the waveform counter. It corresponds to the higher 4 decimal digits of the nanoseconds part. One LSB of this field counts 100 us. */
#define TOD_WCNS_NSHI_MASK 0x3FFF0000
/** field offset */
#define TOD_WCNS_NSHI_OFFSET 16
/** Lower Nanoseconds Part
    Shows the actual lower nanoseconds part of the waveform counter. It correspons to the lowest 5 decimal digits of the nanoseconds part. One LSB of this field counts 100000/31104 ns as the counting frequency is 311.04 MHz. */
#define TOD_WCNS_NSLO_MASK 0x00007FFF
/** field offset */
#define TOD_WCNS_NSLO_OFFSET 0

/* Fields of "PPS Seconds Register" */
/** PPS Seconds
    Shows the seconds part of the ToD counter at the time of the rising edge of the pps-signal. */
#define TOD_PPSSEC_SEC_MASK 0x7FFFFFFF
/** field offset */
#define TOD_PPSSEC_SEC_OFFSET 0

/* Fields of "IRN Capture Register" */
/** Pulse Per Second
    There was a rising edge on pps. This interrupt is not delayed. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define TOD_IRNCR_PPS 0x00000002
/* Nothing
#define TOD_IRNCR_PPS_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define TOD_IRNCR_PPS_INTACK 0x00000002
/** Read: Interrupt occurred. */
#define TOD_IRNCR_PPS_INTOCC 0x00000002
/** Pulse Per Second Delayed
    There was a rising edge on pps. This interrupt is delayed by the value of CFG.INTDEL. This bit is edge-sensitive. This bit contributes to the indirect interrupt. */
#define TOD_IRNCR_PPSDEL 0x00000001
/* Nothing
#define TOD_IRNCR_PPSDEL_NULL 0x00000000 */
/** Write: Acknowledge the interrupt. */
#define TOD_IRNCR_PPSDEL_INTACK 0x00000001
/** Read: Interrupt occurred. */
#define TOD_IRNCR_PPSDEL_INTOCC 0x00000001

/* Fields of "IRN Interrupt Control Register" */
/** Pulse Per Second
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define TOD_IRNICR_PPS 0x00000002
/** Pulse Per Second Delayed
    Interrupt control bit for the corresponding bit in the IRNCR register. */
#define TOD_IRNICR_PPSDEL 0x00000001

/* Fields of "IRN Interrupt Enable Register" */
/** Pulse Per Second
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define TOD_IRNEN_PPS 0x00000002
/* Disable
#define TOD_IRNEN_PPS_DIS 0x00000000 */
/** Enable */
#define TOD_IRNEN_PPS_EN 0x00000002
/** Pulse Per Second Delayed
    Interrupt enable bit for the corresponding bit in the IRNCR register. */
#define TOD_IRNEN_PPSDEL 0x00000001
/* Disable
#define TOD_IRNEN_PPSDEL_DIS 0x00000000 */
/** Enable */
#define TOD_IRNEN_PPSDEL_EN 0x00000001

/*! @} */ /* TOD_REGISTER */

#endif /* _drv_onu_reg_tod_h */
