/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_gtc_pma_h
#define _drv_optic_reg_gtc_pma_h

/** \addtogroup GTC_PMA_REGISTER
   @{
*/
/* access macros */
#define gtc_pma_r32(reg) reg_r32(&gtc_pma->reg)
#define gtc_pma_w32(val, reg) reg_w32(val, &gtc_pma->reg)
#define gtc_pma_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &gtc_pma->reg)
#define gtc_pma_r32_table(reg, idx) reg_r32_table(gtc_pma->reg, idx)
#define gtc_pma_w32_table(val, reg, idx) reg_w32_table(val, gtc_pma->reg, idx)
#define gtc_pma_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, gtc_pma->reg, idx)
#define gtc_pma_adr_table(reg, idx) adr_table(gtc_pma->reg, idx)


/** GTC_PMA register structure */
struct optic_reg_gtc_pma
{
   /** Datarate Control Register
       Controls the datarate of the GPON link. The contents of the writeable fields of this register shall not be changed during operation. */
   unsigned int drc; /* 0x00000000 */
   /** Laser Training Sequence Control Register
       Controls the insertion of training patterns into the upstream datapath. */
   unsigned int ltsc; /* 0x00000004 */
   /** Reserved */
   unsigned int res_0[30]; /* 0x00000008 */
   /** Laser Training Sequence Data Register 0..19 (manually changed) */
   unsigned int ltsdata[20]; /* 0x00000080 .. 0x000000CC */
   /** Reserved */
   unsigned int res_1[12]; /* 0x000000D0 */
};


/* Fields of "Datarate Control Register" */
/** Downstream Delay
    Shows the part of the delay, in multiples of 311.04MHz periods, introduced by the FIFO due to synchronization. This delay is static as long as the rx_ready bit of the PMA is set, and recalculated at a rising edge of rx_ready. */
#define GTC_PMA_DRC_DSDLY_MASK 0x00070000
/** field offset */
#define GTC_PMA_DRC_DSDLY_OFFSET 16
/** Upstream Datarate
    Selects the datarate of the GPON upstream interface. */
#define GTC_PMA_DRC_USDR 0x00000002
/** 0,62208 GBit/s. */
#define GTC_PMA_DRC_USDR_USLO 0x00000000
/** 1,24416 GBit/s. */
#define GTC_PMA_DRC_USDR_USHI 0x00000002
/** Downstream Datarate
    Selects the datarate of the GPON downstream interface. */
#define GTC_PMA_DRC_DSDR 0x00000001
/** 1,24416 GBit/s. */
#define GTC_PMA_DRC_DSDR_DSLO 0x00000000
/** 2,48832 GBit/s. */
#define GTC_PMA_DRC_DSDR_DSHI 0x00000001

/* Fields of "Laser Training Sequence Control Register" */
/** Enable
    Enables the insertion of the training pattern after the next upstream burst. If this bit is set at the end of an upstream burst, the training pattern defined by the data registers and the length field of this register will be inserted immediately after the burst and the bit will be reset to its inactive value when done. */
#define GTC_PMA_LTSC_EN 0x80000000
/** Disable */
#define GTC_PMA_LTSC_EN_DIS 0x00000000
/** Enable Loop
    Enables cyclic streaming of the training pattern defined by the data registers and the length field of this register. If this bit is set any other upstream traffic is suppressed. */
#define GTC_PMA_LTSC_ENL 0x40000000
/** Disable */
#define GTC_PMA_LTSC_ENL_DIS 0x00000000
/** Enable */
#define GTC_PMA_LTSC_ENL_EN 0x40000000
/** Length
    Controls how many bytes of the training pattern will be inserted after the next upstream burst. Values larger than 78 are limited to 78, values lower than 2 are limited to 2. */
#define GTC_PMA_LTSC_LEN_MASK 0x0000007F
/** field offset */
#define GTC_PMA_LTSC_LEN_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 0" */
/** Laser Training Sequence Byte 0
    Data byte 0 of the training pattern. */
#define GTC_PMA_LTSDATA0_LTSBYTE0_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA0_LTSBYTE0_OFFSET 24
/** Laser Training Sequence Byte 1
    Data byte 1 of the training pattern. */
#define GTC_PMA_LTSDATA0_LTSBYTE1_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA0_LTSBYTE1_OFFSET 16
/** Laser Training Sequence Byte 2
    Data byte 2 of the training pattern. */
#define GTC_PMA_LTSDATA0_LTSBYTE2_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA0_LTSBYTE2_OFFSET 8
/** Laser Training Sequence Byte 3
    Data byte 3 of the training pattern. */
#define GTC_PMA_LTSDATA0_LTSBYTE3_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA0_LTSBYTE3_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 1" */
/** Laser Training Sequence Byte 4
    Data byte 4 of the training pattern. */
#define GTC_PMA_LTSDATA1_LTSBYTE4_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA1_LTSBYTE4_OFFSET 24
/** Laser Training Sequence Byte 5
    Data byte 5 of the training pattern. */
#define GTC_PMA_LTSDATA1_LTSBYTE5_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA1_LTSBYTE5_OFFSET 16
/** Laser Training Sequence Byte 6
    Data byte 6 of the training pattern. */
#define GTC_PMA_LTSDATA1_LTSBYTE6_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA1_LTSBYTE6_OFFSET 8
/** Laser Training Sequence Byte 7
    Data byte 7 of the training pattern. */
#define GTC_PMA_LTSDATA1_LTSBYTE7_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA1_LTSBYTE7_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 2" */
/** Laser Training Sequence Byte 8
    Data byte 8 of the training pattern. */
#define GTC_PMA_LTSDATA2_LTSBYTE8_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA2_LTSBYTE8_OFFSET 24
/** Laser Training Sequence Byte 9
    Data byte 9 of the training pattern. */
#define GTC_PMA_LTSDATA2_LTSBYTE9_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA2_LTSBYTE9_OFFSET 16
/** Laser Training Sequence Byte 10
    Data byte 10 of the training pattern. */
#define GTC_PMA_LTSDATA2_LTSBYTE10_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA2_LTSBYTE10_OFFSET 8
/** Laser Training Sequence Byte 11
    Data byte 11 of the training pattern. */
#define GTC_PMA_LTSDATA2_LTSBYTE11_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA2_LTSBYTE11_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 3" */
/** Laser Training Sequence Byte 12
    Data byte 12 of the training pattern. */
#define GTC_PMA_LTSDATA3_LTSBYTE12_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA3_LTSBYTE12_OFFSET 24
/** Laser Training Sequence Byte 13
    Data byte 13 of the training pattern. */
#define GTC_PMA_LTSDATA3_LTSBYTE13_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA3_LTSBYTE13_OFFSET 16
/** Laser Training Sequence Byte 14
    Data byte 14 of the training pattern. */
#define GTC_PMA_LTSDATA3_LTSBYTE14_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA3_LTSBYTE14_OFFSET 8
/** Laser Training Sequence Byte 15
    Data byte 15 of the training pattern. */
#define GTC_PMA_LTSDATA3_LTSBYTE15_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA3_LTSBYTE15_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 4" */
/** Laser Training Sequence Byte 16
    Data byte 16 of the training pattern. */
#define GTC_PMA_LTSDATA4_LTSBYTE16_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA4_LTSBYTE16_OFFSET 24
/** Laser Training Sequence Byte 17
    Data byte 17 of the training pattern. */
#define GTC_PMA_LTSDATA4_LTSBYTE17_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA4_LTSBYTE17_OFFSET 16
/** Laser Training Sequence Byte 18
    Data byte 18 of the training pattern. */
#define GTC_PMA_LTSDATA4_LTSBYTE18_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA4_LTSBYTE18_OFFSET 8
/** Laser Training Sequence Byte 19
    Data byte 19 of the training pattern. */
#define GTC_PMA_LTSDATA4_LTSBYTE19_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA4_LTSBYTE19_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 5" */
/** Laser Training Sequence Byte 20
    Data byte 20 of the training pattern. */
#define GTC_PMA_LTSDATA5_LTSBYTE20_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA5_LTSBYTE20_OFFSET 24
/** Laser Training Sequence Byte 21
    Data byte 21 of the training pattern. */
#define GTC_PMA_LTSDATA5_LTSBYTE21_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA5_LTSBYTE21_OFFSET 16
/** Laser Training Sequence Byte 22
    Data byte 22 of the training pattern. */
#define GTC_PMA_LTSDATA5_LTSBYTE22_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA5_LTSBYTE22_OFFSET 8
/** Laser Training Sequence Byte 23
    Data byte 23 of the training pattern. */
#define GTC_PMA_LTSDATA5_LTSBYTE23_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA5_LTSBYTE23_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 6" */
/** Laser Training Sequence Byte 24
    Data byte 24 of the training pattern. */
#define GTC_PMA_LTSDATA6_LTSBYTE24_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA6_LTSBYTE24_OFFSET 24
/** Laser Training Sequence Byte 25
    Data byte 25 of the training pattern. */
#define GTC_PMA_LTSDATA6_LTSBYTE25_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA6_LTSBYTE25_OFFSET 16
/** Laser Training Sequence Byte 26
    Data byte 26 of the training pattern. */
#define GTC_PMA_LTSDATA6_LTSBYTE26_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA6_LTSBYTE26_OFFSET 8
/** Laser Training Sequence Byte 27
    Data byte 27 of the training pattern. */
#define GTC_PMA_LTSDATA6_LTSBYTE27_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA6_LTSBYTE27_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 7" */
/** Laser Training Sequence Byte 28
    Data byte 28 of the training pattern. */
#define GTC_PMA_LTSDATA7_LTSBYTE28_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA7_LTSBYTE28_OFFSET 24
/** Laser Training Sequence Byte 29
    Data byte 29 of the training pattern. */
#define GTC_PMA_LTSDATA7_LTSBYTE29_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA7_LTSBYTE29_OFFSET 16
/** Laser Training Sequence Byte 30
    Data byte 30 of the training pattern. */
#define GTC_PMA_LTSDATA7_LTSBYTE30_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA7_LTSBYTE30_OFFSET 8
/** Laser Training Sequence Byte 31
    Data byte 31 of the training pattern. */
#define GTC_PMA_LTSDATA7_LTSBYTE31_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA7_LTSBYTE31_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 8" */
/** Laser Training Sequence Byte 32
    Data byte 32 of the training pattern. */
#define GTC_PMA_LTSDATA8_LTSBYTE32_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA8_LTSBYTE32_OFFSET 24
/** Laser Training Sequence Byte 33
    Data byte 33 of the training pattern. */
#define GTC_PMA_LTSDATA8_LTSBYTE33_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA8_LTSBYTE33_OFFSET 16
/** Laser Training Sequence Byte 34
    Data byte 34 of the training pattern. */
#define GTC_PMA_LTSDATA8_LTSBYTE34_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA8_LTSBYTE34_OFFSET 8
/** Laser Training Sequence Byte 35
    Data byte 35 of the training pattern. */
#define GTC_PMA_LTSDATA8_LTSBYTE35_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA8_LTSBYTE35_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 9" */
/** Laser Training Sequence Byte 36
    Data byte 36 of the training pattern. */
#define GTC_PMA_LTSDATA9_LTSBYTE36_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA9_LTSBYTE36_OFFSET 24
/** Laser Training Sequence Byte 37
    Data byte 37 of the training pattern. */
#define GTC_PMA_LTSDATA9_LTSBYTE37_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA9_LTSBYTE37_OFFSET 16
/** Laser Training Sequence Byte 38
    Data byte 38 of the training pattern. */
#define GTC_PMA_LTSDATA9_LTSBYTE38_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA9_LTSBYTE38_OFFSET 8
/** Laser Training Sequence Byte 39
    Data byte 39 of the training pattern. */
#define GTC_PMA_LTSDATA9_LTSBYTE39_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA9_LTSBYTE39_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 10" */
/** Laser Training Sequence Byte 40
    Data byte 40 of the training pattern. */
#define GTC_PMA_LTSDATA10_LTSBYTE40_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA10_LTSBYTE40_OFFSET 24
/** Laser Training Sequence Byte 41
    Data byte 41 of the training pattern. */
#define GTC_PMA_LTSDATA10_LTSBYTE41_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA10_LTSBYTE41_OFFSET 16
/** Laser Training Sequence Byte 42
    Data byte 42 of the training pattern. */
#define GTC_PMA_LTSDATA10_LTSBYTE42_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA10_LTSBYTE42_OFFSET 8
/** Laser Training Sequence Byte 43
    Data byte 43 of the training pattern. */
#define GTC_PMA_LTSDATA10_LTSBYTE43_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA10_LTSBYTE43_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 11" */
/** Laser Training Sequence Byte 44
    Data byte 44 of the training pattern. */
#define GTC_PMA_LTSDATA11_LTSBYTE44_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA11_LTSBYTE44_OFFSET 24
/** Laser Training Sequence Byte 45
    Data byte 45 of the training pattern. */
#define GTC_PMA_LTSDATA11_LTSBYTE45_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA11_LTSBYTE45_OFFSET 16
/** Laser Training Sequence Byte 46
    Data byte 46 of the training pattern. */
#define GTC_PMA_LTSDATA11_LTSBYTE46_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA11_LTSBYTE46_OFFSET 8
/** Laser Training Sequence Byte 47
    Data byte 47 of the training pattern. */
#define GTC_PMA_LTSDATA11_LTSBYTE47_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA11_LTSBYTE47_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 12" */
/** Laser Training Sequence Byte 48
    Data byte 48 of the training pattern. */
#define GTC_PMA_LTSDATA12_LTSBYTE48_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA12_LTSBYTE48_OFFSET 24
/** Laser Training Sequence Byte 49
    Data byte 49 of the training pattern. */
#define GTC_PMA_LTSDATA12_LTSBYTE49_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA12_LTSBYTE49_OFFSET 16
/** Laser Training Sequence Byte 50
    Data byte 50 of the training pattern. */
#define GTC_PMA_LTSDATA12_LTSBYTE50_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA12_LTSBYTE50_OFFSET 8
/** Laser Training Sequence Byte 51
    Data byte 51 of the training pattern. */
#define GTC_PMA_LTSDATA12_LTSBYTE51_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA12_LTSBYTE51_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 13" */
/** Laser Training Sequence Byte 52
    Data byte 52 of the training pattern. */
#define GTC_PMA_LTSDATA13_LTSBYTE52_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA13_LTSBYTE52_OFFSET 24
/** Laser Training Sequence Byte 53
    Data byte 53 of the training pattern. */
#define GTC_PMA_LTSDATA13_LTSBYTE53_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA13_LTSBYTE53_OFFSET 16
/** Laser Training Sequence Byte 54
    Data byte 54 of the training pattern. */
#define GTC_PMA_LTSDATA13_LTSBYTE54_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA13_LTSBYTE54_OFFSET 8
/** Laser Training Sequence Byte 55
    Data byte 55 of the training pattern. */
#define GTC_PMA_LTSDATA13_LTSBYTE55_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA13_LTSBYTE55_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 14" */
/** Laser Training Sequence Byte 56
    Data byte 56 of the training pattern. */
#define GTC_PMA_LTSDATA14_LTSBYTE56_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA14_LTSBYTE56_OFFSET 24
/** Laser Training Sequence Byte 57
    Data byte 57 of the training pattern. */
#define GTC_PMA_LTSDATA14_LTSBYTE57_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA14_LTSBYTE57_OFFSET 16
/** Laser Training Sequence Byte 58
    Data byte 58 of the training pattern. */
#define GTC_PMA_LTSDATA14_LTSBYTE58_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA14_LTSBYTE58_OFFSET 8
/** Laser Training Sequence Byte 59
    Data byte 59 of the training pattern. */
#define GTC_PMA_LTSDATA14_LTSBYTE59_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA14_LTSBYTE59_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 15" */
/** Laser Training Sequence Byte 60
    Data byte 60 of the training pattern. */
#define GTC_PMA_LTSDATA15_LTSBYTE60_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA15_LTSBYTE60_OFFSET 24
/** Laser Training Sequence Byte 61
    Data byte 61 of the training pattern. */
#define GTC_PMA_LTSDATA15_LTSBYTE61_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA15_LTSBYTE61_OFFSET 16
/** Laser Training Sequence Byte 62
    Data byte 62 of the training pattern. */
#define GTC_PMA_LTSDATA15_LTSBYTE62_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA15_LTSBYTE62_OFFSET 8
/** Laser Training Sequence Byte 63
    Data byte 63 of the training pattern. */
#define GTC_PMA_LTSDATA15_LTSBYTE63_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA15_LTSBYTE63_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 16" */
/** Laser Training Sequence Byte 64
    Data byte 64 of the training pattern. */
#define GTC_PMA_LTSDATA16_LTSBYTE64_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA16_LTSBYTE64_OFFSET 24
/** Laser Training Sequence Byte 65
    Data byte 65 of the training pattern. */
#define GTC_PMA_LTSDATA16_LTSBYTE65_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA16_LTSBYTE65_OFFSET 16
/** Laser Training Sequence Byte 66
    Data byte 66 of the training pattern. */
#define GTC_PMA_LTSDATA16_LTSBYTE66_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA16_LTSBYTE66_OFFSET 8
/** Laser Training Sequence Byte 67
    Data byte 67 of the training pattern. */
#define GTC_PMA_LTSDATA16_LTSBYTE67_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA16_LTSBYTE67_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 17" */
/** Laser Training Sequence Byte 68
    Data byte 68 of the training pattern. */
#define GTC_PMA_LTSDATA17_LTSBYTE68_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA17_LTSBYTE68_OFFSET 24
/** Laser Training Sequence Byte 69
    Data byte 69 of the training pattern. */
#define GTC_PMA_LTSDATA17_LTSBYTE69_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA17_LTSBYTE69_OFFSET 16
/** Laser Training Sequence Byte 70
    Data byte 70 of the training pattern. */
#define GTC_PMA_LTSDATA17_LTSBYTE70_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA17_LTSBYTE70_OFFSET 8
/** Laser Training Sequence Byte 71
    Data byte 71 of the training pattern. */
#define GTC_PMA_LTSDATA17_LTSBYTE71_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA17_LTSBYTE71_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 18" */
/** Laser Training Sequence Byte 72
    Data byte 72 of the training pattern. */
#define GTC_PMA_LTSDATA18_LTSBYTE72_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA18_LTSBYTE72_OFFSET 24
/** Laser Training Sequence Byte 73
    Data byte 73 of the training pattern. */
#define GTC_PMA_LTSDATA18_LTSBYTE73_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA18_LTSBYTE73_OFFSET 16
/** Laser Training Sequence Byte 74
    Data byte 74 of the training pattern. */
#define GTC_PMA_LTSDATA18_LTSBYTE74_MASK 0x0000FF00
/** field offset */
#define GTC_PMA_LTSDATA18_LTSBYTE74_OFFSET 8
/** Laser Training Sequence Byte 75
    Data byte 75 of the training pattern. */
#define GTC_PMA_LTSDATA18_LTSBYTE75_MASK 0x000000FF
/** field offset */
#define GTC_PMA_LTSDATA18_LTSBYTE75_OFFSET 0

/* Fields of "Laser Training Sequence Data Register 19" */
/** Laser Training Sequence Byte 76
    Data byte 76 of the training pattern. */
#define GTC_PMA_LTSDATA19_LTSBYTE76_MASK 0xFF000000
/** field offset */
#define GTC_PMA_LTSDATA19_LTSBYTE76_OFFSET 24
/** Laser Training Sequence Byte 77
    Data byte 77 of the training pattern. */
#define GTC_PMA_LTSDATA19_LTSBYTE77_MASK 0x00FF0000
/** field offset */
#define GTC_PMA_LTSDATA19_LTSBYTE77_OFFSET 16

/*! @} */ /* GTC_PMA_REGISTER */

#endif /* _drv_optic_reg_gtc_pma_h */
