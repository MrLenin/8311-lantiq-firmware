/******************************************************************************

                               Copyright (c) 2012
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_onu_reg_gtc_h
#define _drv_onu_reg_gtc_h

/** \addtogroup GTC_REGISTER
   @{
*/
/* access macros */
#define gtc_r32(reg) reg_r32(&gtc->reg)
#define gtc_w32(val, reg) reg_w32(val, &gtc->reg)
#define gtc_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &gtc->reg)
#define gtc_r32_table(reg, idx) reg_r32_table(gtc->reg, idx)
#define gtc_w32_table(val, reg, idx) reg_w32_table(val, gtc->reg, idx)
#define gtc_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, gtc->reg, idx)
#define gtc_adr_table(reg, idx) adr_table(gtc->reg, idx)


/** GTC register structure */
struct onu_reg_gtc
{
   /** DOWNSTR: DOWNSTR */
   /** GTC Status Register
       The status register GTC_DSSTAT_1 provides status information of the downstream (receive) data path. */
   unsigned int downstr_gtc_dsstat_1; /* 0x00000000 */
   /** GTC Delay Status Register
       The status register GTC_DSSTAT_1 provides status information of the downstream (receive) data path. */
   unsigned int downstr_gtc_dsdelstat; /* 0x00000004 */
   /** GTC Digital Loss of Signal Register
       This register provides the window and threshold settings for digital Loss of Signal detection. */
   unsigned int downstr_gtc_dlos; /* 0x00000008 */
   /** GTC Signal Fail Window Register
       This register provides the window settings for Signal Fail detection. */
   unsigned int downstr_gtc_sfwin; /* 0x0000000C */
   /** GTC Signal Degrade Window Register
       This register provides the window settings for Signal Degrade detection. */
   unsigned int downstr_gtc_sdwin; /* 0x00000010 */
   /** GTC Signal Fail Threshold Register
       This register provides the threshold settings for Signal Fail detection and clearing. Two separate values are used to provide a programmable hysteresis (CLEAR less than or equal to DETECT). */
   unsigned int downstr_gtc_sfthr; /* 0x00000014 */
   /** GTC Signal Degrade Threshold Register
       This register provides the threshold settings for Signal degrade detection and clearing. Two separate values are used to provide a programmable hysteresis (CLEAR less than or equal to DETECT). */
   unsigned int downstr_gtc_sdthr; /* 0x00000018 */
   /** GTC BIP Error Interval Register
       The BIP Error Interval Register GTC_BERRINTV provides the number of downstream frames to be accumulated before updating the BIP error counter GTC_BERRCNT. */
   unsigned int downstr_gtc_berrintv; /* 0x0000001C */
   /** GTC GEM Frame Starvation Interval Register
       The observation time counter is loaded with the programmed INTV value. It is decremented with every 1 ms the Loss of GEM Frame Delineation alarm persists. The frame starvation interrupt is generated when the counter is decremented to zero. The counter is reloaded after reception of correct GEM Headers. */
   unsigned int downstr_gtc_gemstintv; /* 0x00000020 */
   /** GTC Ploam Timeout Value Register
       Whenever the timeout value register is written the timer is automatically started. */
   unsigned int downstr_gtc_pltout; /* 0x00000024 */
   /** GEM Receive Status Register
       The status register GEM_RSTAT provides status information for the GEM deframer. */
   unsigned int downstr_gem_rstat; /* 0x00000028 */
   /** GTC Downstream Test Register 1
       This register is used for test purposes only. */
   unsigned int downstr_gtc_dstest_1; /* 0x0000002C */
   /** GTC Downstream Test Register 1
       This register is used for test purposes only. */
   unsigned int downstr_gtc_dstest_2; /* 0x00000030 */
   /** GTC Synchronization Control Register
       This register provides control information needed for the downstream frame and superframe synchronization state machines. */
   unsigned int downstr_gtc_scon; /* 0x00000034 */
   /** GTC Control Register 1
       This register provides control information for downstream data handling. */
   unsigned int downstr_gtc_dscon_1; /* 0x00000038 */
   /** GTC Superframe Counter Register
       The Superframe Counter Register GTC_SFCNT provides the actual value of the superframe counter. This counter does not generate an interrupt on overflow. */
   unsigned int downstr_gtc_sfcnt; /* 0x0000003C */
   /** AES Decryption Key Register 0
       This register provides a part of the decryption key. */
   unsigned int downstr_aes_dekey[4]; /* 0x00000040 */
   /** AES Decryption key Switchover Time
       This register provides the Superframe count value for next key change (key switchover). */
   unsigned int downstr_aes_key_switch; /* 0x00000050 */
   /** GTC Receive PORT-ID Address Registers
       These control registers select which PORT-IDs are owned by the ONT and how these are handled. There are 4096 PORT-IDs possible, each uses 4 bit of control information. Each address selected by this register addresses eight PORT-IDs (ADDR = 0 to 511, Group = 0 to 7, PORT-ID = ADDR*8 + GROUP). */
   unsigned int downstr_gtc_rxpid_addr; /* 0x00000054 */
   /** GTC Receive PORT-ID Write Register */
   unsigned int downstr_gtc_rxpid_wr; /* 0x00000058 */
   /** GTC Receive PORT-ID Read Register
       This status register provides read access to the control registers that select which PORT-IDs are owned by the ONT and how these are to be handled. There are 4096 PORT-IDs possible, each uses a group of 4 bit of control information. Each read access delivers the setting of eight PORT-IDs (ADDR = 0 to 511, GROUP = 0 to 7, PORTID = ADDR x 8 + GROUP). */
   unsigned int downstr_gtc_rxpid_rd; /* 0x0000005C */
   /** GTC PLOAMd Message Receive Register 1
       The Message Receive Register GTC_MRX_1 provides data received through a PLOAMd message. If no more data is available, ONUID FF and MESID 0B (no message), MB0, MB1 = zero is read from this registers. */
   unsigned int downstr_gtc_mrx_1; /* 0x00000060 */
   /** GTC PLOAMd Message Receive Register 2
       The Message Receive Register GTC_MRX2 provides data received through a PLOAM message. If no more data is available, all-zero is read from this registers. */
   unsigned int downstr_gtc_mrx_2; /* 0x00000064 */
   /** GTC PLOAMd Message Receive Register 3
       The Message Receive Register GTC_MRX3 provides data received through a PLOAM message. Reading this register triggers the data transfer from the receive FIFO to GTC_MRX1, GTC_MRX2, and GTC_MRX3. If no more data is available, all-zero is read from this registers. */
   unsigned int downstr_gtc_mrx_3; /* 0x00000068 */
   /** GTC Downstream Identification Register */
   unsigned int downstr_gtc_id; /* 0x0000006C */
   /** GTC Downstream Interrupt Status Register 1
       The interrupt status register GTC_DSISTAT_1 provides status information interrupts to the controlling MCU. Interrupt bits are set to a high level as soon as an interrupt condition is detected. All interrupt bits are cleared upon writing a 1B to the corresponding interrupt bit. If an interrupt condition is still active during read access, the corresponding bit is not cleared. */
   unsigned int downstr_gtc_dsistat_1; /* 0x00000070 */
   /** GTC Downstream Interrupt Mask Register 1
       The interrupt mask register GTC_DSIMASK_1 defines which of interrupts are signaled to the MCU. */
   unsigned int downstr_gtc_dsimask_1; /* 0x00000074 */
   /** GTC Downstream Counter Status Register
       The counter status register GTC_DSCNTRSTAT indicates counter overflows. Each time one of the downstream counters either overflows or stops a the maximum count value (depending on the counter mode selection, GTC_DSCON_1.CM), the corresponding bit is set. All bits are cleared upon read access. If one or more bits are set, an interrupt is generated. */
   unsigned int downstr_gtc_dscntrstat; /* 0x00000078 */
   /** GTC BIP Error Count Register
       The BIP Error Count Register GTC_BERRCNT provides the number of BIP errors detected within the last measurement interval. The register is updated at regular intervals which are defined by GTC_BERRINTV. The software can accumulate these values to cover larger time intervals locally or report the value via PLOAMu messages. This counter is not reset by reading the value. The counter cannot overflow, because of the maximum programmable BERRINTV. */
   unsigned int downstr_gtc_berrcnt; /* 0x0000007C */
   /** GEM HEC Error Counter Register 1
       The error count register GEM_HERR_1 counts the number of frames with correctable errors. Errors detected on all GEM detected during GEM frame reception are counted (global counter). The error counter can be operated in wrap-around or saturation mode. In saturation mode, the register is reset to zero by a read access to this register. */
   unsigned int downstr_gem_herr_1; /* 0x00000080 */
   /** GEM HEC Error Counter Register 2
       The error count register GEM_HERR_2 counts the number of dropped GEM frames due to receive errors such as uncorrectable HEC errors or not supported PTI codes. Errors detected on all GEM ports are counted (global counter). The error counter can be operated in wrap-around or saturation mode. In saturation mode, the register is reset to zero by a read access to this register. */
   unsigned int downstr_gem_herr_2; /* 0x00000084 */
   /** GEM Bandwidth Map Correctable Error Counter
       This counter provides the number of received bandwidth maps that contained correctable errors. The counter can be operated in wrap-around or saturation mode. In saturation mode, the register is reset to zero by a read access to this register. */
   unsigned int downstr_gem_bwmcerr; /* 0x00000088 */
   /** GEM Bandwidth Map Uncorrectable Error Counter
       This counter provides the number of received bandwidth maps that contained uncorrectable errors. The counter can be operated in wrap-around or saturation mode. In saturation mode, the register is reset to zero by a read access to this register. */
   unsigned int downstr_gem_bwmuerr; /* 0x0000008C */
   /** GEM Receive Frame Counter Register
       The frame counter register GEM_RXFCNT counts the number of received and accepted GEM frames not including GEM idles frames from all GEM ports assigned to the ONT (with valid PORT-ID). The counter can be operated in wrap-around or saturation mode. In saturation mode, the register is reset to zero by a read access to this register. */
   unsigned int downstr_gem_rxfcnt; /* 0x00000090 */
   /** GEM Receive Byte Counter Register
       The payload byte counter register GEM_RXBCNT counts the total number of bytes contained in the received and acccepted GEM frames that are addressed to the ONT (with valid PORT-ID). GEM header bytes are not counted. The counter can be operated in wrap-around or saturation mode. In saturation mode, the register is reset to zero by a read access to this register. */
   unsigned int downstr_gem_rxbcnt; /* 0x00000094 */
   /** FEC Correctable Error Counter Register
       This counter register provides the number of received FEC blocks which have been corrected by FEC decoding. */
   unsigned int downstr_gtc_fcerrcnt; /* 0x00000098 */
   /** FEC Uncorrectable Error Counter
       This counter provides the number of received FEC blocks that contained uncorrectable errors. */
   unsigned int downstr_gtc_fuerrcnt; /* 0x0000009C */
   /** FEC Receive Block Counter
       This counter counts the number of all received FEC blocks. */
   unsigned int downstr_gtc_frcnt; /* 0x000000A0 */
   /** FEC Receive Corrected Byte Counter
       This counter counts the number the number of FEC bytes which have been corrected by FEC decoding. */
   unsigned int downstr_gtc_frcbcnt; /* 0x000000A4 */
   /** Rogue ONT reset function
       Summarize all settings for a Rogue ONT Reset PLOAMd message. All settings could be changed as long as EN is set to NO. If EN is set to YES no more changes are possible. */
   unsigned int downstr_gtc_rst_rogue; /* 0x000000A8 */
   /** Reserved */
   unsigned int downstr_res_0[21]; /* 0x000000AC */
   /** UPSTR: UPSTR */
   /** GTC Ranging Time Register 1
       This register provides control information for default upstream data handling. */
   unsigned int upstr_gtc_rtime_1; /* 0x00000100 */
   /** GTC Ranging Time Register 2
       The Round-trip Delay Register GTC_RTIME2 provides data received in the Ranging_Time PLOAMd message. This register is updated by software and used by hardware. */
   unsigned int upstr_gtc_rtime_2; /* 0x00000104 */
   /** GTC Ranging Time Register 3
       This register provides control information for default upstream data handling. This value is fixed by application, change for test purposes only. */
   unsigned int upstr_gtc_rtime_3; /* 0x00000108 */
   /** GTC Status Register
       The status register GTC_USSTAT provides status information for upstream (transmit) data path. */
   unsigned int upstr_gtc_usstat; /* 0x0000010C */
   /** GTC Upstream Error Status Register
       The status register GTC_USESTAT provides error status information of the upstream (transmit) data path. Bits are set once the related error condition has been detected and cleared by reading the register. If an error condition is still pending while reading the register, the related bit is not cleared (immediately set again). */
   unsigned int upstr_gtc_usestat; /* 0x00000110 */
   /** GTC Control Register
       This register provides control information for upstream data handling. */
   unsigned int upstr_gtc_uscon; /* 0x00000114 */
   /** GTC Upstream Header Length Register
       The Upstream Header Register GTC_USHDL provides the upstream frame synchronization header length (number of bytes). The length value is extracted by software from the Upstream_Overhead PLOAMd message. To change the value in this register the upstream data transmission shall be disabled (GTC_USCON.USEN = 0B). */
   unsigned int upstr_gtc_ushdl; /* 0x00000118 */
   /** GTC Upstream Header Address Register
       The Upstream Header Register GTC_USHDRC_AD provides the address to the header pattern memory. */
   unsigned int upstr_gtc_ushdrc_ad; /* 0x0000011C */
   /** GTC Upstream Header Configuration Write Data Register
       This register provides data to be written to the header pattern memory. */
   unsigned int upstr_gtc_ushdrc_wd; /* 0x00000120 */
   /** GTC Upstream Header Read Data Register
       This register provides data to be read from the header pattern memory. */
   unsigned int upstr_gtc_ushdrc_rd; /* 0x00000124 */
   /** GTC PLOAM Message Transmit Control Register
       The Message Transmit Control Register GTC_MTX_CTRL allows to set a message repeat factor or to flush the message buffer. It aso controls the configuration of specail PLOAMu message handling for Dying Gasp and No Message. */
   unsigned int upstr_gtc_mtx_ctrl; /* 0x00000128 */
   /** GTC PLOAM Message Transmit Register 1
       The Message Transmit Register GTC_MTX1 provides data needed to insert the PLOAM message into the GTC frame. */
   unsigned int upstr_gtc_mtx_1; /* 0x0000012C */
   /** GTC PLOAM Message Transmit Register 2
       The Message Transmit Register GTC_MTX2 provides data needed to insert the PLOAM message into the GTC frame. */
   unsigned int upstr_gtc_mtx_2; /* 0x00000130 */
   /** GTC PLOAM Message Transmit Register 1
       The Message Transmit Register GTC_MTX3 provides data needed to insert the PLOAM message into the GTC frame. */
   unsigned int upstr_gtc_mtx_3; /* 0x00000134 */
   /** GTC Interrupt Status Register
       The interrupt status register GTC_USISTAT provides status information interrupts to the controlling MCU. Interrupt bits are set to a high level as soon as an interrupt condition is detected. All interrupt bits are cleared upon writing a 1B to the corresponding interrupt bit. If an interrupt condition is still active during the write access, the corresponding bit is not cleared. */
   unsigned int upstr_gtc_usistat; /* 0x00000138 */
   /** GTC Upstream Interrupt Mask Register
       GTC Upstream Interrupt Mask Register 1 */
   unsigned int upstr_gtc_usimask; /* 0x0000013C */
   /** GTC Upstream Laser Power On/Off Register
       The settings in this register are used to handle the power-up sequence before the start of an upstream burst and the power-off behavior for T-CONT gaps. */
   unsigned int upstr_gtc_laser; /* 0x00000140 */
   /** GTC Upstream Test Register
       This register is used for test purposes only. */
   unsigned int upstr_gtc_ustest; /* 0x00000144 */
   /** GTC Fetch Offset Register
       GTC Fetch Strobe Offset Register */
   unsigned int upstr_gtc_usfetch; /* 0x00000148 */
   /** GTC Start Offset Register Configuration */
   unsigned int upstr_gtc_start_offset; /* 0x0000014C */
   /** GTC Bandwidth Map Register Write Low
       The Bandwidth Map Register GTC_BWMAPWL provides the Upstream Bandwidth Map. This register is updated by software for test purposes. */
   unsigned int upstr_gtc_bwmapwl; /* 0x00000150 */
   /** GTC Bandwidth Map Register Write High
       The Bandwidth Map Register GTC_BWMAP_WH_0 provides the Upstream Bandwidth Map. This register is updated by software for test purposes only. */
   unsigned int upstr_gtc_bwmapwh; /* 0x00000154 */
   /** GTC T-CONT Allocation Register
       The control registers GTC_TCONT_0 to DBA_TCONT_31 provide the Allocation ID assignment to T-CONTs. The assignment is performed by software during the ONT startup. */
   unsigned int upstr_gtc_tcont[32]; /* 0x00000158 */
   /** GTC Bandwidth Map Register Read High
       The Bandwidth Map Register GTC_BWMAPRH_0 provides data received in the Upstream Bandwidth Map field of the GTC downstream frame for T-CONT #1. This register is updated by hardware for every 125 microseconds and read-only by software for test purposes. */
   unsigned int upstr_gtc_bwmaprh[32]; /* 0x000001D8 */
   /** GTC Bandwidth Map Register Read Low
       The Bandwidth Map Register GTC_BWMAPRL_0 provides data received in the Upstream Bandwidth Map field of the GTC downstream frame for T-CONT #1. */
   unsigned int upstr_gtc_bwmaprl[32]; /* 0x00000258 */
   /** GTC Frame Range
       This register provides the min SSTART and max SSTOP values. They are derived from all BW-Maps send by the OLT. */
   unsigned int upstr_gtc_frm_range; /* 0x000002D8 */
   /** GTC BW-Map Trace Control
       This register provides control settings for all BW-Map trace features. */
   unsigned int upstr_gtc_bwmt_ctrl; /* 0x000002DC */
   /** GTC BW-Map Interrupt Status Register
       The interrupt status register GTC_BWMSTAT provides status information interrupts to the controlling MCU. Interrupt bits are set to a high level as soon as an interrupt condition is detected. All interrupt bits are cleared upon writing a 1B to the corresponding interrupt bit. If an interrupt condition is still active during the write access, the corresponding bit is not cleared. */
   unsigned int upstr_gtc_bwmstat; /* 0x000002E0 */
   /** GTC BW-Map Interrupt Status Register
       The interrupt mask register GTC_BWMMASK defines which of the interrupts are signaled to the controlling MCU. */
   unsigned int upstr_gtc_bwmmask; /* 0x000002E4 */
   /** GTC BW-Map Actual Pointer Register
       This register provides the actual hardware BWM FIFO pointer. It's only useful in trace mode if a trace event has occurred and hardware access is disabled. */
   unsigned int upstr_gtc_bwmptr_act; /* 0x000002E8 */
   /** GTC BW-Map Buffer Address Register
       With this register the address for a controller read access is selected. In auto mode the trace buffer start address is set automatically. With each read access to the GTC_BWM_RD register the address is incremented. */
   unsigned int upstr_gtc_bwmb_ad; /* 0x000002EC */
   /** GTC BW-Map Buffer Read Register
       Read data from the BW-Map buffer selected by the GTC_BWMB_AD register. After read access the GTC_BWMB_AD register is incremented. */
   unsigned int upstr_gtc_bwmb_rd; /* 0x000002F0 */
   /** GTC All TCONT Counter
       Count all TCONTs of this ONU */
   unsigned int upstr_gtc_all_tc; /* 0x000002F4 */
   /** GTC Rejected TCONT Counter
       Count all rejected TCONTs of this ONU */
   unsigned int upstr_gtc_rej_tc; /* 0x000002F8 */
   /** Reserved */
   unsigned int upstr_res_4; /* 0x000002FC */
};


/* Fields of "GTC Status Register" */
/** Downstream data FIFO overflow. Data written to the FIFO is lost. */
#define GTC_DSSTAT_1_DFIFO_OFL 0x00020000
/* (default) no error
#define GTC_DSSTAT_1_DFIFO_OFL_OK 0x00000000 */
/** error condition detected */
#define GTC_DSSTAT_1_DFIFO_OFL_ERR 0x00020000
/** Downstream data FIFO is full. Only threshold words are free in the FIFO. */
#define GTC_DSSTAT_1_DFIFO_FULL 0x00010000
/* (default) no error
#define GTC_DSSTAT_1_DFIFO_FULL_OK 0x00000000 */
/** error condition detected */
#define GTC_DSSTAT_1_DFIFO_FULL_ERR 0x00010000
/** Reflects the Status of the Ident Reserved Bit in the downstream frame. This bit is extracted from the downstream header before FEC error correction is (optionally) applied. */
#define GTC_DSSTAT_1_DSRES 0x00008000
/* Ident Reserved Bit is 0
#define GTC_DSSTAT_1_DSRES_OFF 0x00000000 */
/** Ident Reserved Bit is 1 */
#define GTC_DSSTAT_1_DSRES_ON 0x00008000
/** Downstream Forward Error Correction Enable */
#define GTC_DSSTAT_1_DSFEC 0x00004000
/* (default) downstream FEC is disabled.
#define GTC_DSSTAT_1_DSFEC_OFF 0x00000000 */
/** downstream FEC is enabled. */
#define GTC_DSSTAT_1_DSFEC_ON 0x00004000
/** Digital Loss of Signal */
#define GTC_DSSTAT_1_DLOS 0x00002000
/* (default) received signal is ok
#define GTC_DSSTAT_1_DLOS_OK 0x00000000 */
/** received signal is missing */
#define GTC_DSSTAT_1_DLOS_ERR 0x00002000
/** Signal Fail */
#define GTC_DSSTAT_1_SF 0x00001000
/* (default) no error
#define GTC_DSSTAT_1_SF_OK 0x00000000 */
/** Signal Fail error */
#define GTC_DSSTAT_1_SF_ERR 0x00001000
/** Signal Degrade */
#define GTC_DSSTAT_1_SD 0x00000800
/* (default) no warning
#define GTC_DSSTAT_1_SD_OK 0x00000000 */
/** Signal Degrade warning */
#define GTC_DSSTAT_1_SD_ERR 0x00000800
/** Superframe State Machine Status */
#define GTC_DSSTAT_1_SFSTATE_MASK 0x00000600
/** field offset */
#define GTC_DSSTAT_1_SFSTATE_OFFSET 9
/** (default) searching for preamble. */
#define GTC_DSSTAT_1_SFSTATE_SF_HUNT 0x00000000
/** initial preamble(s) found. */
#define GTC_DSSTAT_1_SFSTATE_SF_PSYNC 0x00000200
/** reserved, this value is not used. */
#define GTC_DSSTAT_1_SFSTATE_RES 0x00000400
/** synchronous state. */
#define GTC_DSSTAT_1_SFSTATE_SF_SYNC 0x00000600
/** GTC De-frame State Machine Status */
#define GTC_DSSTAT_1_STATE_MASK 0x00000180
/** field offset */
#define GTC_DSSTAT_1_STATE_OFFSET 7
/** (default) searching for preamble. */
#define GTC_DSSTAT_1_STATE_HUNT 0x00000000
/** initial preamble(s) found. */
#define GTC_DSSTAT_1_STATE_PSYNC 0x00000080
/** reserved, this value is not used. */
#define GTC_DSSTAT_1_STATE_RES 0x00000100
/** synchronous state. */
#define GTC_DSSTAT_1_STATE_SYNC 0x00000180
/** ATM Reception Status */
#define GTC_DSSTAT_1_ATM 0x00000040
/* (default) GEM traffic only, Alen = 0.
#define GTC_DSSTAT_1_ATM_OK 0x00000000 */
/** ATM traffic detected, Alen greater 0. */
#define GTC_DSSTAT_1_ATM_ERR 0x00000040
/** Plen Reception Status */
#define GTC_DSSTAT_1_PLSTAT_MASK 0x00000030
/** field offset */
#define GTC_DSSTAT_1_PLSTAT_OFFSET 4
/** (default) Plen reception without any errors. */
#define GTC_DSSTAT_1_PLSTAT_OK 0x00000000
/** Plen errors have been detected in one of the Plen fields but could be corrected, either by CRC correction or by using the correctly received Plen value. */
#define GTC_DSSTAT_1_PLSTAT_WARN 0x00000010
/** reserved, this value is not used. */
#define GTC_DSSTAT_1_PLSTAT_RES 0x00000020
/** uncorrectable error, Plen value could not be retrieved, frame has been discarded. */
#define GTC_DSSTAT_1_PLSTAT_ERR 0x00000030
/** PLOAM Receive Message Error */
#define GTC_DSSTAT_1_RXCRCE 0x00000008
/* (default) no PLOAMd messages have been discarded.
#define GTC_DSSTAT_1_RXCRCE_OK 0x00000000 */
/** PLOAMd message(s) discarded due to CRC errors. */
#define GTC_DSSTAT_1_RXCRCE_ERR 0x00000008
/** PLOAM Receive Message Buffer Overflow */
#define GTC_DSSTAT_1_RXOFL 0x00000004
/* (default) no PLOAMd messages have been lost.
#define GTC_DSSTAT_1_RXOFL_OK 0x00000000 */
/** PLOAMd buffer has lost one or more messages. */
#define GTC_DSSTAT_1_RXOFL_ERR 0x00000004
/** PLOAM Receive Message Buffer Full */
#define GTC_DSSTAT_1_RXFUL 0x00000002
/* (default) PLOAMd buffer can accept at least one more message.
#define GTC_DSSTAT_1_RXFUL_AVAIL 0x00000000 */
/** PLOAMd buffer can not accept any more messages. */
#define GTC_DSSTAT_1_RXFUL_FULL 0x00000002
/** PLOAM Receive Message Buffer Data Waiting */
#define GTC_DSSTAT_1_RXDAT 0x00000001
/* (default) PLOAMd buffer is empty.
#define GTC_DSSTAT_1_RXDAT_FREE 0x00000000 */
/** PLOAMd data is waiting to be read. */
#define GTC_DSSTAT_1_RXDAT_DATA 0x00000001

/* Fields of "GTC Delay Status Register" */
/** Contains the PSYNC Delay in range from 0 to 31 */
#define GTC_DSDELSTAT_PSDEL_MASK 0x0000001F
/** field offset */
#define GTC_DSDELSTAT_PSDEL_OFFSET 0

/* Fields of "GTC Digital Loss of Signal Register" */
/** Signal Inversion */
#define GTC_DLOS_INV 0x02000000
/* (default) excessive zeros are checked, number of ones is counted and checked if the value is below the threshold.
#define GTC_DLOS_INV_ZERO 0x00000000 */
/** excessive ones are checked, number of zeros is counted and checked if the value is below the threshold. */
#define GTC_DLOS_INV_ONE 0x02000000
/** Observation Window Size */
#define GTC_DLOS_WIN_MASK 0x01C00000
/** field offset */
#define GTC_DLOS_WIN_OFFSET 22
/** (default) LOS detection is disabled */
#define GTC_DLOS_WIN_DIS 0x00000000
/** 125 us interval */
#define GTC_DLOS_WIN_U125 0x00400000
/** 250 us interval */
#define GTC_DLOS_WIN_U250 0x00800000
/** 375 us interval */
#define GTC_DLOS_WIN_U375 0x00C00000
/** 500 us interval */
#define GTC_DLOS_WIN_U500 0x01000000
/** 625 us interval */
#define GTC_DLOS_WIN_U625 0x01400000
/** 750 us interval */
#define GTC_DLOS_WIN_U750 0x01800000
/** 875 us interval */
#define GTC_DLOS_WIN_U875 0x01C00000
/** Trigger Threshold */
#define GTC_DLOS_THR_MASK 0x003FFFFF
/** field offset */
#define GTC_DLOS_THR_OFFSET 0

/* Fields of "GTC Signal Fail Window Register" */
/** Detection/Clearing Window Size */
#define GTC_SFWIN_WSIZE_MASK 0xFFFFFFFF
/** field offset */
#define GTC_SFWIN_WSIZE_OFFSET 0

/* Fields of "GTC Signal Degrade Window Register" */
/** Detection/Clearing Window Size */
#define GTC_SDWIN_WSIZE_MASK 0xFFFFFFFF
/** field offset */
#define GTC_SDWIN_WSIZE_OFFSET 0

/* Fields of "GTC Signal Fail Threshold Register" */
/** Clearing Threshold Value */
#define GTC_SFTHR_CLEAR_MASK 0xFFFF0000
/** field offset */
#define GTC_SFTHR_CLEAR_OFFSET 16
/** Detection Threshold Value */
#define GTC_SFTHR_DETECT_MASK 0x0000FFFF
/** field offset */
#define GTC_SFTHR_DETECT_OFFSET 0

/* Fields of "GTC Signal Degrade Threshold Register" */
/** Clearing Threshold Value */
#define GTC_SDTHR_CLEAR_MASK 0xFFFF0000
/** field offset */
#define GTC_SDTHR_CLEAR_OFFSET 16
/** Detection Threshold Value */
#define GTC_SDTHR_DETECT_MASK 0x0000FFFF
/** field offset */
#define GTC_SDTHR_DETECT_OFFSET 0

/* Fields of "GTC BIP Error Interval Register" */
/** Accumulation Interval for BIP Errors */
#define GTC_BERRINTV_INTV_MASK 0x01FFFFFF
/** field offset */
#define GTC_BERRINTV_INTV_OFFSET 0

/* Fields of "GTC GEM Frame Starvation Interval Register" */
/** Interval for Detection of GEM Starvation in steps of 1 ms */
#define GTC_GEMSTINTV_INTV_MASK 0x0000FFFF
/** field offset */
#define GTC_GEMSTINTV_INTV_OFFSET 0

/* Fields of "GTC Ploam Timeout Value Register" */
/** Value for Timeout programmable in steps of 1 ms from 1 ms up to 256 ms */
#define GTC_PLTOUT_TOUT_MASK 0x000000FF
/** field offset */
#define GTC_PLTOUT_TOUT_OFFSET 0

/* Fields of "GEM Receive Status Register" */
/** ATM Status Flag */
#define GEM_RSTAT_ATM 0x00000008
/* (default) ATM State has not been entered
#define GEM_RSTAT_ATM_NO 0x00000000 */
/** ATM state has been entered */
#define GEM_RSTAT_ATM_YES 0x00000008
/** PRE-SYNC Status Flag */
#define GEM_RSTAT_PSYNC 0x00000004
/* (default) PRE-SYNC State has not been entered
#define GEM_RSTAT_PSYNC_NO 0x00000000 */
/** PRE-SYNC state has been entered */
#define GEM_RSTAT_PSYNC_YES 0x00000004
/** SYNC Status Flag */
#define GEM_RSTAT_SYNC 0x00000002
/* (default) SYNC State has not been entered
#define GEM_RSTAT_SYNC_NO 0x00000000 */
/** SYNC state has been entered */
#define GEM_RSTAT_SYNC_YES 0x00000002
/** HUNT Status Flag */
#define GEM_RSTAT_HUNT 0x00000001
/* (default) HUNT State has not been entered
#define GEM_RSTAT_HUNT_NO 0x00000000 */
/** HUNT state has been entered due to loss of GEM delineation */
#define GEM_RSTAT_HUNT_YES 0x00000001

/* Fields of "GTC Downstream Test Register 1" */
/** Downstream Plen CRC Disable */
#define GTC_DSTEST_1_PLCRCD 0x00004000
/* (default) downstream Plen CRC is enabled.
#define GTC_DSTEST_1_PLCRCD_EN 0x00000000 */
/** downstream Plen CRC is disabled. */
#define GTC_DSTEST_1_PLCRCD_DIS 0x00004000
/** PLOAMd CRC Check Disable */
#define GTC_DSTEST_1_PLCRC 0x00002000
/* (default) CRC check is enabled, CRC correction is tried upon incorrect CRC. If not correctable, PLOAMd messages are discarded.
#define GTC_DSTEST_1_PLCRC_CEN 0x00000000 */
/** CRC check is disabled, all PLOAMd messages are accepted. */
#define GTC_DSTEST_1_PLCRC_DIS 0x00002000
/** Descramble GEM Header De-scrambling Control */
#define GTC_DSTEST_1_DSCRD_HDR 0x00001000
/* GEM headers are not de-scrambled
#define GTC_DSTEST_1_DSCRD_HDR_DIS 0x00000000 */
/** (default) GEM headers are de-scrambled */
#define GTC_DSTEST_1_DSCRD_HDR_EN 0x00001000
/** GEM MISC Frame Control 2 */
#define GTC_DSTEST_1_GEM_MISC_2 0x00000800
/* GEM frames with PTI 01xB are dropped
#define GTC_DSTEST_1_GEM_MISC_2_DROP 0x00000000 */
/** (default) GEM frames with PTI 01xB are forwarded Note: Reset: Shall be set to 0B during SW initialization. */
#define GTC_DSTEST_1_GEM_MISC_2_USE 0x00000800
/** GEM MISC Frame Control 1 */
#define GTC_DSTEST_1_GEM_MISC_1 0x00000400
/* GEM frames with PTI 11xB are dropped
#define GTC_DSTEST_1_GEM_MISC_1_DROP 0x00000000 */
/** (default) GEM frames with PTI 11xB are forwarded Unknown Description */
#define GTC_DSTEST_1_GEM_MISC_1_USE 0x00000400
/** GEM MISC Frame Control 0 */
#define GTC_DSTEST_1_GEM_MISC_0 0x00000200
/* GEM frames with PTI 10xB are dropped
#define GTC_DSTEST_1_GEM_MISC_0_DROP 0x00000000 */
/** (default) GEM frames with PTI 10xB are forwarded */
#define GTC_DSTEST_1_GEM_MISC_0_USE 0x00000200
/** De-scrambling Disable */
#define GTC_DSTEST_1_DSCRD 0x00000100
/* de-scrambling is completely disabled
#define GTC_DSTEST_1_DSCRD_DIS 0x00000000 */
/** (default) de-scrambling is enabled */
#define GTC_DSTEST_1_DSCRD_EN 0x00000100
/** Setting this bit to 1 updates the AES Key Shadow Register. */
#define GTC_DSTEST_1_KEY_STB 0x00000080
/* (default) keep the AES key as it is
#define GTC_DSTEST_1_KEY_STB_KEEP 0x00000000 */
/** update the AES key now */
#define GTC_DSTEST_1_KEY_STB_UPD 0x00000080
/** Setting this bit to 1 starts Initialization of PORT-ID RAM Initialization. The Value for Initialization is defined by PID_SEL */
#define GTC_DSTEST_1_PID_STB 0x00000040
/* (default) normal operation
#define GTC_DSTEST_1_PID_STB_NOP 0x00000000 */
/** initialize the RAM */
#define GTC_DSTEST_1_PID_STB_INIT 0x00000040
/** PORT-ID RAM Initialization Value */
#define GTC_DSTEST_1_PID_SEL_MASK 0x00000038
/** field offset */
#define GTC_DSTEST_1_PID_SEL_OFFSET 3
/** PORT-ID is completely disabled, set all RAM locations to 0000B (default) */
#define GTC_DSTEST_1_PID_SEL_NONE 0x00000000
/** PORT-ID is selected decryption is enabled, set all RAM locations to 1100B */
#define GTC_DSTEST_1_PID_SEL_NORM_CR 0x00000008
/** PORT-ID is selected for OMCI, decryption is enabled, set all RAM locations to 1101B */
#define GTC_DSTEST_1_PID_SEL_OMCI_CR 0x00000010
/** PORT-ID is selected as Multicast, decryption is enabled, set all RAM locations to 1110B */
#define GTC_DSTEST_1_PID_SEL_MULTI_CR 0x00000018
/** PORT-ID is selected decryption is disabled, set all RAM locations to 1100B */
#define GTC_DSTEST_1_PID_SEL_NORM_NOCR 0x00000020
/** PORT-ID is selected for OMCI, decryption is disabled, set all RAM locations to 1101B */
#define GTC_DSTEST_1_PID_SEL_OMCI_NOCR 0x00000028
/** PORT-ID is selected as Multicast, decryption is disabled, set all RAM locations to 1110B */
#define GTC_DSTEST_1_PID_SEL_MULTI_NOCR 0x00000030
/** unused */
#define GTC_DSTEST_1_PID_SEL_RES1 0x00000038
/** AES Decryption Enable */
#define GTC_DSTEST_1_AES 0x00000004
/* AES decryption is disabled
#define GTC_DSTEST_1_AES_DIS 0x00000000 */
/** (default) AES de-cryption is enabled */
#define GTC_DSTEST_1_AES_EN 0x00000004
/** SYNC ACCELERATION */
#define GTC_DSTEST_1_SY_ACC 0x00000002
/* (default) disable test function
#define GTC_DSTEST_1_SY_ACC_DIS 0x00000000 */
/** enable test function */
#define GTC_DSTEST_1_SY_ACC_EN 0x00000002
/** Super Frame Synchronization Acceleration */
#define GTC_DSTEST_1_SF_ACC 0x00000001
/* (default) disable test function
#define GTC_DSTEST_1_SF_ACC_DIS 0x00000000 */
/** enable test function */
#define GTC_DSTEST_1_SF_ACC_EN 0x00000001

/* Fields of "GTC Downstream Test Register 1" */
/** PORT-ID RAM Ready */
#define GTC_DSTEST_2_SW_RAM_Q_VALID 0x00000002
/* RAM is not ready
#define GTC_DSTEST_2_SW_RAM_Q_VALID_WAIT 0x00000000 */
/** RAM is ready to be read */
#define GTC_DSTEST_2_SW_RAM_Q_VALID_RDY 0x00000002
/** PORTID RAM Initialization */
#define GTC_DSTEST_2_SW_RAM_BUSY 0x00000001
/* RAM is ready
#define GTC_DSTEST_2_SW_RAM_BUSY_RDY 0x00000000 */
/** RAM initialization is in progress */
#define GTC_DSTEST_2_SW_RAM_BUSY_BUSY 0x00000001

/* Fields of "GTC Synchronization Control Register" */
/** Superframe Synchronization SF_SYNC to SF_HUNT */
#define GTC_SCON_N2_MASK 0x00003C00
/** field offset */
#define GTC_SCON_N2_OFFSET 10
/** Superframe Synchronization SF_PRE-SYNC to SF_SYNC Count */
#define GTC_SCON_N1_MASK 0x00000380
/** field offset */
#define GTC_SCON_N1_OFFSET 7
/** Frame Synchronization SYNC to HUNT */
#define GTC_SCON_M2_MASK 0x00000078
/** field offset */
#define GTC_SCON_M2_OFFSET 3
/** Frame Synchronization PRE-SYNC to SYNC Count */
#define GTC_SCON_M1_MASK 0x00000007
/** field offset */
#define GTC_SCON_M1_OFFSET 0

/* Fields of "GTC Control Register 1" */
/** GPON Downstream FEC Enable */
#define GTC_DSCON_1_DSFEC_MASK 0x00000006
/** field offset */
#define GTC_DSCON_1_DSFEC_OFFSET 1
/** GPON downstream FEC is manually disabled. No FEC parity bytes are expected in the downstream data. */
#define GTC_DSCON_1_DSFEC_MANDIS 0x00000000
/** GPON downstream FEC is manually enabled. FEC parity bytes are evaluated, bit errors are corrected as far as possible. */
#define GTC_DSCON_1_DSFEC_MANEN 0x00000002
/** GPON downstream FEC is enabled, depending on the received in-band control bit. If selected by the OLT, FEC parity bytes are expected in the downstream data but bit errors are not corrected. */
#define GTC_DSCON_1_DSFEC_AUTONO 0x00000004
/** (default) GPON downstream FEC is enabled, depending on the received in-band control bit. If selected by the OLT, FEC parity bytes are expected in the downstream data and bit errors are corrected as far as possible. */
#define GTC_DSCON_1_DSFEC_AUTO 0x00000006
/** Counter Mode */
#define GTC_DSCON_1_CM 0x00000001
/* (default) wrap around
#define GTC_DSCON_1_CM_WRAP 0x00000000 */
/** saturate */
#define GTC_DSCON_1_CM_SAT 0x00000001

/* Fields of "GTC Superframe Counter Register" */
/** Superframe Count Value */
#define GTC_SFCNT_SFCNT_MASK 0x3FFFFFFF
/** field offset */
#define GTC_SFCNT_SFCNT_OFFSET 0

/* Fields of "AES Decryption Key Register 0" */
/** Decryption Key */
#define AES_DEKEY_KEY_MASK 0xFFFFFFFF
/** field offset */
#define AES_DEKEY_KEY_OFFSET 0

/* Fields of "AES Decryption key Switchover Time" */
/** Switching Time */
#define AES_KEY_SWITCH_SWTIM_MASK 0x3FFFFFFF
/** field offset */
#define AES_KEY_SWITCH_SWTIM_OFFSET 0

/* Fields of "GTC Receive PORT-ID Address Registers" */
/** Read/Write Selection */
#define GTC_RXPID_ADDR_WRITE 0x00000200
/* (default) read access to follow
#define GTC_RXPID_ADDR_WRITE_RD 0x00000000 */
/** write access to follow */
#define GTC_RXPID_ADDR_WRITE_WR 0x00000200
/** Port-ID Group Address */
#define GTC_RXPID_ADDR_ADDR_MASK 0x000001FF
/** field offset */
#define GTC_RXPID_ADDR_ADDR_OFFSET 0

/* Fields of "GTC Receive PORT-ID Write Register" */
/** Valid PORT-ID-Group 7 */
#define GTC_RXPID_WR_VAL_7 0x80000000
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_WR_VAL_7_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_WR_VAL_7_YES 0x80000000
/** Encrypted PORT-ID-Group 7 */
#define GTC_RXPID_WR_CR_7 0x40000000
/* received data is not encrypted (default)
#define GTC_RXPID_WR_CR_7_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_WR_CR_7_YES 0x40000000
/** Frame Type-Group 7 */
#define GTC_RXPID_WR_FT_7_MASK 0x30000000
/** field offset */
#define GTC_RXPID_WR_FT_7_OFFSET 28
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_WR_FT_7_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_WR_FT_7_OMCI 0x10000000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_WR_FT_7_MULTI 0x20000000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_WR_FT_7_BOTH 0x30000000
/** Valid PORT-ID-Group 6 */
#define GTC_RXPID_WR_VAL_6 0x08000000
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_WR_VAL_6_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_WR_VAL_6_YES 0x08000000
/** Encrypted PORT-ID-Group 6 */
#define GTC_RXPID_WR_CR_6 0x04000000
/* received data is not encrypted (default)
#define GTC_RXPID_WR_CR_6_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_WR_CR_6_YES 0x04000000
/** Frame Type-Group 6 */
#define GTC_RXPID_WR_FT_6_MASK 0x03000000
/** field offset */
#define GTC_RXPID_WR_FT_6_OFFSET 24
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_WR_FT_6_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_WR_FT_6_OMCI 0x01000000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_WR_FT_6_MULTI 0x02000000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_WR_FT_6_BOTH 0x03000000
/** Valid PORT-ID-Group 5 */
#define GTC_RXPID_WR_VAL_5 0x00800000
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_WR_VAL_5_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_WR_VAL_5_YES 0x00800000
/** Encrypted PORT-ID-Group 5 */
#define GTC_RXPID_WR_CR_5 0x00400000
/* received data is not encrypted (default)
#define GTC_RXPID_WR_CR_5_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_WR_CR_5_YES 0x00400000
/** Frame Type-Group 5 */
#define GTC_RXPID_WR_FT_5_MASK 0x00300000
/** field offset */
#define GTC_RXPID_WR_FT_5_OFFSET 20
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_WR_FT_5_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_WR_FT_5_OMCI 0x00100000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_WR_FT_5_MULTI 0x00200000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_WR_FT_5_BOTH 0x00300000
/** Valid PORT-ID-Group 4 */
#define GTC_RXPID_WR_VAL_4 0x00080000
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_WR_VAL_4_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_WR_VAL_4_YES 0x00080000
/** Encrypted PORT-ID-Group 4 */
#define GTC_RXPID_WR_CR_4 0x00040000
/* received data is not encrypted (default)
#define GTC_RXPID_WR_CR_4_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_WR_CR_4_YES 0x00040000
/** Frame Type-Group 4 */
#define GTC_RXPID_WR_FT_4_MASK 0x00030000
/** field offset */
#define GTC_RXPID_WR_FT_4_OFFSET 16
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_WR_FT_4_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_WR_FT_4_OMCI 0x00010000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_WR_FT_4_MULTI 0x00020000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_WR_FT_4_BOTH 0x00030000
/** Valid PORT-ID-Group 3 */
#define GTC_RXPID_WR_VAL_3 0x00008000
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_WR_VAL_3_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_WR_VAL_3_YES 0x00008000
/** Encrypted PORT-ID-Group 3 */
#define GTC_RXPID_WR_CR_3 0x00004000
/* received data is not encrypted (default)
#define GTC_RXPID_WR_CR_3_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_WR_CR_3_YES 0x00004000
/** Frame Type-Group 3 */
#define GTC_RXPID_WR_FT_3_MASK 0x00003000
/** field offset */
#define GTC_RXPID_WR_FT_3_OFFSET 12
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_WR_FT_3_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_WR_FT_3_OMCI 0x00001000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_WR_FT_3_MULTI 0x00002000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_WR_FT_3_BOTH 0x00003000
/** Valid PORT-ID-Group 2 */
#define GTC_RXPID_WR_VAL_2 0x00000800
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_WR_VAL_2_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_WR_VAL_2_YES 0x00000800
/** Encrypted PORT-ID-Group 2 */
#define GTC_RXPID_WR_CR_2 0x00000400
/* received data is not encrypted (default)
#define GTC_RXPID_WR_CR_2_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_WR_CR_2_YES 0x00000400
/** Frame Type-Group 2 */
#define GTC_RXPID_WR_FT_2_MASK 0x00000300
/** field offset */
#define GTC_RXPID_WR_FT_2_OFFSET 8
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_WR_FT_2_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_WR_FT_2_OMCI 0x00000100
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_WR_FT_2_MULTI 0x00000200
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_WR_FT_2_BOTH 0x00000300
/** Valid PORT-ID-Group 1 */
#define GTC_RXPID_WR_VAL_1 0x00000080
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_WR_VAL_1_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_WR_VAL_1_YES 0x00000080
/** Encrypted PORT-ID-Group 1 */
#define GTC_RXPID_WR_CR_1 0x00000040
/* received data is not encrypted (default)
#define GTC_RXPID_WR_CR_1_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_WR_CR_1_YES 0x00000040
/** Frame Type-Group 1 */
#define GTC_RXPID_WR_FT_1_MASK 0x00000030
/** field offset */
#define GTC_RXPID_WR_FT_1_OFFSET 4
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_WR_FT_1_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_WR_FT_1_OMCI 0x00000010
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_WR_FT_1_MULTI 0x00000020
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_WR_FT_1_BOTH 0x00000030
/** Valid PORT-ID-Group 0 */
#define GTC_RXPID_WR_VAL_0 0x00000008
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_WR_VAL_0_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_WR_VAL_0_YES 0x00000008
/** Encrypted PORT-ID-Group 0 */
#define GTC_RXPID_WR_CR_0 0x00000004
/* received data is not encrypted (default)
#define GTC_RXPID_WR_CR_0_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_WR_CR_0_YES 0x00000004
/** Frame Type-Group 0 */
#define GTC_RXPID_WR_FT_0_MASK 0x00000003
/** field offset */
#define GTC_RXPID_WR_FT_0_OFFSET 0
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_WR_FT_0_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_WR_FT_0_OMCI 0x00000001
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_WR_FT_0_MULTI 0x00000002
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_WR_FT_0_BOTH 0x00000003

/* Fields of "GTC Receive PORT-ID Read Register" */
/** Valid PORT-ID-Group 7 */
#define GTC_RXPID_RD_VAL_7 0x80000000
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_RD_VAL_7_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_RD_VAL_7_YES 0x80000000
/** Encrypted PORT-ID-Group 7 */
#define GTC_RXPID_RD_CR_7 0x40000000
/* received data is not encrypted (default)
#define GTC_RXPID_RD_CR_7_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_RD_CR_7_YES 0x40000000
/** Frame Type-Group 7 */
#define GTC_RXPID_RD_FT_7_MASK 0x30000000
/** field offset */
#define GTC_RXPID_RD_FT_7_OFFSET 28
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_RD_FT_7_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_RD_FT_7_OMCI 0x10000000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_RD_FT_7_MULTI 0x20000000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_RD_FT_7_BOTH 0x30000000
/** Valid PORT-ID-Group 6 */
#define GTC_RXPID_RD_VAL_6 0x08000000
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_RD_VAL_6_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_RD_VAL_6_YES 0x08000000
/** Encrypted PORT-ID-Group 6 */
#define GTC_RXPID_RD_CR_6 0x04000000
/* received data is not encrypted (default)
#define GTC_RXPID_RD_CR_6_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_RD_CR_6_YES 0x04000000
/** Frame Type-Group 6 */
#define GTC_RXPID_RD_FT_6_MASK 0x03000000
/** field offset */
#define GTC_RXPID_RD_FT_6_OFFSET 24
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_RD_FT_6_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_RD_FT_6_OMCI 0x01000000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_RD_FT_6_MULTI 0x02000000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_RD_FT_6_BOTH 0x03000000
/** Valid PORT-ID-Group 5 */
#define GTC_RXPID_RD_VAL_5 0x00800000
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_RD_VAL_5_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_RD_VAL_5_YES 0x00800000
/** Encrypted PORT-ID-Group 5 */
#define GTC_RXPID_RD_CR_5 0x00400000
/* received data is not encrypted (default)
#define GTC_RXPID_RD_CR_5_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_RD_CR_5_YES 0x00400000
/** Frame Type-Group 5 */
#define GTC_RXPID_RD_FT_5_MASK 0x00300000
/** field offset */
#define GTC_RXPID_RD_FT_5_OFFSET 20
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_RD_FT_5_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_RD_FT_5_OMCI 0x00100000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_RD_FT_5_MULTI 0x00200000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_RD_FT_5_BOTH 0x00300000
/** Valid PORT-ID-Group 4 */
#define GTC_RXPID_RD_VAL_4 0x00080000
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_RD_VAL_4_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_RD_VAL_4_YES 0x00080000
/** Encrypted PORT-ID-Group 4 */
#define GTC_RXPID_RD_CR_4 0x00040000
/* received data is not encrypted (default)
#define GTC_RXPID_RD_CR_4_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_RD_CR_4_YES 0x00040000
/** Frame Type-Group 4 */
#define GTC_RXPID_RD_FT_4_MASK 0x00030000
/** field offset */
#define GTC_RXPID_RD_FT_4_OFFSET 16
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_RD_FT_4_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_RD_FT_4_OMCI 0x00010000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_RD_FT_4_MULTI 0x00020000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_RD_FT_4_BOTH 0x00030000
/** Valid PORT-ID-Group 3 */
#define GTC_RXPID_RD_VAL_3 0x00008000
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_RD_VAL_3_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_RD_VAL_3_YES 0x00008000
/** Encrypted PORT-ID-Group 3 */
#define GTC_RXPID_RD_CR_3 0x00004000
/* received data is not encrypted (default)
#define GTC_RXPID_RD_CR_3_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_RD_CR_3_YES 0x00004000
/** Frame Type-Group 3 */
#define GTC_RXPID_RD_FT_3_MASK 0x00003000
/** field offset */
#define GTC_RXPID_RD_FT_3_OFFSET 12
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_RD_FT_3_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_RD_FT_3_OMCI 0x00001000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_RD_FT_3_MULTI 0x00002000
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_RD_FT_3_BOTH 0x00003000
/** Valid PORT-ID-Group 2 */
#define GTC_RXPID_RD_VAL_2 0x00000800
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_RD_VAL_2_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_RD_VAL_2_YES 0x00000800
/** Encrypted PORT-ID-Group 2 */
#define GTC_RXPID_RD_CR_2 0x00000400
/* received data is not encrypted (default)
#define GTC_RXPID_RD_CR_2_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_RD_CR_2_YES 0x00000400
/** Frame Type-Group 2 */
#define GTC_RXPID_RD_FT_2_MASK 0x00000300
/** field offset */
#define GTC_RXPID_RD_FT_2_OFFSET 8
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_RD_FT_2_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_RD_FT_2_OMCI 0x00000100
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_RD_FT_2_MULTI 0x00000200
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_RD_FT_2_BOTH 0x00000300
/** Valid PORT-ID-Group 1 */
#define GTC_RXPID_RD_VAL_1 0x00000080
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_RD_VAL_1_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_RD_VAL_1_YES 0x00000080
/** Encrypted PORT-ID-Group 1 */
#define GTC_RXPID_RD_CR_1 0x00000040
/* received data is not encrypted (default)
#define GTC_RXPID_RD_CR_1_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_RD_CR_1_YES 0x00000040
/** Frame Type-Group 1 */
#define GTC_RXPID_RD_FT_1_MASK 0x00000030
/** field offset */
#define GTC_RXPID_RD_FT_1_OFFSET 4
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_RD_FT_1_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_RD_FT_1_OMCI 0x00000010
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_RD_FT_1_MULTI 0x00000020
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_RD_FT_1_BOTH 0x00000030
/** Valid PORT-ID-Group 0 */
#define GTC_RXPID_RD_VAL_0 0x00000008
/* PORT-ID shall be ignored (default)
#define GTC_RXPID_RD_VAL_0_NO 0x00000000 */
/** PORT-ID shall be accepted */
#define GTC_RXPID_RD_VAL_0_YES 0x00000008
/** Encrypted PORT-ID-Group 0 */
#define GTC_RXPID_RD_CR_0 0x00000004
/* received data is not encrypted (default)
#define GTC_RXPID_RD_CR_0_NO 0x00000000 */
/** received data shall be decrypted */
#define GTC_RXPID_RD_CR_0_YES 0x00000004
/** Frame Type-Group 0 */
#define GTC_RXPID_RD_FT_0_MASK 0x00000003
/** field offset */
#define GTC_RXPID_RD_FT_0_OFFSET 0
/** this PORT-ID transports frames to be forwarded to the GPE Module, no control bits are set (default) */
#define GTC_RXPID_RD_FT_0_NORM 0x00000000
/** this PORT-ID transports OMCI frames to be forwarded to the GPE Module, OMCI control bit is set */
#define GTC_RXPID_RD_FT_0_OMCI 0x00000001
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, Multicast control bit is set */
#define GTC_RXPID_RD_FT_0_MULTI 0x00000002
/** this PORT-ID transports Multicast frames to be forwarded to the GPE Module, OMCI and Multicast control bits are set */
#define GTC_RXPID_RD_FT_0_BOTH 0x00000003

/* Fields of "GTC PLOAMd Message Receive Register 1" */
/** ONU-ID */
#define GTC_MRX_1_ONUID_MASK 0xFF000000
/** field offset */
#define GTC_MRX_1_ONUID_OFFSET 24
/** Message ID */
#define GTC_MRX_1_MESID_MASK 0x00FF0000
/** field offset */
#define GTC_MRX_1_MESID_OFFSET 16
/** Message Byte 0 */
#define GTC_MRX_1_MB0_MASK 0x0000FF00
/** field offset */
#define GTC_MRX_1_MB0_OFFSET 8
/** Message Byte 1 */
#define GTC_MRX_1_MB1_MASK 0x000000FF
/** field offset */
#define GTC_MRX_1_MB1_OFFSET 0

/* Fields of "GTC PLOAMd Message Receive Register 2" */
/** Message Byte 2 */
#define GTC_MRX_2_MB2_MASK 0xFF000000
/** field offset */
#define GTC_MRX_2_MB2_OFFSET 24
/** Message Byte 3 */
#define GTC_MRX_2_MB3_MASK 0x00FF0000
/** field offset */
#define GTC_MRX_2_MB3_OFFSET 16
/** Message Byte 4 */
#define GTC_MRX_2_MB4_MASK 0x0000FF00
/** field offset */
#define GTC_MRX_2_MB4_OFFSET 8
/** Message Byte 5 */
#define GTC_MRX_2_MB5_MASK 0x000000FF
/** field offset */
#define GTC_MRX_2_MB5_OFFSET 0

/* Fields of "GTC PLOAMd Message Receive Register 3" */
/** Message Byte 6 */
#define GTC_MRX_3_MB6_MASK 0xFF000000
/** field offset */
#define GTC_MRX_3_MB6_OFFSET 24
/** Message Byte 7 */
#define GTC_MRX_3_MB7_MASK 0x00FF0000
/** field offset */
#define GTC_MRX_3_MB7_OFFSET 16
/** Message Byte 8 */
#define GTC_MRX_3_MB8_MASK 0x0000FF00
/** field offset */
#define GTC_MRX_3_MB8_OFFSET 8
/** Message Byte 9 */
#define GTC_MRX_3_MB9_MASK 0x000000FF
/** field offset */
#define GTC_MRX_3_MB9_OFFSET 0

/* Fields of "GTC Downstream Identification Register" */
/** This is the value assigned to the ONT/ONU during initialization. This value is used to identify the source of the upstream data and to select downstream data. */
#define GTC_ID_ONUID_MASK 0x000000FF
/** field offset */
#define GTC_ID_ONUID_OFFSET 0

/* Fields of "GTC Downstream Interrupt Status Register 1" */
/** Rogue ONT Reset message arrived for this ONT. */
#define GTC_DSISTAT_1_ROGUE_MSG 0x00020000
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_ROGUE_MSG_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_ROGUE_MSG_INT 0x00020000
/** Ploam Time Out Intterupt */
#define GTC_DSISTAT_1_PLTOUT 0x00010000
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_PLTOUT_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_PLTOUT_INT 0x00010000
/** Bit Error Rate Interval Elapsed */
#define GTC_DSISTAT_1_BERINTV 0x00008000
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_BERINTV_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_BERINTV_INT 0x00008000
/** AES Key Switch */
#define GTC_DSISTAT_1_KEYSW 0x00004000
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_KEYSW_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_KEYSW_INT 0x00004000
/** Counter Overflow */
#define GTC_DSISTAT_1_CNTOFL 0x00002000
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_CNTOFL_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_CNTOFL_INT 0x00002000
/** Digital Loss of Signal */
#define GTC_DSISTAT_1_DLOS 0x00001000
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_DLOS_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_DLOS_INT 0x00001000
/** Signal Fail */
#define GTC_DSISTAT_1_SF 0x00000800
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_SF_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_SF_INT 0x00000800
/** Signal Degrade */
#define GTC_DSISTAT_1_SD 0x00000400
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_SD_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_SD_INT 0x00000400
/** GEM Frame Starvation */
#define GTC_DSISTAT_1_GEMSTV 0x00000200
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_GEMSTV_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_GEMSTV_INT 0x00000200
/** GEM Loss of Frame */
#define GTC_DSISTAT_1_GEMLOF 0x00000100
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_GEMLOF_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_GEMLOF_INT 0x00000100
/** GTC Loss of Superframe */
#define GTC_DSISTAT_1_GTCLSF 0x00000080
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_GTCLSF_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_GTCLSF_INT 0x00000080
/** GTC Loss of Frame */
#define GTC_DSISTAT_1_GTCLOF 0x00000040
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_GTCLOF_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_GTCLOF_INT 0x00000040
/** Plen Reception Error */
#define GTC_DSISTAT_1_PLERR 0x00000020
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_PLERR_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_PLERR_INT 0x00000020
/** Plen Reception Warning */
#define GTC_DSISTAT_1_PLWARN 0x00000010
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_PLWARN_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_PLWARN_INT 0x00000010
/** PLOAMd Receive Message Error */
#define GTC_DSISTAT_1_RXCRCE 0x00000008
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_RXCRCE_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_RXCRCE_INT 0x00000008
/** PLOAMd Receive Message Buffer Overflow */
#define GTC_DSISTAT_1_RXOFL 0x00000004
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_RXOFL_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_RXOFL_INT 0x00000004
/** PLOAMd Receive Message Buffer Full */
#define GTC_DSISTAT_1_RXFUL 0x00000002
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_RXFUL_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_RXFUL_INT 0x00000002
/** PLOAMd Receive Message Buffer Data Waiting */
#define GTC_DSISTAT_1_RXDAT 0x00000001
/* (default) no interrupt is pending
#define GTC_DSISTAT_1_RXDAT_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_DSISTAT_1_RXDAT_INT 0x00000001

/* Fields of "GTC Downstream Interrupt Mask Register 1" */
/** Rogue ONT Reset message */
#define GTC_DSIMASK_1_ROGUE_MSG 0x00020000
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_ROGUE_MSG_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_ROGUE_MSG_EN 0x00020000
/** Bit Error Rate Interval Elapsed */
#define GTC_DSIMASK_1_PLTOUT 0x00010000
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_PLTOUT_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_PLTOUT_EN 0x00010000
/** Bit Error Rate Interval Elapsed */
#define GTC_DSIMASK_1_BERINTV 0x00008000
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_BERINTV_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_BERINTV_EN 0x00008000
/** AES Key Switch */
#define GTC_DSIMASK_1_KEYSW 0x00004000
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_KEYSW_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_KEYSW_EN 0x00004000
/** Counter Overflow */
#define GTC_DSIMASK_1_CNTOFL 0x00002000
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_CNTOFL_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_CNTOFL_EN 0x00002000
/** Digital Loss of Signal */
#define GTC_DSIMASK_1_DLOS 0x00001000
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_DLOS_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_DLOS_EN 0x00001000
/** Signal Fail */
#define GTC_DSIMASK_1_SF 0x00000800
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_SF_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_SF_EN 0x00000800
/** Signal Degrade */
#define GTC_DSIMASK_1_SD 0x00000400
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_SD_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_SD_EN 0x00000400
/** GEM Frame Starvation */
#define GTC_DSIMASK_1_GEMSTV 0x00000200
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_GEMSTV_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_GEMSTV_EN 0x00000200
/** GEM Loss of Frame. */
#define GTC_DSIMASK_1_GEMLOF 0x00000100
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_GEMLOF_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_GEMLOF_EN 0x00000100
/** GTC Loss of Superframe */
#define GTC_DSIMASK_1_GTCLSF 0x00000080
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_GTCLSF_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_GTCLSF_EN 0x00000080
/** GTC Loss of Frame */
#define GTC_DSIMASK_1_GTCLOF 0x00000040
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_GTCLOF_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_GTCLOF_EN 0x00000040
/** Plen Reception Error */
#define GTC_DSIMASK_1_PLERR 0x00000020
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_PLERR_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_PLERR_EN 0x00000020
/** Plen Reception Warning */
#define GTC_DSIMASK_1_PLWARN 0x00000010
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_PLWARN_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_PLWARN_EN 0x00000010
/** PLOAM Receive Message Error */
#define GTC_DSIMASK_1_RXCRCE 0x00000008
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_RXCRCE_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_RXCRCE_EN 0x00000008
/** PLOAM Receive Message Buffer Overflow */
#define GTC_DSIMASK_1_RXOFL 0x00000004
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_RXOFL_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_RXOFL_EN 0x00000004
/** PLOAM Receive Message Buffer Full */
#define GTC_DSIMASK_1_RXFUL 0x00000002
/* (default) interrupt is disabled (masked)
#define GTC_DSIMASK_1_RXFUL_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_DSIMASK_1_RXFUL_EN 0x00000002
/** PLOAM Receive Message Buffer Data Waiting */
#define GTC_DSIMASK_1_RXDAT 0x00000001
/* (default) Interrupt is disabled (masked)
#define GTC_DSIMASK_1_RXDAT_DIS 0x00000000 */
/** Interrupt is enabled */
#define GTC_DSIMASK_1_RXDAT_EN 0x00000001

/* Fields of "GTC Downstream Counter Status Register" */
/** GEM_RXBCNT Counter Overflow */
#define GTC_DSCNTRSTAT_RXBCNT 0x00000200
/* (default) counter is within the maximum counting limit
#define GTC_DSCNTRSTAT_RXBCNT_OK 0x00000000 */
/** counter has reached the maximum counting value */
#define GTC_DSCNTRSTAT_RXBCNT_OFL 0x00000200
/** GEM_RXFCNT Counter Overflow */
#define GTC_DSCNTRSTAT_RXFCNT 0x00000100
/* (default) counter is within the maximum counting limit
#define GTC_DSCNTRSTAT_RXFCNT_OK 0x00000000 */
/** counter has reached the maximum counting value */
#define GTC_DSCNTRSTAT_RXFCNT_OFL 0x00000100
/** GTC_BWMUERR Counter Overflow */
#define GTC_DSCNTRSTAT_BWM_UERR 0x00000080
/* (default) counter is within the maximum counting limit
#define GTC_DSCNTRSTAT_BWM_UERR_OK 0x00000000 */
/** counter has reached the maximum counting value */
#define GTC_DSCNTRSTAT_BWM_UERR_OFL 0x00000080
/** GTC_BWMCERR Counter Overflow */
#define GTC_DSCNTRSTAT_BWM_CERR 0x00000040
/* (default) counter is within the maximum counting limit
#define GTC_DSCNTRSTAT_BWM_CERR_OK 0x00000000 */
/** counter has reached the maximum counting value */
#define GTC_DSCNTRSTAT_BWM_CERR_OFL 0x00000040
/** GEM_HERR_2 Counter Overflow */
#define GTC_DSCNTRSTAT_HERR2 0x00000020
/* (default) counter is within the maximum counting limit
#define GTC_DSCNTRSTAT_HERR2_OK 0x00000000 */
/** counter has reached the maximum counting value */
#define GTC_DSCNTRSTAT_HERR2_OFL 0x00000020
/** GEM_HERR_1 Counter Overflow */
#define GTC_DSCNTRSTAT_HERR1 0x00000010
/* (default) counter is within the maximum counting limit
#define GTC_DSCNTRSTAT_HERR1_OK 0x00000000 */
/** counter has reached the maximum counting value */
#define GTC_DSCNTRSTAT_HERR1_OFL 0x00000010
/** GTC_FCERRCNT Counter Overflow */
#define GTC_DSCNTRSTAT_FEC_UERR 0x00000008
/* (default) counter is within the maximum counting limit
#define GTC_DSCNTRSTAT_FEC_UERR_OK 0x00000000 */
/** counter has reached the maximum counting value */
#define GTC_DSCNTRSTAT_FEC_UERR_OFL 0x00000008
/** GTC_FUERRENT Counter Overflow */
#define GTC_DSCNTRSTAT_FEC_CERR 0x00000004
/* (default) counter is within the maximum counting limit
#define GTC_DSCNTRSTAT_FEC_CERR_OK 0x00000000 */
/** counter has reached the maximum counting value */
#define GTC_DSCNTRSTAT_FEC_CERR_OFL 0x00000004
/** GTC_FRCNT Counter Overflow */
#define GTC_DSCNTRSTAT_FEC_RCNT 0x00000002
/* (default) counter is within the maximum counting limit
#define GTC_DSCNTRSTAT_FEC_RCNT_OK 0x00000000 */
/** counter has reached the maximum counting value */
#define GTC_DSCNTRSTAT_FEC_RCNT_OFL 0x00000002
/** GTC_FRCBCNT Counter Overflow */
#define GTC_DSCNTRSTAT_FEC_RBCNT 0x00000001
/* (default) counter is within the maximum counting limit
#define GTC_DSCNTRSTAT_FEC_RBCNT_OK 0x00000000 */
/** counter has reached the maximum counting value */
#define GTC_DSCNTRSTAT_FEC_RBCNT_OFL 0x00000001

/* Fields of "GTC BIP Error Count Register" */
/** Number of BIP Errors */
#define GTC_BERRCNT_BERR_MASK 0xFFFFFFFF
/** field offset */
#define GTC_BERRCNT_BERR_OFFSET 0

/* Fields of "GEM HEC Error Counter Register 1" */
/** Correctable HEC Error Count */
#define GEM_HERR_1_CERR_MASK 0xFFFFFFFF
/** field offset */
#define GEM_HERR_1_CERR_OFFSET 0

/* Fields of "GEM HEC Error Counter Register 2" */
/** Uncorrectable HEC Error Count */
#define GEM_HERR_2_UERR_MASK 0xFFFFFFFF
/** field offset */
#define GEM_HERR_2_UERR_OFFSET 0

/* Fields of "GEM Bandwidth Map Correctable Error Counter" */
/** Correctable Errors */
#define GEM_BWMCERR_CERR_MASK 0x0000FFFF
/** field offset */
#define GEM_BWMCERR_CERR_OFFSET 0

/* Fields of "GEM Bandwidth Map Uncorrectable Error Counter" */
/** Uncorrectable Errors */
#define GEM_BWMUERR_UERR_MASK 0x0000FFFF
/** field offset */
#define GEM_BWMUERR_UERR_OFFSET 0

/* Fields of "GEM Receive Frame Counter Register" */
/** GEM Receive Frame Count */
#define GEM_RXFCNT_FCNT_MASK 0xFFFFFFFF
/** field offset */
#define GEM_RXFCNT_FCNT_OFFSET 0

/* Fields of "GEM Receive Byte Counter Register" */
/** GEM Receive Byte Count */
#define GEM_RXBCNT_BCNT_MASK 0xFFFFFFFF
/** field offset */
#define GEM_RXBCNT_BCNT_OFFSET 0

/* Fields of "FEC Correctable Error Counter Register" */
/** Correctable Error Blocks */
#define GTC_FCERRCNT_CERR_MASK 0x00FFFFFF
/** field offset */
#define GTC_FCERRCNT_CERR_OFFSET 0

/* Fields of "FEC Uncorrectable Error Counter" */
/** Uncorrectable Error Blocks */
#define GTC_FUERRCNT_UERR_MASK 0x00FFFFFF
/** field offset */
#define GTC_FUERRCNT_UERR_OFFSET 0

/* Fields of "FEC Receive Block Counter" */
/** Uncorrectable Error Blocks */
#define GTC_FRCNT_RCNT_MASK 0x00FFFFFF
/** field offset */
#define GTC_FRCNT_RCNT_OFFSET 0

/* Fields of "FEC Receive Corrected Byte Counter" */
/** Correctable received bytes. */
#define GTC_FRCBCNT_RCBCNT_MASK 0xFFFFFFFF
/** field offset */
#define GTC_FRCBCNT_RCBCNT_OFFSET 0

/* Fields of "Rogue ONT reset function" */
/** Repeat setting for the MSG_RST message. Could only be changed as long as EN is set to NO. */
#define GTC_RST_ROGUE_RPT_RST_MASK 0x07000000
/** field offset */
#define GTC_RST_ROGUE_RPT_RST_OFFSET 24
/** Message-ID register for the rogue PLOAMd message to reset the complete device. Store the message ID to reset the complete device in this register. Could only be changed as long as EN is set to NO. */
#define GTC_RST_ROGUE_MSG_RST_MASK 0x00FF0000
/** field offset */
#define GTC_RST_ROGUE_MSG_RST_OFFSET 16
/** Enables the Rogue ONT Reset function. If set to YES all register bits could only be changed by a hardware reset of this register block. */
#define GTC_RST_ROGUE_EN 0x00001000
/* (default) Function is not active.
#define GTC_RST_ROGUE_EN_NO 0x00000000 */
/** Function is active. */
#define GTC_RST_ROGUE_EN_YES 0x00001000
/** Repeat setting for the MSG_USRST message. Could only be changed as long as EN is set to NO. */
#define GTC_RST_ROGUE_RPT_USRST_MASK 0x00000700
/** field offset */
#define GTC_RST_ROGUE_RPT_USRST_OFFSET 8
/** Message-ID register for the rogue PLOAMd message to reset the upstream path. Store the message ID to reset the upstream path in this register. Could only be changed as long as EN is set to NO. */
#define GTC_RST_ROGUE_MSG_USRST_MASK 0x000000FF
/** field offset */
#define GTC_RST_ROGUE_MSG_USRST_OFFSET 0

/* Fields of "GTC Ranging Time Register 1" */
/** In PRE mode a TCONT is only generated if PLOAMu flag is set to '1' and SSTOP = SSTART + 12. The POST mode is for operational state and TCONTs are generated according to the requirements of the BW-Map. */
#define GTC_RTIME_1_O5 0x20000000
/* (default) Pre O5 state. Used during serial number and ranging request (O1 to O4)
#define GTC_RTIME_1_O5_PRE 0x00000000 */
/** Post O5 state. Has to be set as soon as O5 is reached. */
#define GTC_RTIME_1_O5_POST 0x20000000
/** Use Random Equalization Delay and Pre-Assigned Equalization Delay */
#define GTC_RTIME_1_USE 0x10000000
/* use normal (GTC_RTIME_2.DELAY) equalization delay value
#define GTC_RTIME_1_USE_POST 0x00000000 */
/** (default) use pre-assigned (PADEL) equalization delay value */
#define GTC_RTIME_1_USE_PRE 0x10000000
/** Random Equalization Delay */
#define GTC_RTIME_1_RANDEL_MASK 0x01FF0000
/** field offset */
#define GTC_RTIME_1_RANDEL_OFFSET 16
/** Pre-Assigned Equalization Delay */
#define GTC_RTIME_1_PADEL_MASK 0x0000FFFF
/** field offset */
#define GTC_RTIME_1_PADEL_OFFSET 0

/* Fields of "GTC Ranging Time Register 2" */
/** Equalization Delay */
#define GTC_RTIME_2_DELAY_MASK 0xFFFFFFFF
/** field offset */
#define GTC_RTIME_2_DELAY_OFFSET 0

/* Fields of "GTC Ranging Time Register 3" */
/** Minimum Response Time */
#define GTC_RTIME_3_MRT_MASK 0x000007FF
/** field offset */
#define GTC_RTIME_3_MRT_OFFSET 0

/* Fields of "GTC Status Register" */
/** The OLT has send a SSTART address less then total PLOu legth minus start offset: MIN_SSTART < GTC_USHDL.LEN + 3 - GTC_START_OFFSET.OFFSET. To release this bit set GTC_START_OFFSET.OFFSET to the right value. */
#define GTC_USSTAT_MINSST 0x00000040
/* (default) PLOu length fits to all SSTART from the OLT.
#define GTC_USSTAT_MINSST_OK 0x00000000 */
/** Violation: PLOu length is bigger than lowest SSTART address. */
#define GTC_USSTAT_MINSST_VIOL 0x00000040
/** This bit is set if the upstream framer has recognized the start time value of a T-CONT (SStart) and started to send. It is cleared by reading the register. */
#define GTC_USSTAT_FSTART 0x00000020
/* (default) no start time has been detected
#define GTC_USSTAT_FSTART_NONE 0x00000000 */
/** at least one start time has been detected */
#define GTC_USSTAT_FSTART_START 0x00000020
/** A new bandwidth map has been received and is ready to be used for upstream transmission. It is cleared by reading the register. */
#define GTC_USSTAT_BWM_RDY 0x00000010
/* (default) bandwidth map is not ready
#define GTC_USSTAT_BWM_RDY_BUSY 0x00000000 */
/** bandwidth map is ready */
#define GTC_USSTAT_BWM_RDY_RDY 0x00000010
/** Downstream Tick Generation Indication */
#define GTC_USSTAT_DSTICK 0x00000008
/* (default) no downstream tick has been detected
#define GTC_USSTAT_DSTICK_NONE 0x00000000 */
/** at least one downstream tick has been detected */
#define GTC_USSTAT_DSTICK_TICK 0x00000008
/** Upstream Tick Generation Indication */
#define GTC_USSTAT_USTICK 0x00000004
/* (default) no upstream tick has been detected
#define GTC_USSTAT_USTICK_NONE 0x00000000 */
/** at least one upstream tick has been detected */
#define GTC_USSTAT_USTICK_TICK 0x00000004
/** Upstream PLOAM Indication */
#define GTC_USSTAT_PLOAMU 0x00000002
/* (default) no PLOAMu has been sent since the last read access to this register
#define GTC_USSTAT_PLOAMU_NOTSENT 0x00000000 */
/** at least one PLOAMu message has been sent since the last read access to this register */
#define GTC_USSTAT_PLOAMU_SENT 0x00000002
/** Upstream Forward Error Correction Enable */
#define GTC_USSTAT_USFEC 0x00000001
/* (default) upstream FEC is disabled.
#define GTC_USSTAT_USFEC_OFF 0x00000000 */
/** upstream FEC is enabled. */
#define GTC_USSTAT_USFEC_ON 0x00000001

/* Fields of "GTC Upstream Error Status Register" */
/** PLOu memory access error. */
#define GTC_USESTAT_PLOU_MEM 0x00004000
/* (default) no error
#define GTC_USESTAT_PLOU_MEM_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_PLOU_MEM_ERR 0x00004000
/** Bandwidth Map overflow. */
#define GTC_USESTAT_BWM_OFL 0x00002000
/* (default) no error
#define GTC_USESTAT_BWM_OFL_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_BWM_OFL_ERR 0x00002000
/** Transmitted ALLOC-ID from package engine is not the expected one. */
#define GTC_USESTAT_BAD_ALLOC 0x00001000
/* (default) no error
#define GTC_USESTAT_BAD_ALLOC_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_BAD_ALLOC_ERR 0x00001000
/** Upstream T-CONT FIFO (from GTC to GPE) overflow. Data written to the FIFO are lost. */
#define GTC_USESTAT_TFIFO_OFL 0x00000800
/* (default) no error
#define GTC_USESTAT_TFIFO_OFL_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_TFIFO_OFL_ERR 0x00000800
/** Upstream T-CONT FIFO (from GTC to GPE) is full. Only threshold words are free in the FIFO. */
#define GTC_USESTAT_TFIFO_FULL 0x00000400
/* (default) no error
#define GTC_USESTAT_TFIFO_FULL_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_TFIFO_FULL_ERR 0x00000400
/** Upstream data FIFO (from GPE to GTC) underflow. Data fetched with this cycle are false. */
#define GTC_USESTAT_DFIFO_UFL 0x00000200
/* (default) no error
#define GTC_USESTAT_DFIFO_UFL_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_DFIFO_UFL_ERR 0x00000200
/** Upstream data FIFO (from GPE to GTC) is empty. Only threshold words are left in the FIFO. */
#define GTC_USESTAT_DFIFO_EMPTY 0x00000100
/* (default) no error
#define GTC_USESTAT_DFIFO_EMPTY_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_DFIFO_EMPTY_ERR 0x00000100
/** Bandwidth Map Alignment Error */
#define GTC_USESTAT_BWAL 0x00000080
/* (default) no error
#define GTC_USESTAT_BWAL_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_BWAL_ERR 0x00000080
/** GTC Header Request Error */
#define GTC_USESTAT_GTCHREQ 0x00000040
/* (default) no error
#define GTC_USESTAT_GTCHREQ_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_GTCHREQ_ERR 0x00000040
/** PLOu Request Error */
#define GTC_USESTAT_PLOU_REQ 0x00000020
/* (default) no error
#define GTC_USESTAT_PLOU_REQ_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_PLOU_REQ_ERR 0x00000020
/** Empty T-CONT Error. */
#define GTC_USESTAT_TCONT 0x00000010
/* (default) no error
#define GTC_USESTAT_TCONT_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_TCONT_ERR 0x00000010
/** Data Count Error */
#define GTC_USESTAT_DCNT 0x00000008
/* (default) no error
#define GTC_USESTAT_DCNT_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_DCNT_ERR 0x00000008
/** Stuck in GTC Error */
#define GTC_USESTAT_GTC 0x00000004
/* (default) no error
#define GTC_USESTAT_GTC_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_GTC_ERR 0x00000004
/** Stuck in GEM Error */
#define GTC_USESTAT_GEM 0x00000002
/* (default) no error
#define GTC_USESTAT_GEM_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_GEM_ERR 0x00000002
/** Stuck in PLOu Error */
#define GTC_USESTAT_PLOU 0x00000001
/* (default) no error
#define GTC_USESTAT_PLOU_OK 0x00000000 */
/** error condition detected */
#define GTC_USESTAT_PLOU_ERR 0x00000001

/* Fields of "GTC Control Register" */
/** PLSu Data Pattern */
#define GTC_USCON_PLSUD_MASK 0xFFFF0000
/** field offset */
#define GTC_USCON_PLSUD_OFFSET 16
/** Bandwidth Map Mode */
#define GTC_USCON_BWMAP 0x00000800
/* (default) allocations are valid for one upstream frame only and automatically de-allocated .
#define GTC_USCON_BWMAP_REFRESH 0x00000000 */
/** allocations are valid until de-allocated explicitly. */
#define GTC_USCON_BWMAP_HIST 0x00000800
/** Enable automatic hardware trigger for the Dying Gasp message. */
#define GTC_USCON_EN_DG 0x00000400
/* (default) Hardware trigger is disabled.
#define GTC_USCON_EN_DG_DIS 0x00000000 */
/** Hardware trigger is enabled and the Dying Gasp message is generated automatically. */
#define GTC_USCON_EN_DG_EN 0x00000400
/** Enable dozing mode */
#define GTC_USCON_DOZE 0x00000200
/* (default) Dozing mode is disabled
#define GTC_USCON_DOZE_DIS 0x00000000 */
/** Dozing mode is enabled */
#define GTC_USCON_DOZE_EN 0x00000200
/** 'gpon_rx_lock' (downstream is synchronized) signal handling. */
#define GTC_USCON_LOCKDIS 0x00000100
/* (default) The SerDes Transmit Enable is automaticaly disabled if the receive path is not locked (loss of frame).
#define GTC_USCON_LOCKDIS_EN 0x00000000 */
/** The receive path lock signal has no influence on the SerDes Transmit Enable. */
#define GTC_USCON_LOCKDIS_DIS 0x00000100
/** Ind Value - Bit 5 */
#define GTC_USCON_IND5 0x00000040
/* (default) no RDI detected
#define GTC_USCON_IND5_NO 0x00000000 */
/** RDI has been detected */
#define GTC_USCON_IND5_YES 0x00000040
/** Ind Value - Bit 4 */
#define GTC_USCON_IND4 0x00000020
/* (default) no T-CONT type 2 traffic waiting
#define GTC_USCON_IND4_NO 0x00000000 */
/** T-CONT type 2 traffic is waiting */
#define GTC_USCON_IND4_YES 0x00000020
/** Ind Value - Bit 3 */
#define GTC_USCON_IND3 0x00000010
/* (default) no T-CONT type 3 traffic waiting
#define GTC_USCON_IND3_NO 0x00000000 */
/** T-CONT type 3 traffic is waiting */
#define GTC_USCON_IND3_YES 0x00000010
/** Ind Value - Bit 2 */
#define GTC_USCON_IND2 0x00000008
/* (default) no T-CONT type 4 traffic waiting
#define GTC_USCON_IND2_NO 0x00000000 */
/** T-CONT type 4 traffic is waiting */
#define GTC_USCON_IND2_YES 0x00000008
/** Ind Value - Bit 1 */
#define GTC_USCON_IND1 0x00000004
/* (default) no T-CONT type 5 traffic waiting
#define GTC_USCON_IND1_NO 0x00000000 */
/** T-CONT type 5 traffic is waiting */
#define GTC_USCON_IND1_YES 0x00000004
/** Ind Value - Bit 0 */
#define GTC_USCON_IND0 0x00000002
/* (default) Ind0 = 0B
#define GTC_USCON_IND0_ZERO 0x00000000 */
/** Ind0 = 1B */
#define GTC_USCON_IND0_ONE 0x00000002
/** GPON Upstream Transmission Enable */
#define GTC_USCON_USEN 0x00000001
/* (default) GPON upstream traffic is inhibited immediately.
#define GTC_USCON_USEN_STOP 0x00000000 */
/** GPON upstream traffic is enabled */
#define GTC_USCON_USEN_RUN 0x00000001

/* Fields of "GTC Upstream Header Length Register" */
/** Frame Header Length */
#define GTC_USHDL_LEN_MASK 0x000001FF
/** field offset */
#define GTC_USHDL_LEN_OFFSET 0

/* Fields of "GTC Upstream Header Address Register" */
/** Address Data */
#define GTC_USHDRC_AD_ADDR_MASK 0x0000007F
/** field offset */
#define GTC_USHDRC_AD_ADDR_OFFSET 0

/* Fields of "GTC Upstream Header Configuration Write Data Register" */
/** Write Data */
#define GTC_USHDRC_WD_WDATA_MASK 0xFFFFFFFF
/** field offset */
#define GTC_USHDRC_WD_WDATA_OFFSET 0

/* Fields of "GTC Upstream Header Read Data Register" */
/** Read Data */
#define GTC_USHDRC_RD_RDATA_MASK 0xFFFFFFFF
/** field offset */
#define GTC_USHDRC_RD_RDATA_OFFSET 0

/* Fields of "GTC PLOAM Message Transmit Control Register" */
/** No Message Write enable. Select the No Message buffer instead of the PLOAMu FIFO. */
#define GTC_MTX_CTRL_NM_WR 0x00001000
/* (default) Disable writing to the No Message buffer
#define GTC_MTX_CTRL_NM_WR_DIS 0x00000000 */
/** Enable writing to the No Message buffer */
#define GTC_MTX_CTRL_NM_WR_EN 0x00001000
/** Initiate the Dying Gasp message by software. */
#define GTC_MTX_CTRL_SW_DG 0x00000400
/* (default) Disabled. Dying Gasp message handling is only hardware based.
#define GTC_MTX_CTRL_SW_DG_DIS 0x00000000 */
/** Enabled. Dying Gasp message is send with the next allocated PLOAMu channel. */
#define GTC_MTX_CTRL_SW_DG_EN 0x00000400
/** Dying Gasp Write enable. Select the Dying Gasp message buffer. This setting has priority over the NM_WR bit. */
#define GTC_MTX_CTRL_DG_WR 0x00000100
/* (default) Disable writing to the Dying Gasp buffer
#define GTC_MTX_CTRL_DG_WR_DIS 0x00000000 */
/** Enable writing to the Dying Gasp buffer */
#define GTC_MTX_CTRL_DG_WR_EN 0x00000100
/** Flush pending messages */
#define GTC_MTX_CTRL_FLUSH 0x00000008
/* (default) normal operation, messages in the FIFO are sent if possible
#define GTC_MTX_CTRL_FLUSH_NO 0x00000000 */
/** empty the message FIFO without sending, other bits in this register and in GTC_MTX_2 and GTC_MTX_3 are ignored */
#define GTC_MTX_CTRL_FLUSH_YES 0x00000008
/** Message Repeat Factor */
#define GTC_MTX_CTRL_REPEAT_MASK 0x00000007
/** field offset */
#define GTC_MTX_CTRL_REPEAT_OFFSET 0
/** (default) no repeat */
#define GTC_MTX_CTRL_REPEAT_NR 0x00000000
/** send PLOAMu message one time */
#define GTC_MTX_CTRL_REPEAT_X1 0x00000001
/** send PLOAMu message twice */
#define GTC_MTX_CTRL_REPEAT_X2 0x00000002
/** send PLOAMu message 3 times */
#define GTC_MTX_CTRL_REPEAT_X3 0x00000003
/** send PLOAMu message 4 times */
#define GTC_MTX_CTRL_REPEAT_X4 0x00000004
/** send PLOAMu message 5 times */
#define GTC_MTX_CTRL_REPEAT_X5 0x00000005
/** send PLOAMu message 6 times */
#define GTC_MTX_CTRL_REPEAT_X6 0x00000006
/** send PLOAMu message forever until the buffer is flushed. */
#define GTC_MTX_CTRL_REPEAT_X7 0x00000007

/* Fields of "GTC PLOAM Message Transmit Register 1" */
/** ONU ID */
#define GTC_MTX_1_ONUID_MASK 0xFF000000
/** field offset */
#define GTC_MTX_1_ONUID_OFFSET 24
/** Message ID */
#define GTC_MTX_1_MESID_MASK 0x00FF0000
/** field offset */
#define GTC_MTX_1_MESID_OFFSET 16
/** Message Byte 0 */
#define GTC_MTX_1_MB0_MASK 0x0000FF00
/** field offset */
#define GTC_MTX_1_MB0_OFFSET 8
/** Message Byte 1 */
#define GTC_MTX_1_MB1_MASK 0x000000FF
/** field offset */
#define GTC_MTX_1_MB1_OFFSET 0

/* Fields of "GTC PLOAM Message Transmit Register 2" */
/** Message Byte 2 */
#define GTC_MTX_2_MB2_MASK 0xFF000000
/** field offset */
#define GTC_MTX_2_MB2_OFFSET 24
/** Message Byte 3 */
#define GTC_MTX_2_MB3_MASK 0x00FF0000
/** field offset */
#define GTC_MTX_2_MB3_OFFSET 16
/** Message Byte 4 */
#define GTC_MTX_2_MB4_MASK 0x0000FF00
/** field offset */
#define GTC_MTX_2_MB4_OFFSET 8
/** Message Byte 5 */
#define GTC_MTX_2_MB5_MASK 0x000000FF
/** field offset */
#define GTC_MTX_2_MB5_OFFSET 0

/* Fields of "GTC PLOAM Message Transmit Register 1" */
/** Message Byte 6 */
#define GTC_MTX_3_MB6_MASK 0xFF000000
/** field offset */
#define GTC_MTX_3_MB6_OFFSET 24
/** Message Byte 7 */
#define GTC_MTX_3_MB7_MASK 0x00FF0000
/** field offset */
#define GTC_MTX_3_MB7_OFFSET 16
/** Message Byte 8 */
#define GTC_MTX_3_MB8_MASK 0x0000FF00
/** field offset */
#define GTC_MTX_3_MB8_OFFSET 8
/** Message Byte 9 */
#define GTC_MTX_3_MB9_MASK 0x000000FF
/** field offset */
#define GTC_MTX_3_MB9_OFFSET 0

/* Fields of "GTC Interrupt Status Register" */
/** A trace event arised from the GTC_BWMSTAT register. Check this register for the root cause. */
#define GTC_USISTAT_TRACE 0x00010000
/* (default) no interrupt is pending
#define GTC_USISTAT_TRACE_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_USISTAT_TRACE_INT 0x00010000
/** The OLT has send a SSTART address less then total PLOu legth minus start offset: MIN_SSTART < GTC_USHDL.LEN + 3 - GTC_START_OFFSET.OFFSET */
#define GTC_USISTAT_MINSST 0x00000400
/* (default) no interrupt is pending
#define GTC_USISTAT_MINSST_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_USISTAT_MINSST_INT 0x00000400
/** The GTC_FRM_RANGE register has changed. MIN SSTART or MAX SSTOP value was updated by hardware. */
#define GTC_USISTAT_RANGE 0x00000200
/* (default) no interrupt is pending
#define GTC_USISTAT_RANGE_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_USISTAT_RANGE_INT 0x00000200
/** PLOAM Transmit Message Buffer Empty */
#define GTC_USISTAT_EMPTY 0x00000100
/* (default) no interrupt is pending
#define GTC_USISTAT_EMPTY_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_USISTAT_EMPTY_INT 0x00000100
/** PLOAMu Message Response */
#define GTC_USISTAT_PLRESP 0x00000080
/* (default) no interrupt is pending
#define GTC_USISTAT_PLRESP_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_USISTAT_PLRESP_INT 0x00000080
/** A request event (serial number, ranging) occurred. A request event is defined as a TCONT with just a PLOAMu message in it. */
#define GTC_USISTAT_REQE 0x00000040
/* (default) no interrupt is pending
#define GTC_USISTAT_REQE_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_USISTAT_REQE_INT 0x00000040
/** Map FIFO Pointer Error */
#define GTC_USISTAT_MAP_FIFO 0x00000020
/* (default) no interrupt is pending
#define GTC_USISTAT_MAP_FIFO_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_USISTAT_MAP_FIFO_INT 0x00000020
/** PLOAM Transmit Message Buffer Overflow */
#define GTC_USISTAT_TXOFL 0x00000002
/* (default) no interrupt is pending
#define GTC_USISTAT_TXOFL_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_USISTAT_TXOFL_INT 0x00000002
/** PLOAM Transmit Message Buffer Full */
#define GTC_USISTAT_TXFUL 0x00000001
/* (default) no interrupt is pending
#define GTC_USISTAT_TXFUL_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_USISTAT_TXFUL_INT 0x00000001

/* Fields of "GTC Upstream Interrupt Mask Register" */
/** A trace event arised from the GTC_BWMSTAT register. */
#define GTC_USIMASK_TRACE 0x00010000
/* (default) interrupt is disabled (masked)
#define GTC_USIMASK_TRACE_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_USIMASK_TRACE_EN 0x00010000
/** The OLT has send a SSTART address less then total PLOu legth minus start offset. */
#define GTC_USIMASK_MINSST 0x00000400
/* (default) interrupt is disabled (masked)
#define GTC_USIMASK_MINSST_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_USIMASK_MINSST_EN 0x00000400
/** GTC_FRM_RANGE register change */
#define GTC_USIMASK_RANGE 0x00000200
/* (default) interrupt is disabled (masked)
#define GTC_USIMASK_RANGE_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_USIMASK_RANGE_EN 0x00000200
/** PLOAM Transmit Message Buffer Empty */
#define GTC_USIMASK_EMPTY 0x00000100
/* (default) interrupt is disabled (masked)
#define GTC_USIMASK_EMPTY_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_USIMASK_EMPTY_EN 0x00000100
/** PLOAMu Message Response */
#define GTC_USIMASK_PLRESP 0x00000080
/* (default) interrupt is disabled (masked)
#define GTC_USIMASK_PLRESP_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_USIMASK_PLRESP_EN 0x00000080
/** A request event (serial number, ranging) occurred. */
#define GTC_USIMASK_REQE 0x00000040
/* (default) interrupt is disabled (masked)
#define GTC_USIMASK_REQE_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_USIMASK_REQE_EN 0x00000040
/** Map FIFO Pointer Error */
#define GTC_USIMASK_MAP_FIFO 0x00000020
/* (default) interrupt is disabled (masked)
#define GTC_USIMASK_MAP_FIFO_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_USIMASK_MAP_FIFO_EN 0x00000020
/** PLOAM Transmit Message Buffer Overflow */
#define GTC_USIMASK_TXOFL 0x00000002
/* (default) interrupt is disabled (masked)
#define GTC_USIMASK_TXOFL_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_USIMASK_TXOFL_EN 0x00000002
/** PLOAM Transmit Message Buffer Full */
#define GTC_USIMASK_TXFUL 0x00000001
/* (default) interrupt is disabled (masked)
#define GTC_USIMASK_TXFUL_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_USIMASK_TXFUL_EN 0x00000001

/* Fields of "GTC Upstream Laser Power On/Off Register" */
/** Laser Enable Start Extension */
#define GTC_LASER_LE_EXTS_MASK 0xF0000000
/** field offset */
#define GTC_LASER_LE_EXTS_OFFSET 28
/** Laser Enable End Extension */
#define GTC_LASER_LE_EXTE_MASK 0x0F000000
/** field offset */
#define GTC_LASER_LE_EXTE_OFFSET 24
/** Laser Power-Off Disable. The power-off function in T-CONT gaps is disabled and the laser is always powered on. */
#define GTC_LASER_LPO_DIS 0x00001000
/* (default) Laser power-off function is enabled. In T-CONT gaps the laser is powered off according to the LPO_GAP size.
#define GTC_LASER_LPO_DIS_EN 0x00000000 */
/** Laser power-off function is disabled. The laser is always on. */
#define GTC_LASER_LPO_DIS_DIS 0x00001000
/** Laser Power-Up offset in 77-MHz cycles prior to the laser enable signal. The default value is 4 (51ns). */
#define GTC_LASER_LPU_OFFS_MASK 0x00000700
/** field offset */
#define GTC_LASER_LPU_OFFS_OFFSET 8
/** Laser Power-Off gap in 77-MHz cycles. This represents the minimum gap between SSTOP of the actual and SSTART of the next T-CONT to power off the laser. The default value is 22, resulting in a gap of 283ns. */
#define GTC_LASER_LPO_GAP_MASK 0x0000003F
/** field offset */
#define GTC_LASER_LPO_GAP_OFFSET 0

/* Fields of "GTC Upstream Test Register" */
/** ALLOC-ID check disabled */
#define GTC_USTEST_ID_CHK_DIS 0x00400000
/* (default) Normal operation. A wrong ALLOC-ID is blocking the assigned TCONT traffic.
#define GTC_USTEST_ID_CHK_DIS_NORM 0x00000000 */
/** ALLOC-ID check in GPE interface is disabled. */
#define GTC_USTEST_ID_CHK_DIS_DIS 0x00400000
/** Upstream Independent Test Mode */
#define GTC_USTEST_INDTEST 0x00200000
/* (default) Normal operation.
#define GTC_USTEST_INDTEST_NORM 0x00000000 */
/** self-test mode. */
#define GTC_USTEST_INDTEST_TEST 0x00200000
/** Upstream Bandwidth Map Mode */
#define GTC_USTEST_BWMOD 0x00100000
/* (default) the bandwidth map is received in the upstream bandwidth map fields of the downstream GTC frame, registers are read only
#define GTC_USTEST_BWMOD_HW 0x00000000 */
/** the bandwidth map is not updated by hardware, registers are read/write. */
#define GTC_USTEST_BWMOD_SW 0x00100000
/** Bandwidth Map CRC Check Disable */
#define GTC_USTEST_BWCRC 0x00080000
/* CRC check is disabled, all bandwidth maps are accepted.
#define GTC_USTEST_BWCRC_CRCDIS 0x00000000 */
/** (default) CRC check is enabled, CRC correction is tried upon incorrect CRC. If not correctable, bandwidth map is discarded. */
#define GTC_USTEST_BWCRC_CRCEN 0x00080000
/** Error Insertion Control Word */
#define GTC_USTEST_ERR_MASK 0x0007F800
/** field offset */
#define GTC_USTEST_ERR_OFFSET 11
/** FEC Error Insertion Control */
#define GTC_USTEST_FECE 0x00000400
/* (default) no errors are inserted.
#define GTC_USTEST_FECE_NO 0x00000000 */
/** errors are inserted. */
#define GTC_USTEST_FECE_YES 0x00000400
/** BIP Error Insertion Control */
#define GTC_USTEST_BIPE 0x00000200
/* (default) no errors are inserted into the BIP byte.
#define GTC_USTEST_BIPE_NO 0x00000000 */
/** errors are inserted into the BIP byte. */
#define GTC_USTEST_BIPE_YES 0x00000200
/** PLOAM Error Insertion */
#define GTC_USTEST_PLE 0x00000100
/* no errors are inserted into the PLOAMu CRC byte.
#define GTC_USTEST_PLE_NO 0x00000000 */
/** errors are inserted into the PLOAMu CRC byte. */
#define GTC_USTEST_PLE_YES 0x00000100
/** DBRu CRC Error Insertion */
#define GTC_USTEST_DBRE 0x00000080
/* (default) no errors are inserted into the DBRu CRC byte.
#define GTC_USTEST_DBRE_NO 0x00000000 */
/** errors are inserted into the DBRu CRC byte. */
#define GTC_USTEST_DBRE_YES 0x00000080
/** GPON Upstream PLOAM Enable */
#define GTC_USTEST_PLOAMU_MASK 0x00000060
/** field offset */
#define GTC_USTEST_PLOAMU_OFFSET 5
/** GPON PLOAMu is disabled */
#define GTC_USTEST_PLOAMU_DIS 0x00000000
/** GPON PLOAMu is enabled */
#define GTC_USTEST_PLOAMU_EN 0x00000020
/** reserved */
#define GTC_USTEST_PLOAMU_RES 0x00000040
/** (default) GPON PLOAMu is enabled or disabled depending on received flag bit */
#define GTC_USTEST_PLOAMU_AUTO 0x00000060
/** GPON Upstream FEC Enable */
#define GTC_USTEST_USFEC_MASK 0x00000018
/** field offset */
#define GTC_USTEST_USFEC_OFFSET 3
/** GPON upstream FEC is disabled. No parity bytes are inserted. */
#define GTC_USTEST_USFEC_DIS 0x00000000
/** GPON upstream FEC is enabled */
#define GTC_USTEST_USFEC_EN 0x00000008
/** reserved */
#define GTC_USTEST_USFEC_RES 0x00000010
/** (default) GPON upstream FEC is enabled or disabled depending on received flag bit */
#define GTC_USTEST_USFEC_AUTO 0x00000018
/** Scrambling Enable */
#define GTC_USTEST_SCREN 0x00000004
/* scrambling is disabled.
#define GTC_USTEST_SCREN_DIS 0x00000000 */
/** (default) scrambling is enabled. */
#define GTC_USTEST_SCREN_EN 0x00000004
/** PLSU Enable */
#define GTC_USTEST_PLSU_MASK 0x00000003
/** field offset */
#define GTC_USTEST_PLSU_OFFSET 0
/** GPON upstream PLSu is disabled */
#define GTC_USTEST_PLSU_DIS 0x00000000
/** GPON upstream PLSu is enabled for all T-CONTS allocations */
#define GTC_USTEST_PLSU_EN 0x00000001
/** PLSu is added to all request events (TCONTs with only a PLOAMu in it). */
#define GTC_USTEST_PLSU_REQE 0x00000002
/** (default) PLSu is enabled, sent if requested by downstream flag for a specific T-CONT allocation */
#define GTC_USTEST_PLSU_AUTO 0x00000003

/* Fields of "GTC Fetch Offset Register" */
/** Fetch Strobe Offset Value */
#define GTC_USFETCH_OFFS_MASK 0x0000FFFF
/** field offset */
#define GTC_USFETCH_OFFS_OFFSET 0

/* Fields of "GTC Start Offset Register Configuration" */
/** Offset Value */
#define GTC_START_OFFSET_OFFSET_MASK 0x000001FF
/** field offset */
#define GTC_START_OFFSET_OFFSET_OFFSET 0

/* Fields of "GTC Bandwidth Map Register Write Low" */
/** Start Time Value */
#define GTC_BWMAPWL_SSTART_MASK 0xFFFF0000
/** field offset */
#define GTC_BWMAPWL_SSTART_OFFSET 16
/** Stop time Value */
#define GTC_BWMAPWL_SSTOP_MASK 0x0000FFFF
/** field offset */
#define GTC_BWMAPWL_SSTOP_OFFSET 0

/* Fields of "GTC Bandwidth Map Register Write High" */
/** Allocation ID */
#define GTC_BWMAPWH_ALLOCID_MASK 0x00FFF000
/** field offset */
#define GTC_BWMAPWH_ALLOCID_OFFSET 12
/** Flags Value */
#define GTC_BWMAPWH_FLAGS_MASK 0x00000FFF
/** field offset */
#define GTC_BWMAPWH_FLAGS_OFFSET 0

/* Fields of "GTC T-CONT Allocation Register" */
/** Allocation ID In Use Indication */
#define GTC_TCONT_USED 0x00001000
/* (default) this Allocation ID register is not used.
#define GTC_TCONT_USED_NO 0x00000000 */
/** this Allocation ID register is used. */
#define GTC_TCONT_USED_YES 0x00001000
/** Allocation ID */
#define GTC_TCONT_ALLOCID_MASK 0x00000FFF
/** field offset */
#define GTC_TCONT_ALLOCID_OFFSET 0

/* Fields of "GTC Bandwidth Map Register Read High" */
/** Allocation ID */
#define GTC_BWMAPRH_ALLOCID_MASK 0x00FFF000
/** field offset */
#define GTC_BWMAPRH_ALLOCID_OFFSET 12
/** Flags Value */
#define GTC_BWMAPRH_FLAGS_MASK 0x00000FFF
/** field offset */
#define GTC_BWMAPRH_FLAGS_OFFSET 0

/* Fields of "GTC Bandwidth Map Register Read Low" */
/** Start time Value */
#define GTC_BWMAPRL_SSTART_MASK 0xFFFF0000
/** field offset */
#define GTC_BWMAPRL_SSTART_OFFSET 16
/** Stop Time Value */
#define GTC_BWMAPRL_SSTOP_MASK 0x0000FFFF
/** field offset */
#define GTC_BWMAPRL_SSTOP_OFFSET 0

/* Fields of "GTC Frame Range" */
/** SSTART min value of all BW-Maps seen by this device. Reset to 0xFFFF with GTC_BWMT_CTRL.RST_MIN */
#define GTC_FRM_RANGE_MIN_MASK 0xFFFF0000
/** field offset */
#define GTC_FRM_RANGE_MIN_OFFSET 16
/** SSTOP max value of all BW-Maps seen by this device. Reset to 0x0000 with GTC_BWMT_CTRL.RST_MAX */
#define GTC_FRM_RANGE_MAX_MASK 0x0000FFFF
/** field offset */
#define GTC_FRM_RANGE_MAX_OFFSET 0

/* Fields of "GTC BW-Map Trace Control" */
/** Reset GTC_FRM_RANGE.MIN to 0xFFFF. */
#define GTC_BWMT_CTRL_RST_MIN 0x00000020
/* (default) Reset is not active.
#define GTC_BWMT_CTRL_RST_MIN_NO 0x00000000 */
/** Reset is active. Reset to NO will be done automatically. */
#define GTC_BWMT_CTRL_RST_MIN_YES 0x00000020
/** Reset GTC_FRM_RANGE.MAX to 0x0000. */
#define GTC_BWMT_CTRL_RST_MAX 0x00000010
/* (default) Reset is not active.
#define GTC_BWMT_CTRL_RST_MAX_NO 0x00000000 */
/** Reset is active. Reset to NO will be done automatically. */
#define GTC_BWMT_CTRL_RST_MAX_YES 0x00000010
/** Trace Buffer Software Trigger. Set this bit to YES to stop the trace buffer like an error event. Afterwards the bit is set to NO automatically. */
#define GTC_BWMT_CTRL_SWT 0x00000008
/* (default) Trigger is not active.
#define GTC_BWMT_CTRL_SWT_NO 0x00000000 */
/** Trigger is active. Reset to NO will be done automatically. */
#define GTC_BWMT_CTRL_SWT_YES 0x00000008
/** In auto mode the new trace start address is set after each write access to the BW-Map buffer. */
#define GTC_BWMT_CTRL_AUTO 0x00000004
/* Auto mode is disabled.
#define GTC_BWMT_CTRL_AUTO_NO 0x00000000 */
/** (default) Auto mode is enabled. */
#define GTC_BWMT_CTRL_AUTO_YES 0x00000004
/** In trace mode the hardware BWM-Buffer access is stopped if a trace_stop event occurred. If set to YES the trace_stop function is released. Afterwards the bit is set to NO automatically. */
#define GTC_BWMT_CTRL_REL 0x00000002
/* (default) Don't release trace_stop, trace_stop could get active.
#define GTC_BWMT_CTRL_REL_NO 0x00000000 */
/** Release trace_stop. Reset to NO will be done automatically. */
#define GTC_BWMT_CTRL_REL_YES 0x00000002
/** Enable the BW-Map trace function. If enabled additional to the BW-Map the superframe counter is saved to the BW-Map FIFO and all BW-Map trace function are available. */
#define GTC_BWMT_CTRL_TRACE 0x00000001
/* (default) Trace function is disabled.
#define GTC_BWMT_CTRL_TRACE_DIS 0x00000000 */
/** Trace function is enabled. */
#define GTC_BWMT_CTRL_TRACE_EN 0x00000001

/* Fields of "GTC BW-Map Interrupt Status Register" */
/** This bit is set if the trace buffer software trigger was set. */
#define GTC_BWMSTAT_SWT 0x00000200
/* (default) no interrupt is pending
#define GTC_BWMSTAT_SWT_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_BWMSTAT_SWT_INT 0x00000200
/** This bit is set if no GEM but overhead data is available. */
#define GTC_BWMSTAT_NO_GEM 0x00000100
/* (default) no interrupt is pending
#define GTC_BWMSTAT_NO_GEM_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_BWMSTAT_NO_GEM_INT 0x00000100
/** This bit is set if the actual TCONT overlaps the previous TCONT */
#define GTC_BWMSTAT_TCOVLP 0x00000080
/* (default) no interrupt is pending
#define GTC_BWMSTAT_TCOVLP_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_BWMSTAT_TCOVLP_INT 0x00000080
/** This bit is set if the gap in front of a TCONT is to small for PLOu data */
#define GTC_BWMSTAT_PLOGAP 0x00000040
/* (default) no interrupt is pending
#define GTC_BWMSTAT_PLOGAP_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_BWMSTAT_PLOGAP_INT 0x00000040
/** This bit is set if the StartTime is bigger than StopTime */
#define GTC_BWMSTAT_MIN_TC 0x00000020
/* (default) no interrupt is pending
#define GTC_BWMSTAT_MIN_TC_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_BWMSTAT_MIN_TC_INT 0x00000020
/** This bit is set if the StopTime is bigger than GTC upstream frame size */
#define GTC_BWMSTAT_STOP 0x00000010
/* (default) no interrupt is pending
#define GTC_BWMSTAT_STOP_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_BWMSTAT_STOP_INT 0x00000010
/** This bit is set if the StartTime is bigger than GTC upstream frame size */
#define GTC_BWMSTAT_START 0x00000008
/* (default) no interrupt is pending
#define GTC_BWMSTAT_START_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_BWMSTAT_START_INT 0x00000008
/** This bit is set if the remaining bytes of a TCONT are not enough to hold a parity block or a parity block violates the start/stop pointer restriction of contiguous TCONTs */
#define GTC_BWMSTAT_PAR_SZ 0x00000004
/* (default) no interrupt is pending
#define GTC_BWMSTAT_PAR_SZ_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_BWMSTAT_PAR_SZ_INT 0x00000004
/** This bit is set if the TCONT size is to small to hold GEM and, if active, FEC data. */
#define GTC_BWMSTAT_DAT_SZ 0x00000002
/* (default) no interrupt is pending
#define GTC_BWMSTAT_DAT_SZ_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_BWMSTAT_DAT_SZ_INT 0x00000002
/** This bit is set if the TCONT size is to small for overhead data like PLSU, PLOAM, DBRU and, if active, FEC. */
#define GTC_BWMSTAT_OVH_SZ 0x00000001
/* (default) no interrupt is pending
#define GTC_BWMSTAT_OVH_SZ_NOINT 0x00000000 */
/** interrupt is pending */
#define GTC_BWMSTAT_OVH_SZ_INT 0x00000001

/* Fields of "GTC BW-Map Interrupt Status Register" */
/** This bit is set if the trace buffer software trigger was set. */
#define GTC_BWMMASK_SWT 0x00000200
/* (default) interrupt is disabled (masked)
#define GTC_BWMMASK_SWT_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_BWMMASK_SWT_EN 0x00000200
/** This bit is set if no GEM but overhead data is available. */
#define GTC_BWMMASK_NO_GEM 0x00000100
/* (default) interrupt is disabled (masked)
#define GTC_BWMMASK_NO_GEM_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_BWMMASK_NO_GEM_EN 0x00000100
/** This bit is set if the actual TCONT overlaps the previous TCONT */
#define GTC_BWMMASK_TCOVLP 0x00000080
/* (default) interrupt is disabled (masked)
#define GTC_BWMMASK_TCOVLP_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_BWMMASK_TCOVLP_EN 0x00000080
/** This bit is set if the gap in front of a TCONT is to small for PLOu data */
#define GTC_BWMMASK_PLOGAP 0x00000040
/* (default) interrupt is disabled (masked)
#define GTC_BWMMASK_PLOGAP_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_BWMMASK_PLOGAP_EN 0x00000040
/** This bit is set if the StartTime is bigger than StopTime */
#define GTC_BWMMASK_MIN_TC 0x00000020
/* (default) interrupt is disabled (masked)
#define GTC_BWMMASK_MIN_TC_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_BWMMASK_MIN_TC_EN 0x00000020
/** This bit is set if the StopTime is bigger than GTC upstream frame size */
#define GTC_BWMMASK_STOP 0x00000010
/* (default) interrupt is disabled (masked)
#define GTC_BWMMASK_STOP_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_BWMMASK_STOP_EN 0x00000010
/** This bit is set if the StartTime is bigger than GTC upstream frame size */
#define GTC_BWMMASK_START 0x00000008
/* (default) interrupt is disabled (masked)
#define GTC_BWMMASK_START_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_BWMMASK_START_EN 0x00000008
/** This bit is set if the remaining bytes of a TCONT are not enough to hold a parity block or a parity block violates the start/stop pointer restriction of contiguous TCONTs */
#define GTC_BWMMASK_PAR_SZ 0x00000004
/* (default) interrupt is disabled (masked)
#define GTC_BWMMASK_PAR_SZ_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_BWMMASK_PAR_SZ_EN 0x00000004
/** This bit is set if the TCONT size is to small to hold GEM and, if active, FEC data. */
#define GTC_BWMMASK_DAT_SZ 0x00000002
/* (default) interrupt is disabled (masked)
#define GTC_BWMMASK_DAT_SZ_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_BWMMASK_DAT_SZ_EN 0x00000002
/** This bit is set if the TCONT size is to small for overhead data like PLSU, PLOAM, DBRU and, if active, FEC. */
#define GTC_BWMMASK_OVH_SZ 0x00000001
/* (default) interrupt is disabled (masked)
#define GTC_BWMMASK_OVH_SZ_DIS 0x00000000 */
/** interrupt is enabled */
#define GTC_BWMMASK_OVH_SZ_EN 0x00000001

/* Fields of "GTC BW-Map Actual Pointer Register" */
/** Provides the actual hardware write pointer to the BWM FIFO. */
#define GTC_BWMPTR_ACT_WR_MASK 0x01FF0000
/** field offset */
#define GTC_BWMPTR_ACT_WR_OFFSET 16
/** Provides the actual hardware read pointer to the BWM FIFO. */
#define GTC_BWMPTR_ACT_RD_MASK 0x000001FF
/** field offset */
#define GTC_BWMPTR_ACT_RD_OFFSET 0

/* Fields of "GTC BW-Map Buffer Address Register" */
/** Read Address for the BW-Map buffer. */
#define GTC_BWMB_AD_ADDR_MASK 0x000001FF
/** field offset */
#define GTC_BWMB_AD_ADDR_OFFSET 0

/* Fields of "GTC BW-Map Buffer Read Register" */
/** Provides data selected by GTC_BWMB_AD. */
#define GTC_BWMB_RD_DATA_MASK 0xFFFFFFFF
/** field offset */
#define GTC_BWMB_RD_DATA_OFFSET 0

/* Fields of "GTC All TCONT Counter" */
/** Received TCONTs since last reset. This is a wrap around counter. */
#define GTC_ALL_TC_CNT_MASK 0xFFFFFFFF
/** field offset */
#define GTC_ALL_TC_CNT_OFFSET 0

/* Fields of "GTC Rejected TCONT Counter" */
/** Rejected TCONTs since last reset. This is a wrap around counter. */
#define GTC_REJ_TC_CNT_MASK 0x0000FFFF
/** field offset */
#define GTC_REJ_TC_CNT_OFFSET 0

/*! @} */ /* GTC_REGISTER */

#endif /* _drv_onu_reg_gtc_h */
