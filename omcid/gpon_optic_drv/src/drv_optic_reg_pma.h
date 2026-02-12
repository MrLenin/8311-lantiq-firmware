/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifndef _drv_optic_reg_pma_h
#define _drv_optic_reg_pma_h

/** \addtogroup PMA_REGISTER
   @{
*/
/* access macros */
#define pma_r32(reg) reg_r32(&pma->reg)
#define pma_w32(val, reg) reg_w32(val, &pma->reg)
#define pma_w32_mask(clear, set, reg) reg_w32_mask(clear, set, &pma->reg)
#define pma_r32_table(reg, idx) reg_r32_table(pma->reg, idx)
#define pma_w32_table(val, reg, idx) reg_w32_table(val, pma->reg, idx)
#define pma_w32_table_mask(clear, set, reg, idx) reg_w32_table_mask(clear, set, pma->reg, idx)
#define pma_adr_table(reg, idx) adr_table(pma->reg, idx)


/** PMA register structure */
struct optic_reg_pma
{
   /** GPON_RX_SLICE_PDI: receiver slice pma */
   /** Reserved */
   unsigned int gpon_rx_slice_pdi_res_0[32]; /* 0x00000000 */
   /** Control register for data rising edge CDR */
   unsigned int gpon_rx_slice_pdi_cdr1; /* 0x00000080 */
   /** Control register for data falling edge CDR */
   unsigned int gpon_rx_slice_pdi_cdr2; /* 0x00000084 */
   /** Control register for data CDR
       The data CDR is the real sampling clock. It can be set between cdr1 (rising edge) and cdr2(falling edge) with register calctrl */
   unsigned int gpon_rx_slice_pdi_cdr3; /* 0x00000088 */
   /** Control register for the monitor CDR */
   unsigned int gpon_rx_slice_pdi_monitorcdr; /* 0x0000008C */
   /** Control register for data rising edge CDR loopfilter
       loopfilter control */
   unsigned int gpon_rx_slice_pdi_cdr1lf; /* 0x00000090 */
   /** Control register for data falling edge CDR loopfilter
       loopfilter control */
   unsigned int gpon_rx_slice_pdi_cdr2lf; /* 0x00000094 */
   /** Control register for data CDR loopfilter
       loopfilter control */
   unsigned int gpon_rx_slice_pdi_cdr3lf; /* 0x00000098 */
   /** Control register for the monitor loopfilter
       loopfilter control */
   unsigned int gpon_rx_slice_pdi_monitorlf; /* 0x0000009C */
   /** Control register for data sync to data_lo in CDR loopfilter
       loopfilter control */
   unsigned int gpon_rx_slice_pdi_cdr3dsm; /* 0x000000A0 */
   /** Control register for data sync to data_lo in CDR loopfilter
       loopfilter control */
   unsigned int gpon_rx_slice_pdi_cdr3dsmread; /* 0x000000A4 */
   /** data input path for high threshold
       The data path consists of two comparators hi and low, */
   unsigned int gpon_rx_slice_pdi_data_hi; /* 0x000000A8 */
   /** data input path for low threshold
       As for data_hi */
   unsigned int gpon_rx_slice_pdi_data_lo; /* 0x000000AC */
   /** monitor input path
       the monitor input path allows for a completely indepedant phase and threshold sampling of the data. The phase interpolator must clearly be initially calibrated to the other PI, to allow optimal phase aqusitions to be transferred */
   unsigned int gpon_rx_slice_pdi_monitor; /* 0x000000B0 */
   /** monitor and data input path data
       the monitor input path allows for a completely indepedant phase and threshold sampling of the data. */
   unsigned int gpon_rx_slice_pdi_monitorread; /* 0x000000B4 */
   /** edge sampler for falling transition, CDR, Data and PI Control
       The edge sampling is data transition dependant. */
   unsigned int gpon_rx_slice_pdi_edge_fall; /* 0x000000B8 */
   /** edge sampler path rising transition, CDR, Data and PI Control
       as above for edge_fall */
   unsigned int gpon_rx_slice_pdi_edge_rise; /* 0x000000BC */
   /** DFE control
       Not Specified */
   unsigned int gpon_rx_slice_pdi_dfectrl; /* 0x000000C0 */
   /** CALCTRL
       used for calibration with FW. PI values can be read, offset can be written to CDR */
   unsigned int gpon_rx_slice_pdi_calctrl; /* 0x000000C4 */
   /** CALREAD
       used for calibration with FW. PI values can be read from CDR */
   unsigned int gpon_rx_slice_pdi_calread; /* 0x000000C8 */
   /** CALWRITE
       used for calibration with FW. PI values can be read, offset can be written to CDR, */
   unsigned int gpon_rx_slice_pdi_calwrite; /* 0x000000CC */
   /** LOL_ALARMCFG_LO
       lower limit of dsm control word to rise the loss of lock alarm */
   unsigned int gpon_rx_slice_pdi_lol_alarmcfg_lo; /* 0x000000D0 */
   /** LOL_ALARMCFG_HI
       upper limit of dsm control word to rise the loss of lock alarm */
   unsigned int gpon_rx_slice_pdi_lol_alarmcfg_hi; /* 0x000000D4 */
   /** MONITOR_COUNT_CFG
       enable and configuration of monitor to data difference counters */
   unsigned int gpon_rx_slice_pdi_monitor_count_cfg; /* 0x000000D8 */
   /** MONITOR_DIFF_COUNT
       monitor to data difference counts */
   unsigned int gpon_rx_slice_pdi_monitor_diff_count; /* 0x000000DC */
   /** MONITOR_ERR_COUNT0
       read out of monitor to data error counter for 00 and 01 transitions */
   unsigned int gpon_rx_slice_pdi_monitor_err_count0; /* 0x000000E0 */
   /** MONITOR_ERR_COUNT1
       read out of monitor to data error counters for 10 and 11 transitions */
   unsigned int gpon_rx_slice_pdi_monitor_err_count1; /* 0x000000E4 */
   /** AFECTRL
       used for control of AFE */
   unsigned int gpon_rx_slice_pdi_afectrl; /* 0x000000E8 */
   /** Reserved */
   unsigned int gpon_rx_slice_pdi_res_1[5]; /* 0x000000EC */
   /** GPON_MM_SLICE_PDI: measurement slice pma */
   /** ADC conf0
       Not Specified */
   unsigned int gpon_mm_slice_pdi_adc; /* 0x00000100 */
   /** Set up clocking for ADC clock
       Not Specified */
   unsigned int gpon_mm_slice_pdi_mmadc_clk; /* 0x00000104 */
   /** M_TIME_CONFIG
       Not Specified */
   unsigned int gpon_mm_slice_pdi_m_time_config; /* 0x00000108 */
   /** M_RESULT_0
       Not Specified */
   unsigned int gpon_mm_slice_pdi_m_result[10]; /* 0x0000010C */
   /** M_SET_0
       Not Specified */
   unsigned int gpon_mm_slice_pdi_m_set[10]; /* 0x00000134 */
   /** ALARM_CFG
       Not Specified */
   unsigned int gpon_mm_slice_pdi_alarm_cfg; /* 0x0000015C */
   /** MM_CFG
       Not Specified */
   unsigned int gpon_mm_slice_pdi_mm_cfg; /* 0x00000160 */
   /** Reserved */
   unsigned int gpon_mm_slice_pdi_res_4[7]; /* 0x00000164 */
   /** GPON_BFD_SLICE_PDI: monitor diode slice control */
   /** laser safety threshold control
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_threshold_ctrl; /* 0x00000180 */
   /** laser safety threshold control
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_threshold_sumctrl; /* 0x00000184 */
   /** persistency counter for threshold alarms
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_threshold_sum_persistency; /* 0x00000188 */
   /** saturationj limits for bias and modulation dac
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_saturation; /* 0x0000018C */
   /** initialisation values before burst starts
       Intelligent burst dual loop control is achieved by the FW reading */
   unsigned int gpon_bfd_slice_pdi_dual_loop_mod_init; /* 0x00000190 */
   /** initialisation values before burst starts
       Intelligent burst dual loop control is achieved by the FW reading */
   unsigned int gpon_bfd_slice_pdi_dual_loop_bias_init; /* 0x00000194 */
   /** status of modulation DAC control
       used to read back the DAC value for the modulation DAC */
   unsigned int gpon_bfd_slice_pdi_dual_loop_mod_status; /* 0x00000198 */
   /** status of bias DAC control
       used to read back the DAC value for the bias DAC */
   unsigned int gpon_bfd_slice_pdi_dual_loop_bias_status; /* 0x0000019C */
   /** regulation control parameters
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_loop_regulation_bias; /* 0x000001A0 */
   /** regulation control parameters
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_loop_regulation_modulation; /* 0x000001A4 */
   /** TIA DAC calibration control
       The BFD path includes 3 gain stages: */
   unsigned int gpon_bfd_slice_pdi_tiaoffset; /* 0x000001A8 */
   /** TIA P0 level DAC calibration control
       The P0 light is sensed via the BFD and the current is amplified in the TIA. The resulting signal */
   unsigned int gpon_bfd_slice_pdi_p0level; /* 0x000001AC */
   /** TIA P1 level DAC calibration control
       The P1 light is sensed via the BFD and the current is amplified in the TIA. The resulting signal */
   unsigned int gpon_bfd_slice_pdi_p1level; /* 0x000001B0 */
   /** result of P0 and P1 comparator
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_comparator_status; /* 0x000001B4 */
   /** dual loop recognition for P0
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_p0_dual_loop; /* 0x000001B8 */
   /** P0 data path
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_p0_datapath; /* 0x000001BC */
   /** dual loop recognition for P1
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_p1_dual_loop; /* 0x000001C0 */
   /** compare pattern for BFD level
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_comparepattern; /* 0x000001C4 */
   /** P1 data path
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_p1_datapath; /* 0x000001C8 */
   /** power save for P1 correlator / BFD
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_p1_bfd_powersave; /* 0x000001CC */
   /** power save for P0 correlator / BFD
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_p0_bfd_powersave; /* 0x000001D0 */
   /** powersave control for bias and modulation current DAC
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_powersave; /* 0x000001D4 */
   /** trace p0 comparator
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_p0_trace; /* 0x000001D8 */
   /** trace p1 comparator
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_p1_trace; /* 0x000001DC */
   /** delay data to bfd capture
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_data_delay; /* 0x000001E0 */
   /** DAC slice control
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_dac_ctrl; /* 0x000001E4 */
   /** monitor input TIA
       Not Specified */
   unsigned int gpon_bfd_slice_pdi_gain_ctrl; /* 0x000001E8 */
   /** Status for interburst */
   unsigned int gpon_bfd_slice_pdi_comparator_statusib; /* 0x000001EC */
   /** Saturation for BIAS (low current) */
   unsigned int gpon_bfd_slice_pdi_biaslowsat_ctrl; /* 0x000001F0 */
   /** Threshold for low BIAS Interrupt (low current) */
   unsigned int gpon_bfd_slice_pdi_biaslowthreshold_ctrl; /* 0x000001F4 */
   /** Reserved */
   unsigned int gpon_bfd_slice_pdi_res_2[2]; /* 0x000001F8 */
   /** GPON_TX_SLICE_PDI: transmitter slice control */
   /** data path control
       Not Specified */
   unsigned int gpon_tx_slice_pdi_datapath; /* 0x00000200 */
   /** bias path control
       Not Specified */
   unsigned int gpon_tx_slice_pdi_biaspath; /* 0x00000204 */
   /** delay data to PMD
       Not Specified */
   unsigned int gpon_tx_slice_pdi_data_delay; /* 0x00000208 */
   /** laser enable control
       Not Specified */
   unsigned int gpon_tx_slice_pdi_laser_enable; /* 0x0000020C */
   /** bit exact delay to laser
       Not Specified */
   unsigned int gpon_tx_slice_pdi_laser_bitdelay; /* 0x00000210 */
   /** phase interpolator control
       The transmit phase of the data, and the clock phase of the distortion of the complement output can be directly controlled. */
   unsigned int gpon_tx_slice_pdi_pi_ctrl; /* 0x00000214 */
   /** phase modulator
       In order to allow productive testing and in system margin testing the phase of the transmit data can be modulated */
   unsigned int gpon_tx_slice_pdi_modulator_1; /* 0x00000218 */
   /** MODULATOR_2
       Not Specified */
   unsigned int gpon_tx_slice_pdi_modulator_2; /* 0x0000021C */
   /** Reserved */
   unsigned int gpon_tx_slice_pdi_res_6[24]; /* 0x00000220 */
   /** GPON_PLL_SLICE_PDI: PLL Slice Registers */
   /** reset and power down control for PMD
       Not Specified */
   unsigned int gpon_pll_slice_pdi_pmd_resetcontrol; /* 0x00000280 */
   /** Control 1 Register
       This Register is for controlling the PMA portion of PLL SLICE behavior. */
   unsigned int gpon_pll_slice_pdi_ctrl1; /* 0x00000284 */
   /** Control 2 Register
       This Register is for controlling the PMA portion of PLL SLICE behavior. */
   unsigned int gpon_pll_slice_pdi_ctrl2; /* 0x00000288 */
   /** Control 3 Register
       This Register is for controlling the PMA portion of PLL SLICE behavior. */
   unsigned int gpon_pll_slice_pdi_ctrl3; /* 0x0000028C */
   /** Control 4 Register
       This Register is for controlling the PMA portion of PLL SLICE behavior. */
   unsigned int gpon_pll_slice_pdi_ctrl4; /* 0x00000290 */
   /** Control 5 Register
       This Register is for controlling the PMA portion of PLL SLICE behavior. */
   unsigned int gpon_pll_slice_pdi_ctrl5; /* 0x00000294 */
   /** Control 6 Register
       This Register is for controlling the PMA portion of PLL SLICE behavior. */
   unsigned int gpon_pll_slice_pdi_ctrl6; /* 0x00000298 */
   /** Control 7 Register
       This Register is for controlling the PMA portion of PLL SLICE behavior. */
   unsigned int gpon_pll_slice_pdi_ctrl7; /* 0x0000029C */
   /** Analog Control 1 Register
       This Register is for controlling of analog PLL SLICE behavior. */
   unsigned int gpon_pll_slice_pdi_a_ctrl1; /* 0x000002A0 */
   /** Analog Control 2 Register
       This Register is for controlling of analog PLL SLICE behavior. */
   unsigned int gpon_pll_slice_pdi_a_ctrl2; /* 0x000002A4 */
   /** Analog Control 3 Register
       This Register is for controlling of analog PLL SLICE behavior. */
   unsigned int gpon_pll_slice_pdi_a_ctrl3; /* 0x000002A8 */
   /** PLL Status Register
       This Register is for reading PLL status. */
   unsigned int gpon_pll_slice_pdi_status; /* 0x000002AC */
   /** PMA top level control
       This Register contains bits for controlling blocks in the PMA, which need to be configured during startup, */
   unsigned int gpon_pll_slice_pdi_pma_top_ctrl; /* 0x000002B0 */
   /** Reserved */
   unsigned int gpon_pll_slice_pdi_res_7[19]; /* 0x000002B4 */
   /** GPON_PMA_BERT_PDI: pma bert control */
   /** BERT control
       The BERT can be used to generate standard data and pipe this into the normal data path. Various patterns can be selected */
   unsigned int gpon_bert_pdi_bert_control; /* 0x00000300 */
   /** BERT fixed pattern */
   unsigned int gpon_bert_pdi_bert_pattern; /* 0x00000304 */
   /** BERT clock pattern */
   unsigned int gpon_bert_pdi_bert_clk; /* 0x00000308 */
   /** BERT pattern endcounter value */
   unsigned int gpon_bert_pdi_bert_cnt; /* 0x0000030C */
   /** BERT status control
       Freeze the BERT word counter and failure counter, reset counters */
   unsigned int gpon_bert_pdi_bert_statusctrl; /* 0x00000310 */
   /** BERT received word count status
       When active the BERT counts the number of receiver 8 bit words */
   unsigned int gpon_bert_pdi_bert_wrdcnt; /* 0x00000314 */
   /** BERT detected error status
       When active the BERT counts the number of errors (error in 8bit granularity) */
   unsigned int gpon_bert_pdi_bert_errcnt; /* 0x00000318 */
   /** Reserved */
   unsigned int gpon_bert_pdi_res_8[57]; /* 0x0000031C */
};


/* Fields of "Control register for data rising edge CDR" */
/** shift data/edge relationship
    0... used with order in time: d<0>, e<0>, d<1>, e<1>,...(edge lags data with the same index) */
#define PMA_CDR1_XOR_INV 0x00000080
/** invert the sum/integration
    0... early increases output, late decreases output */
#define PMA_CDR1_SUM_INV 0x00000040
/** select saturation level */
#define PMA_CDR1_SEL_SATLEV_MASK 0x00000038
/** field offset */
#define PMA_CDR1_SEL_SATLEV_OFFSET 3
/** bpd mode
    Only active if calibration via SW is choosen (bit hwcal) */
#define PMA_CDR1_SEL_BPD_MODE_MASK 0x00000006
/** field offset */
#define PMA_CDR1_SEL_BPD_MODE_OFFSET 1
/** binary phase detector enable */
#define PMA_CDR1_BPD_EN 0x00000001

/* Fields of "Control register for data falling edge CDR" */
/** shift data/edge relationship
    0... used with order in time: d<0>, e<0>, d<1>, e<1>,...(edge lags data with the same index) */
#define PMA_CDR2_XOR_INV 0x00000080
/** invert the sum/integration
    0... early increases output, late decreases output */
#define PMA_CDR2_SUM_INV 0x00000040
/** select saturation level */
#define PMA_CDR2_SEL_SATLEV_MASK 0x00000038
/** field offset */
#define PMA_CDR2_SEL_SATLEV_OFFSET 3
/** bpd mode
    01 .. rising edge, */
#define PMA_CDR2_SEL_BPD_MODE_MASK 0x00000006
/** field offset */
#define PMA_CDR2_SEL_BPD_MODE_OFFSET 1
/** binary phase detector enable */
#define PMA_CDR2_BPD_EN 0x00000001

/* Fields of "Control register for data CDR" */
/** shift data/edge relationship
    0... used with order in time: d<0>, e<0>, d<1>, e<1>,...(edge lags data with the same index) */
#define PMA_CDR3_XOR_INV 0x00000080
/** invert the sum/integration
    0... early increases output, late decreases output */
#define PMA_CDR3_SUM_INV 0x00000040
/** select saturation level */
#define PMA_CDR3_SEL_SATLEV_MASK 0x00000038
/** field offset */
#define PMA_CDR3_SEL_SATLEV_OFFSET 3
/** bpd mode
    01 .. rising edge, */
#define PMA_CDR3_SEL_BPD_MODE_MASK 0x00000006
/** field offset */
#define PMA_CDR3_SEL_BPD_MODE_OFFSET 1
/** binary phase detector enable */
#define PMA_CDR3_BPD_EN 0x00000001

/* Fields of "Control register for the monitor CDR" */
/** shift data/edge relationship
    0... used with order in time: d<0>, e<0>, d<1>, e<1>,...(edge lags data with the same index) */
#define PMA_MONITORCDR_XOR_INV 0x00000080
/** invert the sum/integration
    0... early increases output, late decreases output */
#define PMA_MONITORCDR_SUM_INV 0x00000040
/** select saturation level */
#define PMA_MONITORCDR_SEL_SATLEV_MASK 0x00000038
/** field offset */
#define PMA_MONITORCDR_SEL_SATLEV_OFFSET 3
/** bpd mode
    01 .. rising edge, 10 .. falling edge */
#define PMA_MONITORCDR_SEL_BPD_MODE_MASK 0x00000006
/** field offset */
#define PMA_MONITORCDR_SEL_BPD_MODE_OFFSET 1
/** binary phase detector enable */
#define PMA_MONITORCDR_BPD_EN 0x00000001

/* Fields of "Control register for data rising edge CDR loopfilter" */
/** select the constant for the PI path */
#define PMA_CDR1LF_K_PI_MASK 0x001C0000
/** field offset */
#define PMA_CDR1LF_K_PI_OFFSET 18
/** set level of integrate and dump */
#define PMA_CDR1LF_SEL_ID_LEV_MASK 0x00038000
/** field offset */
#define PMA_CDR1LF_SEL_ID_LEV_OFFSET 15
/** offset value for the PI control */
#define PMA_CDR1LF_PI_OFFS_MASK 0x00007E00
/** field offset */
#define PMA_CDR1LF_PI_OFFS_OFFSET 9
/** load zero into main integrator */
#define PMA_CDR1LF_MI_ZERO 0x00000100
/** load internal states with mux_state_i, cur_state_i */
#define PMA_CDR1LF_PI_LOAD_EXT 0x00000080
/** enable integrate and dump */
#define PMA_CDR1LF_EID_EN 0x00000040
/** input for loading of internal state */
#define PMA_CDR1LF_EXT_PI_CTRL_MASK 0x0000003F
/** field offset */
#define PMA_CDR1LF_EXT_PI_CTRL_OFFSET 0

/* Fields of "Control register for data falling edge CDR loopfilter" */
/** select the constant for the PI path */
#define PMA_CDR2LF_K_PI_MASK 0x001C0000
/** field offset */
#define PMA_CDR2LF_K_PI_OFFSET 18
/** set level of integrate and dump */
#define PMA_CDR2LF_SEL_ID_LEV_MASK 0x00038000
/** field offset */
#define PMA_CDR2LF_SEL_ID_LEV_OFFSET 15
/** offset value for the PI control */
#define PMA_CDR2LF_PI_OFFS_MASK 0x00007E00
/** field offset */
#define PMA_CDR2LF_PI_OFFS_OFFSET 9
/** load zero into main integrator */
#define PMA_CDR2LF_MI_ZERO 0x00000100
/** load internal states with mux_state_i, cur_state_i */
#define PMA_CDR2LF_PI_LOAD_EXT 0x00000080
/** enable integrate and dump */
#define PMA_CDR2LF_EID_EN 0x00000040
/** input for loading of internal state */
#define PMA_CDR2LF_EXT_PI_CTRL_MASK 0x0000003F
/** field offset */
#define PMA_CDR2LF_EXT_PI_CTRL_OFFSET 0

/* Fields of "Control register for data CDR loopfilter" */
/** select the constant for the PI path */
#define PMA_CDR3LF_K_PI_MASK 0x001C0000
/** field offset */
#define PMA_CDR3LF_K_PI_OFFSET 18
/** set level of integrate and dump */
#define PMA_CDR3LF_SEL_ID_LEV_MASK 0x00038000
/** field offset */
#define PMA_CDR3LF_SEL_ID_LEV_OFFSET 15
/** offset value for the PI control */
#define PMA_CDR3LF_PI_OFFS_MASK 0x00007E00
/** field offset */
#define PMA_CDR3LF_PI_OFFS_OFFSET 9
/** load zero into main integrator */
#define PMA_CDR3LF_MI_ZERO 0x00000100
/** load internal states with mux_state_i, cur_state_i */
#define PMA_CDR3LF_PI_LOAD_EXT 0x00000080
/** enable integrate and dump */
#define PMA_CDR3LF_EID_EN 0x00000040
/** input for loading of internal state */
#define PMA_CDR3LF_EXT_PI_CTRL_MASK 0x0000003F
/** field offset */
#define PMA_CDR3LF_EXT_PI_CTRL_OFFSET 0

/* Fields of "Control register for the monitor loopfilter" */
/** select the constant for the PI path */
#define PMA_MONITORLF_K_PI_MASK 0x001C0000
/** field offset */
#define PMA_MONITORLF_K_PI_OFFSET 18
/** set level of integrate and dump */
#define PMA_MONITORLF_SEL_ID_LEV_MASK 0x00038000
/** field offset */
#define PMA_MONITORLF_SEL_ID_LEV_OFFSET 15
/** offset value for the PI control */
#define PMA_MONITORLF_PI_OFFS_MASK 0x00007E00
/** field offset */
#define PMA_MONITORLF_PI_OFFS_OFFSET 9
/** load zero into main integrator */
#define PMA_MONITORLF_MI_ZERO 0x00000100
/** load internal states with mux_state_i, cur_state_i */
#define PMA_MONITORLF_PI_LOAD_EXT 0x00000080
/** enable integrate and dump */
#define PMA_MONITORLF_EID_EN 0x00000040
/** input for loading of internal state */
#define PMA_MONITORLF_EXT_PI_CTRL_MASK 0x0000003F
/** field offset */
#define PMA_MONITORLF_EXT_PI_CTRL_OFFSET 0

/* Fields of "Control register for data sync to data_lo in CDR loopfilter" */
/** select the constant for the DSM path */
#define PMA_CDR3DSM_K_DSM_MASK 0x0E000000
/** field offset */
#define PMA_CDR3DSM_K_DSM_OFFSET 25
/** offset value for the DSM control
    Used as start value for DSM */
#define PMA_CDR3DSM_DSM_CTRL_OFFS_MASK 0x01FFFFFE
/** field offset */
#define PMA_CDR3DSM_DSM_CTRL_OFFS_OFFSET 1
/** enable the DSM control
    This enables the PLL synchronisation with CDR3 controlled clock */
#define PMA_CDR3DSM_DSM_CTRL_EN 0x00000001

/* Fields of "Control register for data sync to data_lo in CDR loopfilter" */
/** offset value for the DSM control
    Read current value for DSM */
#define PMA_CDR3DSMREAD_DSM_CTRL_MASK 0x00FFFFFF
/** field offset */
#define PMA_CDR3DSMREAD_DSM_CTRL_OFFSET 0

/* Fields of "data input path for high threshold" */
/** DFE decision threshold
    Bit 16: 0 .. negative sign, */
#define PMA_DATA_HI_DAC_HI_MASK 0x0FFFF800
/** field offset */
#define PMA_DATA_HI_DAC_HI_OFFSET 11
/** force the programmed data path */
#define PMA_DATA_HI_DATA_HI_PRG_EN 0x00000400
/** program the data path */
#define PMA_DATA_HI_DATA_HI_PRG_DATA_MASK 0x000003FC
/** field offset */
#define PMA_DATA_HI_DATA_HI_PRG_DATA_OFFSET 2
/** inverse the data */
#define PMA_DATA_HI_DATA_HI_INVERSE 0x00000002
/** flip LSB and MSB */
#define PMA_DATA_HI_DATA_HI_FLIP 0x00000001

/* Fields of "data input path for low threshold" */
/** DFE decision threshold
    Bit 16: 0 .. negative sign, */
#define PMA_DATA_LO_DAC_LO_MASK 0x0FFFF800
/** field offset */
#define PMA_DATA_LO_DAC_LO_OFFSET 11
/** force the programmed data path */
#define PMA_DATA_LO_DATA_LO_PRG_EN 0x00000400
/** program the data path */
#define PMA_DATA_LO_DATA_LO_PRG_DATA_MASK 0x000003FC
/** field offset */
#define PMA_DATA_LO_DATA_LO_PRG_DATA_OFFSET 2
/** inverse the data */
#define PMA_DATA_LO_DATA_LO_INVERSE 0x00000002
/** flip LSB and MSB */
#define PMA_DATA_LO_DATA_LO_FLIP 0x00000001

/* Fields of "monitor input path" */
/** DFE decision threshold
    Bit 16: 0 .. negative sign, */
#define PMA_MONITOR_DAC_MONITOR_MASK 0x0FFFF800
/** field offset */
#define PMA_MONITOR_DAC_MONITOR_OFFSET 11
/** force the programmed data path */
#define PMA_MONITOR_MONITOR_PRG_EN 0x00000400
/** program the data path */
#define PMA_MONITOR_MONITOR_PRG_DATA_MASK 0x000003FC
/** field offset */
#define PMA_MONITOR_MONITOR_PRG_DATA_OFFSET 2
/** inverse the data */
#define PMA_MONITOR_MONITOR_INVERSE 0x00000002
/** flip LSB and MSB */
#define PMA_MONITOR_MONITOR_FLIP 0x00000001

/* Fields of "monitor and data input path data" */
/** received data word
    this word is used by the DFE adaption algorithm */
#define PMA_MONITORREAD_DATA_RX_MASK 0xFFFF0000
/** field offset */
#define PMA_MONITORREAD_DATA_RX_OFFSET 16
/** received monitor word
    this word is used by the DFE adaption algorithm */
#define PMA_MONITORREAD_MONITOR_RX_MASK 0x0000FFFF
/** field offset */
#define PMA_MONITORREAD_MONITOR_RX_OFFSET 0

/* Fields of "edge sampler for falling transition, CDR, Data and PI Control" */
/** force the programmed data path */
#define PMA_EDGE_FALL_EDGE_FALL_PRG_EN 0x00000400
/** program the data path */
#define PMA_EDGE_FALL_EDGE_FALL_PRG_DATA_MASK 0x000003FC
/** field offset */
#define PMA_EDGE_FALL_EDGE_FALL_PRG_DATA_OFFSET 2
/** inverse the data */
#define PMA_EDGE_FALL_EDGE_FALL_INVERSE 0x00000002
/** flip LSB and MSB */
#define PMA_EDGE_FALL_EDGE_FALL_FLIP 0x00000001

/* Fields of "edge sampler path rising transition, CDR, Data and PI Control" */
/** force the programmed data path */
#define PMA_EDGE_RISE_EDGE_RISE_PRG_EN 0x00000400
/** program the data path */
#define PMA_EDGE_RISE_EDGE_RISE_PRG_DATA_MASK 0x000003FC
/** field offset */
#define PMA_EDGE_RISE_EDGE_RISE_PRG_DATA_OFFSET 2
/** inverse the data */
#define PMA_EDGE_RISE_EDGE_RISE_INVERSE 0x00000002
/** flip LSB and MSB */
#define PMA_EDGE_RISE_EDGE_RISE_FLIP 0x00000001

/* Fields of "DFE control" */
/** select the bit for xtalk compensation
    0 ..... 0 bit (no) delay */
#define PMA_DFECTRL_XTALK_DATA_DEL_MASK 0x0007C000
/** field offset */
#define PMA_DFECTRL_XTALK_DATA_DEL_OFFSET 14
/** force the programmed data path */
#define PMA_DFECTRL_XTALK_PRG_EN 0x00002000
/** program the data path */
#define PMA_DFECTRL_XTALK_PRG_DATA_MASK 0x00001FE0
/** field offset */
#define PMA_DFECTRL_XTALK_PRG_DATA_OFFSET 5
/** inverse the data */
#define PMA_DFECTRL_XTALK_INVERSE 0x00000010
/** flip LSB and MSB */
#define PMA_DFECTRL_XTALK_FLIP 0x00000008
/** Force the DFE automatic data selection
    The decision feedback selects either automatic or from data hi or data lo */
#define PMA_DFECTRL_DFE_DATA_SEL_MASK 0x00000007
/** field offset */
#define PMA_DFECTRL_DFE_DATA_SEL_OFFSET 0

/* Fields of "CALCTRL" */
/** cdr3 deadzone calculation
    0 ... disable CDR3 deadzone calculation, */
#define PMA_CALCTRL_PI_CDR3_CALC 0x00000001

/* Fields of "CALREAD" */
/** pi value monitor */
#define PMA_CALREAD_MONITOR_PI_CTRL_MASK 0x00FC0000
/** field offset */
#define PMA_CALREAD_MONITOR_PI_CTRL_OFFSET 18
/** pi value CDR3 */
#define PMA_CALREAD_CDR3_PI_CTRL_MASK 0x0003F000
/** field offset */
#define PMA_CALREAD_CDR3_PI_CTRL_OFFSET 12
/** pi value CDR2 */
#define PMA_CALREAD_CDR2_PI_CTRL_MASK 0x00000FC0
/** field offset */
#define PMA_CALREAD_CDR2_PI_CTRL_OFFSET 6
/** pi value CDR1 */
#define PMA_CALREAD_CDR1_PI_CTRL_MASK 0x0000003F
/** field offset */
#define PMA_CALREAD_CDR1_PI_CTRL_OFFSET 0

/* Fields of "CALWRITE" */
/** CDR3 offset value */
#define PMA_CALWRITE_OFFS_CDR3_MASK 0x0003F000
/** field offset */
#define PMA_CALWRITE_OFFS_CDR3_OFFSET 12
/** CDR2 offset value */
#define PMA_CALWRITE_OFFS_CDR2_MASK 0x00000FC0
/** field offset */
#define PMA_CALWRITE_OFFS_CDR2_OFFSET 6
/** CDR1 offset value */
#define PMA_CALWRITE_OFFS_CDR1_MASK 0x0000003F
/** field offset */
#define PMA_CALWRITE_OFFS_CDR1_OFFSET 0

/* Fields of "LOL_ALARMCFG_LO" */
/** loss of lock limit
    this value is compared against the signal dsm_ctrl of CDR1. */
#define PMA_LOL_ALARMCFG_LO_LOL_LIMIT_MASK 0x00FFFFFF
/** field offset */
#define PMA_LOL_ALARMCFG_LO_LOL_LIMIT_OFFSET 0

/* Fields of "LOL_ALARMCFG_HI" */
/** loss of lock limit
    this value is compared against the signal dsm_ctrl of CDR1. */
#define PMA_LOL_ALARMCFG_HI_LOL_LIMIT_MASK 0x00FFFFFF
/** field offset */
#define PMA_LOL_ALARMCFG_HI_LOL_LIMIT_OFFSET 0

/* Fields of "MONITOR_COUNT_CFG" */
/** shift and align data with monitor
    0000 no shift */
#define PMA_MONITOR_COUNT_CFG_DIFF_SHIFT_MASK 0x0000003C
/** field offset */
#define PMA_MONITOR_COUNT_CFG_DIFF_SHIFT_OFFSET 2
/** left to right swap for dfe */
#define PMA_MONITOR_COUNT_CFG_DIFF_SWAP 0x00000002
/** enable the diff count
    with a 0 -> 1 transition of this bit the differences between the monitor path and the data path are counted */
#define PMA_MONITOR_COUNT_CFG_DIFF_EN 0x00000001

/* Fields of "MONITOR_DIFF_COUNT" */
/** counts how many bytes are compared */
#define PMA_MONITOR_DIFF_COUNT_DIFF_CNT_MASK 0xFFFFFFFF
/** field offset */
#define PMA_MONITOR_DIFF_COUNT_DIFF_CNT_OFFSET 0

/* Fields of "MONITOR_ERR_COUNT0" */
/** counts the byte differences */
#define PMA_MONITOR_ERR_COUNT0_ERR_CNT0_MASK 0xFFFFFFFF
/** field offset */
#define PMA_MONITOR_ERR_COUNT0_ERR_CNT0_OFFSET 0

/* Fields of "MONITOR_ERR_COUNT1" */
/** counts the byte differences */
#define PMA_MONITOR_ERR_COUNT1_ERR_CNT1_MASK 0xFFFFFFFF
/** field offset */
#define PMA_MONITOR_ERR_COUNT1_ERR_CNT1_OFFSET 0

/* Fields of "AFECTRL" */
/** pma rx ready
    This bit enables the PMA to send out data to the GTC. */
#define PMA_AFECTRL_PMA_RX_DATA_EN 0x00020000
/** enable the testbus input path */
#define PMA_AFECTRL_RX_TESTBUS_EN 0x00010000
/** AFE termination resistor select */
#define PMA_AFECTRL_RTERM_SEL_MASK 0x0000F800
/** field offset */
#define PMA_AFECTRL_RTERM_SEL_OFFSET 11
/** AFE change tailcurrent */
#define PMA_AFECTRL_DOUBLE_TAILCUR 0x00000400
/** AFE emphasis */
#define PMA_AFECTRL_EMP_MASK 0x00000300
/** field offset */
#define PMA_AFECTRL_EMP_OFFSET 8
/** AFE common mode select */
#define PMA_AFECTRL_OUTPUT_CM_SEL_MASK 0x000000E0
/** field offset */
#define PMA_AFECTRL_OUTPUT_CM_SEL_OFFSET 5
/** AFE offset control
    offset control of receiver AFE */
#define PMA_AFECTRL_OFFSET_MASK 0x0000001E
/** field offset */
#define PMA_AFECTRL_OFFSET_OFFSET 1
/** input calibration
    enable the calibration input path of the AFE */
#define PMA_AFECTRL_CALIBRATION_ON 0x00000001

/* Fields of "ADC conf0" */
/** reference buffer current
    ??? */
#define PMA_ADC_SET_REFBUF_CURR_MASK 0x03800000
/** field offset */
#define PMA_ADC_SET_REFBUF_CURR_OFFSET 23
/** number of cycles per conversion minus one
    number of cycles per conversion minus one 0:1:11 */
#define PMA_ADC_SET_START_MASK 0x00780000
/** field offset */
#define PMA_ADC_SET_START_OFFSET 19
/** highest rom address while iterating
    highest rom address while iterating 0:1:11 */
#define PMA_ADC_SET_ROM_START_MASK 0x00078000
/** field offset */
#define PMA_ADC_SET_ROM_START_OFFSET 15
/** set scrambling state
    set scrambling state 0:1:3 */
#define PMA_ADC_SET_SCR_STATE_MASK 0x00006000
/** field offset */
#define PMA_ADC_SET_SCR_STATE_OFFSET 13
/** set comparator bias current
    set comparator bias current to 12.5uA x 2:1:6 */
#define PMA_ADC_SET_COMP_CURR_MASK 0x00001C00
/** field offset */
#define PMA_ADC_SET_COMP_CURR_OFFSET 10
/** enable comparator offset calibration
    1: enable comparator offset calibration */
#define PMA_ADC_SET_OFFSET_CAL_EN 0x00000200
/** set reset arithunit
    0: start from last sample */
#define PMA_ADC_SET_RESETARITH 0x00000100
/** choose rom bank */
#define PMA_ADC_SET_ROM_SEL_MASK 0x000000C0
/** field offset */
#define PMA_ADC_SET_ROM_SEL_OFFSET 6
/** set comparator-to-array clock delay
    set comparator-to-array clock delay 0:1:7 */
#define PMA_ADC_SET_COMP2ARRAY_MASK 0x00000038
/** field offset */
#define PMA_ADC_SET_COMP2ARRAY_OFFSET 3
/** set comparator-to-arith clock delay
    set comparator-to-arith clock delay 0:1:3 */
#define PMA_ADC_SET_COMP2ARITH_MASK 0x00000007
/** field offset */
#define PMA_ADC_SET_COMP2ARITH_OFFSET 0

/* Fields of "Set up clocking for ADC clock" */
/** invert the data ready signal
    The sample clock of the ADC is also the data ready signal for the mm state machine. This signal can be inverted */
#define PMA_MMADC_CLK_DATA_READY_INV 0x00000002
/** clock divider reset
    The ADC of the MM path is clocked with 2.5GHz/8=311MHz. This is the iteration clock for the SAR ADC. */
#define PMA_MMADC_CLK_DIV_RESET 0x00000001

/* Fields of "M_TIME_CONFIG" */
/** name
    time for one measurement in 31MHz cycles. At the end of this time, */
#define PMA_M_TIME_CONFIG_MEAS_TIME_MASK 0x0000FFFF
/** field offset */
#define PMA_M_TIME_CONFIG_MEAS_TIME_OFFSET 0

/* Fields of "M_RESULT_0" */
/** name
    Result for Measurement */
#define PMA_M_RESULT_M_RESULT0_R_MASK 0x0000FFFF
/** field offset */
#define PMA_M_RESULT_M_RESULT0_R_OFFSET 0

/* Fields of "M_SET_0" */
/** name
    lock to current measurement, mm mux will not proceed */
#define PMA_M_SET_LOCK 0x00200000
/** name
    select input from internal temp sensor. */
#define PMA_M_SET_TS_MASK 0x00180000
/** field offset */
#define PMA_M_SET_TS_OFFSET 19
/** name
    defines SC buffer gain: */
#define PMA_M_SET_GAIN_MASK 0x00070000
/** field offset */
#define PMA_M_SET_GAIN_OFFSET 16
/** name
    input vref to n: */
#define PMA_M_SET_VREF_VAL_MASK 0x0000C000
/** field offset */
#define PMA_M_SET_VREF_VAL_OFFSET 14
/** name
    shorts p and n at SC buffer input */
#define PMA_M_SET_PN_SHORT 0x00002000
/** name
    connect to p GP_ADC_APD */
#define PMA_M_SET_DCDCAPD 0x00001000
/** name
    connect to n GP_ADC_ROP1490, include voltage divider */
#define PMA_M_SET_ROP1490N 0x00000800
/** name
    connect to p GP_ADC_ROP1490 */
#define PMA_M_SET_ROP1490P 0x00000400
/** name
    connect diode to GP_ADC_TS_TR input */
#define PMA_M_SET_TSTRN1 0x00000200
/** name
    connect to n GP_ADC_TS_TR */
#define PMA_M_SET_TSTRN 0x00000100
/** name
    connect to p GP_ADC_TS_TR */
#define PMA_M_SET_TSTRP 0x00000080
/** name
    connect GP_ADC_RF1550 */
#define PMA_M_SET_RF1550 0x00000040
/** name
    connect GP_ADC_ROP1550 */
#define PMA_M_SET_ROP1550 0x00000020
/** name
    connect GP_ADC_TS_PN */
#define PMA_M_SET_TSPN 0x00000010
/** name
    select reference current: */
#define PMA_M_SET_IREFVAL 0x00000008
/** name
    connect reference current */
#define PMA_M_SET_IREF 0x00000004
/** name
    connect 1V reference */
#define PMA_M_SET_VREF 0x00000002
/** name
    connect internal bandbgap voltage for trimming (unbuffered) */
#define PMA_M_SET_VREFR 0x00000001

/* Fields of "ALARM_CFG" */
/** name
    compare against m_result9, will cause overload interrupt (RSSI too high) */
#define PMA_ALARM_CFG_OVERLOAD_CFG_MASK 0xFFFF0000
/** field offset */
#define PMA_ALARM_CFG_OVERLOAD_CFG_OFFSET 16
/** name
    compare against m_result9, will cause los interrupt(Loss Of Signal) */
#define PMA_ALARM_CFG_LOS_CFG_MASK 0x0000FFFF
/** field offset */
#define PMA_ALARM_CFG_LOS_CFG_OFFSET 0

/* Fields of "MM_CFG" */
/** name
    configure comb filter decimation rate: */
#define PMA_MM_CFG_MM_DECCFG_MASK 0x00000700
/** field offset */
#define PMA_MM_CFG_MM_DECCFG_OFFSET 8
/** name
    configure division factor for sample clock of SC buffer: */
#define PMA_MM_CFG_MM_CLKCFG_MASK 0x000000FF
/** field offset */
#define PMA_MM_CFG_MM_CLKCFG_OFFSET 0

/* Fields of "laser safety threshold control" */
/** bias threshold */
#define PMA_THRESHOLD_CTRL_BIAS_THR_MASK 0x007FF000
/** field offset */
#define PMA_THRESHOLD_CTRL_BIAS_THR_OFFSET 12
/** modulation threshold */
#define PMA_THRESHOLD_CTRL_MODULATION_THR_MASK 0x00000FFE
/** field offset */
#define PMA_THRESHOLD_CTRL_MODULATION_THR_OFFSET 1
/** force a threshold failure
    Bias and Modulation DAC for the laser diose are supervised. */
#define PMA_THRESHOLD_CTRL_THRESHOLD_OVR 0x00000001

/* Fields of "laser safety threshold control" */
/** bias+modulation summation threshold
    sum_thr=limit_mod(10:0)*122mA+limit_bias(10:0)*72mA */
#define PMA_THRESHOLD_SUMCTRL_SUM_THR_MASK 0x000FFFFE
/** field offset */
#define PMA_THRESHOLD_SUMCTRL_SUM_THR_OFFSET 1
/** force a threshold failure
    Bias and Modulation DAC for the laser diose are supervised. */
#define PMA_THRESHOLD_SUMCTRL_THRESHOLD_OVR 0x00000001

/* Fields of "persistency counter for threshold alarms" */
/** compare value for 311MHz counter */
#define PMA_THRESHOLD_SUM_PERSISTENCY_CNT_MASK 0x0000FFFF
/** field offset */
#define PMA_THRESHOLD_SUM_PERSISTENCY_CNT_OFFSET 0

/* Fields of "saturationj limits for bias and modulation dac" */
/** saturation for modulation DAC */
#define PMA_SATURATION_MODULATION_SAT_MASK 0x003FF800
/** field offset */
#define PMA_SATURATION_MODULATION_SAT_OFFSET 11
/** saturation for bias DAC */
#define PMA_SATURATION_BIAS_SAT_MASK 0x000007FF
/** field offset */
#define PMA_SATURATION_BIAS_SAT_OFFSET 0

/* Fields of "initialisation values before burst starts" */
/** initial modulation
    set the modulation current DAC (range:30mA*4) */
#define PMA_DUAL_LOOP_MOD_INIT_INIT_MODULATION_MASK 0x000007FF
/** field offset */
#define PMA_DUAL_LOOP_MOD_INIT_INIT_MODULATION_OFFSET 0

/* Fields of "initialisation values before burst starts" */
/** initial bias
    set the bias current DAC (range:18mA*4) */
#define PMA_DUAL_LOOP_BIAS_INIT_INIT_BIAS_MASK 0x000007FF
/** field offset */
#define PMA_DUAL_LOOP_BIAS_INIT_INIT_BIAS_OFFSET 0

/*set the low saturation bias current (range:18mA*4) */
#define PMA_DUAL_LOOP_BIASLOWSAT_CTRL_BIASLOW_SAT_MASK 0x000007FF
/** field offset */
#define PMA_DUAL_LOOP_BIASLOWSAT_CTRL_BIASLOW_SAT_OFFSET 0



/* Fields of "status of modulation DAC control" */
/** actual modulation DAC value
    modulation current DAC value(range:30mA*4). */
#define PMA_DUAL_LOOP_MOD_STATUS_ACTUAL_MODULATION_MASK 0x000007FF
/** field offset */
#define PMA_DUAL_LOOP_MOD_STATUS_ACTUAL_MODULATION_OFFSET 0

/* Fields of "status of bias DAC control" */
/** actual bias DAC value
    bias current DAC value (range:18mA*4) */
#define PMA_DUAL_LOOP_BIAS_STATUS_ACTUAL_BIAS_MASK 0x000007FF
/** field offset */
#define PMA_DUAL_LOOP_BIAS_STATUS_ACTUAL_BIAS_OFFSET 0

/* Fields of "regulation control parameters" */
/** use c_fast coefficient
    0 .. use old step value (1 after reset) as start value for regulation step */
#define PMA_LOOP_REGULATION_BIAS_FASTON 0x80000000
/** allow correction of modulation current, when regulating the bias current
    For the laser diode the bias and modulation DAC currents are added */
#define PMA_LOOP_REGULATION_BIAS_MOD_COMP 0x40000000
/** integration factor
    Used for integration of the calculated current DAC value. This is needed in case of a noisy BFD comparator result. */
#define PMA_LOOP_REGULATION_BIAS_C_INT_MASK 0x38000000
#define PMA_LOOP_REGULATION_BIAS_C_INT_MASK_A21 0x3C000000
/** field offset */
#define PMA_LOOP_REGULATION_BIAS_C_INT_OFFSET 27
#define PMA_LOOP_REGULATION_BIAS_C_INT_OFFSET_A21 26
/** saturation value for stepsize
    The stepsize for changing the DAC digital control word is saturated with this value. This is needed to limit the */
#define PMA_LOOP_REGULATION_BIAS_C_SAT_MASK 0x07FE0000
#define PMA_LOOP_REGULATION_BIAS_C_SAT_MASK_A21 0x03FE0000
/** field offset */
#define PMA_LOOP_REGULATION_BIAS_C_SAT_OFFSET 17
/** limit of successive errors to switch between decreased and increased stepsize
    The number of low or high comparator values are counted. If for a c_alpha the detected value is too low or */
#define PMA_LOOP_REGULATION_BIAS_C_ALPHA_MASK 0x0001F800
/** field offset */
#define PMA_LOOP_REGULATION_BIAS_C_ALPHA_OFFSET 11
/** fast regulation start stepsize
    This value is the start value for the HW regulation. A higher value speeds up the initial regulation, */
#define PMA_LOOP_REGULATION_BIAS_C_FAST_MASK 0x000007FC
/** field offset */
#define PMA_LOOP_REGULATION_BIAS_C_FAST_OFFSET 2
/** type of control
    00 .. dual loop regulation off (used for SW controlled regulation) */
#define PMA_LOOP_REGULATION_BIAS_CONTROL_TYPE_MASK 0x00000003
/** field offset */
#define PMA_LOOP_REGULATION_BIAS_CONTROL_TYPE_OFFSET 0

/* Fields of "regulation control parameters" */
/** use c_fast coefficient
    0 .. use old step value (1 after reset) as start value for regulation step */
#define PMA_LOOP_REGULATION_MODULATION_FASTON 0x80000000
/** reserved */
#define PMA_LOOP_REGULATION_MODULATION_RESERVED 0x40000000
/** integration factor
    Used for integration of the calculated current DAC value. This is needed in case of a noisy BFD comparator result. */
#define PMA_LOOP_REGULATION_MODULATION_C_INT_MASK 0x38000000
#define PMA_LOOP_REGULATION_MODULATION_C_INT_MASK_A21 0x3C000000
/** field offset */
#define PMA_LOOP_REGULATION_MODULATION_C_INT_OFFSET 27
#define PMA_LOOP_REGULATION_MODULATION_C_INT_OFFSET_A21 26
/** saturation value for stepsize
    The stepsize for changing the DAC digital control word is saturated with this value. This is needed to limit the */
#define PMA_LOOP_REGULATION_MODULATION_C_SAT_MASK 0x07FE0000
#define PMA_LOOP_REGULATION_MODULATION_C_SAT_MASK_A21 0x03FE0000
/** field offset */
#define PMA_LOOP_REGULATION_MODULATION_C_SAT_OFFSET 17
/** limit of successive errors to switch between decreased and increased stepsize
    The number of low or high comparator values are counted. If for a c_alpha the detected value is too low or */
#define PMA_LOOP_REGULATION_MODULATION_C_ALPHA_MASK 0x0001F800
/** field offset */
#define PMA_LOOP_REGULATION_MODULATION_C_ALPHA_OFFSET 11
/** fast regulation start stepsize
    This value is the start value for the HW regulation. A higher value speeds up the initial regulation, */
#define PMA_LOOP_REGULATION_MODULATION_C_FAST_MASK 0x000007FC
/** field offset */
#define PMA_LOOP_REGULATION_MODULATION_C_FAST_OFFSET 2
/** type of control
    00 .. dual loop regulation off (used for SW controlled regulation) */
#define PMA_LOOP_REGULATION_MODULATION_CONTROL_TYPE_MASK 0x00000003
/** field offset */
#define PMA_LOOP_REGULATION_MODULATION_CONTROL_TYPE_OFFSET 0

/* Fields of "TIA DAC calibration control" */
/** set fine voltage offset in DAC BFD path. Added after gain stage C.)
    Sets the fine DAC for TIA path offset compensation (range: +/-32mV) */
#define PMA_TIAOFFSET_OFFSETFINE_MASK 0x0003FE00
/** field offset */
#define PMA_TIAOFFSET_OFFSETFINE_OFFSET 9
/** set coarse voltage offset in DAC BFD path. Added between stage A.) and B.)
    Sets the coarse DAC for the TIA path offset compensation (range: +/-192mV) */
#define PMA_TIAOFFSET_OFFSETCOARSE_MASK 0x000001FF
/** field offset */
#define PMA_TIAOFFSET_OFFSETCOARSE_OFFSET 0

/* Fields of "TIA P0 level DAC calibration control" */
/** set the P0 comparator level
    Sets the fine DAC for P0 level comparator (range: 32uA*600Ohm) */
#define PMA_P0LEVEL_LEVELFINE_MASK 0x0003FE00
/** field offset */
#define PMA_P0LEVEL_LEVELFINE_OFFSET 9
/** set the P0 comparator level
    Sets the coarse DAC for P0 level comparator (range: 640uA*600Ohm) */
#define PMA_P0LEVEL_LEVELCOARSE_MASK 0x000001FF
/** field offset */
#define PMA_P0LEVEL_LEVELCOARSE_OFFSET 0

/* Fields of "TIA P1 level DAC calibration control" */
/** set the P1 comparator level
    Sets the fine DAC for P1 level comparator (range: 32uA*600Ohm) */
#define PMA_P1LEVEL_LEVELFINE_MASK 0x0003FE00
/** field offset */
#define PMA_P1LEVEL_LEVELFINE_OFFSET 9
/** set the P1 comparator level
    Sets the coarse DAC for P1 level comparator (range: 640uA*600Ohm) */
#define PMA_P1LEVEL_LEVELCOARSE_MASK 0x000001FF
/** field offset */
#define PMA_P1LEVEL_LEVELCOARSE_OFFSET 0

/* Fields of "result of P0 and P1 comparator" */
/** sequence number
    counter is incremented when new data (p0_bfd_compdata)is available */
#define PMA_COMPARATOR_STATUS_P1_BFD_CNT_MASK 0x3FF00000
/** field offset */
#define PMA_COMPARATOR_STATUS_P1_BFD_CNT_OFFSET 20
/** number of larger P1 out of PMD p1 comparator
    For p1_compare_method=0: */
#define PMA_COMPARATOR_STATUS_P1_BFD_COMPDATA_MASK 0x000F8000
/** field offset */
#define PMA_COMPARATOR_STATUS_P1_BFD_COMPDATA_OFFSET 15
/** sequence number
    counter is incremented when new data (p0_bfd_compdata)is available */
#define PMA_COMPARATOR_STATUS_P0_BFD_CNT_MASK 0x00007FE0
/** field offset */
#define PMA_COMPARATOR_STATUS_P0_BFD_CNT_OFFSET 5
/** number of smaller than P0 symbols out of comparator
    For p0_compare_method=0: */
#define PMA_COMPARATOR_STATUS_P0_BFD_COMPDATA_MASK 0x0000001F
/** field offset */
#define PMA_COMPARATOR_STATUS_P0_BFD_COMPDATA_OFFSET 0

/* Fields of "dual loop recognition for P0" */
/** in case of p0_compare_method=1 choose how to compare
    0 .. any bit of the mask (comparepattern:p0_cp) must be set */
#define PMA_P0_DUAL_LOOP_P0_MATCH_ALL 0x40000000
/** detection method for digital level detection
    0 .. check the comparator result of the complete p0_capture_width window, */
#define PMA_P0_DUAL_LOOP_P0_COMPARE_METHOD 0x20000000
/** enable traces of p0
    The 16symbol trace register can be filled during the capture phase with bfd comparator data. */
#define PMA_P0_DUAL_LOOP_P0_TRACEREG_EN 0x10000000
/** no symbol change config count
    generate Laser/BFD Alarm after detection: */
#define PMA_P0_DUAL_LOOP_P0_ALARM_MASK 0x0FE00000
/** field offset */
#define PMA_P0_DUAL_LOOP_P0_ALARM_OFFSET 21
/** minimal time in auto_zero
    Time in nibble clock periods, during that the auto_zero signal is assigned to the limiting amplifier (LA). */
#define PMA_P0_DUAL_LOOP_P0_MIN_AZ_MASK 0x001E0000
/** field offset */
#define PMA_P0_DUAL_LOOP_P0_MIN_AZ_OFFSET 17
/** minimum recognition bits for detection
    number of detected comparator values <P0, after which a <P0 is considered to be true. */
#define PMA_P0_DUAL_LOOP_P0_MIN_DET_BITS_MASK 0x0001E000
/** field offset */
#define PMA_P0_DUAL_LOOP_P0_MIN_DET_BITS_OFFSET 13
/** minimum recognition bits for correlation
    minimal number of same symbols in sequence, that can be used to compare */
#define PMA_P0_DUAL_LOOP_P0_MIN_BITS_MASK 0x00001E00
/** field offset */
#define PMA_P0_DUAL_LOOP_P0_MIN_BITS_OFFSET 9
/** sample capture window
    Sample capture window size in steps of 4 symbols. During this time the */
#define PMA_P0_DUAL_LOOP_P0_CAPTURE_WIDTH_MASK 0x000001C0
/** field offset */
#define PMA_P0_DUAL_LOOP_P0_CAPTURE_WIDTH_OFFSET 6
/** sample capture window delay
    delay in steps of 4 symbols for the delay between */
#define PMA_P0_DUAL_LOOP_P0_CAPTURE_DELAY_MASK 0x00000038
/** field offset */
#define PMA_P0_DUAL_LOOP_P0_CAPTURE_DELAY_OFFSET 3
/** autozero disable delay
    delay in steps of 4 symbols for disabling the auto zero of the limiting amplifier */
#define PMA_P0_DUAL_LOOP_P0_AZ_DELAY_MASK 0x00000006
/** field offset */
#define PMA_P0_DUAL_LOOP_P0_AZ_DELAY_OFFSET 1
/** interburst power check
    If no burst is send and the bfd path is not in power save mode (see p0_bfd_powersave), */
#define PMA_P0_DUAL_LOOP_P0_IB_CHECK 0x00000001

/* Fields of "P0 data path" */
/** invers auto zero signal to Limiting Amplifier */
#define PMA_P0_DATAPATH_P0AZ_INV 0x00000080
/** force data value */
#define PMA_P0_DATAPATH_P0_PRG_EN 0x00000040
/** data value
    used to feed in test data (of bfd sampler). */
#define PMA_P0_DATAPATH_P0_PRG_DATA_MASK 0x0000003C
/** field offset */
#define PMA_P0_DATAPATH_P0_PRG_DATA_OFFSET 2
/** invert data */
#define PMA_P0_DATAPATH_P0_INV 0x00000002
/** flip LSB and MSB */
#define PMA_P0_DATAPATH_P0_FLIP 0x00000001

/* Fields of "dual loop recognition for P1" */
/** in case of p1_compare_method=1 choose how to compare
    0 .. any bit of the mask (comparepattern:p1_cp) must be set */
#define PMA_P1_DUAL_LOOP_P1_MATCH_ALL 0x40000000
/** detection method for digital level detection
    0 .. check the comparator result of the complete p1_capture_width window, */
#define PMA_P1_DUAL_LOOP_P1_COMPARE_METHOD 0x20000000
/** enable traces of p0
    The 16symbol trace register can be filled during the capture phase with bfd comparator data. */
#define PMA_P1_DUAL_LOOP_P1_TRACEREG_EN 0x10000000
/** no symbol change config count
    generate Laser/BFD Alarm after detection: */
#define PMA_P1_DUAL_LOOP_P1_ALARM_MASK 0x0FE00000
/** field offset */
#define PMA_P1_DUAL_LOOP_P1_ALARM_OFFSET 21
/** minimal time in auto_zero
    Time in nibble clock periods, during that the auto_zero signal is assigned to the limiting amplifier (LA). */
#define PMA_P1_DUAL_LOOP_P1_MIN_AZ_MASK 0x001E0000
/** field offset */
#define PMA_P1_DUAL_LOOP_P1_MIN_AZ_OFFSET 17
/** minimum recognition bits for detection
    number of detected comparator values >P1, after which a >P1 is considered to be true. */
#define PMA_P1_DUAL_LOOP_P1_MIN_DET_BITS_MASK 0x0001E000
/** field offset */
#define PMA_P1_DUAL_LOOP_P1_MIN_DET_BITS_OFFSET 13
/** minimum recognition bits for correlation
    minimal number of same symbols in sequence, that can be used to compare */
#define PMA_P1_DUAL_LOOP_P1_MIN_BITS_MASK 0x00001E00
/** field offset */
#define PMA_P1_DUAL_LOOP_P1_MIN_BITS_OFFSET 9
/** sample capture window
    Sample capture window size in steps of 4 symbols. During this time the */
#define PMA_P1_DUAL_LOOP_P1_CAPTURE_WIDTH_MASK 0x000001C0
/** field offset */
#define PMA_P1_DUAL_LOOP_P1_CAPTURE_WIDTH_OFFSET 6
/** sample capture window delay
    delay in steps of 4 symbols for the delay between */
#define PMA_P1_DUAL_LOOP_P1_CAPTURE_DELAY_MASK 0x00000038
/** field offset */
#define PMA_P1_DUAL_LOOP_P1_CAPTURE_DELAY_OFFSET 3
/** autozero disable delay
    delay in steps of 4 symbols for disabling the auto zero of the limiting amplifier */
#define PMA_P1_DUAL_LOOP_P1_AZ_DELAY_MASK 0x00000006
/** field offset */
#define PMA_P1_DUAL_LOOP_P1_AZ_DELAY_OFFSET 1
/** interburst power check
    If no burst is send and the bfd path is not in power save mode (see p1_bfd_powersave), */
#define PMA_P1_DUAL_LOOP_P1_IB_CHECK 0x00000001

/* Fields of "compare pattern for BFD level" */
/** comparepattern
    used to match in case of p1_compare_method=1 the output of the P1 level comparator */
#define PMA_COMPAREPATTERN_P1_CP_MASK 0xFFFF0000
/** field offset */
#define PMA_COMPAREPATTERN_P1_CP_OFFSET 16
/** comparepattern
    used to match in case of p0_compare_method=1 the output of the P0 level comparator */
#define PMA_COMPAREPATTERN_P0_CP_MASK 0x0000FFFF
/** field offset */
#define PMA_COMPAREPATTERN_P0_CP_OFFSET 0

/* Fields of "P1 data path" */
/** invers auto zero signal to Limiting Amplifier */
#define PMA_P1_DATAPATH_P1AZ_INV 0x00000080
/** force data value */
#define PMA_P1_DATAPATH_P1_PRG_EN 0x00000040
/** data value
    used to feed in test data (of bfd sampler). */
#define PMA_P1_DATAPATH_P1_PRG_DATA_MASK 0x0000003C
/** field offset */
#define PMA_P1_DATAPATH_P1_PRG_DATA_OFFSET 2
/** invert data */
#define PMA_P1_DATAPATH_P1_INV 0x00000002
/** flip LSB and MSB */
#define PMA_P1_DATAPATH_P1_FLIP 0x00000001

/* Fields of "power save for P1 correlator / BFD" */
/** powersave off time
    time in nibble count for transition between powersave and poweron in correlator */
#define PMA_P1_BFD_POWERSAVE_P1_PS_OFF_TIME_MASK 0x000000FE
/** field offset */
#define PMA_P1_BFD_POWERSAVE_P1_PS_OFF_TIME_OFFSET 1
/** tis/bfd path powersave
    enable the power save in BFD / TIA path. This will disable the BFD comparator detection. */
#define PMA_P1_BFD_POWERSAVE_P1_POWER_SAVE_BFD_EN 0x00000001

/* Fields of "power save for P0 correlator / BFD" */
/** powersave off time
    time in nibble count for transition between powersave and poweron in correlator statemachine */
#define PMA_P0_BFD_POWERSAVE_P0_PS_OFF_TIME_MASK 0x000000FE
/** field offset */
#define PMA_P0_BFD_POWERSAVE_P0_PS_OFF_TIME_OFFSET 1
/** tis/bfd path powersave
    enable the power save in BFD / TIA path. This will disable the BFD comparator detection. */
#define PMA_P0_BFD_POWERSAVE_P0_POWER_SAVE_BFD_EN 0x00000001

/* Fields of "powersave control for bias and modulation current DAC" */
/** bias DAC powersave value
    bias current DAC value during power save(range:11bit == 72mA). */
#define PMA_POWERSAVE_BIAS_PD_MASK 0x00FFE000
/** field offset */
#define PMA_POWERSAVE_BIAS_PD_OFFSET 13
/** modulation DAC powersave value
    modulation current DAC value during power save (range:11bit == 122mA). */
#define PMA_POWERSAVE_MODULATION_PD_MASK 0x00001FFC
/** field offset */
#define PMA_POWERSAVE_MODULATION_PD_OFFSET 2
/** override powersave */
#define PMA_POWERSAVE_POWER_UP_OVR 0x00000002
/** enable signal controlled powersave */
#define PMA_POWERSAVE_POWER_UP_EN 0x00000001

/* Fields of "trace p0 comparator" */
/** p0 traces
    Filled up (lsb first) with P0 comparator data after CID in TX found. */
#define PMA_P0_TRACE_TRACE_MASK 0xFFFF0000
/** field offset */
#define PMA_P0_TRACE_TRACE_OFFSET 16
/** correlator trace tx
    Filled up (lsb first) with tx data, when correlator has detected a valid CID pattern */
#define PMA_P0_TRACE_CORR_TRACE_MASK 0x0000FFFF
/** field offset */
#define PMA_P0_TRACE_CORR_TRACE_OFFSET 0

/* Fields of "trace p1 comparator" */
/** p1 traces
    Filled up (lsb first) with P1 comparator data after CID in TX found. */
#define PMA_P1_TRACE_TRACE_MASK 0xFFFF0000
/** field offset */
#define PMA_P1_TRACE_TRACE_OFFSET 16
/** correlator trace tx
    Filled up (lsb first) with tx data, when correlator has detected a valid CID pattern */
#define PMA_P1_TRACE_CORR_TRACE_MASK 0x0000FFFF
/** field offset */
#define PMA_P1_TRACE_CORR_TRACE_OFFSET 0

/* Fields of "delay data to bfd capture" */
/** data delay
    delay in number of nibbles, inserted in PMD to PMA path. Used to delay data for state machine */
#define PMA_DATA_DELAY_DATA_DELAY_MASK 0x00000007
/** field offset */
#define PMA_DATA_DELAY_DATA_DELAY_OFFSET 0

/* Fields of "DAC slice control" */
/** DAC slice resolution
    The DAC is build up of 4 slices a' 18mA/9bit. The sum of the slice currents is supplied to the laser diode. */
#define PMA_DAC_CTRL_BIAS_DAC_MODE 0x00000020
/** slice control for bias DAC
    Controls the DAC slices in the AFE */
#define PMA_DAC_CTRL_BIAS_EN_MASK 0x00000018
/** field offset */
#define PMA_DAC_CTRL_BIAS_EN_OFFSET 3
/** DAC slice resolution
    The DAC is build up of 4 slices a' 30mA/9bit. The sum of the slice currents is supplied to the laser diode. */
#define PMA_DAC_CTRL_MODULATION_DAC_MODE 0x00000004
/** slice control for modulation DAC
    Controls the DAC slices in the AFE */
#define PMA_DAC_CTRL_MODULATION_EN_MASK 0x00000003
/** field offset */
#define PMA_DAC_CTRL_MODULATION_EN_OFFSET 0

/* Fields of "monitor input TIA" */
/** automatic pd switching of DAC COMPARATOR and LA block in bfd, directed by state machine
    1 .. automatic power down */
#define PMA_GAIN_CTRL_PD_AUTO_P1LA_ON 0x00000080
/** automatic pd switching of DAC COMPARATOR and LA block in bfd, directed by state machine
    1 .. automatic power down */
#define PMA_GAIN_CTRL_PD_AUTO_P0LA_ON 0x00000040
/** automatic pd switching of CML2CMOS and DEMUX block in bfd, directed by state machine
    1 .. automatic power down */
#define PMA_GAIN_CTRL_PD_AUTO_DEMUX_ON 0x00000020
/** program/enable the calibration current
    00 ... no calibration current injected, BFD input to tia */
#define PMA_GAIN_CTRL_BFD_CALIBRATION_MASK 0x00000018
/** field offset */
#define PMA_GAIN_CTRL_BFD_CALIBRATION_OFFSET 3
/** gain control
    With bit 1:0 a mux selects between 4 different gain settings for the 3 TIA gain stages. */
#define PMA_GAIN_CTRL_GAIN_TIA_MASK 0x00000007
/** field offset */
#define PMA_GAIN_CTRL_GAIN_TIA_OFFSET 0

/* Fields of "data path control" */
/** to pmd ...
    Note that all other bits that control the testbus are programmed via FCSI */
#define PMA_DATAPATH_DATA_TESTBUS_EN 0x00000400
/** enable sending out BERT data
    0 .. no BERT data send out, */
#define PMA_DATAPATH_BERT 0x00000200
/** programmable data
    data to laser tx, send if data_prg_en=1 */
#define PMA_DATAPATH_DATA_PRG_DATA_MASK 0x000001E0
/** field offset */
#define PMA_DATAPATH_DATA_PRG_DATA_OFFSET 5
/** flip LSB and MSB */
#define PMA_DATAPATH_DATA_FLIP 0x00000010
/** invert data */
#define PMA_DATAPATH_DATA_INV 0x00000008
/** force burst valid signal
    The burst valid signal is needed for the correlator in the bfd path. */
#define PMA_DATAPATH_BURST_VALID_PRG_EN 0x00000004
/** force programmable data
    feed in data to LD. An alternative method for feeding a longer test pattern is */
#define PMA_DATAPATH_DATA_PRG_EN 0x00000002
/** force power up
    powerup also if GTC laser active line is not activated. */
#define PMA_DATAPATH_POWER_UP_OVR 0x00000001

/* Fields of "bias path control" */
/** to pmd ...
    Note that all other bits that control the testbus are programmed via FCSI */
#define PMA_BIASPATH_BIAS_TESTBUS_EN 0x00000400
/** enable sending out BERT data
    0 .. no BERT data send out, 1 .. BERT data send out */
#define PMA_BIASPATH_BERT 0x00000200
/** programmable data */
#define PMA_BIASPATH_BIAS_PRG_DATA_MASK 0x000001E0
/** field offset */
#define PMA_BIASPATH_BIAS_PRG_DATA_OFFSET 5
/** flip LSB and MSB */
#define PMA_BIASPATH_BIAS_FLIP 0x00000010
/** invert data */
#define PMA_BIASPATH_BIAS_INV 0x00000008
/** force burst valid signal
    The burst valid signal is needed for the correlator in the bfd path. */
#define PMA_BIASPATH_BURST_VALID_PRG_EN 0x00000004
/** force programmable data
    feed in data to LD. An alternative method for feeding a longer test pattern is */
#define PMA_BIASPATH_BIAS_PRG_EN 0x00000002
/** force power up
    powerup also if GTC laser active line is not aactivated. */
#define PMA_BIASPATH_POWER_UP_OVR 0x00000001

/* Fields of "delay data to PMD" */
/** general data delay in TX ...
    delays the data to pmd in relation to rx for crosstalk reduction. */
#define PMA_DATA_DELAY_INTRINSIC_DELAY_MASK 0x00000070
/** field offset */
#define PMA_DATA_DELAY_INTRINSIC_DELAY_OFFSET 4
/** enable predriver pd, switched with laser_enable signal from GTC */
#define PMA_DATA_DELAY_EN_PMD_TX_PD 0x00000008
/** Override the latch of the predriver power down values */
#define PMA_DATA_DELAY_EN_PMD_TX_PD_LATCHOR_MASK_A21 0x00000080
#define PMA_DATA_DELAY_EN_PMD_TX_PD_LATCHOR_OFFSET_A21 7

/* Fields of "laser enable control" */
/** tx buffer size in nibbles
    The physical size of the TX buffer is 128nibble. With this parameter the used size can be determined: */
#define PMA_LASER_ENABLE_BUFFER_SIZE_MASK 0x00007F00
#define PMA_LASER_ENABLE_BUFFER_SIZE_MASK_A21 0x0003FF00
/** field offset */
#define PMA_LASER_ENABLE_BUFFER_SIZE_OFFSET 8
/** disable delay word
    delay in number of nibbles for bias DAC disable after burst finished. Used to ensure that the last bit in the burst */
#define PMA_LASER_ENABLE_DISABLE_DELAY_MASK 0x000000F0
/** field offset */
#define PMA_LASER_ENABLE_DISABLE_DELAY_OFFSET 4
/** enable delay word
    delay in number of nibbles for bias DAC enable before burst starts */
#define PMA_LASER_ENABLE_ENABLE_DELAY_MASK 0x0000000F
/** field offset */
#define PMA_LASER_ENABLE_ENABLE_DELAY_OFFSET 0

#define PMA_LASER_ENABLE_NEG_ENABLE_DELAY_MASK_A21 0x00040000
#define PMA_LASER_ENABLE_NEG_ENABLE_DELAY_OFFSET_A21 18

/* Fields of "bit exact delay to laser" */
/** delay of data and data_valid
    0 .. 0 bit delay */
#define PMA_LASER_BITDELAY_BITDELAY_MASK 0x00000007
/** field offset */
#define PMA_LASER_BITDELAY_BITDELAY_OFFSET 0

/* Fields of "phase interpolator control" */
/** enable pi */
#define PMA_PI_CTRL_PI_EN 0x00004000
/** force value */
#define PMA_PI_CTRL_PI_CTRL2_MASK 0x00003F00
/** field offset */
#define PMA_PI_CTRL_PI_CTRL2_OFFSET 8
/** enable force value */
#define PMA_PI_CTRL_LOAD2 0x00000080
/** force value */
#define PMA_PI_CTRL_PI_CTRL_MASK 0x0000007E
/** field offset */
#define PMA_PI_CTRL_PI_CTRL_OFFSET 1
/** enable force value */
#define PMA_PI_CTRL_LOAD 0x00000001

/* Fields of "phase modulator" */
/** low frequency skewing */
#define PMA_MODULATOR_1_MOD_OUT_SKEW_EN 0x00200000
/** reverse modulation */
#define PMA_MODULATOR_1_MOD_OUT_FLIP 0x00100000
/** period */
#define PMA_MODULATOR_1_MOD_PERIOD_MASK 0x000FFF00
/** field offset */
#define PMA_MODULATOR_1_MOD_PERIOD_OFFSET 8
/** amplitude */
#define PMA_MODULATOR_1_MOD_AMP_MASK 0x000000FE
/** field offset */
#define PMA_MODULATOR_1_MOD_AMP_OFFSET 1
/** enable */
#define PMA_MODULATOR_1_MOD_EN 0x00000001

/* Fields of "MODULATOR_2" */
/** reverse low frequency skewing */
#define PMA_MODULATOR_2_SKEW_PERIOD_FLIP 0x00020000
/** low frequency period */
#define PMA_MODULATOR_2_SKEW_PERIOD_MASK 0x0001FFFF
/** field offset */
#define PMA_MODULATOR_2_SKEW_PERIOD_OFFSET 0

/* Fields of "reset and power down control for PMD" */
/** dll pmd power down
    0 .. no pd, 1 .. pd */
#define PMA_PMD_RESETCONTROL_DLL_PD 0x00000800
/** dll pmd reset
    0 .. reset, 1 .. no reset */
#define PMA_PMD_RESETCONTROL_DLL_RSTN 0x00000400
/** mm pmd power down
    0 .. no pd, 1 .. pd */
#define PMA_PMD_RESETCONTROL_MM_PD 0x00000200
/** mm pmd reset
    0 .. reset, 1 .. no reset */
#define PMA_PMD_RESETCONTROL_MM_RSTN 0x00000100
/** bfd pmd power down
    0 .. no pd, 1 .. pd */
#define PMA_PMD_RESETCONTROL_BFD_PD 0x00000080
/** bfd pmd reset
    0 .. reset, 1 .. no reset */
#define PMA_PMD_RESETCONTROL_BFD_RSTN 0x00000040
/** txomu pmd power down
    0 .. no pd, 1 .. pd */
#define PMA_PMD_RESETCONTROL_TXOMU_PD 0x00000020
/** tx pmd power down
    0 .. no pd, 1 .. pd */
#define PMA_PMD_RESETCONTROL_TX_PD 0x00000010
/** tx pmd reset
    0 .. reset, 1 .. no reset */
#define PMA_PMD_RESETCONTROL_TX_RSTN 0x00000008
/** rx pmd power down
    0 .. no pd, 1 .. pd */
#define PMA_PMD_RESETCONTROL_RXOMU_PD 0x00000004
/** rx pmd power down
    0 .. no pd, 1 .. pd */
#define PMA_PMD_RESETCONTROL_RX_PD 0x00000002
/** rx pmd reset
    0 .. reset, 1 .. no reset */
#define PMA_PMD_RESETCONTROL_RX_RSTN 0x00000001

/* Fields of "Control 1 Register" */
/** 16 LSBs of the CONST_SDM. */
#define PMA_CTRL1_CONST_SDM_MASK 0x0000FFFF
/** field offset */
#define PMA_CTRL1_CONST_SDM_OFFSET 0

/* Fields of "Control 2 Register" */
/** pll reset
    0 .. pll in reset */
#define PMA_CTRL2_PLL_RESETN 0x00020000
/** plldigtest_r */
#define PMA_CTRL2_PLLDIGTEST_MASK 0x0001F000
/** field offset */
#define PMA_CTRL2_PLLDIGTEST_OFFSET 12
/** pll_enwavegen_r */
#define PMA_CTRL2_PLL_ENWAVEGEN 0x00000800
/** Disable */
#define PMA_CTRL2_PLL_ENWAVEGEN_DIS 0x00000000
/** Enable */
#define PMA_CTRL2_PLL_ENWAVEGEN_EN 0x00000800
/** pll_ensdm_r */
#define PMA_CTRL2_PLL_ENSDM 0x00000400
/** Disable */
#define PMA_CTRL2_PLL_ENSDM_DIS 0x00000000
/** Enable */
#define PMA_CTRL2_PLL_ENSDM_EN 0x00000400
/** en_const_sdm_r */
#define PMA_CTRL2_EN_CONST_SDM 0x00000200
/** Disable */
#define PMA_CTRL2_EN_CONST_SDM_DIS 0x00000000
/** Enable */
#define PMA_CTRL2_EN_CONST_SDM_EN 0x00000200
/** enable the CONST_SDM input to pll_digital from register value
    0 .. SDM from CDR1 */
#define PMA_CTRL2_EN_CONST_SDM_REG 0x00000100
/** 8 MSBs of the CONST_SDM. */
#define PMA_CTRL2_CONST_SDM_MASK 0x000000FF
/** field offset */
#define PMA_CTRL2_CONST_SDM_OFFSET 0

/* Fields of "Control 3 Register" */
/** en_ext_selvco_r */
#define PMA_CTRL3_EXT_SELVCO_MASK 0x00003E00
/** field offset */
#define PMA_CTRL3_EXT_SELVCO_OFFSET 9
/** ext_VCO_vctrl_mux_r */
#define PMA_CTRL3_EXT_VCO_VCTRL_MUX_MASK 0x00000180
/** field offset */
#define PMA_CTRL3_EXT_VCO_VCTRL_MUX_OFFSET 7
/** ext_MMD_div_ratio_r */
#define PMA_CTRL3_EXT_MMD_DIV_RATIO_MASK 0x00000070
/** field offset */
#define PMA_CTRL3_EXT_MMD_DIV_RATIO_OFFSET 4
/** en_ext_selvco_r */
#define PMA_CTRL3_EN_EXT_SELVCO 0x00000008
/** Disable */
#define PMA_CTRL3_EN_EXT_SELVCO_DIS 0x00000000
/** Enable */
#define PMA_CTRL3_EN_EXT_SELVCO_EN 0x00000008
/** en_ext_VCO_vctrl_mux_r */
#define PMA_CTRL3_EN_EXT_VCO_VCTRL_MUX 0x00000004
/** Disable */
#define PMA_CTRL3_EN_EXT_VCO_VCTRL_MUX_DIS 0x00000000
/** Enable */
#define PMA_CTRL3_EN_EXT_VCO_VCTRL_MUX_EN 0x00000004
/** en_ext_MMD_div_ratio_r */
#define PMA_CTRL3_EN_EXT_MMD_DIV_RATIO 0x00000002
/** Disable */
#define PMA_CTRL3_EN_EXT_MMD_DIV_RATIO_DIS 0x00000000
/** Enable */
#define PMA_CTRL3_EN_EXT_MMD_DIV_RATIO_EN 0x00000002
/** en_binary_cal_r */
#define PMA_CTRL3_EN_BIN_CAL 0x00000001
/** Disable */
#define PMA_CTRL3_EN_BIN_CAL_DIS 0x00000000
/** Enable */
#define PMA_CTRL3_EN_BIN_CAL_EN 0x00000001

/* Fields of "Control 4 Register" */
/** pllmod_r
    First (Least Significant) word of the PLLMOD. */
#define PMA_CTRL4_PLLMOD_MASK 0x0000FFFF
/** field offset */
#define PMA_CTRL4_PLLMOD_OFFSET 0

/* Fields of "Control 5 Register" */
/** pllmod_r
    Second word of the PLLMOD. */
#define PMA_CTRL5_PLLMOD_MASK 0x0000FFFF
/** field offset */
#define PMA_CTRL5_PLLMOD_OFFSET 0

/* Fields of "Control 6 Register" */
/** pllmod_r
    Third word of the PLLMOD. */
#define PMA_CTRL6_PLLMOD_MASK 0x0000FFFF
/** field offset */
#define PMA_CTRL6_PLLMOD_OFFSET 0

/* Fields of "Control 7 Register" */
/** pllmod_r
    Fourth (Most significant) word of the PLLMOD. */
#define PMA_CTRL7_PLLMOD_MASK 0x0000FFFF
/** field offset */
#define PMA_CTRL7_PLLMOD_OFFSET 0

/* Fields of "Analog Control 1 Register" */
/** pfd_force_up_r */
#define PMA_A_CTRL1_PFD_FORCE_UP 0x00000080
/** pfd_force_dw_r */
#define PMA_A_CTRL1_PFD_FORCE_DW 0x00000040
/** cp_sel_r */
#define PMA_A_CTRL1_CP_SEL_MASK 0x00000038
/** field offset */
#define PMA_A_CTRL1_CP_SEL_OFFSET 3
/** cp_ref_sel_r */
#define PMA_A_CTRL1_CP_REF_SEL_MASK 0x00000006
/** field offset */
#define PMA_A_CTRL1_CP_REF_SEL_OFFSET 1
/** cp_force_fix_p_bias_r */
#define PMA_A_CTRL1_CP_FORCE_FIX_P_BIAS 0x00000001

/* Fields of "Analog Control 2 Register" */
/** lf_mode_r */
#define PMA_A_CTRL2_LF_MODE 0x00040000
/** ldo_vref_sel_r */
#define PMA_A_CTRL2_LDO_VREF_SEL_MASK 0x00038000
/** field offset */
#define PMA_A_CTRL2_LDO_VREF_SEL_OFFSET 15
/** div_clk_o_mtr_en_r */
#define PMA_A_CTRL2_DIV_CLK_O_MTR_EN 0x00004000
/** Disable */
#define PMA_A_CTRL2_DIV_CLK_O_MTR_EN_DIS 0x00000000
/** Enable */
#define PMA_A_CTRL2_DIV_CLK_O_MTR_EN_EN 0x00004000
/** current_sel_fixph_buf_r */
#define PMA_A_CTRL2_CURR_SEL_FIXPH_BUF_MASK 0x00003000
/** field offset */
#define PMA_A_CTRL2_CURR_SEL_FIXPH_BUF_OFFSET 12
/** current_sel_ref_mux_r */
#define PMA_A_CTRL2_CURR_SEL_REF_MUX_MASK 0x00000C00
/** field offset */
#define PMA_A_CTRL2_CURR_SEL_REF_MUX_OFFSET 10
/** current_sel_pi_r */
#define PMA_A_CTRL2_CURR_SEL_PI_MASK 0x00000300
/** field offset */
#define PMA_A_CTRL2_CURR_SEL_PI_OFFSET 8
/** current_sel_lf_r */
#define PMA_A_CTRL2_CURR_SEL_LF_MASK 0x000000C0
/** field offset */
#define PMA_A_CTRL2_CURR_SEL_LF_OFFSET 6
/** current_sel_ldo_r */
#define PMA_A_CTRL2_CURR_SEL_LDO_MASK 0x00000030
/** field offset */
#define PMA_A_CTRL2_CURR_SEL_LDO_OFFSET 4
/** current_sel_div2_r */
#define PMA_A_CTRL2_CURR_SEL_DIV2_MASK 0x0000000C
/** field offset */
#define PMA_A_CTRL2_CURR_SEL_DIV2_OFFSET 2
/** current_sel_pi_driver_r */
#define PMA_A_CTRL2_CURR_SEL_PI_DRIVER_MASK 0x00000003
/** field offset */
#define PMA_A_CTRL2_CURR_SEL_PI_DRIVER_OFFSET 0

/* Fields of "Analog Control 3 Register" */
/** mmd_r */
#define PMA_A_CTRL3_MMD_MASK 0x00FC0000
/** field offset */
#define PMA_A_CTRL3_MMD_OFFSET 18
/** vco_vctrl_when_ct_r */
#define PMA_A_CTRL3_VCO_VCTRL_WHEN_CT_MASK 0x00030000
/** field offset */
#define PMA_A_CTRL3_VCO_VCTRL_WHEN_CT_OFFSET 16
/** test_ext_fd_in_en_r */
#define PMA_A_CTRL3_TEST_EXT_FD_IN_EN 0x00008000
/** Disable */
#define PMA_A_CTRL3_TEST_EXT_FD_IN_EN_DIS 0x00000000
/** Enable */
#define PMA_A_CTRL3_TEST_EXT_FD_IN_EN_EN 0x00008000
/** refclk_sel_r
    1 .. CML */
#define PMA_A_CTRL3_REFCLK_SEL 0x00004000
/** refclk_o_en_r */
#define PMA_A_CTRL3_REFCLK_O_EN 0x00002000
/** Disable */
#define PMA_A_CTRL3_REFCLK_O_EN_DIS 0x00000000
/** Enable */
#define PMA_A_CTRL3_REFCLK_O_EN_EN 0x00002000
/** ref_clk_o_mtr_en_r */
#define PMA_A_CTRL3_REF_CLK_O_MTR_EN 0x00001000
/** Disable */
#define PMA_A_CTRL3_REF_CLK_O_MTR_EN_DIS 0x00000000
/** Enable */
#define PMA_A_CTRL3_REF_CLK_O_MTR_EN_EN 0x00001000
/** pwd_vrefs_r */
#define PMA_A_CTRL3_PWD_VREFS 0x00000800
/** pwd_lf_r */
#define PMA_A_CTRL3_PWD_LF 0x00000400
/** pwd_ldo_vco_r */
#define PMA_A_CTRL3_PWD_LDO_VCO 0x00000200
/** pwd_fd_in_buffer_r */
#define PMA_A_CTRL3_PWD_FD_IN_BUFFER 0x00000100
/** pwd_fix_ph_core_f_r */
#define PMA_A_CTRL3_PWD_FIX_PH_CORE_F 0x00000080
/** pwd_div8_r */
#define PMA_A_CTRL3_PWD_DIV8 0x00000040
/** pwd_div5_r */
#define PMA_A_CTRL3_PWD_DIV5 0x00000020
/** pwd_div2_r */
#define PMA_A_CTRL3_PWD_DIV2 0x00000010
/** pwd_div_r */
#define PMA_A_CTRL3_PWD_DIV 0x00000008
/** pwd_cp_r */
#define PMA_A_CTRL3_PWD_CP 0x00000004
/** pwd_bias_r */
#define PMA_A_CTRL3_PWD_BIAS 0x00000002
/** pwd_r
    power down of all analog blocks ??: */
#define PMA_A_CTRL3_PWD 0x00000001

/* Fields of "PLL Status Register" */
/** Startup Ready */
#define PMA_STATUS_STARTUP_RDY_MASK 0x0000000C
/** field offset */
#define PMA_STATUS_STARTUP_RDY_OFFSET 2
/** Lock */
#define PMA_STATUS_LOCK 0x00000002
/** Force Start */
#define PMA_STATUS_FORCE_START 0x00000001

/* Fields of "PMA top level control" */
/** select tx clock from OMU or bidi
    0 ... bidi; 1.. OMU */
#define PMA_PMA_TOP_CTRL_TX_CLK_SEL 0x00000004
/** select rx clock and data from OMU or bidi
    0 ... bidi; 1.. OMU */
#define PMA_PMA_TOP_CTRL_RX_CLK_SEL 0x00000002
/** external laser enable
    0 .. pecl level on OMU_TXEN, 1 .. cmos level on OMU_TXEN */
#define PMA_PMA_TOP_CTRL_EXT_LASER_EN 0x00000001

/* Fields of "BERT control" */
/** analyze PRBS with 1.25 or 2.5GHz
    0 ... analyze the RX data with 1.25GHz, used for external face to face test with ONU */
#define PMA_BERT_CONTROL_MODE_2G5_RX 0x00020000
/** generate PRBS with 1.25 or 2.5GHz
    0 ... generate the PRBS with 1.25GHz in TX, used for external bit error measurement */
#define PMA_BERT_CONTROL_MODE_2G5_TX 0x00010000
/** select the pattern for loop#4
    0 .. clockgen out */
#define PMA_BERT_CONTROL_MUX_SEL4_MASK 0x0000C000
/** field offset */
#define PMA_BERT_CONTROL_MUX_SEL4_OFFSET 14
/** select the pattern for loop#3
    0 .. clockgen out */
#define PMA_BERT_CONTROL_MUX_SEL3_MASK 0x00003000
/** field offset */
#define PMA_BERT_CONTROL_MUX_SEL3_OFFSET 12
/** select the pattern for loop#2
    0 .. clockgen out */
#define PMA_BERT_CONTROL_MUX_SEL2_MASK 0x00000C00
/** field offset */
#define PMA_BERT_CONTROL_MUX_SEL2_OFFSET 10
/** select the pattern for loop#1
    0 .. clockgen out */
#define PMA_BERT_CONTROL_MUX_SEL1_MASK 0x00000300
/** field offset */
#define PMA_BERT_CONTROL_MUX_SEL1_OFFSET 8
/** PRBS poly select
    7 .. prbs7 */
#define PMA_BERT_CONTROL_PRBS_SEL_MASK 0x000000F8
/** field offset */
#define PMA_BERT_CONTROL_PRBS_SEL_OFFSET 3
/** enable LFSR input path */
#define PMA_BERT_CONTROL_SELFSYNC_EN 0x00000004
/** enable simple loopback */
#define PMA_BERT_CONTROL_LOOPBACK_ENABLE 0x00000002
/** enable BERT generation and analysis */
#define PMA_BERT_CONTROL_ANALYZER_EN 0x00000001

/* Fields of "BERT fixed pattern" */
/** pattern */
#define PMA_BERT_PATTERN_FIXEDIN_MASK 0xFFFFFFFF
/** field offset */
#define PMA_BERT_PATTERN_FIXEDIN_OFFSET 0

/* Fields of "BERT clock pattern" */
/** clock period */
#define PMA_BERT_CLK_GENCLKPERIOD_MASK 0x0000FF00
/** field offset */
#define PMA_BERT_CLK_GENCLKPERIOD_OFFSET 8
/** clock hi phase */
#define PMA_BERT_CLK_GENCLKHI_MASK 0x000000FF
/** field offset */
#define PMA_BERT_CLK_GENCLKHI_OFFSET 0

/* Fields of "BERT pattern endcounter value" */
/** endcounter 4, select the length for loop#4 */
#define PMA_BERT_CNT_ENDCOUNTER_4_MASK 0xFF000000
/** field offset */
#define PMA_BERT_CNT_ENDCOUNTER_4_OFFSET 24
/** endcounter 3, select the length for loop#3 */
#define PMA_BERT_CNT_ENDCOUNTER_3_MASK 0x00FF0000
/** field offset */
#define PMA_BERT_CNT_ENDCOUNTER_3_OFFSET 16
/** endcounter 2, select the length for loop#2 */
#define PMA_BERT_CNT_ENDCOUNTER_2_MASK 0x0000FF00
/** field offset */
#define PMA_BERT_CNT_ENDCOUNTER_2_OFFSET 8
/** endcounter 1, select the length for loop#1 */
#define PMA_BERT_CNT_ENDCOUNTER_1_MASK 0x000000FF
/** field offset */
#define PMA_BERT_CNT_ENDCOUNTER_1_OFFSET 0

/* Fields of "BERT status control" */
/** received word count reset
    1 .. reset to zero */
#define PMA_BERT_STATUSCTRL_WORD_RESET 0x00000004
/** error count reset
    1 .. reset to zero */
#define PMA_BERT_STATUSCTRL_ERROR_RESET 0x00000002
/** freeze error counter and word counter
    1 .. freeze: error and word counter content with matched timestamp; */
#define PMA_BERT_STATUSCTRL_COUNTER_FREEZE 0x00000001

/* Fields of "BERT received word count status" */
/** received word count */
#define PMA_BERT_WRDCNT_WORD_COUNT_MASK 0xFFFFFFFF
/** field offset */
#define PMA_BERT_WRDCNT_WORD_COUNT_OFFSET 0

/* Fields of "BERT detected error status" */
/** error count */
#define PMA_BERT_ERRCNT_ERROR_COUNT_MASK 0xFFFFFFFF
/** field offset */
#define PMA_BERT_ERRCNT_ERROR_COUNT_OFFSET 0

/*! @} */ /* PMA_REGISTER */

#endif /* _drv_optic_reg_pma_h */
