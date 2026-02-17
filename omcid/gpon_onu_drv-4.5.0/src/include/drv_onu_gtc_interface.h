/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_onu_gtc_interface.h
   This is the GPON GTC header file, used for Lantiq's FALCON GPON Modem driver.
*/
#ifndef _drv_onu_gtc_interface_h_
#define _drv_onu_gtc_interface_h_

#include "drv_onu_std_defs.h"

#ifndef __PACKED__
#  if defined (__GNUC__) || defined (__GNUG__)
   /* GNU C or C++ compiler */
#    define __PACKED__ __attribute__ ((packed))
#  else
   /* Byte alignment adjustment */
#    pragma pack(1)
#    if !defined (_PACKED_)
#      define __PACKED__	/* nothing */
#    endif
#  endif
#  define __PACKED_DEFINED__
#endif

EXTERN_C_BEGIN
/** \addtogroup ONU_MAPI_REFERENCE
   @{
*/
/** \defgroup ONU_GTC GPON Transmission Convergence Layer

    This chapter describes the interface to access and configure the GPON TC
    layer module (GTC).
   @{
*/

/* Constant Definitions - GTC
   ================================== */
/** Reset mask for the BIP counter*/
#define ONU_GTC_CNT_RST_MASK_BIP				(1 << 0)
/** Reset mask for the Received correctable HEC errors counter*/
#define ONU_GTC_CNT_RST_MASK_HEC_ERR_CORR			(1 << 1)
/** Reset mask for the Received uncorrectable HEC errors counter*/
#define ONU_GTC_CNT_RST_MASK_HEC_ERR_UNCORR			(1 << 2)
/** Reset mask for the Received correctable bandwidth map errors counter*/
#define ONU_GTC_CNT_RST_MASK_BWMAP_ERR_CORR			(1 << 3)
/** Reset mask for the Received uncorrectable bandwidth map errors counter*/
#define ONU_GTC_CNT_RST_MASK_BWMAP_ERR_UNCORR			(1 << 4)
/** Reset mask for the Received uncorrectable bandwidth map errors counter*/
#define ONU_GTC_CNT_RST_MASK_FEC_ERR_CORR			(1 << 5)
/** Reset mask for the Number of corrected FEC code words counter*/
#define ONU_GTC_CNT_RST_MASK_FEC_WRD_CORR			(1 << 6)
/** Reset mask for the Number of uncorrectable FEC code words counter*/
#define ONU_GTC_CNT_RST_MASK_FEC_WRD_UNCORR			(1 << 7)
/** Reset mask for the Total number of received FEC code words counter*/
#define ONU_GTC_CNT_RST_MASK_FEC_WRD_TOTAL			(1 << 8)
/** Reset mask for the Total number of transmitted GEM frames counter*/
#define ONU_GTC_CNT_RST_MASK_TX_GEM_FRAMES_TOTAL		(1 << 9)
/** Reset mask for the Total number of transmitted GEM payload bytes counter*/
#define ONU_GTC_CNT_RST_MASK_TX_GEM_BYTES_TOTAL			(1 << 10)
/** Reset mask for the Total number of transmitted GEM Idle Frames counter*/
#define ONU_GTC_CNT_RST_MASK_TX_GEM_IDLE_FRAMES_TOTAL		(1 << 11)
/** Reset mask for the Received GEM frames/packets counter*/
#define ONU_GTC_CNT_RST_MASK_RX_GEM_FRAMES_TOTAL		(1 << 12)
/** Reset mask for the Received GEM payload bytes counter*/
#define ONU_GTC_CNT_RST_MASK_RX_GEM_BYTES_TOTAL			(1 << 13)
/** Reset mask for the dropped GEM frames counter*/
#define ONU_GTC_CNT_RST_MASK_RX_GEM_FRAMES_DROPPED		(1 << 14)
/** Reset mask for the Dropped bad OMCI frames/packets counter*/
#define ONU_GTC_CNT_RST_MASK_OMCI_DROPPED			(1 << 15)
/** Reset mask for all dropped frames/packets counter*/
#define ONU_GTC_CNT_RST_MASK_TOTAL_DROPPED			(1 << 16)
/** Reset mask for the Oversized frames/packets counter*/
#define ONU_GTC_CNT_RST_MASK_RX_OVSZ_FRAMES			(1 << 17)


/* Enumeration Definitions - GTC
   ================================== */
/** Power saving mode selection.
    Used by \ref gtc_init_data.
*/
enum gtc_power_saving_mode {
	/** Normal operation, no power saving mode is active.*/
	GPON_POWER_SAVING_MODE_OFF = 0,
	/** GPON deep sleep mode.*/
	GPON_POWER_SAVING_DEEP_SLEEP = 1,
	/** GPON fast sleep mode.*/
	GPON_POWER_SAVING_FAST_SLEEP = 2,
	/** GPON dozing mode.*/
	GPON_POWER_SAVING_DOZING = 3,
	/** GPON power shedding mode.*/
	GPON_POWER_SAVING_POWER_SHEDDING = 4
};

/** Receive state machine status.
*/
enum gtc_receive_state {
	/** HUNT state.*/
	GPON_STATE_HUNT = 0,
	/** Pre-Sync state.*/
	GPON_STATE_PRESYNC = 1,
	/** Sync state.*/
	GPON_STATE_SYNC = 3
};

/** Receive superframe state machine status.
*/
enum gtc_receive_sf_state {
	/** HUNT state.*/
	GPON_SF_STATE_HUNT = 0,
	/** Pre-Sync state.*/
	GPON_SF_STATE_PRESYNC = 1,
	/** Sync state.*/
	GPON_SF_STATE_SYNC = 3
};

/* Structure Definitions - GTC
   ================================
*/

/** DLOS mode configuration.
    Used by \ref gtc_init_data.
*/
struct gtc_dlos_mode {
	/** DLOS enable.*/
	uint32_t dlos_enable;
	/** Signal inversion,
	    \remark false = check for excessive zeros,
	     true = check for excessive ones.*/
	uint32_t dlos_inversion;
	/** Window size in multiples of 125 us.
	    \remark The valid range is from 1 to 7.*/
	uint32_t dlos_window_size;
	/** DLOS trigger threshold.
	    \remark The valid range is from 1 to 4,194,303.*/
	uint32_t dlos_trigger_threshold;
} __PACKED__;

/** GTC module initialization values.
    These settings are fixed during the operation of the ONU and related to the
    used hardware (PCB and external laser driver components.
    Used by \ref FIO_GTC_INIT.*/
struct gtc_init_data {
	/** Digital Loss of Signal (DLOS) initialization.
	    This is used to define the detection of a loss of signal condition
	    based on the received digital signal at the input of the
	    GTC hardware module.*/
	struct gtc_dlos_mode dlos;
	/** Laser-off minimum timing gap.
	    Laser Power-Off gap in units of 13 ns. This represents the minimum
	    gap between SSTOP of the actual and SSTART of the next T-CONT to
	    power off the laser.
	    The recommended default value is 22, resulting in a gap of 283 ns.*/
	uint32_t laser_gap;
	/** Laser timing offset.
	    Laser Power-Up offset prior to the laser enable signal.
	    The value is given in units of 13 ns.
	    The recommended default value is 4 (51 ns).*/
	uint32_t laser_offset;
	/** Laser enable end extension.
	    This value defines the extension (padding) of the laser burst enable
	    signal to the end of the transmitted data burst. It can be used to
	    compensate for signal skew due to external circuitry.
	    The offset is programmable in steps of 8 bit (1 byte).*/
	uint32_t laser_en_end_ext;
	/** Laser enable start extension.
	    This value defines extension of the laser burst enable signal to the
	    start of the transmitted data burst. It can be used to compensate
	    for signal skew due to external circuitry.
	    The offset is programmable in steps of 8 bit (1 byte).*/
	uint32_t laser_en_start_ext;
};

/** GPON TC layer hardware configuration settings.
     Used by \ref FIO_GTC_CFG_SET and \ref FIO_GTC_CFG_GET.
*/
struct gtc_cfg {
	/** BIP error interval, given in units of 1 ms.*/
	uint32_t bip_error_interval;
	/** Signal Fail threshold.
	For a given value of x, the threshold is 10Ex.*/
	uint32_t sf_threshold;
	/** Signal Degrade threshold.
	For a given value of x, the threshold is 10Ex.*/
	uint32_t sd_threshold;
	/** ONU response time.
	Given in multiples of 32 bytes (~205.8 ns at 1.244 Gbit/s upstream
	data rate), up to 35 microseconds typically. Default value 0xAA is
	equivalent to ~35 microseconds at 1.244 Gbit/s.*/
	uint32_t onu_response_time;
	/** Threshold for ONU-activated power levelling,
	    a value of 0xFF deactivates the power levelling.*/
	uint32_t serial_number_request_threshold;
	/** PLOAMd rogue ONU message identifier */
	uint32_t rogue_msg_id;
	/** PLOAMd rogue ONU message required repeat count */
	uint32_t rogue_msg_rpt;
	/** PLOAMd rogue ONU message reception enable */
	uint32_t rogue_msg_enable;
	/** TO1 value, given in multiples of 1 ms */
	uint32_t ploam_timeout_1;
	/** TO2 value, given in multiples of 1 ms */
	uint32_t ploam_timeout_2;
	/** set to 1 to force emergency stop state (O7) */
	uint32_t emergency_stop_state;
	/** PLOAM password.*/
	uint8_t password[10];
	/** v7.5.1: reserved (appended, exact semantics unknown). */
	uint32_t _v751_reserved;
} __PACKED__;

/** GPON TC layer hardware alarm information.
    Used by \ref FIO_GTC_ALARM_GET.
*/
struct gtc_alarm {
	/** General fail indication.
	    This flag is set if any of the below failure flags is set.*/
	uint32_t alarm;
	/** Signal fail indication.*/
	uint32_t sig_fail;
	/** Signal degrade indication.*/
	uint32_t sig_degrade;
	/** Loss of Signal indication.*/
	uint32_t loss_of_signal;
	/** Loss of GEM frame delineation.*/
	uint32_t loss_of_gem_frame;
	/** GEM frame starvation.*/
	uint32_t gem_frame_starvation;
	/** Loss of GTC frame delineation.*/
	uint32_t loss_of_gtc_frame;
	/** Loss of GTC superframe delineation.*/
	uint32_t loss_of_gtc_superframe;
	/**  PLOAM receive error.*/
	uint32_t ploam_rx_error;
	/**  PLOAM receive buffer overflow.*/
	uint32_t ploam_rx_buffer_error;
	/**  PLOAM transmit buffer overflow.*/
	uint32_t ploam_tx_buffer_error;
	/**  Hardware counter overflow.
	     Indicates that one of the hardware counters reached its limit.*/
	uint32_t counter_overflow;
	/**  Plen reception warning.*/
	uint32_t plen_warning;
	/**  Plen reception error.*/
	uint32_t plen_error;
	/**  Physical Equipment Error (PEE) received from OLT.*/
	uint32_t physical_equipment_error;
	/** TBD */
	uint32_t loss_of_allocation;
} __PACKED__;

/** GPON TC layer hardware status information.
    Used by \ref FIO_GTC_STATUS_GET.
*/
struct gtc_status {
	/** Downstream FEC enable status.*/
	uint32_t ds_fec_enable;
	/** Upstream FEC enable status.*/
	uint32_t us_fec_enable;
	/** PLOAMd message waiting in buffer.*/
	uint32_t ds_ploam_waiting;
	/** PLOAMd message buffer overflow.*/
	uint32_t ds_ploam_overflow;
	/** Receive state machine status.*/
	enum gtc_receive_state ds_state;
	/** Receive superframe state machine status.*/
	enum gtc_receive_sf_state ds_sf_state;
	/** Physical Equipment Error (PEE) received from OLT through PLOAMd.*/
	uint32_t ds_physical_equipment_error;
	/** ONU ID.*/
	uint32_t onu_id;
	/** Variable downstream synchronization delay.
	    Contains the PSYNC Delay in range from 0 to 31.
	    This value represents the Delay of the MSB Bit of the PSYNC Word in
	    the 32 Bit Data In Word.*/
	uint32_t gtc_ds_delay;
	/** v7.5.1: two additional status fields (exact semantics unknown). */
	uint32_t _v751_reserved[2];
} __PACKED__;

/** GPON upstream frame header configuration.
    Used by \ref FIO_GTC_US_HEADER_CFG_GET.
*/
struct gtc_us_header_cfg {
	/** 128-byte GPON upstream header pattern.*/
	uint32_t us_pattern[32];
	/** GPON upstream header length.
	    A maximum value of 128 (1024 bit) is supported, in steps of 8 bit.
	    The minimum length supported is 1 (8 bit).*/
	uint32_t us_header_len;
} __PACKED__;

/** GPON T-CONT configuration value.
    Currently unused.
*/
struct gtc_tcont_set {
	/** T-CONT index (used resource).*/
	uint32_t tcont_idx;
	/** 12-bit Allocation ID.
	    The lower 12 bit (11:0) are used, the upper 4 bit (15:12) shall
	    be set to zero.*/
	uint32_t alloc_id;
} __PACKED__;

/** GPON T-CONT configuration value.
    Currently unused.
*/
struct gtc_tcont {
	/** T-CONT index (used resource).*/
	uint32_t tcont_idx;
} __PACKED__;

/** GPON ranging values.
    Used by \ref FIO_GTC_RANGING_GET.
*/
struct gtc_ranging_val {
	/** Ranging delay selection.
	    - false: pre-assigned and random delay.
	    - true: ranged delay.*/
	uint32_t ranged_delay_enable;
	/** 12-bit random equalization delay.
	    Bit 15:12 shall be set to zero.*/
	uint32_t random_delay;
	/** 16-bit pre-assigned equalization delay.*/
	uint32_t preassigned_delay;
	/** 32-bit ranged equalization delay.*/
	uint32_t ranged_delay;
} __PACKED__;

/** Dying Gasp message configuration.
    This structure is used by \ref FIO_GTC_DYING_GASP_CFG_SET
    and \ref FIO_GTC_DYING_GASP_CFG_GET.
    The pre-configured Dying Gasp message can be sent automatically if the
    hardware detects a supply voltage drop.
*/
struct gtc_dgasp_msg {
	/** "Dying Gasp" PLOAMu message.
	    The first two bytes are ignored for the "set" function.*/
	uint8_t dying_gasp_msg[12];
	/** Automatic hardware mode for Dying Gasp is enabled, if true.*/
	uint32_t dying_gasp_auto;
} __PACKED__;

/** "No Message" PLOAMu message configuration.
    This structure is used by \ref FIO_GTC_NO_MESSAGE_CFG_SET
    and \ref FIO_GTC_NO_MESSAGE_CFG_GET.
    The pre-configured "No Message" message is sent automatically if no other
    PLOAMu message can be transmitted. This structure holds the configurable
    message contents.
*/
struct gtc_no_msg_msg {
	/** No Message scrambling enable.*/
	uint32_t no_msg_is_scrambled;
	/** No Message PLOAMu message.
	    The first two bytes are ignored for the "set" function.*/
	uint8_t no_msg[12];
} __PACKED__;

/** GTC operation mode selection. Used by \ref FIO_GTC_POWER_SAVING_MODE_SET
   and \ref FIO_GTC_POWER_SAVING_MODE_GET.
*/
struct gtc_op_mode {
	/** GPON power saving modes.*/
	enum gtc_power_saving_mode gpon_op_mode;
	/** v7.5.1: power saving timing parameters (9 fields, 36 bytes).
	    Exact field names unknown — padded to match v7.5.1 size of 40. */
	uint32_t _v751_reserved[9];
} __PACKED__;

/** PLOAM receive message structure.
    Used by \ref FIO_GTC_PLOAM_RECEIVE.
*/
struct gtc_ploamd {
	/** ONU ID.*/
	uint8_t onu_id;
	/** Message ID.*/
	uint8_t msg_id;
	/** Message contents.*/
	uint8_t data[10];
} __PACKED__;

/** PLOAM transmit message structure.
    Used by \ref FIO_GTC_PLOAM_SEND.
*/
struct gtc_ploamu {
	/** ONU ID.*/
	uint8_t onu_id;
	/** Message ID.*/
	uint8_t msg_id;
	/** Message contents.*/
	uint8_t data[10];
	/** Repetition factor.
	    Valid range is from 0 to 7.*/
	uint8_t repeat;
} __PACKED__;

/** Serial Number.
    Used by \ref FIO_GTC_SERIAL_NUMBER_GET.
*/
struct gtc_serial_num {
	/** Serial number string.*/
	uint8_t serial_number[8];
};

/** Password used by \ref FIO_GTC_PASSWORD_GET.
*/
struct gtc_password {
	/** Password string.*/
	uint8_t password[10];
};

/** Forced upstream allocation time slot setting. This is a system debug
    function. used by \ref FIO_GTC_FORCED_ALLOC_SET
    and \ref FIO_GTC_FORCED_ALLOC_GET.
*/
struct gtc_forced_alloc {
	/** Debug mode enable.*/
	uint32_t enable;
	/** Start time.*/
	uint32_t start_time;
	/** Stop time.*/
	uint32_t stop_time;
	/** Allocation ID.*/
	uint32_t alloc_id;
	/** Upstream flags.*/
	uint32_t flags;
};

/** Bandwidth map trace configuration setting.
    Used by \ref FIO_GTC_BWMT_CFG_SET and \ref FIO_GTC_BWMT_CFG_GET.
*/
struct gtc_bwmt_cfg {
	/** Trace function enable.*/
	uint32_t trace_enable;
	/** GTC overhead size trigger enable.*/
	uint32_t overhead_size_enable;
	/** GTC data size trigger enable.*/
	uint32_t data_size_enable;
	/** FEC parity size trigger enable.*/
	uint32_t parity_size_enable;
	/** Start time trigger enable.*/
	uint32_t start_time_enable;
	/** Stop time trigger enable.*/
	uint32_t stop_time_enable;
	/** Start/stop trigger enable.*/
	uint32_t start_stop_enable;
	/** PLOu size trigger enable.*/
	uint32_t plou_enable;
	/** T-CONT overlap trigger enable.*/
	uint32_t overlap_enable;
	/** No GEM data trigger enable.*/
	uint32_t no_gem_enable;
	/** Software trigger enable.*/
	uint32_t sw_trigger;
};

/** Bandwidth map trace restart trigger.
    Used by \ref FIO_GTC_BWMT_NEXT.
*/
struct gtc_bwmt_next_data {
	/** Trace function restart.*/
	uint32_t trace_start;
};

/** Data structure of Bandwidth map trace result items.
    Used by \ref gtc_bwmt_status.
*/
struct gtc_bwmt_data {
	/** Start time.*/
	uint32_t start;
	/** Stop time.*/
	uint32_t stop;
	/** Allocation identifier.*/
	uint32_t alloc_id;
	/** Flags field.*/
	uint32_t flags;
};

/** Bandwidth map trace result.
    Used by \ref FIO_GTC_BWMT_STATUS_GET.
*/
struct gtc_bwmt_status {
	/** GTC overhead size trigger.*/
	uint32_t overhead_size_enable;
	/** GTC data size trigger.*/
	uint32_t data_size_enable;
	/** FEC parity size trigger.*/
	uint32_t parity_size_enable;
	/** Start time trigger.*/
	uint32_t start_time_enable;
	/** Stop time trigger.*/
	uint32_t stop_time_enable;
	/** Start/stop trigger.*/
	uint32_t start_stop_enable;
	/** PLOu size trigger.*/
	uint32_t plou_enable;
	/** T-CONT overlap trigger.*/
	uint32_t overlap_enable;
	/** No GEM data trigger.*/
	uint32_t no_gem_enable;
	/** Software trigger enable.*/
	uint32_t sw_trigger;
};

/** GTC counter supervision. used by \ref FIO_GTC_COUNTER_RESET.
*/
struct gtc_cnt_interval {
	/** Reset Mask.*/
	uint32_t reset_mask;
	/** True if current, false if previous.*/
	uint32_t curr;
} __PACKED__;

/** GPON TC layer counters.
*/
struct gtc_cnt_value {
	/** Received BIP errors.*/
	uint64_t bip;
	/** Received correctable HEC errors.*/
	uint64_t hec_error_corr;
	/** Received uncorrectable HEC errors.*/
	uint64_t hec_error_uncorr;
	/** Received correctable bandwidth map errors.*/
	uint64_t bwmap_error_corr;
	/** Received uncorrectable bandwidth map errors.*/
	uint64_t bwmap_error_uncorr;
	/** Number of corrected FEC bytes.*/
	uint64_t fec_error_corr;
	/** Number of corrected FEC code words.*/
	uint64_t fec_words_corr;
	/** Number of uncorrectable FEC code words.*/
	uint64_t fec_words_uncorr;
	/** Total number of received FEC code words.*/
	uint64_t fec_words_total;
	/** Total number of transmitted GEM frames (not including GEM Idle
	    frames).*/
	uint64_t tx_gem_frames_total;
	/** Total number of transmitted GEM payload bytes.*/
	uint64_t tx_gem_bytes_total;
	/** Total number of transmitted GEM Idle Frames Counter.*/
	uint64_t tx_gem_idle_frames_total;
	/** Received GEM frames/packets.*/
	uint64_t rx_gem_frames_total;
	/** Received GEM payload bytes.*/
	uint64_t rx_gem_bytes_total;
	/** dropped GEM frames.*/
	uint64_t rx_gem_frames_dropped;
	/** Dropped bad OMCI frames/packets.*/
	uint64_t omci_drop;
	/** All dropped frames/packets, due to FCS errors, reassembly errors,
	    undersize error, oversize error,
	    or invalid GEM header; does not include the dropped OMCI
	    frames/packets.*/
	uint64_t drop;
	/** Oversized frames/packets.*/
	uint64_t rx_oversized_frames;
	/** Count all TCONTs of this ONU.*/
	uint64_t allocations_total;
	/** GTC Rejected TCONT Counter.*/
	uint64_t allocations_lost;
	/** v7.5.1: additional counter (exact semantics unknown). */
	uint64_t _v751_reserved;
};

/** GPON TC layer hardware counter access.
    Used by \ref FIO_GTC_COUNTER_GET.
*/
struct gtc_counters {
	/** Specified interval to retrieve GTC counters.*/
	struct gtc_cnt_interval interval;
	/** GTC counters values.*/
	struct gtc_cnt_value val;
};

/** Union to retrieve GTC counters.
    Used by \ref FIO_GTC_COUNTER_GET.
*/
union gtc_counter_get_u {
	/** Specified interval to retrieve GTC counters.*/
	struct gtc_cnt_interval in;
	/** Retrieved GTC counters.*/
	struct gtc_counters out;
};

/** Structure contains information about the last PLOAM status change into or
    out of state O5.
    Used by \ref FIO_GTC_LAST_CHANGE_TIME_GET.
*/
struct gtc_last_change_time {
	/** Time since the last change. */
	uint32_t time;
};

/** Structure contains information received through the latest PON ID PLOAMd
    message Used by \ref FIO_GTC_PON_ID_GET.
*/
struct gtc_pon_id {
	/** Presence of a reach extender.
	- false: No reach extender is present in the ODN.
	- true: A reach extender is present in the ODN. */
	uint8_t reach_extender_present;
	/** ODN class
	- 0: Class A
	- 1: Class B
	- 2: Class B+
	- 3: Class C
	- 4: Class C+ */
	uint8_t odn_class;
	/** OLT transmit optical power. */
	uint16_t olt_tx_power;
	/** PON identifier string */
	uint8_t pon_id[7];
};

/* IOCTL Command Declaration - GTC
   =============================== */

/** magic number */
#define GTC_MAGIC 3

/**
   Initialize the GPON Transmission Convergence layer (GTC) hardware.

   This function is called once after power-up reset to initialize the GTC
   hardware module. Several parameters are set through this function that are
   specific for the applications implementation. These can not be changed
   during operation.

   \param gtc_init_data Pointer to \ref gtc_init_data.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_INIT _IOW(GTC_MAGIC, 0x00, struct gtc_init_data)

/**
   Configure the GPON TC layer hardware.

   This function is called at least once after power-up reset to configure the
   GTC hardware module. The parameters are specific for the given implementation
   but may be changed during operation (for example, through OMCI).

   \param gtc_cfg Pointer to \ref gtc_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_CFG_SET _IOW(GTC_MAGIC, 0x01, struct gtc_cfg)

/**
   Read the GPON TC layer hardware configuration.

   This function can be read at any time after GTC initialization. It reflects
   the settings that have been applied through \ref FIO_GTC_CFG_SET.

   \param gtc_cfg Pointer to \ref gtc_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_CFG_GET _IOR(GTC_MAGIC, 0x02, struct gtc_cfg)

/**
   Read the GPON upstream frame header pattern configuration.

   This function delivers the setting of the upstream overhead that has been
   defined by the PLOAM state machine software during the PLOAM-based connection
   setup. This is intended to be used for debug purposes. The pattern itself can
   not be modified through a "set" driver function.

   \param gtc_us_header_cfg Pointer to \ref gtc_us_header_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_US_HEADER_CFG_GET \
				_IOR(GTC_MAGIC, 0x03, struct gtc_us_header_cfg)

/**
   GTC hardware status readout.

   This function provides non-critical status information related to the GTC
   hardware module.

   \param gtc_status Pointer to \ref gtc_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_STATUS_GET _IOR(GTC_MAGIC, 0x04, struct gtc_status)

/**
   GTC hardware alarm indication.

   This function provides critical status information related to the GTC
   hardware or the GPON logical link.
   It indicates all alarms that have been found since the previous call
   of this function. Persisting alarms are indicated through this function each
   time the function is called. To check if an alarm still persists, the
   function shall be called twice.

   \param gtc_alarm Pointer to \ref gtc_alarm.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_ALARM_GET _IOR(GTC_MAGIC, 0x05, struct gtc_alarm)

/**
   Read the ranging time values.

   This function displays the ranging time that has been assigned by the OLT to
   the ONU through the ranging process. If ranging has not yet been established,
   the pre-ranged value is returned.

   \param gtc_ranging_val Pointer to \ref gtc_ranging_val.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_RANGING_GET _IOR(GTC_MAGIC, 0x06, struct gtc_ranging_val)

/**
   Define the "Dying Gasp" PLOAMu message and select optional hardware handling.

   There are two modes to generate a "Dying Gasp" PLOAM message:
   1. Hardware mode - Software pre-configures the "Dying Gasp" message in
                      dedicated registers. Upon voltage drop, the message
                      is automatically sent without the need for software
                      handling. This is the preferred method.
                      The default value set by the FIO_GTC_INIT function is:
                      0x[ONU ID]
                      0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                      The ONU ID (first byte) is defined during the GPON
                      connection setup by the PLOAM state machine. This value
                      and also the message identifier (second byte, 0x03) can
                      not be changed.

   2. Software mode - Voltage drop detection triggers an NMI, software writes
                      the message contents to the PLOAMu FIFO.
                      This method can be used if beside the sending of the
                      "Dying Gasp" message other actions are intended.

   \param gtc_dgasp_msg Pointer to \ref gtc_dgasp_msg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.
*/
#define FIO_GTC_DYING_GASP_CFG_SET _IOW(GTC_MAGIC, 0x07, struct gtc_dgasp_msg)

/**
   Read the "Dying Gasp" PLOAMu message configuration.

   \param gtc_dgasp_msg Pointer to \ref gtc_dgasp_msg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_DYING_GASP_CFG_GET _IOR(GTC_MAGIC, 0x08, struct gtc_dgasp_msg)

/**
   Define the "No Message" PLOAMu message.
   This function is used to define the contents of the "No Message" PLOAMu
   message. The default value set by the FIO_GTC_INIT function is:
   0x[ONU ID] 0x04 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00

   The ONU ID (first byte) is defined during the GPON connection setup by the
   PLOAM state machine. This value and also the message identifier (second byte,
   0x04) can not be changed.

   \param gtc_no_msg_msg Pointer to \ref gtc_no_msg_msg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_NO_MESSAGE_CFG_SET _IOW(GTC_MAGIC, 0x09, struct gtc_no_msg_msg)

/**
   Read the "No Message" PLOAMu message configuration.

   \param gtc_no_msg_msg Pointer to \ref gtc_no_msg_msg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_NO_MESSAGE_CFG_GET _IOR(GTC_MAGIC, 0x0A, struct gtc_no_msg_msg)

/**
   GPON power saving mode selection. The following modes are provided:
   - Normal operation
   - Fast Sleep
   - Deep Sleep
   - Dozing
   - Power Shedding

   \param gtc_op_mode Pointer to \ref gtc_op_mode.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_POWER_SAVING_MODE_SET _IOW(GTC_MAGIC, 0x0B, struct gtc_op_mode)

/**
   GPON power saving mode readout, read back the current power saving mode.

   \param gtc_op_mode Pointer to \ref gtc_op_mode.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_POWER_SAVING_MODE_GET _IOR(GTC_MAGIC, 0x0C, struct gtc_op_mode)

/**
   Send a PLOAMu upstream message.
   This function should not interfere with the messages that are sent by the
   PLOAM state machine autonomously. It is provided to send additional messages
   that are not part of the normal PLOAM connection setup process. It shall be
   used for these messages only:
   - Dying Gasp
   - Physical Equipment Error

   \param gtc_ploamu Pointer to \ref gtc_ploamu.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_PLOAM_SEND _IOW(GTC_MAGIC, 0x0D, struct gtc_ploamu)

/**
   Receive a PLOAMd downstream message.
   This function should not interfere with the messages that are received by the
   PLOAM state machine autonomously. This is for debug purposes only.

   \param gtc_ploamd Pointer to \ref gtc_ploamd.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
/* REMOVED in v7.5.1 — FIO_GTC_PLOAM_RECEIVE no longer exists in the
   shipping kernel. All subsequent cmd numbers shifted by -1. */
/* #define FIO_GTC_PLOAM_RECEIVE _IOR(GTC_MAGIC, 0x0E, struct gtc_ploamd) */

/**
   Read the GPON TC layer counters.
   This function delivers the hardware counter values that are related to the
   GPON TC layer:
   - Received BIP errors
   - Received correctable HEC errors
   - Received uncorrectable HEC errors
   - Received correctable bandwidth map errors
   - Received uncorrectable bandwidth map errors
   - Number of corrected FEC bytes
   - Number of corrected FEC code words
   - Number of uncorrectable FEC code words
   - Total number of received FEC code words
   - Total number of transmitted GEM frames (not including GEM Idle frames)
   - Total number of transmitted GEM payload bytes
   - Total number of transmitted GEM idle frames
   - Received GEM frames/packets
   - Received GEM payload bytes
   - Dropped GEM frames
   - Dropped bad OMCI frames/packets
   - Oversized frames/packets
   - All dropped frames/packets, due to FCS errors, reassembly errors, undersize
      error, oversize error, or invalid GEM header; does not include the dropped
      OMCI frames/packets.

   \param gtc_cnt_value Pointer to \ref gtc_counter_get_u.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - GTC_STATUS_COUNTER_ERR: if one of the counters suffered from an overflow
                                 event
*/
#define FIO_GTC_COUNTER_GET _IOWR(GTC_MAGIC, 0x0E, union gtc_counter_get_u)

/**
   This function writes the counter thresholds that are related
   to the GPON TC layer.

   \param gtc_cnt_value Pointer to \ref gtc_cnt_value.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_COUNTER_THRESHOLD_SET \
				_IOW(GTC_MAGIC, 0x0F, struct gtc_cnt_value)

/**
   This function reads back the counter threshold values that are
   related to the GPON TC layer.

   \param gtc_cnt_value Pointer to \ref gtc_cnt_value.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_COUNTER_THRESHOLD_GET \
				_IOR(GTC_MAGIC, 0x10, struct gtc_cnt_value)

/**
   This function reads the counter threshold alarms that are related to the
   GPON TC layer.

   \param gtc_cnt_value Pointer to \ref gtc_cnt_value.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_TCA_GET _IOR(GTC_MAGIC, 0x11, struct gtc_cnt_value)

/**
   GPON counter reset.
   Calling this function clears all counters that are
   covered by \ref FIO_GTC_COUNTER_GET.

   \param No parameter is used, set to 0.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
*/
#define FIO_GTC_COUNTER_RESET _IOW(GTC_MAGIC, 0x12, struct gtc_cnt_interval)

/**
   Set the serial number.
   This functions defines the serial number that is used to identify the ONU
   through the PLOAM-based connection setup with the OLT.

   \param gtc_serial_num Pointer to \ref gtc_serial_num.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_SERIAL_NUMBER_SET _IOW(GTC_MAGIC, 0x13, struct gtc_serial_num)

/**
   Get the serial number.
   This functions reads back the serial number that is used to identify the ONU
   through the PLOAM-based connection setup with the OLT.

   \param gtc_serial_num Pointer to \ref gtc_serial_num.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_SERIAL_NUMBER_GET _IOR(GTC_MAGIC, 0x14, struct gtc_serial_num)

/**
   Set the password string in the GTC hardware. This function is used if the
   customer or maintenance staff needs to set a password to complete the
   ONU installation.

   This function does not store the password in a non-volatile memory.
   This is up to the operating software of the ONU.

   \param gtc_password Pointer to \ref gtc_password.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_PASSWORD_SET _IOW(GTC_MAGIC, 0x15, struct gtc_password)

/**
   Read back the password string from the hardware. This is a debug function.
   \warning For security reasons, this function should not be provided in a
   productive version of the ONU software.

   \param gtc_password Pointer to \ref gtc_password.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_PASSWORD_GET _IOR(GTC_MAGIC, 0x16, struct gtc_password)

/**
   Set a fixed upstream allocation time slot. This can be used for system debug
   purposes such as rogue ONU isolation.
   \warning This function shall be used carefully, as it can break the upstream
            traffic of other ONUs that are connected to the same ODN.

   \param gtc_forced_alloc Pointer to \ref gtc_forced_alloc.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_FORCED_ALLOC_SET \
				_IOW(GTC_MAGIC, 0x17, struct gtc_forced_alloc)

/**
   Read the setting of the fixed upstream allocation time slot.

   \param gtc_forced_alloc Pointer to \ref gtc_forced_alloc.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_FORCED_ALLOC_GET \
				_IOR(GTC_MAGIC, 0x18, struct gtc_forced_alloc)

/**
   Configure the bandwidth map trace function (BWMT).
   This function is provided for debug purposes and allows to check for
   incorrectly received bandwidth map allocations.

   \param gtc_bwmt_cfg Pointer to \ref gtc_bwmt_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_BWMT_CFG_SET _IOW(GTC_MAGIC, 0x19, struct gtc_bwmt_cfg)

/**
   Read back the setting of the bandwidth map trace configuration.

   \param gtc_bwmt_cfg Pointer to \ref gtc_bwmt_cfg.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_BWMT_CFG_GET _IOR(GTC_MAGIC, 0x1A, struct gtc_bwmt_cfg)

/**
   Arm the bandwidth map trace function (BWMT).
   This function is used to prepare the trigger for a bandwidth map trace.

   \param gtc_bwmt_next_data Pointer to \ref gtc_bwmt_next_data.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_BWMT_NEXT _IOW(GTC_MAGIC, 0x1B, struct gtc_bwmt_next_data)

/**
   Get the result of the bandwidth map trace function.
   This function delivers the bandwidth map trace that has been stored through
   the latest acquisition.

   \param gtc_bwmt_status Pointer to \ref gtc_bwmt_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_BWMT_STATUS_GET _IOR(GTC_MAGIC, 0x1C, struct gtc_bwmt_status)

/**
   This function provides the time since the last PLOAM status change into or
   out of state O5.
   Corresponds to TR-181 requirement for the optical link:
   "The accumulated time in seconds since the optical interface entered its
   current operational state."

   \param gtc_last_change_time Pointer to \ref gtc_last_change_time.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_LAST_CHANGE_TIME_GET \
			_IOR(GTC_MAGIC, 0x1D, struct gtc_last_change_time)

/**
   This function provides the information received through the latest PON ID
   PLOAMd message.

   \param gtc_pon_id Pointer to \ref gtc_pon_id.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref onu_errorcode.

   \return Return value as follows:
   - 0: if successful
   - An error code in case of error.

*/
#define FIO_GTC_PON_ID_GET _IOR(GTC_MAGIC, 0x1E, struct gtc_pon_id)

/*! @} */

/*! @} */

EXTERN_C_END
#ifdef __PACKED_DEFINED__
#  if !defined (__GNUC__) && !defined (__GNUG__)
#    pragma pack()
#  endif
#  undef __PACKED_DEFINED__
#  undef __PACKED__
#endif
#endif				/* _drv_onu_gtc_interface_h_ */
