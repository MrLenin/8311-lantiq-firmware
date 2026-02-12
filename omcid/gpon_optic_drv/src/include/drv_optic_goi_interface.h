/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_goi_interface.h
   This is the GPON Optical Interface header file,
   used for the FALC(tm) ON GPON Optical Interface (GOI) driver.
*/
#ifndef _drv_optic_goi_interface_h_
#define _drv_optic_goi_interface_h_

#include "drv_optic_std_defs.h"
/*
#include "drv_optic_resource.h"
*/
#include "drv_optic_interface.h"


#ifndef __PACKED__
#  if defined (__GNUC__) || defined (__GNUG__)
   /* GNU C or C++ compiler */
#    define __PACKED__ __attribute__ ((packed))
#  else
   /* Byte alignment adjustment */
#    pragma pack(1)
#    if !defined (_PACKED_)
#      define __PACKED__        /* nothing */
#    endif
#  endif
#  define __PACKED_DEFINED__
#endif

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI Optical Interface API Reference
   @{
*/

/** \defgroup OPTIC_GOI Optical Interface Global Functions

    This chapter describes the software interface to access and configure the
    GPON Optical Interface (GOI PMA/PMD).
   @{
*/


#define OPTIC_CONFIGREAD_MAX  11
#define OPTIC_TABLEREAD_MAX    9


/* Enumeration Type Definitions - GOI (GPON Optical Interface)
   =========================================================== */



/* Table Definitions - GOI (GPON Optical Interface)
   ========================================================= */

/** Transfer table: Pth, MPD responsivity, Rssi 1490, Rssi 1550, Rf 1550 */
struct optic_tt_factor {
	/** Laser temperature in K. */
	uint16_t temp;
	/** Correction factor, shift by OPTIC_FLOAT2INTSHIFT_CORRFACTOR */
	uint16_t corr_factor;
	/** Data quality, coded as given by \ref optic_tableval_quality. */
	uint8_t quality;
};

/** Transfer table: Ith/SE */
struct optic_tt_laserref {
	/** Laser temperature in K. */
	uint16_t temp;
	/** Laser Threshold (Ith in uA),
	    shift by OPTIC_FLOAT2INTSHIFT_CURRENT */
	uint16_t ith;
	/** Laser Slope Efficiency (SE in uW/mA),
	    shift by OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY */
	uint16_t se;
	/** Laser operating time, in seconds. */
	uint32_t age;
	/** Data quality, coded as given by \ref optic_tableval_quality. */
	uint8_t quality;
};

/** Transfer table: Ibias/Imod */
struct optic_tt_ibiasimod {
	/** Laser temperature in K. */
	uint16_t temp;
	/** Bias current (Ibias in mA),
	    shift by OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t ibias[3];
	/** Modulation current (Imod in mA),
	    shift by OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t imod[3];
	/** Laser operating time, in seconds. */
	uint32_t age;
	/** Data quality, coded as given by \ref optic_tableval_quality. */
	uint8_t quality;
};

/** Transfer table: VAPD */
struct optic_tt_vapd {
	/** Laser temperature in K. */
	uint16_t temp;
	/** APD supply voltage (Vapd in V),
	    shift by OPTIC_FLOAT2INTSHIFT_VOLTAGE. */
	uint16_t vref;
	/** APD duty cycle saturation maximum. */
	uint8_t sat;
	/** Data quality, coded as given by \ref optic_tableval_quality. */
	uint8_t quality;
};

/** Transfer table: Temperature translation */
struct optic_tt_temptrans {
	/** Laser temperature in K. */
	uint16_t temp;
	/** Corrected laser temperature in K. */
	uint16_t temp_corr;
	/** Data quality, coded as given by \ref optic_tableval_quality. */
	uint8_t quality;
};

/** GOI configuration and operation parameters. */
struct optic_goi_config {
	/** Time interval to check for a temperature change, in ms. */
	uint16_t temperature_check_time;
	/** Threshold to force MPD offset cancelation and gain correction. */
	uint8_t temperature_thres_mpdcorr;

	/** Laser age update cycle [seconds]. */
	uint16_t update_laser_age;
	/** Laser age offset [seconds]. */
	uint32_t laser_age;

	/** Transmit FIFO delay enable. */
	uint16_t delay_tx_enable;
	/** Transmit FIFO delay disable. */
	uint16_t delay_tx_disable;
	/** Transmit FIFO buffer size (delay, in number of
	    bits at 1.244 Gbit/s). */
	uint16_t size_tx_fifo;

	/** Start temperature = Tref [K] */
	uint16_t temp_ref;

	/** Receive path pin polarity (BO_RXDP, BO_RXDN).
	- true: Use the polarity as described in the hardware pin description.
	- false: Exchange the functionality of BO_RXDP and BO_RXDN. */
	bool rx_polarity_regular;
	/** Transmit bias path pin polarity (BO_BIAS, BO_CBIAS).
	- true: Use the polarity as described in the hardware pin description.
	- false: Exchange the functionality of BO_BIAS and BO_CBIAS. */
	bool bias_polarity_regular;
	/** Transmit modulation path pin polarity (BO_MOD, BO_CMOD).
	- true: Use the polarity as described in the hardware pin description.
	- false: Exchange the functionality of BO_MOD and BO_CMOD. */
	bool mod_polarity_regular;

	/** Alarm temperature threshold to set a yellow alarm, in K. */
	uint16_t temp_alarm_yellow_set;
	/** Alarm temperature threshold to clear a yellow alarm, in K. */
	uint16_t temp_alarm_yellow_clear;
	/** Alarm temperature threshold to set a red alarm, in K. */
	uint16_t temp_alarm_red_set;
	/** Alarm temperature threshold to clear a red alarm, in K. */
	uint16_t temp_alarm_red_clear;

} __PACKED__;

/** Optical interface range definition for
    temperatures, currents, and voltages. */
struct optic_range_config {
	/** Minimum temperature covered by the temperature tables, in K */
	uint16_t tabletemp_extcorr_min;
	/** Maximum temperature covered by the temperature tables, in K */
	uint16_t tabletemp_extcorr_max;
	/** Minimum temperature covered by the temperature translation
	    table, in K */
	uint16_t tabletemp_extnom_min;
	/** Maximum temperature covered by the temperature translation
	    table, in K */
	uint16_t tabletemp_extnom_max;
	/** Minimum corrected internal temperature, in K */
	uint16_t tabletemp_intcorr_min;
	/** Maximum corrected internal temperature, in K */
	uint16_t tabletemp_intcorr_max;
	/** Minimum nominal internal temperature, in K */
	uint16_t tabletemp_intnom_min;
	/** Maximum nominal internal temperature, in K */
	uint16_t tabletemp_intnom_max;

	/** Maximum Ibias, <<OPTIC_FLOAT2INTSHIFT_CURRENT, in mA */
	uint16_t ibias_max;
	/** Maximum Imod, <<OPTIC_FLOAT2INTSHIFT_CURRENT, in mA */
	uint16_t imod_max;
	/** Maximum Ibias+Imod, <<OPTIC_FLOAT2INTSHIFT_CURRENT, in mA */
	uint16_t ibiasimod_max;
	/** Bias/Modulation integration coefficient maximum value */
	uint8_t intcoeff_max[2];

	/** Minimum APD voltage, <<OPTIC_FLOAT2INTSHIFT_VOLTAGE, in V */
	uint16_t vapd_min;
	/** Maximum APD voltage, <<OPTIC_FLOAT2INTSHIFT_VOLTAGE, in V */
	uint16_t vapd_max;
	/** Minimum duty cycle saturation */
	uint8_t sat_min;
	/** Maximum duty cycle saturation */
	uint8_t sat_max;
	/** Minimum Vcore voltage, <<OPTIC_FLOAT2INTSHIFT_VOLTAGE, in V */
	uint16_t vcore_min;
	/** Maximum Vcore voltage, <<OPTIC_FLOAT2INTSHIFT_VOLTAGE, in V */
	uint16_t vcore_max;
	/** Minimum Vcore voltage, <<OPTIC_FLOAT2INTSHIFT_VOLTAGE, in V */
	uint16_t vddr_min;
	/** Maximum Vcore voltage, <<OPTIC_FLOAT2INTSHIFT_VOLTAGE, in V */
	uint16_t vddr_max;
	/** Modulation overcurrent threshold */
	uint16_t oc_imod_thr;
	/** Bias overcurrent threshold */
	uint16_t oc_ibias_thr;
	/** Bias and Imod sum overcurrent threshold */
	uint16_t oc_ibias_imod_thr;
} __PACKED__;


/** Table transfer parameters.
    Used to copy tables between driver and application. */
struct optic_transfer_table_set {
	/** Type of table to transfer. */
	enum optic_tabletype table_type;
	/** Number of table entries to transfer. */
	uint16_t table_depth;
	/** Pointer to memory where the table is stored. */
	void *p_data;
} __PACKED__;

/** Table transfer control. */
struct optic_transfer_table_get_in {
	/** Type of table to transfer. */
	enum optic_tabletype table_type;
	/** Quality of entries to read back:
	    typically  (>=) OPTIC_TABLEQUAL_MEAS. */
	uint8_t quality;
	/** Number of table entries, for which memory is allocated. */
	uint16_t table_depth;
	/** Pointer to memory where table is stored. */
	void *p_data;
} __PACKED__;

/** Table transfer result. */
struct optic_transfer_table_get_out {
	/** Number of table entries that have been written. */
	uint16_t table_depth;
} __PACKED__;

/** GPON optical layer table transfer from driver to application.
    Used by \ref FIO_GOI_TABLE_GET.
    The tables should be configured at initialization time and read back by the
    application periodically. */
union optic_transfer_table_get {
	/** Input value. */
	struct optic_transfer_table_get_in in;
	/** Output value. */
	struct optic_transfer_table_get_out out;
};

/** Optical interface status history. Used by \ref FIO_GOI_STATUS_GET. */
struct optic_status {
	/** Optical interface ready to be used */
	uint8_t goi_ready;
	/** Basic operation mode matching to the external optical
	    components (OMU or BOSA). */
	uint8_t mode;
	/** Receiver enable,
	    indicates if the optical receiver has been enabled either by
	    \ref FIO_GOI_OMU_RX_ENABLE or \ref FIO_BOSA_RX_ENABLE.
	    This status information is also
	    available in \ref FIO_OMU_RX_STATUS_GET and
	    \ref FIO_BOSA_RX_STATUS_GET. */
	bool rx_enable;
	/** Transmitter enable,
	    indicates if the optical transmitter has been enabled either by
	    \ref FIO_OMU_TX_ENABLE or \ref FIO_BOSA_TX_ENABLE.
	    This status information is also available in
	    \ref FIO_OMU_TX_STATUS_GET and \ref FIO_BOSA_TX_STATUS_GET. */
	bool tx_enable;
	/** Loss of signal,
	    the optical signal level is insufficient, indicated by the optical
	    module's "signal detect" line.
	    - false: The receive signal level is ok.
	    - true: The receive signal has been lost
		    (insufficient power level). */
	bool loss_of_signal;
}/* __PACKED__*/;

/** Optical interface status history. Used by \ref FIO_GOI_EXT_STATUS_GET. */
struct optic_ext_status {
	/** Chip version id (used for debugging only). */
	uint16_t chip;
	/** Fusing format (used for debugging only). */
	uint8_t fuse_format;
	/** Optical interface state history (used for debugging only). */
	uint8_t state_history[OPTIC_STATE_HISTORY_DEPTH];
	/** Debug information. */
	uint8_t table_read[OPTIC_TABLEREAD_MAX];
	/** Debug information. */
	uint8_t config_read[OPTIC_CONFIGREAD_MAX];
	/** Basic operation mode. Must be selected according to the external
	    optical components (OMU or BOSA). */
	uint8_t mode;
	/** Receiver offset cancellation value (only available in BOSA mode). */
	int16_t rx_offset;
	/** Flexible maximum modulation current definition [mA]
	    << OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t mod_max;
	/** Flexible maximum bias current definition  [mA]
	    << OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t bias_max;
	/** Receiver enable,
	    indicates if the optical receiver has been enabled either by
	    \ref FIO_GOI_OMU_RX_ENABLE or \ref FIO_BOSA_RX_ENABLE.
	    This status information is also available in
	    \ref FIO_OMU_RX_STATUS_GET and \ref FIO_BOSA_RX_STATUS_GET. */
	bool rx_enable;
	/** Transmitter enable,
	    indicates if the optical transmitter has been enabled either by
	    \ref FIO_OMU_TX_ENABLE or \ref FIO_BOSA_TX_ENABLE.
	    This status information is also available in
	    \ref FIO_OMU_TX_STATUS_GET and \ref FIO_BOSA_TX_STATUS_GET. */
	bool tx_enable;
	/** Actual transmit laser bias current [mA]
	    << OPTIC_FLOAT2INTSHIFT_CURRENT.
	    This status information is also available in
	    \ref FIO_BOSA_TX_STATUS_GET. */
	uint16_t bias_current;
	/** Actual transmit laser modulation current [mA]
	    << OPTIC_FLOAT2INTSHIFT_CURRENT.
	    This status information is also available in
	    \ref FIO_BOSA_TX_STATUS_GET. */
	uint16_t modulation_current;

	/** Measured RSSI 1490 receive power [mW]
	    << OPTIC_FLOAT2INTSHIFT_POWER */
	uint16_t meas_power_1490_rssi;
	/** Measured RSSI 1550 receive power [mW]
	    << OPTIC_FLOAT2INTSHIFT_POWER */
	uint16_t meas_power_1550_rssi;
	/** Measured RF 1550 receive power [mW]
	    << OPTIC_FLOAT2INTSHIFT_POWER */
	uint16_t meas_power_1550_rf;

	/** Measured RSSI 1490 voltage -> for receive power calculation [V]
	    << OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t meas_voltage_1490_rssi;
	/** Measured RSSI 1490 current -> for receive power calculation [mA]
	    << OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t meas_current_1490_rssi;
	bool meas_current_1490_rssi_is_positive;
	/** Measured RF 1550 voltage -> for receive power calculation [V]
	    << OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t meas_voltage_1550_rf;
	/** Measured RSSI 1550 voltage -> for receive power calculation [V]
	    << OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t meas_voltage_1550_rssi;

	/** PLL lock status (to clock reference),
		- false: The PLL is unlocked.
		- true: The PLL is locked. */
	bool pll_lock_status;
	/** Loss of signal,
	    the optical signal level is insufficient, indicated by the optical
	    module's "signal detect" line.
	    - false: The receive signal level is ok.
	    - true: The receive signal has been lost
		    (insufficient power level). */
	bool loss_of_signal;
	/** Receive CDR status (Clock and Data Recovery),
		- false: The CDR is locked.
		- true: The CDR is unlocked. */
	bool loss_of_lock;

	/** Temperature yellow alarm.
		- false: No yellow alarm.
		- true: Yellow temperature alarm is active. */
	bool temp_alarm_yellow;
	/** Temperature red alarm.
	    - false: No red alarm.
	    - true: Red temperature alarm is active. */
	bool temp_alarm_red;
}/* __PACKED__*/;

/** Laser Training Sequence (LTS) configuration parameters.
	 Used by \ref FIO_GOI_LTS_CFG_SET and \ref FIO_GOI_LTS_CFG_GET. */
struct optic_lts_config {
	/** Activation flag for Laser Training Sequence .
	- false: trigger is not allowed
	- true: LTS can be triggered */
	bool enable;
	/** Pattern length for LTS, given in number of bytes, up to 78 is
	    allowed. */
	uint8_t pattern_length;
	/** Pattern definition for Plsu. */
	uint8_t pattern[78];
} __PACKED__;

/** DAC1550 (Video DAC) configuration parameters.
	 Used by \ref FIO_GOI_VIDEO_CFG_SET and \ref FIO_GOI_VIDEO_CFG_GET. */
struct optic_video_config {
	/** 9-bit word to program the R2R video DAC. */
	uint16_t video_word;
	/** Output range
	- true: Range is low = 0.2 V - 1.4 V.
	- false: Range is high = 0.5 V - 2.8 V. */
	bool video_range_low;
} __PACKED__;

/** Video DAC status.
	 Used by \ref FIO_GOI_VIDEO_STATUS_GET. */
struct optic_video_status {
	/** Activation flag for the video DAC.
	- false: Disabled.
	- true: Enabled. */
	bool video_enable;
} __PACKED__;

/** Set the optic measurement interval
	 Used by \ref FIO_GOI_MM_INTERVAL_SET. */
struct optic_mm_interval_config {
	/** measurement interval */
	uint32_t measure_interval;
} __PACKED__;

/* IOCTL Command Declaration - GOI
   =============================== */
/* magic number: see drv_optic_interface.h */

/**
   Initialize the GPON optical interface layer hardware.
   This function provides a basic initialization of the GOI hardware modules
   and leaves all settings in a defined state. This functions must be called
   even after a hardware reset before any other GOI function is executed.

   \param optic_init Pointer to \ref optic_init.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_INIT _IO(OPTIC_GOI_MAGIC, 0)

/**
   Set GOI global configurations and prepare internal tables.

   \param optic_goi_config Pointer to \ref optic_goi_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_CFG_SET _IOW(OPTIC_GOI_MAGIC, 1, struct optic_goi_config)

/**
   Returns configuration settings which were configured by
   \ref FIO_GOI_CFG_SET

   \param optic_goi_config Pointer to \ref optic_goi_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_CFG_GET _IOR(OPTIC_GOI_MAGIC, 2, struct optic_goi_config)

/**
   Set global range configurations.

   \param optic_range_config Pointer to \ref optic_range_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_RANGE_CFG_SET _IOW(OPTIC_GOI_MAGIC, 3, struct optic_range_config)

/**
   Returns global range configurations.

   \param optic_range_config Pointer to \ref optic_range_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_RANGE_CFG_GET _IOR(OPTIC_GOI_MAGIC, 4, struct optic_range_config)

/**
   Configure a specifies table.

   \param optic_transfer_table_set Pointer to \ref optic_transfer_table_set.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_TABLE_SET _IOW(OPTIC_GOI_MAGIC, 5, struct optic_transfer_table_set)

/**
   Read a specified table from driver.

   \param optic_transfer_table_get Pointer to \ref optic_transfer_table_get.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_TABLE_GET _IOWR(OPTIC_GOI_MAGIC, 6, union optic_transfer_table_get)

/**
   Retrieve global optical interface status information.
   This functions provides information that is related to the overall GOI module.
   A part (but not all) of this information is also contained in the specific
   sub-module status functions.
   For more information see
   - \ref FIO_OMU_RX_STATUS_GET,
   - \ref FIO_OMU_TX_STATUS_GET,
   - \ref FIO_BOSA_RX_STATUS_GET,
   - \ref FIO_BOSA_TX_STATUS_GET, and
   - \ref FIO_BERT_STATUS_GET.

   \param optic_status Pointer to \ref optic_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_STATUS_GET _IOR(OPTIC_GOI_MAGIC, 7, struct optic_status)

/**
   Set the configuration for the LTS buffer (Laser Training Sequence).
   This defines a pattern that can be used for transmit laser training.

   \param optic_lts_config Pointer to \ref optic_lts_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_LTS_CFG_SET _IOW(OPTIC_GOI_MAGIC, 8, struct optic_lts_config)

/**
   Read back the configuration for the LTS buffer (Laser Training Sequence).
   This reads back a pattern that can be used for transmit laser training.

   \param optic_lts_config Pointer to \ref optic_lts_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_LTS_CFG_GET _IOR(OPTIC_GOI_MAGIC, 9, struct optic_lts_config)

/**
   Set the configuration for the Video DAC.

   \param optic_video_config Pointer to \ref optic_video_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_VIDEO_CFG_SET _IOW(OPTIC_GOI_MAGIC, 10, struct optic_video_config)

/**
   Read back the configuration for Video DAC.

   \param optic_lts_config Pointer to \ref optic_video_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_VIDEO_CFG_GET _IOR(OPTIC_GOI_MAGIC, 11, struct optic_video_config)

/**
   Activate the Video DAC (DAC 1550).

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_VIDEO_ENABLE _IO(OPTIC_GOI_MAGIC, 12)

/**
   Deactivate the Video DAC (DAC 1550).

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_VIDEO_DISABLE _IO(OPTIC_GOI_MAGIC, 13)

/**
   Read back activation status of the Video DAC (dac 1550).

   \param optic_video_status Pointer to \ref optic_video_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_VIDEO_STATUS_GET _IOR(OPTIC_GOI_MAGIC, 14, \
	struct optic_video_status)

/**
   Retrieve global optical interface extended status information.
   This functions provides information that is related to the overall
   GOI module. A part (but not all) of this information is also contained in
   the specific sub-module status functions.
   For more information see
   - \ref FIO_OMU_RX_STATUS_GET,
   - \ref FIO_OMU_TX_STATUS_GET,
   - \ref FIO_BOSA_RX_STATUS_GET,
   - \ref FIO_BOSA_TX_STATUS_GET, and
   - \ref FIO_BERT_STATUS_GET.

   \param optic_status Pointer to \ref optic_ext_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_GOI_EXT_STATUS_GET _IOR(OPTIC_GOI_MAGIC, 15, \
	struct optic_ext_status)

#define FIO_GOI_MM_INTERVAL_SET _IOW(OPTIC_GOI_MAGIC, 16, struct optic_mm_interval_config)

#define OPTIC_GOI_MAX  17

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
#endif                          /* _drv_optic_goi_interface_h_ */
