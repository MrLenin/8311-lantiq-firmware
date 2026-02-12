/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_cal_interface.h
   This is the GPON Optical Interface header file,
   used for the FALC(tm) ON GPON ONU driver, Calibration block.
*/
#ifndef _drv_optic_cal_interface_h_
#define _drv_optic_cal_interface_h_

#include "drv_optic_std_defs.h"


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

/** \defgroup GPON_CAL Calibration and Debug Interface

    This chapter describes the software interface to access the calibration
    functions for the GPON Optical Interface (GOI).
    Some debug functions are provided as well.
   @{
*/

/** This enumeration is used to indicate the quality of operational data. **/
enum optic_quality {
	/** The data values are based on a configuration pre-set. */
	OPTIC_QUALITY_CONFIG,
	/** The data quality is based on individual device characterization. */
	OPTIC_QUALITY_CALIBRATION
};

/** Debug mode control and status. used by \ref FIO_CAL_DEBUG_STATUS_GET. */
struct optic_debug_status {
	/** Debug mode status.
	- false: Debug mode is disabled
	- true:  Debug mode is enabled. */
	bool debug_enable;
} __PACKED__;

/** Time stamp for laser age calculation. Used by \ref FIO_CAL_LASER_AGE_GET. */
struct optic_timestamp {
	/** Laser age [s]. */
	uint32_t seconds;
} __PACKED__;

/** Laser threshold current and slope efficiency (Ith/SE) set parameters.
    Used by \ref FIO_CAL_LASERREF_TABLE_SET
    and \ref FIO_CAL_LASERREF_TABLE_GET. */
struct optic_laserref_set {
	/** External temperature (corrected) in K. */
	uint16_t temperature;
	/** laser threshold current value in mA, integer data format
	    according to << \ref OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t ith;
	/** Slope efficiency value in uW/mA, integer data format according to
	    << \ref OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY. */
	uint16_t se;
} __PACKED__;

/** Ith/SE input parameters.
    Used by \ref FIO_CAL_LASERREF_TABLE_SET. */
struct optic_laserref_get_in {
	/** External temperature (corrected) in K. */
	uint16_t temperature;
} __PACKED__;

/** Ith/SE output parameters.
    Used by \ref FIO_CAL_LASERREF_TABLE_GET.*/
struct optic_laserref_get_out {
	/** laser threshold value [mA], integer data format according to
	<< \ref OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t ith;
	/** Slope efficiency value [uW/mA], integer data format according to
	<< \ref OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY. */
	uint16_t se;
	/** Timestamp [s]. */
	uint32_t age;
	/** Data quality flag. */
	enum optic_tableval_quality quality;
} __PACKED__;

/** Ith/SE get parameters. Used by
   \ref FIO_CAL_LASERREF_TABLE_SET and \ref FIO_CAL_LASERREF_TABLE_GET. */
union optic_laserref_get {
	/** Input value. */
	struct optic_laserref_get_in in;
	/** Output value. */
	struct optic_laserref_get_out out;
};

/** Bias and modulation current set parameters. Used by
   \ref FIO_CAL_IBIASIMOD_TABLE_SET and \ref FIO_CAL_IBIASIMOD_TABLE_GET. */
struct optic_ibiasimod_set {
	/** External temperature (corrected) in K. */
	uint16_t temperature;
	/** Power level (0 dB, -3 dB, -6 dB). */
	enum optic_powerlevel powerlevel;
	/** Bias current value [mA], integer data format according to
	<< \ref OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t ibias;
	/** Modulation current value [mA], integer data format according to
	<< \ref OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t imod;
} __PACKED__;

/** Bias and modulation current input parameters.
   Used by \ref FIO_CAL_IBIASIMOD_TABLE_SET. */
struct optic_ibiasimod_get_in {
	/** External temperature (corrected) in K. */
	uint16_t temperature;
	/** Power level (0 dB, -3 dB, -6 dB). */
	enum optic_powerlevel powerlevel;
} __PACKED__;

/** Bias and modulation current output parameters.
   Used by \ref FIO_CAL_IBIASIMOD_TABLE_GET.*/
struct optic_ibiasimod_get_out {
	/** Bias current value [mA], integer data format according to
	<< \ref OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t ibias;
	/** Modulation current value [mA], integer data format according to
	<< \ref OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t imod;
	/** Data quality flag. */
	enum optic_tableval_quality quality;
} __PACKED__;

/** Bias and modulation current get parameters. Used by
   \ref FIO_CAL_IBIASIMOD_TABLE_SET and \ref FIO_CAL_IBIASIMOD_TABLE_GET. */
union optic_ibiasimod_get {
	/** Input value. */
	struct optic_ibiasimod_get_in in;
	/** Output value. */
	struct optic_ibiasimod_get_out out;
};

/** APD voltage set parameters. Used by \ref FIO_CAL_VAPD_TABLE_SET. */
struct optic_vapd_set {
	/** External temperature (corrected) in K. */
	uint16_t temperature;
	/** APD voltage [V],
	    integer value shifted by \ref OPTIC_FLOAT2INTSHIFT_VOLTAGE. */
	uint16_t vref;
	/** APD duty cycle saturation maximum. */
	uint8_t sat;
} __PACKED__;

/** APD voltage get_in parameters. Used by \ref FIO_CAL_VAPD_TABLE_GET. */
struct optic_vapd_get_in {
	/** External temperature (corrected) in K. */
	uint16_t temperature;
} __PACKED__;

/** APD voltage get_out parameters. Used by \ref FIO_CAL_VAPD_TABLE_SET. */
struct optic_vapd_get_out {
	/** APD voltage [V],
       integer value shifted by  \ref OPTIC_FLOAT2INTSHIFT_VOLTAGE. */
	uint16_t vref;
	/** APD duty cycle saturation maximum */
	uint8_t sat;
	/** Data quality flag. */
	enum optic_tableval_quality quality;
} __PACKED__;

/** APD voltage get parameters. Used by \ref FIO_CAL_VAPD_TABLE_SET and
   \ref FIO_CAL_VAPD_TABLE_GET.*/
union optic_vapd_get {
	/** Input value. */
	struct optic_vapd_get_in in;
	/** Output value. */
	struct optic_vapd_get_out out;
};

/** Correction factor set parameters. Used by \ref FIO_CAL_CORR_TABLE_SET. */
struct optic_corr_set {
	/** Type of correction factor table. */
	enum optic_cfactor type;
	/** External temperature (corrected) in K. */
	uint16_t temperature;
	/** Correction factor, - [ <<  \ref OPTIC_FLOAT2INTSHIFT_CORRFACTOR]. */
	uint16_t corr_factor;
} __PACKED__;

/** Correction factor get_in parameters. Used by \ref FIO_CAL_CORR_TABLE_GET. */
struct optic_corr_get_in {
	/** Type of correction factor table. */
	enum optic_cfactor type;
	/** External temperature (corrected) in K. */
	uint16_t temperature;
} __PACKED__;

/** Correction factor get_out parameters. Used by \ref FIO_CAL_CORR_TABLE_GET. */
struct optic_corr_get_out {
	/** Correction factor, - [ <<  \ref OPTIC_FLOAT2INTSHIFT_CORRFACTOR]. */
	uint16_t corr_factor;
	/** Data quality flag. */
	enum optic_tableval_quality quality;
} __PACKED__;

/** Correction factor get parameters. Used by \ref FIO_CAL_CORR_TABLE_GET. */
union optic_corr_get {
	/** Input value. */
	struct optic_corr_get_in in;
	/** Output value. */
	struct optic_corr_get_out out;
};

/** External temperature correction set parameters.
    Used by \ref FIO_CAL_TCORREXT_TABLE_SET. */
struct optic_tcorrext_set {
	/** External temperature (corrected) in K. */
	uint16_t temperature;
	/** Corrected external temperature. */
	uint16_t temp_corr;
} __PACKED__;

/** External temperature correction get_in parameters. */
struct optic_tcorrext_get_in {
	/** External temperature (corrected) in K. */
	uint16_t temperature;
} __PACKED__;

/** External temperature correction get_out parameters. */
struct optic_tcorrext_get_out {
	/** Corrected external temperature [K].*/
	uint16_t temp_corr;
	/** Data quality flag. */
	enum optic_tableval_quality quality;
} __PACKED__;

/** External temperature correction get parameters. */
union optic_tcorrext_get {
	/** Input value. */
	struct optic_tcorrext_get_in in;
	/** Output value. */
	struct optic_tcorrext_get_out out;
};

/** Transmit laser bias current. Used by \ref FIO_CAL_INIT_BIAS_CURRENT_SET,
   \ref FIO_CAL_INIT_BIAS_CURRENT_GET, \ref FIO_CAL_ACT_BIAS_CURRENT_SET, and
   \ref FIO_CAL_ACT_BIAS_CURRENT_GET. */
struct optic_bias {
	/** Ibias value [mA], << \ref OPTIC_FLOAT2INTSHIFT_CURRENT */
	uint16_t bias_current;
} __PACKED__;

/** Transmit laser modulation current. Used by \ref FIO_CAL_INIT_MOD_CURRENT_SET,
   \ref FIO_CAL_INIT_MOD_CURRENT_GET, and
   \ref FIO_CAL_ACT_MOD_CURRENT_GET. */
struct optic_mod {
	/** Modulation current value [mA], integer value shifted by
	    << \ref OPTIC_FLOAT2INTSHIFT_CURRENT. */
	uint16_t modulation_current;
} __PACKED__;

/** MPD gain setting. Used by \ref FIO_CAL_MPD_GAIN_SET */
struct optic_gain_set {
	/** Gain bank selector: power level0..2 + global */
	enum optic_gainbank gainbank;
	/** TIA gain selector. */
	uint8_t tia_gain_selector;
} __PACKED__;

/** MPD gain input value. */
struct optic_gain_get_in {
	/** Gainbank: power level0..2 and global */
	enum optic_gainbank gainbank;
} __PACKED__;

/** MPD gain output value. */
struct optic_gain_get_out {
	/** TIA gain selector. */
	uint8_t tia_gain_selector;
	/** Data quality flag. */
	enum optic_quality quality;
} __PACKED__;

/** MPD gain setting. Used by \ref FIO_CAL_MPD_GAIN_GET */
union optic_gain_get {
	/** MPD gain input value. */
	struct optic_gain_get_in in;
	/** MPD gain output value. */
	struct optic_gain_get_out out;
};

/** MPD gain setting. Used by \ref FIO_CAL_MPD_DBG_GAIN_SET and
   \ref FIO_CAL_MPD_DBG_GAIN_GET. */
struct optic_dbg_gain {
	/** TIA gain selector. */
	uint8_t tia_gain_selector;
} __PACKED__;

/** MPD calibration current value. Used by \ref FIO_CAL_MPD_CAL_CURRENT_SET */
struct optic_cal_set {
	/** Gain bank selector: power level0..2 and global */
	enum optic_gainbank gainbank;
	/** Calibration current selector (off/open/100uA/1mA) */
	uint8_t cal_current;
} __PACKED__;

/** MPD calibration input value. */
struct optic_cal_get_in {
	/** Gain bank selector: power level0..2 + global */
	enum optic_gainbank gainbank;
} __PACKED__;

/** MPD calibration output value. */
struct optic_cal_get_out {
	/** Calibration current selector (100uA/1mA. */
	uint8_t cal_current;
	/** Data quality flag. */
	enum optic_quality quality;
} __PACKED__;

/** MPD calibration current value. Used by \ref FIO_CAL_MPD_CAL_GET. */
union optic_cal_get {
   /** MPD calibration input value. */
	struct optic_cal_get_in in;
	/** MPD calibration output value. */
	struct optic_cal_get_out out;
};

/** MPD calibration current value. Used by \ref FIO_CAL_MPD_DBG_CAL_CURRENT_SET
   and \ref FIO_CAL_MPD_DBG_CAL_CURRENT_GET. */
struct optic_dbg_cal {
	/** Calibration current selector, use values as defined by
	\ref optic_cal_current (off/open/100uA/1mA). */
	uint8_t cal_current;
} __PACKED__;


/** Laser monitor diode reference codeword set.
    Used by \ref FIO_CAL_MPD_REF_CODEWORD_SET and
    \ref FIO_CAL_MPD_REF_CODEWORD_GET.

   These values are used to compensate the high/low level comparator thresholds
   for the internal temperature dependence of the internal monitor path.

   The initial values are evaluated during calibration at a single temperature.
   During operation, the values are continuously re-calibrated
   (update related to the calibrated dcal_ref_p0/1) to compensate for
   temperature dependencies of the monitoring path (MPD/BFD) (uses dref_p0/1).

   Legend:
   - d: This is a digital codeword, not a physical value.
   - p0: Selects the logical low level.
   - p1: Selects the logical high level.
   - ref: This is related to the reference temperature
          (at factory calibration).
   - cal: This is related to the calibration current.
*/
struct optic_refcw_set {
	/** Transmit power level.
	    Selects to which of the power levels the data values shall
	    correspond. */
	enum optic_powerlevel powerlevel;
	/** Digital code word, measured with the internal calibration current
	    applied (1 mA or 100 uA), for a logical low level. */
	int32_t dcal_ref_p0;
	/** Digital code word, measured with the internal calibration current
	    applied (1 mA or 100 uA), for a logical high level. */
	int32_t dcal_ref_p1;
	/** Digital code word for a logical high level. */
	int32_t dref_p0;
	/** Digital code word for a logical low level. */
	int32_t dref_p1;
} __PACKED__;

/** Laser reference codeword get_in. */
struct optic_refcw_get_in {
	/** Transmit power level. */
	enum optic_powerlevel powerlevel;
} __PACKED__;

/** Laser reference codeword get_out. */
struct optic_refcw_get_out {
	/** DcalrefP0 at Tref */
	int32_t dcal_ref_p0;
	/** DcalrefP1 at Tref */
	int32_t dcal_ref_p1;
	/** DrefP0 */
	int32_t dref_p0;
	/** DrefP1 */
	int32_t dref_p1;
	/** Data quality flag. */
	enum optic_quality quality;
} __PACKED__;

/** Laser reference codeword get. */
union optic_refcw_get {
	/** Input value. */
	struct optic_refcw_get_in in;
	/** Output value. */
	struct optic_refcw_get_out out;
};

/** Laser reference codeword for debug. */
struct optic_dbg_refcw {
	/** DcalrefP0 at Tref */
	int32_t dcal_ref_p0;
	/** DcalrefP1 at Tref */
	int32_t dcal_ref_p1;
	/** DrefP0 */
	int32_t dref_p0;
	/** DrefP1 */
	int32_t dref_p1;
} __PACKED__;

/** MPD TIA offset value. Used by \ref FIO_CAL_MPD_DBG_TIA_OFFSET_SET */
struct optic_tia_offset_set {
	/** Gainbank: power level0..2 + global */
	enum optic_gainbank gainbank;
	/** Coarse offset (offset DAC) */
	int16_t tia_offset_coarse;
	/** Fine offset (offset DAC) */
	int16_t tia_offset_fine;
	/** Coarse offset (level 1 DAC delta) */
	int16_t tia_offset_p1_coarse;
	/** Fine offset (level 1 DAC delta) */
	int16_t tia_offset_p1_fine;
} __PACKED__;

/** MPD TIA gain input value. */
struct optic_tia_offset_get_in {
	/** Gainbank: power level0..2 + global */
	enum optic_gainbank gainbank;
} __PACKED__;

/** MPD TIA offset output value. */
struct optic_tia_offset_get_out {
	/** Coarse offset (offset DAC) */
	int16_t tia_offset_coarse;
	/** Fine offset (offset DAC) */
	int16_t tia_offset_fine;
	/** Coarse offset (level 1 DAC delta) */
	int16_t tia_offset_p1_coarse;
	/** Fine offset (level 1 DAC delta) */
	int16_t tia_offset_p1_fine;
} __PACKED__;

/** MPD TIA offset value. Used by \ref FIO_CAL_MPD_DBG_TIA_OFFSET_GET */
union optic_tia_offset_get {
   /** MPD TIA offset input value. */
	struct optic_tia_offset_get_in in;
   /** MPD TIA offset output value. */
	struct optic_tia_offset_get_out out;
};

/** MPD TIA offset value. Used by \ref FIO_CAL_MPD_DBG_TIA_OFFSET_SET,
   \ref FIO_CAL_MPD_DBG_TIA_OFFSET_GET */
struct optic_dbg_tia_offset {
	/** Coarse offset (offset DAC) */
	int16_t tia_offset_coarse;
	/** Fine offset (offset DAC) */
	int16_t tia_offset_fine;
	/** Coarse offset (level 1 DAC delta) */
	int16_t tia_offset_p1_coarse;
	/** Fine offset (level 1 DAC delta) */
	int16_t tia_offset_p1_fine;
} __PACKED__;


/** MPD "zero" or "one" level. Used by \ref FIO_CAL_MPD_LEVEL_SET */
struct optic_level_set {
	/** MPD level selection.
	    - 0: "zero" level.
	    - 1: "one" level. */
	uint8_t level_select;
	/** Codeword P0 / P1, << OPTIC_FLOAT2INTSHIFT_DREF */
	int32_t level_value;
} __PACKED__;

/** MPD level input value. */
struct optic_level_get_in {
	/** MPD level selection.
	    - 0: "zero" level.
	    - 1: "one" level. */
	uint8_t level_select;
} __PACKED__;

/** MPD level output value. */
struct optic_level_get_out {
	/** P0/P1 gain correction factor (<< OPTIC_FLOAT2INTSHIFT_CORRFACTOR) */
	uint16_t gain_correction;
	/** Codeword P0 / P1, << OPTIC_FLOAT2INTSHIFT_DREF */
	int32_t level_value;
} __PACKED__;

/** MPD "zero" or "one" level. Used by \ref FIO_CAL_MPD_LEVEL_GET */
union optic_level_get {
	/** MPD level input value. */
	struct optic_level_get_in in;
	/** MPD level output value. */
	struct optic_level_get_out out;
};

/** MPD level finding with or without offset cancelation.
    Used by \ref FIO_CAL_MPD_LEVEL_FIND */
struct optic_level_find_in {
	/** Enable offset calibration.
		- false: Disabled.
		- true: Enabled. */
	bool offset_cancellation;
	/** Enable P0 level calibration.
		- false: Disabled.
		- true: Enabled. */
	bool calibrate_p0;
	/** Enable P1 level calibration.
		- false: Disabled.
		- true: Enabled. */
	bool calibrate_p1;
} __PACKED__;

/** MPD level finding with or without offset cancelation.
    Used by \ref FIO_CAL_MPD_LEVEL_FIND */
struct optic_level_find_out {
	/** P0, coarse level * c/f-ratio + fine level.
	    If the P0 level was not selected for calibration
	    (calibrate_p0 = false), a value of 0x8000 is returned in this
	    variable, indicating this to be invalid. */
	int16_t level_p0;
	/** P1, coarse level * c/f-ratio + fine level.
	    If the P1 level was not selected for calibration
	    (calibrate_p1 = false), a value of 0x8000 is returned in this
	    variable, indicating this to be invalid. */
	int16_t level_p1;
} __PACKED__;

/** MPD "zero" or "one" level. Used by \ref FIO_CAL_MPD_LEVEL_FIND */
union optic_level_find {
	/** MPD level input value. */
	struct optic_level_find_in in;
	/** MPD level output value. */
	struct optic_level_find_out out;
};

/** MPD coarse/fine-ratio. Used by \ref FIO_CAL_MPD_CFRATIO_SET and
   \ref FIO_CAL_MPD_CFRATIO_GET. */
struct optic_cfratio {
	/** Coarse/fine ratio for
	    P0 << \ref OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO */
	uint16_t ratio_p0;
	/** Coarse/fine ratio for
	    P1 << \ref OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO */
	uint16_t ratio_p1;
} __PACKED__;

/** Pre-driver settings. Used by \ref FIO_CAL_FCSI_PREDRIVER_SET and
   \ref FIO_CAL_FCSI_PREDRIVER_GET*/
struct optic_fcsi_predriver {
	/** DDC0, DDC1, BDC0, BDC1 settings
	for the currently active transmit power level */
	uint8_t dd_loadn;
	/** dd_bias_en */
	uint8_t dd_bias_en;
	/** dd_loadp */
	uint8_t dd_loadp;
	/** dd_cm_load */
	uint8_t dd_cm_load;
	/** bd_loadn */
	uint8_t bd_loadn;
	/** bd_bias_en */
	uint8_t bd_bias_en;
	/** bd_loadp */
	uint8_t bd_loadp;
	/** bd_cm_load */
	uint8_t bd_cm_load;
} __PACKED__;

/** Bit delay of the laser. Used by \ref FIO_CAL_LASERDELAY_SET and
   \ref FIO_CAL_LASERDELAY_GET */
struct optic_laserdelay {
   /** Laser minor delay. */
	uint8_t bitdelay;
} __PACKED__;

/** Dark correction factor. Used by \ref FIO_CAL_MM_DARK_CORR_SET and
    \ref FIO_CAL_MM_DARK_CORR_GET. */
struct optic_rssi_1490_dark {
	/** Correction factor, - [ <<  \ref OPTIC_FLOAT2INTSHIFT_CORRFACTOR]. */
	uint16_t corr_factor;
} __PACKED__;

/** OPTIC fuse parameters */
struct optic_fusing {
	/** Internal fusing structure format identification. */
	uint8_t format;

	/** FBS0.STATUS.FUSE_SPARE0.VCALMM20, 6 bit */
	uint8_t vcal_mm20;
	/** FBS0.STATUS.FUSE_SPARE0.VCALMM100, 6 bit */
	uint8_t vcal_mm100;
	/** FBS0.STATUS.FUSE_SPARE0.VCALMM400, 6 bit */
	uint8_t vcal_mm400;
	/** FBS0.STATUS.FUSE_SPARE0.RCALMM, 8 bit */
	uint8_t rcal_mm;
	/** FBS0.STATUS.ANALOG.TEMPMM, 6 bit */
	uint8_t temp_mm;
	/** FBS0.STATUS.ANALOG.TBGP, 3 bit */
	uint8_t tbgp;
	/** FBS0.STATUS.ANALOG.VBGP, 3 bit */
	uint8_t vbgp;
	/** FBS0.STATUS.ANALOG.IREFBGP, 4 bit */
	uint8_t irefbgp;
	/** FBS0.STATUS.ANALOG.GAINDRIVEDAC, 4 bit */
	uint8_t gain_dac_drive;
	/** FBS0.STATUS.ANALOG.GAINBIASDAC, 4 bit */
	uint8_t gain_dac_bias;
	/** FBS0.STATUS.FUSE1.OFFSETDDRDCDC, 4 bit */
	uint8_t offset_dcdc_ddr;
	/** FBS0.STATUS.FUSE1.GAINDDRDCDC, 6 bit */
	uint8_t gain_dcdc_ddr;
	/** FBS0.STATUS.FUSE1.OFFSET1V0DCDC, 4 bit */
	int8_t offset_dcdc_core;
	/** FBS0.STATUS.FUSE1.GAIN1V0DCDC, 6 bit */
	uint8_t gain_dcdc_core;
	/** FBS0.STATUS.FUSE1.OFFSETAPDDCDC, 4 bit */
	int8_t offset_dcdc_apd;
	/** FBS0.STATUS.FUSE1.GAINAPDDCDC, 6 bit */
	uint8_t gain_dcdc_apd;
} __PACKED__;

/** Power save mode activation */
struct optic_powersave {
   /** Activation status. */
	enum optic_activation powersave;
} __PACKED__;

/** Tscal_ref factor. Used by \ref FIO_CAL_TSCALREF_SET and
    \ref FIO_CAL_TSCALREF_GET. */
struct optic_tscalref {
	/** tscal_ref << OPTIC_FLOAT2INTSHIFT_TSCALREF */

	uint16_t tscal_ref; /** @test \ref test SWIG */
} __PACKED__;

/** RSSI 1490 nm measuring input data. */
struct optic_measure_rssi_1490_get_in {
   /** Number. */
	uint8_t number;
   /** Data. */
	uint16_t *p_data;
} __PACKED__;

/** RSSI 1490 nm measuring output data. */
struct optic_measure_rssi_1490_get_out {
	/** Average value. */
	uint16_t average;
	/** sign flag */
	bool is_positive;
} __PACKED__;

/** MPD "zero" or "one" level. Used by \ref FIO_CAL_MPD_LEVEL_GET */
union optic_measure_rssi_1490_get {
   /** MPD level input value. */
	struct optic_measure_rssi_1490_get_in in;
   /** MPD level output value. */
	struct optic_measure_rssi_1490_get_out out;
};

/** RX offset, Used by \ref FIO_CAL_RX_OFFSET_SET and
    \ref FIO_CAL_RX_OFFSET_GET */
struct optic_rx_offset {
	uint16_t rx_offset;
} __PACKED__;


/**
   Enable debug mode. Automatic recalibration is stopped.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_DEBUG_ENABLE _IO(OPTIC_CAL_MAGIC, 0)

/**
   Disable the debug mode. Automatic recalibration is activated, calibration
   values are restored, according to the selected transmit power level.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_DEBUG_DISABLE _IO(OPTIC_CAL_MAGIC, 1)

/**
   Enable the Measurement Module (MM) background cycle.
   The Measurement Module performs continuous cyclic
   measurements on the configured measurement channels.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MM_ENABLE _IO(OPTIC_CAL_MAGIC, 2)

/**
   Disable the Measurement Module (MM) background cycle.
   Continuous cyclic measurement is stopped.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MM_DISABLE _IO(OPTIC_CAL_MAGIC, 3)

/**
   Returns the selected debug mode setting.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_DEBUG_STATUS_GET _IOR(OPTIC_CAL_MAGIC, 4, struct optic_debug_status )

/**
   Read the laser's age time (in seconds) from the transmission counter
   (laser active sending time).

   \param optic_timestamp Pointer to \ref optic_timestamp.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_LASER_AGE_GET _IOR(OPTIC_CAL_MAGIC, 5, struct optic_timestamp )

/**
   Set a Ith/SE tupel for a specified temperature
   (laser threshold current and laser slope efficiency).

   \param optic_laserref_set Pointer to \ref optic_laserref_set.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_LASERREF_TABLE_SET _IOW(OPTIC_CAL_MAGIC, 6, struct optic_laserref_set )

/**
   Read back the Ith/SE tupel of a specified temperature
   (laser threshold current and laser slope efficiency).

   \param optic_laserref_get Pointer to \ref optic_laserref_get.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_LASERREF_TABLE_GET _IOWR(OPTIC_CAL_MAGIC, 7, union optic_laserref_get )

/**
   Set a Ibias/Imod tupel for a specified temperature and for active power level
   (laser bias and modulation currents).

   \param optic_ibiasimod_set Pointer to \ref optic_ibiasimod_set.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_IBIASIMOD_TABLE_SET _IOW(OPTIC_CAL_MAGIC, 8, struct optic_ibiasimod_set )

/**
   Read back the Ibias/Imod tupel of a specified temperature and
   the active transmit power level (laser bias and modulation currents).

   \param optic_ibiasimod_get Pointer to \ref optic_ibiasimod_get.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_IBIASIMOD_TABLE_GET _IOWR(OPTIC_CAL_MAGIC, 9, union optic_ibiasimod_get )

/**
   Set an APD voltage value (Vapd) for a specified temperature.

   \param optic_vapd_set Pointer to \ref optic_vapd_set.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_VAPD_TABLE_SET _IOW(OPTIC_CAL_MAGIC, 10, struct optic_vapd_set )

/**
   Read back the APD voltage value (Vapd) of a specified temperature.

   \param optic_vapd_get Pointer to \ref optic_vapd_get.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_VAPD_TABLE_GET _IOWR(OPTIC_CAL_MAGIC, 11, union optic_vapd_get )

/**
   Set a correction factor for a specified temperature in specified table.

   \param optic_corr_set Pointer to \ref optic_corr_set.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_CORR_TABLE_SET _IOW(OPTIC_CAL_MAGIC, 12, struct optic_corr_set )

/**
   Read back the correction factor of a specified table and a
   specified temperature.

   \param optic_corr_get Pointer to \ref optic_corr_get.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_CORR_TABLE_GET _IOWR(OPTIC_CAL_MAGIC, 13, union optic_corr_get )

/**
   Set a corrected temperature for a specified nominal (measured) temperature.

   \param optic_tcorrext_set Pointer to \ref optic_tcorrext_set.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_TCORREXT_TABLE_SET _IOW(OPTIC_CAL_MAGIC, 14, struct optic_tcorrext_set )

/**
   Read back the corrected temperature of a specified nominal (measured)
   temperature.

   \param optic_tcorrext_get Pointer to \ref optic_tcorrext_get.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_TCORREXT_TABLE_GET _IOWR(OPTIC_CAL_MAGIC, 15, union optic_tcorrext_get )

/**
   Set the laser bias current value (Ibias) directly to hardware.

   \param optic_bias Pointer to \ref optic_bias.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_INIT_BIAS_CURRENT_SET _IOW(OPTIC_CAL_MAGIC, 16, struct optic_bias )

/**
   Read the laser bias current value (Ibias) directly from hardware.

   \param optic_bias Pointer to \ref optic_bias.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_INIT_BIAS_CURRENT_GET _IOR(OPTIC_CAL_MAGIC, 17, struct optic_bias )

/**
   Set the laser modulation current value (Imod) directly to hardware.

   \param optic_mod Pointer to \ref optic_mod.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_INIT_MOD_CURRENT_SET _IOW(OPTIC_CAL_MAGIC, 18, struct optic_mod )

/**
   Read the laser modulation current value (Imod) directly from hardware.

   \param optic_mod Pointer to \ref optic_mod.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_INIT_MOD_CURRENT_GET _IOR(OPTIC_CAL_MAGIC, 19, struct optic_mod )

/**
   Read the "abias" value directly from hardware.

   \param optic_bias Pointer to \ref optic_bias.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_ACT_BIAS_CURRENT_GET _IOR(OPTIC_CAL_MAGIC, 20, struct optic_bias )

/**
   Read the "amod" value directly from hardware.

   \param optic_mod Pointer to \ref optic_mod.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_ACT_MOD_CURRENT_GET _IOR(OPTIC_CAL_MAGIC, 21, struct optic_mod )

/**
   Set the TIA gain for the specified power level or globally.

   \param optic_gain_set Pointer to \ref optic_gain_set.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_GAIN_SET _IOW(OPTIC_CAL_MAGIC, 22, struct optic_gain_set )

/**
   Reads TIA gain of the specified power level or the globally used value.

   \param optic_gain_get Pointer to \ref optic_gain_get.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_GAIN_GET _IOWR(OPTIC_CAL_MAGIC, 23, union optic_gain_get )

/**
   Set the TIA gain for the debug mode.

   \param optic_dbg_gain Pointer to \ref optic_dbg_gain.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_DBG_GAIN_SET _IOW(OPTIC_CAL_MAGIC, 24, struct optic_dbg_gain )

/**
   Read the TIA gain of the debug mode.

   \param optic_dbg_gain Pointer to \ref optic_dbg_gain.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_DBG_GAIN_GET _IOR(OPTIC_CAL_MAGIC, 25, struct optic_dbg_gain )

/**
   Set the calibration current for the specified power level or globally.

   \param optic_cal_set Pointer to \ref optic_cal_set.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_CAL_CURRENT_SET _IOW(OPTIC_CAL_MAGIC, 26, struct optic_cal_set )

/**
   Read the calibration current of the specified power level or the globally
   used value.

   \param optic_cal_get Pointer to \ref optic_cal_get.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_CAL_CURRENT_GET _IOWR(OPTIC_CAL_MAGIC, 27, union optic_cal_get )

/**
   Set the calibration current for the debug mode.

   \param optic_dbg_cal Pointer to \ref optic_dbg_cal.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_DBG_CAL_CURRENT_SET _IOW(OPTIC_CAL_MAGIC, 28, struct optic_dbg_cal )

/**
   Read the calibration current of the debug mode.

   \param optic_dbg_cal Pointer to \ref optic_dbg_cal.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_DBG_CAL_CURRENT_GET _IOR(OPTIC_CAL_MAGIC, 29, struct optic_dbg_cal )

/**
   Set Dref P0 & P1 and Dcalref P0 & P1 for the specified power level.

   \param optic_refcw_set Pointer to \ref optic_refcw_set.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_REF_CODEWORD_SET _IOW(OPTIC_CAL_MAGIC, 30, struct optic_refcw_set )

/**
   Read Dref P0 & P1 and Dcalref P0 & P1 of the specified power level.

   \param optic_refcw_set Pointer to \ref optic_refcw_set.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_REF_CODEWORD_GET _IOWR(OPTIC_CAL_MAGIC, 31, union optic_refcw_get )

/**
   Set Dref P0 & P1 and Dcalref P0 & P1 for the debug mode.

   \param optic_dbg_refcw Pointer to \ref optic_dbg_refcw.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_DBG_REF_CODEWORD_SET _IOW(OPTIC_CAL_MAGIC, 32, struct optic_dbg_refcw )

/**
   Read Dref P0 & P1 and Dcalref P0 & P1 of the debug mode.

   \param optic_dbg_refcw Pointer to \ref optic_dbg_refcw.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_DBG_REF_CODEWORD_GET _IOR(OPTIC_CAL_MAGIC, 33, struct optic_dbg_refcw )

/**
   Set the TIA offset and p1 level delta offset for the specified
   power level / globally.

   \param optic_tia_offset_set Pointer to \ref optic_tia_offset_set.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_TIA_OFFSET_SET _IOW(OPTIC_CAL_MAGIC, 34, struct optic_tia_offset_set)

/**
   Read back the TIA offset and p1 level delta offset of the specified
   power level / globally.

   \param optic_tia_offset_get Pointer to \ref optic_tia_offset_get.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_TIA_OFFSET_GET _IOWR(OPTIC_CAL_MAGIC, 35, union optic_tia_offset_get)

/**
   Set the TIA offset and p1 level delta offset for the debug mode.

   \param optic_dbg_tia_offset Pointer to \ref optic_dbg_tia_offset.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_DBG_TIA_OFFSET_SET _IOW(OPTIC_CAL_MAGIC, 36, struct optic_dbg_tia_offset )

/**
   Read the TIA offset and p1 level delta offset of the debug mode.

   \param optic_dbg_tia_offset Pointer to \ref optic_dbg_tia_offset.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_DBG_TIA_OFFSET_GET _IOR(OPTIC_CAL_MAGIC, 37, struct optic_dbg_tia_offset )

/**
   Start the internal driver offset cancellation, which measure TIA offset
   and p1 level delta offset for all power levels - or the debug mode
   configuration, if debug mode is activated.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_TIA_OFFSET_FIND _IO(OPTIC_CAL_MAGIC, 38 )

/**
   Set the digital codeword into P0 or P1 level DAC.

   \param optic_level_set Pointer to \ref optic_level_set.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_LEVEL_SET _IOW(OPTIC_CAL_MAGIC, 39, struct optic_level_set )

/**
   Read back the digital codeword from P0 or P1 level DAC.

   \param optic_level_get_in Pointer to \ref optic_level_get_in as input parameter.
   \param optic_level_get_out Pointer to \ref optic_level_get_out as output parameter.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_LEVEL_GET _IOWR(OPTIC_CAL_MAGIC, 40, union optic_level_get )

/**
   Start the internal driver MPD calibration, which calculates P0 or P1
   level DAC codewords. If the driver runs the MPD calibration, offset
   cancellation is always done first. Using this function, initializing offset
   cancellation is optional.

   \param optic_level_find Pointer to \ref optic_level_find.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_LEVEL_FIND _IOWR(OPTIC_CAL_MAGIC, 41, union optic_level_find )

/**
   Sets the coarse/fine ratio of the P0 and P1 level DAC.

   \param optic_cfratio Pointer to \ref optic_cfratio.
   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_CFRATIO_SET _IOW(OPTIC_CAL_MAGIC, 42, struct optic_cfratio )

/**
   Read back the coarse/fine ratio of the P0 and P1 level DAC.

   \param optic_cfratio Pointer to \ref optic_cfratio.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_CFRATIO_GET _IOR(OPTIC_CAL_MAGIC, 43, struct optic_cfratio )

/**
   Start the internal driver coarse/fine ratio calculation for P0 and P1.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_CFRATIO_FIND _IO(OPTIC_CAL_MAGIC, 44 )

/**
   Set the powersave mode.

   \param optic_powersave Pointer to \ref optic_powersave.
   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_POWERSAVE_SET _IOW(OPTIC_CAL_MAGIC, 45, struct optic_powersave )

/**
   Reads back the powersave mode.

   \param optic_powersave Pointer to \ref optic_powersave.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MPD_POWERSAVE_GET _IOR(OPTIC_CAL_MAGIC, 46, struct optic_powersave )

/**
   Sets the fcsi predriver setting directly into hardware.

   \param optic_fcsi_predriver Pointer to \ref optic_fcsi_predriver.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_FCSI_PREDRIVER_SET _IOW(OPTIC_CAL_MAGIC, 47, struct optic_fcsi_predriver )

/**
   Reads back the fcsi predriver setting directly from hardware.

   \param optic_fcsi_predriver Pointer to \ref optic_fcsi_predriver.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_FCSI_PREDRIVER_GET _IOR(OPTIC_CAL_MAGIC, 48, struct optic_fcsi_predriver )

/**
   Sets the DCDC APD voltage. Duty Cycle Saturation is calculated automatically.

   \param optic_voltage Pointer to \ref optic_voltage.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_DCDC_APD_VOLTAGE_SET _IOW(OPTIC_CAL_MAGIC, 49, struct optic_voltage )

/**
   Reads back the DCDC APD voltage.

   \param optic_voltage Pointer to \ref optic_voltage.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_DCDC_APD_VOLTAGE_GET _IOR(OPTIC_CAL_MAGIC, 50, struct optic_voltage )

/**
   Sets the DCDC CORE voltage. Duty Cycle Saturation is calculated automatically.

   \param optic_voltage Pointer to \ref optic_voltage.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_DCDC_CORE_VOLTAGE_SET _IOW(OPTIC_CAL_MAGIC, 51, struct optic_voltage )

/**
   Reads back the DCDC CORE voltage.

   \param optic_voltage Pointer to \ref optic_voltage.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_DCDC_CORE_VOLTAGE_GET _IOR(OPTIC_CAL_MAGIC, 52, struct optic_voltage )

/**
   Sets the DCDC DDR voltage. Duty Cycle Saturation is calculated automatically.

   \param optic_voltage Pointer to \ref optic_voltage.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_DCDC_DDR_VOLTAGE_SET _IOW(OPTIC_CAL_MAGIC, 53, struct optic_voltage )

/**
   Reads back the DCDC DDR voltage.

   \param optic_voltage Pointer to \ref optic_voltage.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_DCDC_DDR_VOLTAGE_GET _IOR(OPTIC_CAL_MAGIC, 54, struct optic_voltage )

/**
   Set the bit delay for the laser transmission signal.

   \param optic_laserdelay Pointer to \ref optic_laserdelay.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_LASERDELAY_SET _IOW(OPTIC_CAL_MAGIC, 55, struct optic_laserdelay )

/**
   Read the bit delay for the laser transmission signal.

   \param optic_laserdelay Pointer to \ref optic_laserdelay.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_LASERDELAY_GET _IOR(OPTIC_CAL_MAGIC, 56, struct optic_laserdelay )

/**
   Set the RSSI 1490 dark correction factor.

   \param optic_rssi_1490_dark Pointer to \ref optic_rssi_1490_dark.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MM_DARK_CORR_SET _IOW(OPTIC_CAL_MAGIC, 57, struct optic_rssi_1490_dark )

/**
   Read the RSSI 1490 dark correction factor.

   \param optic_rssi_1490_dark Pointer to \ref optic_rssi_1490_dark.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MM_DARK_CORR_GET _IOR(OPTIC_CAL_MAGIC, 58, struct optic_rssi_1490_dark )

/**
   (Re)calculate the RSSI 1490 dark correction factor.


   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MM_DARK_CORR_FIND _IO(OPTIC_CAL_MAGIC, 59 )

/**
   Read fusing informations.

   \param optic_fusing Pointer to \ref optic_fusing.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_FUSES_GET _IOR(OPTIC_CAL_MAGIC, 60, struct optic_fusing)

/**
   Write Tscal ref value.

   \param optic_tscalref Pointer to \ref optic_tscalref.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_TSCALREF_SET _IOW(OPTIC_CAL_MAGIC, 61, struct optic_tscalref)

/**
   Read Tscal ref value.

   \param optic_tscalref Pointer to \ref optic_tscalref.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_TSCALREF_GET _IOR(OPTIC_CAL_MAGIC, 62, struct optic_tscalref)

/**
   Read measurement values for RSSI 1490 in a exclusive mode.

   \param optic_measure_rssi Pointer to \ref optic_measure_rssi.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_MEASURE_RSSI_1490_GET _IOWR(OPTIC_CAL_MAGIC, 63, union optic_measure_rssi_1490_get)

/**
   Read current offset.

   \param optic_current_fine Pointer to \ref optic_current_fine.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_CURRENT_OFFSET_GET _IOR(OPTIC_CAL_MAGIC, 64, struct optic_current_fine)

/**
   Set RX offset.

   \param optic_rx_offset Pointer to \ref optic_rx_offset.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_RX_OFFSET_SET _IOW(OPTIC_CAL_MAGIC, 65, struct optic_rx_offset)

/**
   Reads RX offset.

   \param optic_rx_offset Pointer to \ref optic_rx_offset.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_RX_OFFSET_GET _IOR(OPTIC_CAL_MAGIC, 66, struct optic_rx_offset)

/**
   Starts RX offset cancellation.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_CAL_RX_OFFSET_FIND _IO(OPTIC_CAL_MAGIC, 67)


#define OPTIC_CAL_MAX                              68


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
#endif                          /* _drv_optic_cal_interface_h_ */
