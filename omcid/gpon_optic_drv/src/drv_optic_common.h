/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_optic_common_h
#define _drv_optic_common_h

#ifdef HAVE_CONFIG_H
#include "drv_optic_config.h"
#endif

#ifdef OPTIC_SIMULATION
#  include "drv_optic_devio.h"
#endif

#include "ifxos_mutex.h"
#include "ifx_fifo.h"
/** \todo remove from common, or create ll_common.h.
Only needed for event type for upper layer */
#include "ifxos_event.h"
/** \todo move to upper layer header file.
part of optic_control uses threads, but not needed for ll files */
#include "ifxos_thread.h"
#include "ifxos_select.h"

#include "drv_optic_std_defs.h"

#include "drv_optic_timer.h"
#include "drv_optic_interface.h"

#include "drv_optic_event_interface.h"
#include "drv_optic_goi_interface.h"
#include "drv_optic_fcsi_interface.h"
#include "drv_optic_mm_interface.h"
#include "drv_optic_mpd_interface.h"
#include "drv_optic_bert_interface.h"
#include "drv_optic_omu_interface.h"
#include "drv_optic_bosa_interface.h"
#include "drv_optic_cal_interface.h"
#include "drv_optic_dcdc_apd_interface.h"
#include "drv_optic_dcdc_core_interface.h"
#include "drv_optic_dcdc_ddr_interface.h"
#include "drv_optic_ldo_interface.h"

/** \defgroup OPTIC_COMMON_INTERNAL Optic Common Driver Interface - Internal
   This chapter provides definitions common to the optical interface driver.
   This part is for internal use only.
   @{
*/

#ifndef ARRAY_SIZE
#   define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

/** maximum instances of this driver (GPON hardware) */
#ifndef OPTIC_INSTANCES_MAX
#  define OPTIC_INSTANCES_MAX            1
#endif

/** worker thread stack size */
#define OPTIC_WORKER_THREAD_STACK_SIZE   512
/* worker thread priority */
#define OPTIC_WORKER_THREAD_PRIO          64
/** max element size of the notification FIFO */
#define OPTIC_FIFO_ELEM_SIZE              64

/** timer thread stack size */
#define OPTIC_MEASURE_THREAD_STACK_SIZE 1024
/** timer thread priority */
#define OPTIC_MEASURE_THREAD_PRIO         32

#define OPTIC_GAIN_SELECTOR_MAX            6
/* fix setting for gain selector - if internal temperature is measured */
#define OPTIC_GAIN_SELECTOR_TEMP_INT       2
/* initial setting for gain selector - for voltage measurement, needed for power */
#define OPTIC_GAIN_SELECTOR_POWER_INIT     5

/* number of measurement values to build first average value (for filter) */
#define OPTIC_MM_INIT_AVERAGE_DEPTH       20
/* filter factor (weight of current measurement value) */
#define OPTIC_MM_FILTER_FACTOR_MEASURE     5
#define OPTIC_MM_FILTER_FACTOR_GAIN_OFFS   1
#define OPTIC_MM_FILTER_FACTOR_TEMP_INT    6
#define OPTIC_MM_FILTER_FACTOR_TEMP_EXT    6

/* DCDC APD change delay for steps: 10 ms */
#define OPTIC_TIMER_DCDCAPD_RAMP          10
#define OPTIC_TIMER_DCDCAPD_REG_CYCLE_MAX  10
/* measurement cycletime (in ms) for internal MM read:
   200-20 (never below 10ms  - hardware refresh cycle) */
#define OPTIC_TIMER_MEASURE_CALIBRATION   50
#define OPTIC_TIMER_MEASURE               50
/* measurement cycletime (in ms) for laser-age calculation !have to be < 27s! */
#define OPTIC_LASERAGE_UPDATE          10000
/* number of abias/amod values which are used for average calculation -
   to detect change = not stable */
#define OPTIC_DUALLOOP_STABLE_DEPTH       10
/* p0DAC fine steps when ibias is detected to be too low */
#define OPTIC_DUALLOOP_ZERO_P0INC         4
/* number of cycles for MPD calibration (coarse dac) */
#define OPTIC_MPD_CAL_CYCLE_COARSE         1
/* number of cycles for MPD calibration (fine dac) */
/*
#define OPTIC_MPD_CAL_CYCLE_FINE           4
*/
#define OPTIC_MPD_CAL_CYCLE_FINE           1

/* level search / RX dac (offset search) defines */
#define OPTIC_GAIN_COEFF                   5
#define OPTIC_LEVEL_BITS                   9

/* mpd update criteria: for A11/A12 multiple "no-update" detections */
#define OPTIC_NOUPDATE_MAX               100

/** number of internal temperature measurements while no range check is done */
#define OPTIC_MIN_TEMP_MEASURES 10

#define ACTIVE 1
#define INACTIVE 0

#define OPTIC_AUTOSTART_INIT                  ACTIVE
#define OPTIC_CHECK_ADDRESSES                 INACTIVE
#define OPTIC_GPIO                            ACTIVE
#define OPTIC_FCSI_PREDRIVER_RANGECHECK       INACTIVE
#define OPTIC_MPD_COARSE_FINE_RATIO_CALC      INACTIVE
#define OPTIC_MPD_OFFSET_CANCEL_UPDATE        ACTIVE
#define OPTIC_MPD_P1_DELTA_OFFSET             ACTIVE
#define OPTIC_MPD_LEARNING                    ACTIVE

#define OPTIC_MPD_CALIBRATE_OFFSET	true
#define OPTIC_MPD_CALIBRATE_P0		false
#define OPTIC_MPD_CALIBRATE_P1		false
/** enables direct laserref table update (by control application)
    without waiting via goi_config:LaserAgeStoreCycle */
#define OPTIC_DIRECT_TABLE_UPDATE             ACTIVE
#define OPTIC_MM_MEASUREMENT_LOOP             ACTIVE
#define OPTIC_MM_CALIBRATION_UPDATE           ACTIVE
#define OPTIC_MM_GAIN_CORRECTION              ACTIVE
#define OPTIC_AVERAGE_NOM_TEMP_INT            ACTIVE
#define OPTIC_AVERAGE_NOM_TEMP_EXT            ACTIVE
#define OPTIC_TEMPERATURE_ALARM               INACTIVE
#define OPTIC_INT_TEMP_REACTION               ACTIVE
#define OPTIC_EXT_TEMP_REACTION               ACTIVE
#define OPTIC_DCDC_APD_UPDATE                 ACTIVE
#define OPTIC_BOSA_IRQ                        ACTIVE
#define OPTIC_BOSA_IRQ_THRESHOLD_CHECK        INACTIVE
#define OPTIC_BOSA_LOS_DISABLE_RX             INACTIVE
#define OPTIC_CAL_RSSI1490_USE_ALL_CHANNELS   ACTIVE
#define OPTIC_PERIODIC_RSSI                   ACTIVE
#define OPTIC_DCDCAPD_REGULATION_ERROR        ACTIVE
#define OPTIC_DYING_GASP_SHUTDOWN             ACTIVE
#define OPTIC_USE_DCDC_DEADZONE               INACTIVE
#define OPTIC_APD_DEBUG               		  INACTIVE

#ifdef OPTIC_LIBRARY
#define OPTIC_OCAL_SUPPORT                    INACTIVE
#endif

#ifndef OPTIC_OCAL_SUPPORT
#define OPTIC_OCAL_SUPPORT                    ACTIVE
#endif

/** debug stuff */
#ifndef OPTIC_DEBUG
#define OPTIC_DEBUG                     ACTIVE
#endif

#define OPTIC_DEBUG_PRINTOUT_DUMP       INACTIVE
#define OPTIC_DEBUG_PRINTOUT_DUMP_PLL   INACTIVE
#define OPTIC_DEBUG_PRINTOUT_DUMP_RX    INACTIVE
#define OPTIC_DEBUG_PRINTOUT_DUMP_TX    INACTIVE
#define OPTIC_DEBUG_PRINTOUT_DUMP_MPD   INACTIVE
#define OPTIC_DEBUG_PRINTOUT_DUMP_DCDC  INACTIVE
#define OPTIC_DEBUG_PRINTOUT_FCSI       INACTIVE
#define OPTIC_DEBUG_PRINTOUT_REG_R      INACTIVE
#define OPTIC_DEBUG_PRINTOUT_REG_W      INACTIVE
#define OPTIC_DEBUG_PRINTOUT_MMSTACK    INACTIVE
#define OPTIC_DEBUG_PRINTOUT_MMTIME     INACTIVE
#define OPTIC_DEBUG_PRINTOUT_MPD_OFFSET INACTIVE
#define OPTIC_DEBUG_PRINTOUT_RX_OFFSET  INACTIVE

#if (OPTIC_DEBUG == ACTIVE)
#define OPTIC_RUNMODE (1<<OPTIC_RUNMODE_ERROR_IGNORE)
#else
#define OPTIC_RUNMODE OPTIC_RUNMODE_STANDARD
#endif

#define OPTIC_INT16_MIN           (-32768)

/** macro for security checks, to be deactivated for code size optimizations.
    returns with the given return code if the expression is NOT true */
#define OPTIC_ASSERT_RETURN(exp,ret) \
	if (!(exp)) \
		return ret

enum optic_chip {
	OPTIC_CHIP_UNKNOWN = 0,
	OPTIC_CHIP_A11 = 0xA11,
	OPTIC_CHIP_A12 = 0xA12,
	OPTIC_CHIP_A21 = 0xA21,
};

enum optic_run_mode {
	OPTIC_RUNMODE_STANDARD,
	OPTIC_RUNMODE_ERROR_IGNORE
};

enum optic_measure_type {
	OPTIC_MEASURE_GAIN_GS0,
	OPTIC_MEASURE_GAIN_GS1,
	OPTIC_MEASURE_GAIN_GS2,
	OPTIC_MEASURE_GAIN_GS3,
	OPTIC_MEASURE_GAIN_GS4,
	OPTIC_MEASURE_GAIN_GS5,
	OPTIC_MEASURE_OFFSET_GS0,
	OPTIC_MEASURE_OFFSET_GS1,
	OPTIC_MEASURE_OFFSET_GS2,
	OPTIC_MEASURE_OFFSET_GS3,
	OPTIC_MEASURE_OFFSET_GS4,
	OPTIC_MEASURE_OFFSET_GS5,
	OPTIC_MEASURE_VDD_HALF,
	OPTIC_MEASURE_VBE1,
	OPTIC_MEASURE_VBE2,
	OPTIC_MEASURE_VOLTAGE_PN,
	OPTIC_MEASURE_POWER_RSSI_1490,
	OPTIC_MEASURE_POWER_RF_1550,
	OPTIC_MEASURE_POWER_RSSI_1550,
	OPTIC_MEASURE_MAX,
	OPTIC_MEASURE_NONE
};

enum optic_search_type {
	OPTIC_SEARCH_OFFSET_COARSE,
	OPTIC_SEARCH_OFFSET_FINE,
	OPTIC_SEARCH_P0_COARSE,
	OPTIC_SEARCH_P0_FINE,
	OPTIC_SEARCH_P1_COARSE,
	OPTIC_SEARCH_P1_FINE
};

enum measure_mode {
	OPTIC_MEASUREMODE_INIT,
	OPTIC_MEASUREMODE_PARALLEL,
	OPTIC_MEASUREMODE_CALIBRATE,
	OPTIC_MEASUREMODE_OCAL,
	OPTIC_MEASUREMODE_RSSI,
};

enum optic_loop_mode {
	OPTIC_LOOPMODE_INTRABURST,
	OPTIC_LOOPMODE_INTERBURST,
	OPTIC_LOOPMODE_DUALLOOP
};

struct optic_access {
	/** lock for DAC access handling */
	IFXOS_mutex_t dac_lock;
	/** lock for table access handling */
	IFXOS_mutex_t table_lock;
};

struct optic_factor {
	/** correction factor, - [ << OPTIC_FLOAT2INTSHIFT_CORRFACTOR] */
	uint16_t corr_factor;
};

struct optic_laserref {
	/** laser threshold [mA], - [ << OPTIC_FLOAT2INTSHIFT_CURRENT] */
	uint16_t ith;
	/** Slope efficiency,
	    internal units [ << OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY] */
	uint16_t se;
	/** laser operating seconds */
	uint32_t age;
};

struct optic_ibiasimod {
	/** Bias current, internal units [ << OPTIC_FLOAT2INTSHIFT_CURRENT] */
	uint16_t ibias[OPTIC_POWERLEVEL_MAX];
	/** Modulation current,
	    internal units [ << OPTIC_FLOAT2INTSHIFT_CURRENT] */
	uint16_t imod[OPTIC_POWERLEVEL_MAX];
};

struct optic_vapd {
	/** vapd ref, V [ << OPTIC_FLOAT2INTSHIFT_VOLTAGE] */
	uint16_t vref;
	/** APD duty cycle saturation maximum */
	uint8_t sat;
};

struct optic_temptrans {
	/** corrected temperature */
	uint16_t temp_corr;
};

struct optic_table_temperature_corr {
	/** correction factors */
	struct optic_factor factor[OPTIC_CFACTOR_MAX];
	/** laserref */
	struct optic_laserref laserref;
	/** Ibias Imod value for each TX power level */
	struct optic_ibiasimod ibiasimod;
	/** Vapd values */
	struct optic_vapd vapd;

	/** Data quality: /ref OPTIC_TABLEVAL_QUALITY_t */
	uint8_t quality[OPTIC_TABLETYPE_TEMP_CORR_MAX + 1
			- OPTIC_TABLETYPE_TEMP_CORR_MIN];
};

struct optic_table_temperature_nom {
	struct optic_temptrans temptrans;

	/** Data quality: /ref OPTIC_TABLEVAL_QUALITY_t */
	uint8_t quality[OPTIC_TABLETYPE_TEMP_NOM_MAX + 1
			- OPTIC_TABLETYPE_TEMP_NOM_MIN];
};

struct optic_table_mm_gain {
	/** gain factor shifted by 2 bits to the left */
	uint8_t factor;
	/** runtime measured/calculated offset */
	int16_t offset;
	/** runtime measured/calculated gain correction */
	int16_t correction;
};

/** \todo move to ocal header file */
struct optic_ocal {
#ifndef OPTIC_LIBRARY
	/** measurement wakeup event */
	IFXOS_event_t event_measure;
#endif

	uint8_t measure_number;
	uint8_t measure_index;
	uint16_t *measure_buffer;
};

struct optic_measurement {
	/** channel -> measurement type assignment */
	uint8_t measure_type[10];
	/** measurement type -> channel assignment */
	uint8_t channel[OPTIC_MEASURE_MAX];

	/** mm offset/gain/gain_correction table */
	struct optic_table_mm_gain gain[OPTIC_GAIN_SELECTOR_MAX];

	/** gain selector -> optic_table_mm_gain[] */
	uint8_t gain_selector_cal_index;
	uint8_t gain_selector_pn;
	uint8_t gain_selector_1490rx;
	uint8_t gain_selector_1550rf;
	uint8_t gain_selector_1550rx;

	/** voltage offset for pn junction measurement */
	uint16_t voltage_offset_pn;

	enum measure_mode mode;

	int16_t measure_history[OPTIC_MEASURE_MAX][OPTIC_MM_INIT_AVERAGE_DEPTH];
	uint8_t measure_index[OPTIC_MEASURE_MAX];
	int16_t average[OPTIC_MEASURE_MAX];

	/** special measurement mode */
	struct optic_ocal ocal;

	/** variables for internal RSSI control */
	uint8_t rssi1490;
	uint8_t intermediate_rssi1490;
};

struct optic_calibrate {
	struct optic_measurement measurement;

	/* normal mode */
	/** coarse offset (offset DAC) */
	int16_t dac_offset_tia_c[OPTIC_GAINBANK_MAX];
	/** fine offset (offset DAC) */
	int16_t dac_offset_tia_f[OPTIC_GAINBANK_MAX];
	/** coarse offset (level 1 DAC delta) */
	int16_t dac_offset_delta_p1_c[OPTIC_GAINBANK_MAX];
	/** fine offset (level 1 DAC delta) */
	int16_t dac_offset_delta_p1_f[OPTIC_GAINBANK_MAX];

	/** RX offset cancellation (only BOSA mode) */
	int32_t rx_offset;

	/* debug mode */
	/** coarse offset (offset DAC) */
	int16_t dbg_dac_offset_tia_c;
	/** fine offset (offset DAC) */
	int16_t dbg_dac_offset_tia_f;
	/** coarse offset (level 1 DAC delta) */
	int16_t dbg_dac_offset_delta_p1_c;
	/** fine offset (level 1 DAC delta) */
	int16_t dbg_dac_offset_delta_p1_f;

	/** coarse/fine ratio for P0 << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO */
	uint16_t ratio_p0;
	/** coarse/fine ratio for P1 << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO */
	uint16_t ratio_p1;

	/** Bias/Modulation integration coefficient (current value) */
	uint8_t intcoeff[2];

	/** system laser age / timestamp */
	uint32_t timestamp;
	/** current power level */
	enum optic_powerlevel powerlevel;
	/** automatic power level */
	enum optic_powerlevel auto_powerlevel;

	/** hardware loop mode */
	enum optic_loop_mode loopmode[2];

	/** measured internal temperature << OPTIC_FLOAT2INTSHIFT_TEMPERATURE */
	uint16_t temperature_int;
	/** corrected external temperature << OPTIC_FLOAT2INTSHIFT_TEMPERATURE */
	uint16_t temperature_ext;

	/** measured RSSI 1490 voltage -> for receive power calculation [V]
	    << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE */
	uint16_t meas_voltage_1490_rssi;
	/** measured RSSI 1490 current -> for receive power calculation [mA]
	    << OPTIC_FLOAT2INTSHIFT_CURRENT_FINE */
	uint16_t meas_current_1490_rssi;
	/** sign flag */
	bool meas_current_1490_rssi_is_positive;
	/** measured RF 1550 voltage -> for receive power calculation [V]
	    << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE */
	uint16_t meas_voltage_1550_rf;
	/** measured RSSI 1550 voltage -> for receive power calculation [V]
	    << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE */
	uint16_t meas_voltage_1550_rssi;

	/** Measured RSSI 1490 receive power ->  [mW]
	    << OPTIC_FLOAT2INTSHIFT_POWER */
	uint16_t meas_power_1490_rssi;
	/** Measured RSSI 1550 receive power ->  [mW]
	    << OPTIC_FLOAT2INTSHIFT_POWER */
	uint16_t meas_power_1550_rssi;
	/** Measured RF 1550 receive power ->  [mW]
	    << OPTIC_FLOAT2INTSHIFT_POWER */
	uint16_t meas_power_1550_rf;

	uint16_t abias_average;
	uint16_t amod_average;

	/** bias/mod value changed? -> false */
	bool stable[2];
	/** register value for ibias configuration */
	uint16_t dbias;
	/** register value for imod configuration */
	uint16_t dmod;

	/** target DCDC APD voltage [V], << OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t vapd_target;
	/** target Saturation value  */
	uint16_t sat_target;

	/** Offset current [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT_FINE */
	uint16_t current_offset;

	/** threshold voltage, << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE */
	uint16_t thresh_voltage_los;
	/** threshold voltage, << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE */
	uint16_t thresh_voltage_ovl;
	/** threshold current, << OPTIC_FLOAT2INTSHIFT_CURRENT_FINE */
	uint16_t thresh_current_los;
	/** threshold current, << OPTIC_FLOAT2INTSHIFT_CURRENT_FINE */
	uint16_t thresh_current_ovl;
	/** threshold codeword */
	uint16_t thresh_codeword_los;
	/** threshold codeword */
	uint16_t thresh_codeword_ovl;

	/** P0 gain correction factor (<< OPTIC_FLOAT2INTSHIFT_CORRFACTOR) */
	uint16_t gain_correct_p0;
	/** P0 gain correction factor (<< OPTIC_FLOAT2INTSHIFT_CORRFACTOR) */
	uint16_t gain_correct_p1;

	/** digital codeword for P0 << OPTIC_FLOAT2INTSHIFT_DREF */
	int32_t digit_codeword_p0;
	/** digital codeword for P1 << OPTIC_FLOAT2INTSHIFT_DREF */
	int32_t digit_codeword_p1;

	/** flag for current dualloop control: 0: P0, 1: P1
					       (in these cases toggling)
					       2: P0 & P1 (always both) */
	uint8_t dualloop_control;
};

/** OPTIC fuse parameters */
struct optic_fuses {
	/** internal fusing structure format */
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
	/** FBS0.STATUS.FUSE1.OFFSET1V0DCDC, 5 bit */
	int8_t offset_dcdc_core;
	/** FBS0.STATUS.FUSE1.GAIN1V0DCDC, 6 bit */
	uint8_t gain_dcdc_core;
	/** FBS0.STATUS.FUSE1.OFFSETAPDDCDC, 5 bit */
	int8_t offset_dcdc_apd;
	/** FBS0.STATUS.FUSE1.GAINAPDDCDC, 6 bit */
	uint8_t gain_dcdc_apd;
};

/** range config parameters */
struct optic_config_range {
	/** Minimum temperature covered by the temperature tables, in K */
	uint16_t tabletemp_extcorr_min;
	/** Maximum temperature covered by the temperature tables, in K */
	uint16_t tabletemp_extcorr_max;
	/** Minimum temperature covered by the temperature translation table,
	    in K */
	uint16_t tabletemp_extnom_min;
	/** Maximum temperature covered by the temperature translation table,
	    in K */
	uint16_t tabletemp_extnom_max;
	/** Minimum corrected internal temperature, in K */
	uint16_t tabletemp_intcorr_min;
	/** Maximum corrected internal temperature, in K */
	uint16_t tabletemp_intcorr_max;
	/** Minimum nominal internal temperature, in K */
	uint16_t tabletemp_intnom_min;
	/** Maximum nominal internal temperature, in K */
	uint16_t tabletemp_intnom_max;

	/** Maximum Ibias, <<OPTIC_FLOAT2INTSHIFT_CURRENT */
	uint16_t ibias_max;
	/** Maximum Imod, <<OPTIC_FLOAT2INTSHIFT_CURRENT */
	uint16_t imod_max;
	/** Maximum Ibias+Imod, <<OPTIC_FLOAT2INTSHIFT_CURRENT */
	uint16_t ibiasimod_max;
	/** Bias/Modulation integration coefficient maximum value */
	uint8_t intcoeff_max[2];

	/** Minimum VAPD voltage, <<OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t vapd_min;
	/** Maximum VAPD voltage, <<OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t vapd_max;
	/** Minimum duty cycle saturation */
	uint8_t sat_min;
	/** Maximum duty cycle saturation */
	uint8_t sat_max;
	/** Minimum Vcore voltage, <<OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t vcore_min;
	/** Maximum Vcore voltage, <<OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t vcore_max;
	/** Minimum Vcore voltage, <<OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t vddr_min;
	/** Maximum Vcore voltage, <<OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t vddr_max;
};

/** fcsi config parameters */
struct optic_config_fcsi {
	/** init value for FCSI register GVS */
	uint16_t gvs;
	/** power level dependent DDC0, DDC1, BDC0, BDC1 settings */
	uint8_t dd_loadn[OPTIC_POWERLEVEL_MAX];
	uint8_t dd_bias_en[OPTIC_POWERLEVEL_MAX];
	uint8_t dd_loadp[OPTIC_POWERLEVEL_MAX];
	uint8_t dd_cm_load[OPTIC_POWERLEVEL_MAX];
	uint8_t bd_loadn[OPTIC_POWERLEVEL_MAX];
	uint8_t bd_bias_en[OPTIC_POWERLEVEL_MAX];
	uint8_t bd_loadp[OPTIC_POWERLEVEL_MAX];
	uint8_t bd_cm_load[OPTIC_POWERLEVEL_MAX];
};

/** dcdc apd config parameters */
struct optic_config_dcdc_apd {
	/** external attenuation <<OPTIC_FLOAT2INTSHIFT_EXTATT */
	uint16_t ext_att;
	/** voltage divider, ext_att = (r_diff[1] + r_diff[0]) / r_diff[0] */
	uint32_t r_diff[2];
	/** external supply voltage */
	uint32_t v_ext;
};

/** dcdc core, DDR config parameters */
struct optic_config_dcdc {
	/** v_min = Rmin * Imin [V] <<OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t v_min;
	/** v_max = Rmax * Imax [V] <<OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t v_max;
	/** input voltage tolerance [%] */
	uint8_t v_tolerance_input;
	/** target voltage tolerance [%] */
	uint8_t v_tolerance_target;
	/** PMOS transistor switch-on delay after NMOS transistor switch-off. */
	uint32_t pmos_on_delay;
	/** NMOS transistor switch-on delay after PMOS transistor switch-off. */
	uint32_t nmos_on_delay;
};

/** measurement config parameters */
struct optic_config_measurement {
	/** tscal_ref << OPTIC_FLOAT2INTSHIFT_TSCALREF */
	uint16_t tscal_ref;
	/** pnR << OPTIC_FLOAT2INTSHIFT_RESISTOR_FINE */
	uint16_t pn_r;
	/** iref definition for external measurements */
	enum optic_iref pn_iref;
	/** RSSI 1490 measurement method */
	enum optic_rssi_1490_mode rssi_1490_mode;
	/** correction factor, << OPTIC_FLOAT2INTSHIFT_CORRFACTOR */
	uint16_t rssi_1490_dark_corr;
	/** RSSI 1490 shunt resistor, << 0 */
	uint16_t rssi_1490_shunt_res;
	/** RSSI 1550 Vref (1/2/3) = 0.5V 1.0V 1.5V */
	enum optic_vref rssi_1550_vref;
	/** RF 1550 Vref (1/2/3) = 0.5V 1.0V 1.5V */
	enum optic_vref rf_1550_vref;
	/** RSSI 1490 scal ref, << OPTIC_FLOAT2INTSHIFT_PSCALREF */
	uint16_t rssi_1490_scal_ref;
	/** RSSI 1550 scal ref, << OPTIC_FLOAT2INTSHIFT_PSCALREF */
	uint16_t rssi_1550_scal_ref;
	/** RF 1550 scal ref, << OPTIC_FLOAT2INTSHIFT_PSCALREF */
	uint16_t rf_1550_scal_ref;
	/** RF 1490 parabolic ref, << OPTIC_FLOAT2INTSHIFT_PSCALREF */
	uint16_t rssi_1490_parabolic_ref;
	/** measured RSSI 1490 dark current curing calibration */
	uint16_t meas_dark_current_1490_rssi;
	/** RSSI_autolevel switch for automatic power leveling */
	bool RSSI_autolevel;
	/** RSSI1490 low threshold for automatic power leveling */
	uint32_t RSSI_1490threshold_low;
	/** RSSI1490 high threshold for automatic power leveling */
	uint32_t RSSI_1490threshold_high;
};

/** monitor config parameters */
struct optic_config_monitor {
	/** TIA gain selector */
	uint8_t tia_gain_selector[OPTIC_GAINBANK_MAX];
	/** calibration selector (100uA/1mA) */
	enum optic_cal_current cal_current[OPTIC_GAINBANK_MAX];
	/** Data quality flag tia_gain_selector */
	enum optic_tableval_quality tia_gain_selector_quality[OPTIC_GAINBANK_MAX];
	/** Data quality flag cal_current */
	enum optic_tableval_quality cal_current_quality[OPTIC_GAINBANK_MAX];

	/** scale factor for translation between Imod and Dmod per transmit
	    power level, ~1	<<OPTIC_FLOAT2INTSHIFT_CORRFACTOR */
	uint16_t scalefactor_mod[3];

	/** DcalrefP0 at Tref */
	int32_t dcal_ref_p0[OPTIC_POWERLEVEL_MAX];
	/** DcalrefP1 at Tref */
	int32_t dcal_ref_p1[OPTIC_POWERLEVEL_MAX];
	/** DrefP0 */
	int32_t dref_p0[OPTIC_POWERLEVEL_MAX];
	/** DrefP1 */
	int32_t dref_p1[OPTIC_POWERLEVEL_MAX];
	/** Data quality flag dref settings */
	enum optic_tableval_quality dref_quality[OPTIC_POWERLEVEL_MAX];

	/** coarse/fine ratio for P0/P1 << OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO */
	uint16_t ratio_coarse_fine;
	/** power-save mode */
	enum optic_activation powersave;

	/** number of CID bits for P0 detection */
	uint8_t cid_size_p0;
	/** number of CID bits for P1 detection */
	uint8_t cid_size_p1;
	/** select, if any (false) or all (true) bits of p0 CID mask
	    have to be set */
	bool cid_match_all_p0;
	/** select, if any (false) or all (true) bits of p1 CID mask
	    have to be set */
	bool cid_match_all_p1;
	/** CID mask for P0 detection */
	uint16_t cid_mask_p0;
	/** CID mask for P1 detection */
	uint16_t cid_mask_p1;

	/** flexible mod/bias maximum definition [mA] */
	uint8_t mod_max;
	uint8_t bias_max;
	/** Modulation overcurrent threshold */
	uint16_t oc_imod_thr;
	/** Bias overcurrent threshold */
	uint16_t oc_ibias_thr;
	/** Bias and Imod sum overcurrent threshold */
	uint16_t oc_ibias_imod_thr;
	/* Select rogue interburst alarms.
	   - false: disable interburst alarms
  	   - true: enable interburst alarms */
	bool rogue_interburst;
	/* Select rogue intraburst alarms.
	   - false: disable intraburst alarms
  	   - true: enable intraburst alarms */
	bool rogue_intraburst;
};

/** calibration / debug mode specific parameters */
struct optic_config_debug {
	/** TIA gain selector */
	uint8_t tia_gain_selector;
	/** calibration selector (100uA/1mA) */
	uint8_t cal_current;

	/** DcalrefP0 at Tref */
	int32_t dcal_ref_p0;
	/** DcalrefP1 at Tref */
	int32_t dcal_ref_p1;
	/** DrefP0 */
	int32_t dref_p0;
	/** DrefP1 */
	int32_t dref_p1;
};

/** OMU config parameters */
struct optic_config_omu {
	/** Indicate if the "signal detect" status signal is available. */
	bool signal_detect_avail;
	/** GPIO port used as "signal detect" input
	\todo Define the GPIO numbering scheme.*/
	uint8_t signal_detect_port;
	/** GPIO interrupt number */
	uint8_t signal_detect_irq;
	/** loss of lock threshold "set" in % */
	uint8_t threshold_lol_set;
	/** loss of lock threshold "clear" in % */
	uint8_t threshold_lol_clear;
	/** Laser enable signal mode selection. The control signal can be
	single-ended (CMOS) or differential (PECL).
	- true: single-ended laser enable signal
	- false: differential laser enable signal */
	bool laser_enable_single_ended;
};

/** BOSA config parameters */
struct optic_config_bosa {
	/** configured BOSA loop mode */
	enum optic_bosa_loop_mode loop_mode;
	/** CDR dead zone elimination mode:
	    - false: disabled
	    - true:  enabled */
	bool dead_zone_elimination;
	/** Loss of lock alarm threshold 1 (set alarm), in % */
	uint8_t threshold_lol_set;
	/** Loss of lock alarm threshold 2 (clear alarm), in % */
	uint8_t threshold_lol_clear;
	/** Loss of signal threshold [mW] << OPTIC_FLOAT2INTSHIFT_POWER */
	uint16_t threshold_los;
	/** Receiver overload threshold [mW] << OPTIC_FLOAT2INTSHIFT_POWER */
	uint16_t threshold_rx_overload;

	/** Bias/Modulation integration coefficient (initial value) */
	uint8_t intcoeff_init[2];
	/** threshold for update current bias/modulation in [%] */
	uint8_t updatethreshold[2];
	/** threshold for learning current bias/modulation in [%] */
	uint8_t learnthreshold[2];
	/** threshold for stable current bias/modulation in
	   [% difference from average codeword] */
	uint8_t stablethreshold[2];
	/** threshold for reset bias/modulation in
	   [% difference from initialization codeword] */
	uint8_t resetthreshold[2];
	/** Phase interpolator setting */
	uint32_t pi_control;
	/** low power level at reference [-3dB, -6dB] transmit power [uW] */
	int16_t p0[3];
	/** high power level at reference [-3dB, -6dB] transmit power [uW] */
	int16_t p1[3];
	/** optical transmit power at laser threshold [uW] */
	int16_t pth;
};

/** OPTIC config parameters */
struct optic_config {
	/** time interval to check for a temperature change in ms */
	uint16_t temperature_check_time;
	/** threshold to force MPD offset cancelation and gain correction */
	uint8_t temperature_thres_mpdcorr;

	/** laser age update cycle [seconds] */
	uint16_t update_laser_age;

	/** TX FiFo configuration: enable delay */
	int16_t delay_tx_enable;
	/** TX FiFo configuration: disable delay */
	uint16_t delay_tx_disable;
	/** TX FiFo configuration: buffer size */
	uint16_t size_tx_fifo;

	/** start Temp = Tref [K] */
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

	/** alarm temperature ranges */
	uint16_t temp_alarm_yellow_set;
	uint16_t temp_alarm_yellow_clear;
	uint16_t temp_alarm_red_set;
	uint16_t temp_alarm_red_clear;

	/** OMU od BOSA mode */
	enum optic_manage_mode mode;

	/** fusing information list */
	struct optic_fuses fuses;
	struct optic_config_range range;
	struct optic_config_fcsi fcsi;
	struct optic_config_dcdc_apd dcdc_apd;
	struct optic_config_dcdc dcdc_core;
	struct optic_config_dcdc dcdc_ddr;
	struct optic_config_measurement measurement;
	struct optic_config_monitor monitor;
	struct optic_config_debug debug;
	struct optic_config_omu omu;
	struct optic_config_bosa bosa;

	/** debug mode (active/inactive) */
	bool debug_mode;
	/** OPTIC_RUNMODE_STANDARD or bits enabled for debug handling */
	uint32_t run_mode;

	/** Interrupt Service Callback Routine */
	optic_isr callback_isr;

	/** enable Laser Training Sequence */
	bool lts_enable;
};

struct optic_interrupts {
	bool signal_overload;
	bool signal_valid;
	bool signal_lost;

	bool rx_lock_lost;

	bool tx_overcurrent;
	bool tx_p0_interburst_alarm;
	bool tx_p1_interburst_alarm;
	bool tx_p0_intraburst_alarm;
	bool tx_p1_intraburst_alarm;
	bool tx_bias_limit;
	bool tx_mod_limit;

	bool temp_alarm_yellow;
	bool temp_alarm_red;
};

struct optic_temperatures {
	uint32_t timestamp;
	uint16_t temp_int;
	uint16_t temp_ext;
};

struct optic_state {
	enum optic_statetype current_state;
	enum optic_statetype buffer[OPTIC_STATE_HISTORY_DEPTH];
	uint8_t index_buffer;

	/* order of initialisation regarding goi_config.sh
	2 - OPTIC_TABLETYPE_PTH,
	3 - OPTIC_TABLETYPE_LASERREF,
	4 - OPTIC_TABLETYPE_VAPD,
	5 - OPTIC_TABLETYPE_MPDRESP,
	6 - OPTIC_TABLETYPE_RSSI1490,
	7 - OPTIC_TABLETYPE_RSSI1550,
	8 - OPTIC_TABLETYPE_RF1550,
	9 - OPTIC_TABLETYPE_TEMPTRANS
	1 - OPTIC_TABLETYPE_IBIASIMOD <- calculated
*/

	bool table_read[OPTIC_TABLETYPE_INTERN_MAX + 1
	                - OPTIC_TABLETYPE_INTERN_MIN];
	/* -> enum optic_configtype for numeric interpretation */
	bool config_read[OPTIC_CONFIGTYPE_MAX];

	struct optic_temperatures temperatures[OPTIC_TEMPERATURE_HISTORY_DEPTH];
	uint8_t index_temperature;

	struct optic_interrupts interrupts;
};

/** FIFO management entity */
struct optic_fifo {
#ifdef __KERNEL__
	/** FIFO lock */
	spinlock_t lock;
#else
	/** FIFO lock */
	IFXOS_mutex_t lock;
#endif
	/** True if FIFO should be used */
	bool enable;
#ifndef OPTIC_LIBRARY
	/** FIFO overhead */
	IFX_VFIFO data;
	/** FIFO buffer by itself */
	uint8_t buf[OPTIC_FIFO_SIZE];
	/** Number of lost elements */
	uint32_t lost;
	/** FIFO name */
	char name[32];
#endif
};

/** instance related data */
struct optic_control {
	/** lock for device list handling */
	IFXOS_mutex_t list_lock;
	/** device list */
	struct optic_device *p_dev_head;
	/** run flag for the worker thread */
	bool worker_run;
	/** worker wakeup event */
	IFXOS_event_t event_worker;
#ifndef OPTIC_LIBRARY
	/** worker thread context */
	IFXOS_ThreadCtrl_t thread_ctx_worker;
	/** FIFO to inform applications about status changes messages */
	struct optic_fifo fifo_worker;
	/** run flag for the measurement thread */
	bool measure_run;
	/** measurement thread context */
	IFXOS_ThreadCtrl_t thread_ctx_measure;
	/** measurement wakeup event */
	IFXOS_event_t event_measure;
	/** access control */
	struct optic_access access;
#endif
	/** calibration parameters */
	struct optic_calibrate calibrate;
	/** configuration parameter list */
	struct optic_config config;
	/** temperature table (based on corrected external temperature */
	struct optic_table_temperature_corr *table_temperature_corr;
	/** temperature table (based on uncorrected external temperature */
	struct optic_table_temperature_nom *table_temperature_nom;

	/** state structure */
	struct optic_state state;
	/** measurement interval time */
	uint32_t mm_interval;
	/** number of internal temperature measurements to allow a 
	    range check only if stable */
	uint32_t temp_measure;
};
/* driver context */

/** Device related data. */
struct optic_device {
#ifndef OPTIC_LIBRARY
	/** Support for select() */
	IFXOS_drvSelectQueue_t select_queue;
	/** Buffer for ioctl operation */
	uint8_t io_buf[OPTIC_IO_BUF_SIZE];
	/** Notification FIFO */
	struct optic_fifo fifo_nfc;
	/** */
	bool nfc_need_wakeup;
#endif
	/** Next device */
	struct optic_device *p_prev;
	/** Next device */
	struct optic_device *p_next;
	/** Control structure */
	void *p_ctrl;
	/** Helper pointer for CLI */
	char *help_out;
	/** Helper variable for CLI */
	int32_t help_out_len;
	/** Helper variable for CLI */
	int32_t help_max_len;
};
/* device context */

/** control structures */
extern struct optic_control optic_ctrl[OPTIC_INSTANCES_MAX];

/** what string */
extern const char optic_whatversion[];

/** chip version */
extern enum optic_chip chip_version;

#if !defined(CONFIG_WITH_FALCON_A1X) && !defined(CONFIG_WITH_FALCON_A2X)
/* support for all version as default */
#define CONFIG_WITH_FALCON_A1X
#define CONFIG_WITH_FALCON_A2X
#endif

#if defined(CONFIG_WITH_FALCON_A1X) && defined(CONFIG_WITH_FALCON_A2X)
static inline bool is_falcon_chip_a11(void)
{
	return (chip_version == OPTIC_CHIP_A11);
}
static inline bool is_falcon_chip_a12(void)
{
	return (chip_version == OPTIC_CHIP_A12);
}
static inline bool is_falcon_chip_a1x(void)
{
	return (chip_version <= OPTIC_CHIP_A12);
}
static inline bool is_falcon_chip_a2x(void)
{
	return (chip_version >= OPTIC_CHIP_A21);
}
#else
#ifdef CONFIG_WITH_FALCON_A2X
static inline bool is_falcon_chip_a11(void) { return false; }
static inline bool is_falcon_chip_a12(void) { return false; }
static inline bool is_falcon_chip_a1x(void) { return false; }
static inline bool is_falcon_chip_a2x(void) { return true; }
#else
static inline bool is_falcon_chip_a11(void)
{
	return (chip_version == OPTIC_CHIP_A11);
}
static inline bool is_falcon_chip_a12(void)
{
	return (chip_version == OPTIC_CHIP_A12);
}
static inline bool is_falcon_chip_a1x(void) { return true; }
static inline bool is_falcon_chip_a2x(void) { return false; }
#endif
#endif

/**
   Initializes the corresponding driver instance

   \param p_ctrl device control
   \param p_dev     private device data

   \return
   - OPTIC_STATUS_OK           Success
   - OPTIC_STATUS_ERR          in case of error
   - OPTIC_STATUS_ALLOC_ERR    in case of memory allocation error
*/
enum optic_errorcode optic_device_open ( struct optic_control *p_ctrl,
					 struct optic_device *p_dev );
/** device close function */
enum optic_errorcode optic_device_close ( struct optic_device *p_dev );
void optic_irq_omu_init ( const uint8_t signal_detect_irq );
void optic_irq_set ( enum optic_manage_mode mode,
		     enum optic_activation act );
void optic_udelay ( uint32_t u_sec );
#ifdef OPTIC_STATE_HOTPLUG_EVENT
void optic_hotplug_state ( const enum optic_statetype state );
#endif
void optic_hotplug_timestamp (const uint32_t timestamp );
int optic_signal_pending(void *sig);

/** execute Command Line instruction */
enum optic_errorcode optic_cli ( struct optic_device *p_dev,
				 char *param );
/** initialization of overhead resources (lock) */
enum optic_errorcode optic_fifo_init ( struct optic_fifo *p_fifo,
				       const char *pName );
/** delete / free of overhead resources (lock) */
enum optic_errorcode optic_fifo_delete ( struct optic_fifo *p_fifo);
/** add data to FIFO */
enum optic_errorcode optic_fifo_write ( IFXOS_event_t *wakeup_event,
					struct optic_fifo *p_fifo,
					const uint32_t control,
					const void *buf,
					const uint32_t len);
/** add data to FIFO */
enum optic_errorcode optic_fifo_writevalue ( IFXOS_event_t *wakeup_event,
					     struct optic_fifo *p_fifo,
					     const uint32_t control,
					     const uint32_t value );
/** read data from FIFO */
enum optic_errorcode optic_fifo_read ( struct optic_fifo *p_fifo,
				       void *buf,
				       uint32_t *len );
/** add device to internal list */
enum optic_errorcode optic_devicelist_add ( struct optic_control *p_ctrl,
					    struct optic_device *p_dev );
/** remove device from internal list */
enum optic_errorcode optic_devicelist_delete ( struct optic_control *p_ctrl,
					       struct optic_device *p_dev );

#ifdef __KERNEL__
#define optic_lock spinlock_t
#else
#define optic_lock IFXOS_mutex_t
#endif
int32_t optic_spinlock_init ( optic_lock *id, const char *name );
int32_t optic_spinlock_delete ( optic_lock *id );
int32_t optic_spinlock_get ( optic_lock *id, ulong_t *flags );
int32_t optic_spinlock_release ( optic_lock *id, ulong_t flags );

enum optic_errorcode optic_temptrans_size_get ( const enum optic_tabletype
						type,
						uint8_t *size );
enum optic_errorcode optic_init_temptable ( struct optic_control *p_ctrl,
					    const enum optic_tabletype type );

enum optic_errorcode optic_write_temptable ( struct optic_control *p_ctrl,
					     const enum optic_tabletype type,
					     const uint16_t tabledepth,
					     const void *p_transfertable,
					     uint16_t *valuetemp_min,
					     uint16_t *valuetemp_max,
					     bool *complete );
enum optic_errorcode optic_read_temptable ( struct optic_control *p_ctrl,
					    const enum optic_tabletype type,
					    const uint16_t tabledepth_max,
					    void *p_transfertable,
					    enum optic_tableval_quality quality,
					    uint16_t *tabledepth );
enum optic_errorcode optic_complete_table ( struct optic_control *p_ctrl,
					    const enum optic_tabletype type,
					    const uint16_t valuetemp_min,
					    const uint16_t valuetemp_max );
enum optic_errorcode optic_cfactor_table_set ( struct optic_control *p_ctrl,
					       const enum optic_cfactor type,
					       const uint16_t temperature,
					       const uint16_t corr_factor );
enum optic_errorcode optic_cfactor_table_get ( struct optic_control *p_ctrl,
					       const enum optic_cfactor type,
					       const uint16_t temperature,
					       uint16_t *corr_factor,
					       enum optic_tableval_quality
					       *quality );
enum optic_errorcode optic_powersave_set ( struct optic_control *p_ctrl );

/** measurement timer handler */
void optic_timer_measure (struct optic_control *p_ctrl);
/** OPTIC worker thread */
int32_t optic_thread_worker ( IFXOS_ThreadParams_t *param );
/** OPTIC measurement thread */
int32_t optic_thread_measure ( IFXOS_ThreadParams_t *param );
/** common interrupt handler */
enum optic_errorcode optic_interrupt ( struct optic_control *p_ctrl );
enum optic_errorcode optic_temperature_store ( struct optic_control *p_ctrl );

int optic_context_init ( void *ctrl, uint8_t nr );
int optic_context_free ( void *ctrl);

uint32_t optic_register_read ( uint8_t form, void *reg);
enum optic_errorcode optic_register_write ( uint8_t form,
					    void *reg,
					    uint32_t value );

enum optic_errorcode optic_state_set ( struct optic_control *p_ctrl,
				       const enum optic_statetype state );
enum optic_errorcode optic_state_get ( struct optic_control *p_ctrl,
				       enum optic_statetype
				       state[OPTIC_STATE_HISTORY_DEPTH] );
enum optic_errorcode optic_ctrl_reset ( struct optic_control *p_ctrl,
					const bool init );

#ifdef OPTIC_LIBRARY
enum OPTIC_MEM_ID {
	MEM_TBL_TEMP_CORR,
	MEM_TBL_TEMP_NOM
};

extern void* optic_malloc (size_t size, uint32_t id);
#endif

typedef enum optic_errorcode (*optic_function0) (struct optic_device *p_dev);
typedef enum optic_errorcode (*optic_function1) (struct optic_device *p_dev,
						 void *);
typedef enum optic_errorcode (*optic_function2) (struct optic_device *p_dev,
						 const void *, void *);

struct optic_entry {
	uint32_t id;
#ifdef INCLUDE_DEBUG_SUPPORT
	const char *name;
#endif
	uint32_t size_in;
	uint32_t size_out;
	optic_function0 p_entry0;
	optic_function1 p_entry1;
	optic_function2 p_entry2;
};

#ifdef INCLUDE_DEBUG_SUPPORT
#	define TE0(id, f0) \
   {id, #id, 0, 0, (optic_function0) f0, NULL, NULL}
#	define TE1in(id, in_size, f1) \
   {id, #id, in_size, 0, NULL, (optic_function1) f1, NULL}
#	define TE1out(id, out_size, f1) \
   {id, #id, 0, out_size, NULL, (optic_function1) f1, NULL}
#	define TE2(id, in_size, out_size, f2) \
   {id, #id, in_size, out_size, NULL, NULL, (optic_function2) f2}
#else
#	define TE0(id, f0) \
   {id, 0, 0, (optic_function0) f0, NULL, NULL}
#	define TE1in(id, in_size, f1) \
   {id, in_size, 0, NULL, (optic_function1) f1, NULL}
#	define TE1out(id, out_size, f1) \
   {id, 0, out_size, NULL, (optic_function1) f1, NULL}
#	define TE2(id, in_size, out_size, f2) \
   {id, in_size, out_size, NULL, NULL, (optic_function2) f2}
#endif

extern const struct optic_entry optic_function_table[OPTIC_MAX];
extern const struct optic_entry goi_function_table[OPTIC_GOI_MAX];
extern const struct optic_entry fcsi_function_table[OPTIC_FCSI_MAX];
extern const struct optic_entry mm_function_table[OPTIC_MM_MAX];
extern const struct optic_entry mpd_function_table[OPTIC_MPD_MAX];
extern const struct optic_entry bert_function_table[OPTIC_BERT_MAX];
extern const struct optic_entry omu_function_table[OPTIC_OMU_MAX];
extern const struct optic_entry bosa_function_table[OPTIC_BOSA_MAX];
extern const struct optic_entry cal_function_table[OPTIC_CAL_MAX];
extern const struct optic_entry dcdc_apd_function_table[OPTIC_DCDC_APD_MAX];
extern const struct optic_entry dcdc_core_function_table[OPTIC_DCDC_CORE_MAX];
extern const struct optic_entry dcdc_ddr_function_table[OPTIC_DCDC_DDR_MAX];
extern const struct optic_entry ldo_function_table[OPTIC_LDO_MAX];

/*! @} */

EXTERN_C_END

#endif
