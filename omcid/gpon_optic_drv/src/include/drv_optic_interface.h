/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_interface.h
   This file contains common definitions
   used by the FALC(tm) ON Optic Driver.
*/
#ifndef _drv_optic_interface_h
#define _drv_optic_interface_h

#include "drv_optic_std_defs.h"


#ifndef _MKSTR_1
#define _MKSTR_1(x)    #x
#define _MKSTR(x)      _MKSTR_1(x)
#endif

/** \addtogroup MAPI_REFERENCE_GOI Optical Interface API Reference
   This chapter summarizes the optical interface API function calls, separately
   for each of the hardware units that are involved.
   @{
*/

/** \defgroup OPTIC_COMMON Optic Common Driver Interface
   This chapter describes the common driver interface for the optical
   interface module software.
   @{
*/
/** Device name */
#define GPON_OPTIC_NAME          "optic"
#define GPON_OPTIC_TYPE          "GPON Optic Driver"
#define DRV_IO_GPON_OPTIC        "/dev/optic"

/** Driver version, major number */
#define OPTIC_VER_MAJOR            4
/** Driver version, minor number */
#define OPTIC_VER_MINOR            5
/** Driver version, build number */
#define OPTIC_VER_STEP             0
/** Driver version, package type */
/*
#define OPTIC_VER_TYPE             1
*/
#undef OPTIC_VER_TYPE
/** Driver version as string */
#ifdef OPTIC_VER_TYPE
#define OPTIC_VER_STR   _MKSTR(OPTIC_VER_MAJOR)"."_MKSTR(OPTIC_VER_MINOR)"." \
			_MKSTR(OPTIC_VER_STEP)"."_MKSTR(OPTIC_VER_TYPE)
#else
#define OPTIC_VER_STR   _MKSTR(OPTIC_VER_MAJOR)"."_MKSTR(OPTIC_VER_MINOR)"." \
			_MKSTR(OPTIC_VER_STEP)
#endif

/** Driver version, what string */
#define OPTIC_COPYRIGHT "(c) Copyright 2011, Lantiq Deutschland GmbH"
#define OPTIC_WHAT_STR "@(#)FALC(tm) ON Optic Driver, version " OPTIC_VER_STR " " OPTIC_COPYRIGHT

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

#ifdef SWIG
#undef _IO
#define _IO(a,b) ((a)<<8 | (b))
#undef _IOW
#define _IOW(a,b,c) ((a)<<8 | (b))
#undef _IOR
#define _IOR(a,b,c) ((a)<<8 | (b))
#undef _IOWR
#define _IOWR(a,b,c) ((a)<<8 | (b))
#endif

/** Device-specific buffer size used for ioctl(). */
#define OPTIC_IO_BUF_SIZE                4096
/** Size of the notification FIFO. */
#define OPTIC_FIFO_SIZE                  512

/* range value (16 bit): 0,00024 < value <16: 12*/
/* range value (16 bit): 0,00100 < value <64: 10*/

#define OPTIC_FLOAT2INTSHIFT_GAINFACTOR            2
#define OPTIC_FLOAT2INTSHIFT_DREF                  4

/* [K] */
#define OPTIC_FLOAT2INTSHIFT_TEMPERATURE           4
#define OPTIC_FLOAT2INTSHIFT_SLOPEEFFICIENCY       6
#define OPTIC_FLOAT2INTSHIFT_MPDRESPCORRGAINCORR   8
/* [mA] */
#define OPTIC_FLOAT2INTSHIFT_CURRENT               8
/* [V] */
#define OPTIC_FLOAT2INTSHIFT_VOLTAGE               9
#define OPTIC_FLOAT2INTSHIFT_EXTATT                9
#define OPTIC_FLOAT2INTSHIFT_LOG                  10
#define OPTIC_FLOAT2INTSHIFT_CORRFACTOR           11
#define OPTIC_FLOAT2INTSHIFT_COARSEFINERATIO      11
#define OPTIC_FLOAT2INTSHIFT_PSCALREF             11
#define OPTIC_FLOAT2INTSHIFT_TSCALREF             11
/* Ohm */
#define OPTIC_FLOAT2INTSHIFT_RESISTOR_FINE        11
/* [mA] */
#define OPTIC_FLOAT2INTSHIFT_CURRENT_FINE         14
/* [V] */
#define OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE         14
/* [mW] */
#define OPTIC_FLOAT2INTSHIFT_POWER                14

#define OPTIC_USEDBITS_DREF                       18

#define OPTIC_STATE_HISTORY_DEPTH                 10
#define OPTIC_TEMPERATURE_HISTORY_DEPTH           32
/* delay in seconds, after which current system timestamp / laser age is requested by application and written into filesystem */
#define OPTIC_UPDATE_LASERAGE_TIME              3600


/* Table type definitions. */
#define OPTIC_TABLETYPE_TEMP_CORR_MIN   OPTIC_TABLETYPE_IBIASIMOD
#define OPTIC_TABLETYPE_TEMP_CORR_MAX   OPTIC_TABLETYPE_RF1550
#define OPTIC_TABLETYPE_TEMP_NOM_MIN    OPTIC_TABLETYPE_TEMPTRANS
#define OPTIC_TABLETYPE_TEMP_NOM_MAX    OPTIC_TABLETYPE_TEMPTRANS
#define OPTIC_TABLETYPE_INTERN_MIN      OPTIC_TABLETYPE_TEMP_CORR_MIN
#define OPTIC_TABLETYPE_INTERN_MAX      OPTIC_TABLETYPE_TEMP_NOM_MAX


/* Magic numbers for the optical interface. */
#define OPTIC_MAGIC                            200
#define OPTIC_GOI_MAGIC                        201
#define OPTIC_FCSI_MAGIC                       202
#define OPTIC_MM_MAGIC                         203
#define OPTIC_MPD_MAGIC                        204
#define OPTIC_BERT_MAGIC                       205
#define OPTIC_OMU_MAGIC                        206
#define OPTIC_BOSA_MAGIC                       207
#define OPTIC_CAL_MAGIC                        208
#define OPTIC_DCDC_APD_MAGIC                   209
#define OPTIC_DCDC_CORE_MAGIC                  210
#define OPTIC_DCDC_DDR_MAGIC                   211
#define OPTIC_LDO_MAGIC                        212

#define OPTIC_EVENT_MAGIC                      220

/** Activation mode. */
enum optic_activation {
	/** Disable the function. */
	OPTIC_DISABLE,
	/** Enable the function. */
	OPTIC_ENABLE
};

/* Table types in driver stored / only transferred (higher block) */
/** Table type definition. */
enum optic_tabletype {
	/** Unknown table type. */
	OPTIC_TABLETYPE_UNKNOWN,
	/** Bias/modulation current table. */
	OPTIC_TABLETYPE_IBIASIMOD,
	/** Laser threshold correction table. */
	OPTIC_TABLETYPE_PTH,
	/** Laser reference correction table. */
	OPTIC_TABLETYPE_LASERREF,
	/** APD voltage correction table. */
	OPTIC_TABLETYPE_VAPD,
	/** Monitor photo diode responsivity correction table. */
	OPTIC_TABLETYPE_MPDRESP,
	/** 1490 nm optical receive power correction table. */
	OPTIC_TABLETYPE_RSSI1490,
	/** 1550 nm optical receive power correction table. */
	OPTIC_TABLETYPE_RSSI1550,
	/** 1550 nm electrical receive power correction table. */
	OPTIC_TABLETYPE_RF1550,
	/** Temperature correction table. */
	OPTIC_TABLETYPE_TEMPTRANS,
	/** Transmit power correction table. */
	OPTIC_TABLETYPE_POWER,
};

/** Table value quality indication. */
enum optic_tableval_quality {
	/** Unknown table quality. */
	OPTIC_TABLEQUAL_UNKNOWN = 0,
	/** Initial value. */
	OPTIC_TABLEQUAL_INITIAL = 1,
	/** Fixed value. */
	OPTIC_TABLEQUAL_FIXSET = 2,
	/** Limit value. */
	OPTIC_TABLEQUAL_BORDER = 3,
	/** Extrapolated value. */
	OPTIC_TABLEQUAL_EXTRAP = 4,
	/** Interpolated value. */
	OPTIC_TABLEQUAL_INTERP = 5,
	/** Calculated value. */
	OPTIC_TABLEQUAL_CALC = 6,
	/** Stored value. */
	OPTIC_TABLEQUAL_STORE = 7,
	/** Measured value. */
	OPTIC_TABLEQUAL_MEAS = 8
};

/** Optical interface configuration type. */
enum optic_configtype {
	/** Global optical interface configuration. */
	OPTIC_CONFIGTYPE_GOI,
	/** Value range configuration. */
	OPTIC_CONFIGTYPE_RANGE,
	/** Register configuration. */
	OPTIC_CONFIGTYPE_FCSI,
	/** Measurement module configuration. */
	OPTIC_CONFIGTYPE_MM,
	/** Monitor photo diode configuration. */
	OPTIC_CONFIGTYPE_MPD,
	/** Optical module interface configuration. */
	OPTIC_CONFIGTYPE_OMU,
	/** BOSA receive path configuration. */
	OPTIC_CONFIGTYPE_BOSA_RX,
	/** BOSA transmit path configuration. */
	OPTIC_CONFIGTYPE_BOSA_TX,
	/** APD supply DC/DC converter configuration. */
	OPTIC_CONFIGTYPE_DCDC_APD,
	/** Core supply DC/DC converter configuration. */
	OPTIC_CONFIGTYPE_DCDC_CORE,
	/** DDR memory supply DC/DC converter configuration. */
	OPTIC_CONFIGTYPE_DCDC_DDR,
	/** Maximum value for configuration type. */
	OPTIC_CONFIGTYPE_MAX
};

/** Conversion factor. */
enum optic_cfactor {
	/** Laser threshold conversion factor. */
	OPTIC_CFACTOR_PTH,
	/** MPD responsivity conversion factor. */
	OPTIC_CFACTOR_MPDRESP,
	/** 1490 nm optical receive power conversion factor. */
	OPTIC_CFACTOR_RSSI1490,
	/** 1550 nm optical receive power conversion factor. */
	OPTIC_CFACTOR_RSSI1550,
	/** 1550 nm electrical receive power conversion factor. */
	OPTIC_CFACTOR_RF1550,
	/** Maximum conversion factor. */
	OPTIC_CFACTOR_MAX
};

/** Optical transmit power level. */
enum optic_powerlevel {
	/** Transmit power level 0 dB. */
	OPTIC_POWERLEVEL_0,
	/** Transmit power level -3 dB. */
	OPTIC_POWERLEVEL_1,
	/** Transmit power level -6 dB. */
	OPTIC_POWERLEVEL_2,
	/** Maximum transmit power level. */
	OPTIC_POWERLEVEL_MAX
};

/** Optical interface gain bank selection. */
enum optic_gainbank {
	/** Gain bank selection for transmit power level 0 dB. */
	OPTIC_GAINBANK_PL0,
	/** Gain bank selection for transmit power level -3 dB. */
	OPTIC_GAINBANK_PL1,
	/** Gain bank selection for transmit power level -6 dB. */
	OPTIC_GAINBANK_PL2,
	/** Global gain bank selection. */
	OPTIC_GAINBANK_GLOBAL,
	/** Maximum gain bank selection. */
	OPTIC_GAINBANK_MAX
};

/** Reference current selection for measurements. */
enum optic_iref {
	/** 20 uA */
	OPTIC_IREF_20UA  = 0,
	/** 100 uA */
	OPTIC_IREF_100UA = 1,
	/** 400 uA */
	OPTIC_IREF_400UA = 2
};

/** Calibration current selection. */
enum optic_cal_current {
	/** Calibration current switched off. */
	OPTIC_CAL_OFF    = 0,
	/** Calibration current switch is open. */
	OPTIC_CAL_OPEN   = 1,
	/** 100 uA calibration current. */
	OPTIC_CAL_100UA  = 2,
	/** 1 mA calibration current. */
	OPTIC_CAL_1MA    = 3,
	/** Calibration current configuration. */
	OPTIC_CAL_CONFIG = 0xFF
};

/** Reference voltage selection. */
enum optic_vref {
	/** 0.0 V */
	OPTIC_VREF_0MV    = 0,
	/** 0.5 V */
	OPTIC_VREF_500MV  = 1,
	/** 1.0 V */
	OPTIC_VREF_1000MV = 2,
	/** 1.5 V */
	OPTIC_VREF_1500MV = 3
};

/** Receive power measurement mode at 1490 nm. */
enum optic_rssi_1490_mode {
	/** Differential power measurement at 1490 nm receive wavelength,
	    using an external shunt resistor. */
	OPTIC_RSSI_1490_DIFFERENTIAL,
	/** Single-ended power measurement at 1490 nm receive wavelength,
	    using an internal shunt resistor. */
	OPTIC_RSSI_1490_SINGLE_ENDED
};

/** Laser current selection. */
enum optic_current_type {
	/** Laser bias current. */
	OPTIC_BIAS,
	/** Laser modulation current. */
	OPTIC_MOD
};

/** Optical interface operation mode. */
enum optic_manage_mode {
	/** No operation mode selected. */
	OPTIC_NOMODE,
	/** Optical module interface (OMU). */
	OPTIC_OMU,
	/** BOSA interface. */
	OPTIC_BOSA,
	/** BOSA interface, using OMU receive input. */
	OPTIC_BOSA_2
};

/** Optical interface interrupts. */
enum optic_irq {
	/** No interrupt. */
	OPTIC_IRQ_NONE,

	/** Interrupt on "signal detect" (SD).*/
	OPTIC_IRQ_SD,
	/** Interrupt on "loss of signal" (LOS). */
	OPTIC_IRQ_LOS,
	/** Interrupt on overload condition (OVL). */
	OPTIC_IRQ_OVL,
	/** Interrupt on CDR "loss of lock" (LOL). */
	OPTIC_IRQ_LOL,

	/** Interrupt on overcurrent condition. */
	OPTIC_IRQ_OV,
	/** Interrupt on P0 Interburst Alarm. */
	OPTIC_IRQ_BP0IBA,
	/** Interrupt on P1 Interburst Alarm. */
	OPTIC_IRQ_BP1IBA,
	/** Interrupt on P0 Intraburst Alarm. */
	OPTIC_IRQ_BP0BA,
	/** Interrupt on P1 Intraburst Alarm. */
	OPTIC_IRQ_BP1BA,
	/** Interrupt on bias current limit violation. */
	OPTIC_IRQ_BIASL,
	/** Interrupt on modulation current limit violation. */
	OPTIC_IRQ_MODL,

	/** Interrupt on yellow temperature alarm set. */
	OPTIC_IRQ_TEMPALARM_YELLOW_SET,
	/** Interrupt on yellow temperature alarm clear. */
	OPTIC_IRQ_TEMPALARM_YELLOW_CLEAR,
	/** Interrupt on red temperature alarm set. */
	OPTIC_IRQ_TEMPALARM_RED_SET,
	/** Interrupt on red temperature alarm clear. */
	OPTIC_IRQ_TEMPALARM_RED_CLEAR
};

/** Interrupt definition. */
typedef void (*optic_isr) (enum optic_irq);
extern void optic_tx_enable (bool enable);

/** Data exchange structure for all ioctl() calls. */
struct optic_exchange {
	/** Error code. */
	int error;
	/** Length of data in bytes.
            The caller has to provide the length of p_data.
            The ioctl call will return the size or zero in case of failure. */
	uint32_t length;
	/** Pointer to source/destination data. */
	void *p_data;
};

/** Structure for direct register access. */
struct optic_reg_set {
	/** Select 8-, 16-, or 32-bit access. */
	uint8_t form;
	/** Register address. */
	ulong_t address;
	/** Register value. */
	uint32_t value;
} __PACKED__;

/** Input structure for register access. */
struct optic_reg_get_in {
	/** Select 8-, 16-, or 32-bit access. */
	uint8_t form;
	/** Register address. */
	ulong_t address;
} __PACKED__;

/** Output structure to access the registers directly. */
struct optic_reg_get_out {
	/** Select 8-, 16-, or 32-bit access.
	- 8: 8-bit access.
	- 16: 16-bit access.
	- 32: 32-bit access.
	- other values: Invalid. */
	uint8_t form;
	/** Register value. */
	uint32_t value;
} __PACKED__;

/** Union to access the registers directly. */
union optic_reg_get {
	/** Input value. */
	struct optic_reg_get_in in;
	/** Output value. */
	struct optic_reg_get_out out;
};

/** Structure for debug level manipulation. */
struct optic_debuglevel {
	/** Debug level selection.
	    Use only values as defined by \ref optic_debug_levels. */
	uint8_t level;
} __PACKED__;

/** Structure to read the version string.
    The string is available as 'what string' within the binary. */
struct optic_versionstring {
	/** Version string. */
	char version[80];
} __PACKED__;

/** Structure to set/get the optical interface mode. */
struct optic_mode {
	/** OMU or BOSA mode */
	enum optic_manage_mode mode;
} __PACKED__;

/** Structure to register the isr callback. */
struct optic_register {
	optic_isr callback_isr;
} __PACKED__;

/** Optical receiver voltage level. */
struct optic_voltage {
	/** Voltage, [V] << OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t voltage_val;
} __PACKED__;

/** Optical transmit laser current value. */
struct optic_current {
	/** Current, [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT */
	uint16_t current_val;
} __PACKED__;

/** Optical receiver voltage level. */
struct optic_voltage_fine {
	/** Voltage, [V] << OPTIC_FLOAT2INTSHIFT_VOLTAGE_FINE */
	uint16_t voltage_fine_val;
} __PACKED__;

/** Optical transmit laser current value. */
struct optic_current_fine {
	/** Current, [mA] << OPTIC_FLOAT2INTSHIFT_CURRENT_FINE */
	uint16_t current_fine_val;
	/** sign flag */
	bool is_positive;
} __PACKED__;

/** Optical receiver power level. */
struct optic_power {
	/** Power, [mW] << OPTIC_FLOAT2INTSHIFT_POWER */
	uint16_t power_val;
} __PACKED__;

/** BFD/MPD feedback scaling selection. */
struct optic_bfd {
	/** FCSI gain scaling register */
	uint16_t gvs;
	/** FCSI CTRL0 register */
	uint16_t ctrl0;
} __PACKED__;


/**
   Register Set
   \param optic_reg_set Pointer to \ref optic_reg_set.
*/
#define FIO_OPTIC_REGISTER_SET                 _IOW(OPTIC_MAGIC, 0, struct optic_reg_set)

/** Register Get
   \param optic_reg_get Pointer to \ref optic_reg_get.
*/
#define FIO_OPTIC_REGISTER_GET                 _IOWR(OPTIC_MAGIC, 1, union optic_reg_get)

/**
   Specify the level of debug outputs
   \param optic_debuglevel Pointer to \ref optic_debuglevel.
*/
#define FIO_OPTIC_DEBUGLEVEL_SET               _IOW(OPTIC_MAGIC, 2, struct optic_debuglevel)

/**
   Changes the level of debug outputs
   \param optic_debuglevel Pointer to \ref optic_debuglevel.
*/
#define FIO_OPTIC_DEBUGLEVEL_GET               _IOR(OPTIC_MAGIC, 3, struct optic_debuglevel)

/**
   Return the version information
   \param optic_versionstring Pointer to \ref optic_versionstring.
*/
#define FIO_OPTIC_VERSION_GET                  _IOR(OPTIC_MAGIC, 4, struct optic_versionstring)

/**
   Reset optic module
*/
#define FIO_OPTIC_RESET                        _IO(OPTIC_MAGIC, 5)

/**
   Reset optic module
*/
#define FIO_OPTIC_RECONFIG                     _IO(OPTIC_MAGIC, 6)

/**
   Specify the optic mode BOSA or OMU. Mandatory configuration before
   system startup.
   \param optic_manage_mode Pointer to \ref optic_manage_mode.
*/
#define FIO_OPTIC_MODE_SET                     _IOW(OPTIC_MAGIC, 7, struct optic_mode)

/**
   Register a Interrupt Service Callback Routine.
   \param optic_manage_mode Pointer to \ref optic_manage_mode.
*/
#define FIO_OPTIC_ISR_REGISTER                 _IOW(OPTIC_MAGIC, 8, struct optic_register )

#define OPTIC_MAX                              9

/**
   CLI access
*/
#define FIO_OPTIC_CLI                          _IO(OPTIC_MAGIC, 100)


#ifndef SWIG
int optic_init ( void );
void optic_exit ( void );
#endif

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
#endif
