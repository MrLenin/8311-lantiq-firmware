/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_mm_interface.h
   This is the GPON Optical Interface header file,
   used for the FALC(tm) ON GPON ONU driver, Measurement block.
*/
#ifndef _drv_optic_mm_interface_h_
#define _drv_optic_mm_interface_h_

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

/** \defgroup OPTIC_MM Measurement Module Interface

    This chapter describes the software interface to access and configure the
    GPON Optical Interface Measurement Module.
   @{
*/

/**
	Measurement Module configuration setting.
	Used by \ref FIO_MM_CFG_SET and \ref FIO_MM_CFG_GET.
*/
struct optic_mm_config {
	/** tscal_ref - temperature sensor characteristic (K/mV). */
	uint16_t tscal_ref;
	/** pnR - external resistance (Ohm). */
	uint16_t pn_r;
	/** RSSI 1490 measurement method */
	enum optic_rssi_1490_mode rssi_1490_mode;
	/** Iref - measurement current definition for external measurements. */
	enum optic_iref pn_iref;
	/** Correction factor, << OPTIC_FLOAT2INTSHIFT_CORRFACTOR */
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
	/** RSSI 1490 parabolic ref, << OPTIC_FLOAT2INTSHIFT_PSCALREF */
	uint16_t rssi_1490_parabolic_ref;
	/** RSSI 1490 dark current ref, << OPTIC_FLOAT2INTSHIFT_CURRENT_FINE */
	uint16_t rssi_1490_dark_ref;
	/** RSSI_autolevel switch for automatic power leveling */
	bool RSSI_autolevel;
	/** RSSI1490 low threshold for automatic power leveling */
	uint32_t RSSI_1490threshold_low;
	/** RSSI1490 high threshold for automatic power leveling */
	uint32_t RSSI_1490threshold_high;
} __PACKED__;

/**
	Measurement Module temperature measurement result.
	Used by \ref FIO_MM_DIE_TEMPERATURE_GET and
	\ref FIO_MM_LASER_TEMPERATURE_GET.
*/
struct optic_temperature {
	/** Temperature value, given in 1 K, set to 0xFFFF if invalid.
	    Typical values are in the range from 233 (-40 deg C)
	    to 423 (+150 deg C) for the die temperature
	    and up to 363 (+90 deg C) for the external laser temperature. */
	uint16_t temperature;
} __PACKED__ ;

/**
   Set the configuration for measurement block.

   \param optic_mm_config Pointer to \ref optic_mm_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_MM_CFG_SET _IOW(OPTIC_MM_MAGIC, 0, struct optic_mm_config)

/**
   Read back the measurement block configuration.

   \param optic_mm_config Pointer to \ref optic_mm_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_MM_CFG_GET _IOR(OPTIC_MM_MAGIC, 1, struct optic_mm_config)

/**
   Read back the measured internal temperature.

   \param optic_temperature Pointer to \ref optic_temperature.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_MM_DIE_TEMPERATURE_GET _IOR(OPTIC_MM_MAGIC, 2, struct optic_temperature)

/**
   Read back the measured external temperature.

   \param optic_temperature Pointer to \ref optic_temperature.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_MM_LASER_TEMPERATURE_GET _IOR(OPTIC_MM_MAGIC, 3, struct optic_temperature)

/**
   Read back the measured optical receive voltage at 1490 nm.

   \param optic_voltage Pointer to \ref optic_voltage.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_MM_1490_OPTICAL_VOLTAGE_GET _IOR(OPTIC_MM_MAGIC, 4, struct optic_voltage_fine)

/**
   Read back the measured optical receive current at 1490 nm.

   \param optic_current Pointer to \ref optic_current.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_MM_1490_OPTICAL_CURRENT_GET _IOR(OPTIC_MM_MAGIC, 5, struct optic_current_fine)

/**
   Read back the measured optical receive power at 1490 nm.

   \param optic_current Pointer to \ref optic_current.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_MM_1490_OPTICAL_POWER_GET _IOR(OPTIC_MM_MAGIC, 6, struct optic_power)

/**
   Read back the measured optical receive voltage at 1550 nm.

   \param optic_voltage Pointer to \ref optic_voltage.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_MM_1550_OPTICAL_VOLTAGE_GET _IOR(OPTIC_MM_MAGIC, 7, struct optic_voltage_fine)

/**
   Read back the measured electrical receive voltage at 1550 nm.

   \param optic_voltage Pointer to \ref optic_voltage.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_MM_1550_ELECTRICAL_VOLTAGE_GET _IOR(OPTIC_MM_MAGIC, 8, struct optic_voltage_fine)

#define OPTIC_MM_MAX 9


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
#endif                          /* _drv_optic_mm_interface_h_ */
