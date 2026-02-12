/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_dcdc_apd_interface.h
   This is the GPON Optical Interface header file,
   used for the FALC(tm) ON GPON ONU driver, DCDC APD block.
*/
#ifndef _drv_optic_dcdc_apd_interface_h_
#define _drv_optic_dcdc_apd_interface_h_

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

/** \defgroup OPTIC_DCDC_APD DC/DC APD Interface

    This chapter describes the software interface to access and configure the
    GPON Optical Interface for DCDC APD configuration.
   @{
*/


/** APD configuration parameters. Used by \ref FIO_DCDC_APD_CFG_SET and
    \ref FIO_DCDC_APD_CFG_GET. */
struct optic_dcdc_apd_config {
	/** Voltage divider value,
	    ext_att = (r_diff[1] + r_diff[0]) / r_diff[0] */
	uint32_t r_diff[2];
	/** External supply voltage  */
	uint32_t v_ext;
} __PACKED__;


/** GPON optical layer hardware configuration.
    Used by \ref FIO_DCDC_APD_STATUS_GET.
*/
struct optic_dcdc_apd_status {
	/** DC/DC APD enable status, true if enabled. */
	bool enable;
	/** DC/DC APD target voltage, in V << OPTIC_FLOAT2INTSHIFT_VOLTAGE*/
	uint16_t target_voltage;
	/** DC/DC APD output voltage, in V << OPTIC_FLOAT2INTSHIFT_VOLTAGE*/
	int16_t voltage;
	/** Voltage regulation error, in V << OPTIC_FLOAT2INTSHIFT_VOLTAGE*/
	int16_t regulation_error;
	/** APD duty cycle saturation maximum */
	uint8_t saturation;
} __PACKED__;

/**
   Set the configuration for DCDC APD.

   \param optic_dcdc_apd_config Pointer to \ref optic_dcdc_apd_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_DCDC_APD_CFG_SET _IOW(OPTIC_DCDC_APD_MAGIC, 0, struct optic_dcdc_apd_config)

/**
   Read back the DCDC APD configuration.

   \param optic_dcdc_apd_config Pointer to \ref optic_dcdc_apd_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_DCDC_APD_CFG_GET _IOR(OPTIC_DCDC_APD_MAGIC, 1, struct optic_dcdc_apd_config)

/**
   Enables the DCDC APD.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_DCDC_APD_ENABLE _IO(OPTIC_DCDC_APD_MAGIC, 2)

/**
   Disables the DCDC APD.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_DCDC_APD_DISABLE _IO(OPTIC_DCDC_APD_MAGIC, 3)

/**
   Reads back the status of the DCDC APD.

   \param optic_dcdc_apd_status Pointer to \ref optic_dcdc_apd_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_DCDC_APD_STATUS_GET _IOR(OPTIC_DCDC_APD_MAGIC, 4, struct optic_dcdc_apd_status)


#define OPTIC_DCDC_APD_MAX 5


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
#endif                          /* _drv_optic_dcdc_apd_interface_h_ */
