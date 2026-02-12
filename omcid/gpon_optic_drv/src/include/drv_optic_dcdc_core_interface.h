/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_dcdc_apd_interface.h
   This is the GPON Optical Interface header file,
   used for the FALC(tm) ON GPON ONU driver, DCDC CORE block.
*/
#ifndef _drv_optic_dcdc_core_interface_h_
#define _drv_optic_dcdc_core_interface_h_

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

/** \defgroup OPTIC_DCDC_CORE DC/DC CORE Interface

    This chapter describes the software interface to access and configure the
    GPON Optical Interface for DCDC CORE configuration.
   @{
*/

/** Core voltage supply DC/DC converter configuration parameters.
    Used by \ref FIO_DCDC_CORE_CFG_SET and \ref FIO_DCDC_CORE_CFG_GET. */
struct optic_dcdc_core_config {
	/** Minimum voltage,
	    v_min = Rmin * Imin [V] <<OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t v_min;
	/** Maximum voltage,
	    v_max = Rmax * Imax [V] <<OPTIC_FLOAT2INTSHIFT_VOLTAGE */
	uint16_t v_max;
	/** Input voltage tolerance [%] */
	uint8_t v_tolerance_input;
	/** Target voltage tolerance [%] */
	uint8_t v_tolerance_target;
	/** PMOS transistor switch-on delay after NMOS transistor switch-off. */
	uint8_t pmos_on_delay;
	/** NMOS transistor switch-on delay after PMOS transistor switch-off. */
	uint8_t nmos_on_delay;
} __PACKED__;

/** GPON optical layer hardware configuration.
    Used by \ref FIO_DCDC_CORE_STATUS_GET.
*/
struct optic_dcdc_core_status {
	/** Core voltage DC/DC enable status, true if enabled. */
	bool enable;
	/** Core voltage, in V << OPTIC_FLOAT2INTSHIFT_VOLTAGE*/
	uint16_t voltage;
} __PACKED__;

/**
   Set the configuration for DCDC CORE.

   \param optic_dcdc_core_config Pointer to \ref optic_dcdc_core_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_DCDC_CORE_CFG_SET _IOW(OPTIC_DCDC_CORE_MAGIC, 0, struct optic_dcdc_core_config)

/**
   Read back the DCDC CORE configuration.

   \param optic_dcdc_core_config Pointer to \ref optic_dcdc_core_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_DCDC_CORE_CFG_GET _IOR(OPTIC_DCDC_CORE_MAGIC, 1, struct optic_dcdc_core_config)

/**
   Enables the DCDC CORE.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_DCDC_CORE_ENABLE _IO(OPTIC_DCDC_CORE_MAGIC, 2)

/**
   Disables the DCDC CORE.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_DCDC_CORE_DISABLE _IO(OPTIC_DCDC_CORE_MAGIC, 3)

/**
   Reads back the status of the DCDC CORE.

   \param optic_dcdc_core_status Pointer to \ref optic_dcdc_core_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_DCDC_CORE_STATUS_GET _IOR(OPTIC_DCDC_CORE_MAGIC, 4, struct optic_dcdc_core_status)


#define OPTIC_DCDC_CORE_MAX 5


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
