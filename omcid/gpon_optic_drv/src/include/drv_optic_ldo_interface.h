/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ldo_interface.h
   This is the GPON Optical Interface header file,
   used for the FALC(tm) ON GPON ONU driver, LDO block.
*/
#ifndef _drv_optic_ldo_interface_h_
#define _drv_optic_ldo_interface_h_

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

/** \defgroup OPTIC_LDO Linear LDO Interface

    This chapter describes the software interface to access and configure the
    GPON Optical Interface for linear LDO converter configuration.
   @{
*/


/** Linear LDO voltage controller status.
    Used by \ref FIO_LDO_STATUS_GET.
*/
struct optic_ldo_status {
	/** Linear LDO enable status.
	- false: Disabled.
	- true: Enabled. */
	bool enable;
} __PACKED__;


/**
   Enable the linear LDO voltage converter control output.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_LDO_ENABLE _IO(OPTIC_LDO_MAGIC, 0)

/**
   Disable the linear LDO voltage converter control output.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_LDO_DISABLE _IO(OPTIC_LDO_MAGIC, 1)

/**
   Read back the status of the linear LDO voltage converter.

   \param optic_ldo_status Pointer to \ref optic_ldo_status.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_LDO_STATUS_GET _IOR(OPTIC_LDO_MAGIC, 2, struct optic_ldo_status)


#define OPTIC_LDO_MAX                              3




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
