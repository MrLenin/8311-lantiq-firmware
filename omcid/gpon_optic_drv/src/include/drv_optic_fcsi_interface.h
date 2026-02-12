/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_fcsi_interface.h
   This is the GPON Optical Interface header file,
   used for the FALC(tm) ON GPON ONU driver, FCSI block.
*/
#ifndef _drv_optic_fcsi_interface_h_
#define _drv_optic_fcsi_interface_h_

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

/** \defgroup OPTIC_FSCI FCSI Register Interface

    This chapter describes the software interface to access and configure the
    GPON Optical Interface FCSI register set.
   @{
*/

#define OPTIC_POWERLEVEL_CNT    3


/**
	FCSI configuration setting.
	Used by \ref FIO_FCSI_CFG_SET and \ref FIO_FCSI_CFG_GET.
*/
struct optic_fcsi_config {
	/** FCSI register GVS (gain scaling). */
	uint16_t gvs;
	/** FCSI register CTRL0. */
	uint16_t ctrl0;
} __PACKED__;


/**
   Set the configuration for the FCSI hardware block.

   \param optic_fcsi_config Pointer to \ref optic_fcsi_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_FCSI_CFG_SET _IOW(OPTIC_FCSI_MAGIC, 0, struct optic_fcsi_config )

/**
   Read back the configuration of the FCSI hardware block.

   \param optic_fcsi_config Pointer to \ref optic_fcsi_config.

   \remarks The function returns an error code in case of error.
            The error code is described in \ref optic_errorcode.

   \return Return value as follows:
   - OPTIC_STATUS_OK, if successful
   - An error code in case of error.
*/
#define FIO_FCSI_CFG_GET _IOR(OPTIC_FCSI_MAGIC, 1, struct optic_fcsi_config )

#define OPTIC_FCSI_MAX                              2


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
#endif                          /* _drv_optic_fcsi_interface_h_ */
