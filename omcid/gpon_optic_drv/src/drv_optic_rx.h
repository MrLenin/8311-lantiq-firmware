/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_rx.h
*/
#ifndef _drv_optic_rx_h
#define _drv_optic_rx_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_RX_INTERNAL Receive Module - Internal
   @{
*/

#define OPTIC_RX_AFECTRL_RTERM    0x17
#define OPTIC_RX_AFECTRL_EMP      0x03

enum optic_errorcode optic_rx_init ( const enum optic_manage_mode mode,
				     const bool dead_zone_elimination,
				     const uint8_t threshold_lol_clear,
				     const uint8_t threshold_lol_set,
				     const bool rx_polarity_regular,
				     int32_t *p_rx_offset );


/*! @} */

/*! @} */

EXTERN_C_END

#endif
