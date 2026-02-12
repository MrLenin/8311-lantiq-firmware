/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_tx.h
*/
#ifndef _drv_optic_tx_h
#define _drv_optic_tx_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_TX_INTERNAL Transmit Module - Internal
   @{
*/

#define OPTIC_TX_DATA_DELAY           6
#define OPTIC_TX_INTRINSIC_DELAY      0


enum optic_errorcode optic_tx_init ( const enum optic_manage_mode mode,
				     const uint32_t pi_control,
				     const int16_t delay_tx_enable,
				     const uint16_t delay_tx_disable,
				     const uint16_t size_tx_fifo,
				     const bool bias_polarity,
				     const bool mod_polarity );


/*! @} */

/*! @} */

EXTERN_C_END

#endif
