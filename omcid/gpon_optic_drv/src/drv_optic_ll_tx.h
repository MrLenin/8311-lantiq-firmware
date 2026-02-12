/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_tx.h
*/
#ifndef _drv_optic_ll_tx_h
#define _drv_optic_ll_tx_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_TX_INTERNAL Transmit Module - Internal
   @{
*/

enum optic_errorcode optic_ll_tx_path_init (const enum optic_manage_mode mode,
	const bool bias_invert, const bool polarity_invert);


void optic_ll_tx_path_activate (const enum optic_current_type
                                                type, const bool invert);
void optic_ll_tx_biaspath_data_set (const uint8_t data);

enum optic_errorcode optic_ll_tx_path_bert_set (const enum optic_activation
						 bert_data );
enum optic_errorcode optic_ll_tx_fifo_set ( const int16_t delay_enable,
                                            const uint16_t delay_disable,
                                            const uint16_t size_fifo );
enum optic_errorcode optic_ll_tx_fifo_get ( int16_t *delay_enable,
                                            uint16_t *delay_disable,
                                            uint16_t *size_fifo );
void optic_ll_tx_pi_set (const uint32_t pi_ctrl);
void optic_ll_tx_delay_set (const uint8_t data_delay,
			     const uint8_t intrinsic_delay );
void optic_ll_tx_powersave_set (const enum optic_activation powerdown);
#ifdef CONFIG_WITH_FALCON_A2X
enum optic_errorcode optic_ll_tx_pd_latchoverride_set (
		const enum optic_activation override );
#endif
enum optic_errorcode optic_ll_tx_laserdelay_set ( const uint8_t bitdelay );
enum optic_errorcode optic_ll_tx_laserdelay_get ( uint8_t *bitdelay );

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_TX == ACTIVE))
enum optic_errorcode optic_ll_tx_dump ( void );
#endif

/*! @} */

/*! @} */

EXTERN_C_END

#endif
