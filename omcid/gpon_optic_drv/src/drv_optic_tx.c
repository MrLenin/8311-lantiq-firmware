/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/**
   \file drv_optic_tx.c
   \remarks TX module.
*/

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_tx.h"
#include "drv_optic_ll_tx.h"


/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_TX_INTERNAL Common TX Interface - Internal
   @{
*/

enum optic_errorcode optic_tx_init ( const enum optic_manage_mode mode,
				     const uint32_t pi_control,
				     const int16_t delay_tx_enable,
				     const uint16_t delay_tx_disable,
				     const uint16_t size_tx_fifo,
				     const bool bias_polarity,
				     const bool mod_polarity)
{
	enum optic_errorcode ret;

	uint16_t temp_tx_disable_delay;

	/* set data to 0, set flip bit, init polarity */
	ret = optic_ll_tx_path_init (mode, !bias_polarity, !mod_polarity);

	/* PI CTRL set */
	optic_ll_tx_pi_set (pi_control);

	/* GPONSW-924
	 * We additionally need a workaround for OMU mode to have a TxDisableDelay
	 * larger than 3 Nibbles in order send out our S/N response against NSN hiX.
	 * Please use a TxDisable Delay of 0 only for A22 BOSA mode,
	 * in case of A22 OMU mode please use 4 nibbles.
	 * */
	if(is_falcon_chip_a2x() &&
	   mode == OPTIC_OMU &&
	   delay_tx_enable < 16 ) /* bits -> 4 nibbles */
		temp_tx_disable_delay = 16;
	else
		temp_tx_disable_delay = delay_tx_disable;

	optic_ll_tx_fifo_set (delay_tx_enable, temp_tx_disable_delay, size_tx_fifo);
	optic_ll_tx_delay_set (OPTIC_TX_DATA_DELAY, OPTIC_TX_INTRINSIC_DELAY);
	optic_ll_tx_powersave_set (OPTIC_DISABLE);

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_TX == ACTIVE))
	optic_ll_tx_dump ();
#endif

	return ret;
}

/*! @} */

/*! @} */
