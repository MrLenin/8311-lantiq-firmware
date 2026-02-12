/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/**
   \file drv_optic_rx.c
   \remarks RX module.
*/

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_rx.h"
#include "drv_optic_ll_rx.h"


/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_RX_INTERNAL Common RX Interface - Internal
   @{
*/

enum optic_errorcode optic_rx_init ( const enum optic_manage_mode mode,
				     const bool dead_zone_elimination,
				     const uint8_t threshold_lol_clear,
				     const uint8_t threshold_lol_set,
				     const bool rx_polarity_regular,
				     int32_t *p_rx_offset )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	enum optic_rx_type rx_mode;
	uint32_t temp;
	bool invert;

	if (p_rx_offset == NULL)
		return OPTIC_STATUS_ERR;

	switch (mode) {
	case OPTIC_OMU:
		ret = optic_ll_rx_cdr_init ( false, dead_zone_elimination );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_ll_rx_cdr_init: %d",
					ret);
			return OPTIC_STATUS_INIT_FAIL;
		}

		if (rx_polarity_regular == true)
			invert = false;
		else
			invert = true;

		rx_mode = OPTIC_RX_DATA_HIGH;
		break;
	case OPTIC_BOSA:
		ret = optic_ll_rx_cdr_init ( true, dead_zone_elimination );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_ll_rx_cdr_init: %d",
					ret);
			return OPTIC_STATUS_INIT_FAIL;
		}

		if (rx_polarity_regular == true)
			invert = true;
		else
			invert = false;

		rx_mode = OPTIC_RX_DATA_LOW;
		break;

	default:
		return OPTIC_STATUS_POOR;
	}

	/* thresholds */
	ret = optic_ll_rx_lolalarm_thresh_set ( threshold_lol_clear,
						threshold_lol_set );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_ll_rx_lolalarm_thresh_set: %d",
				ret);
		return OPTIC_STATUS_INIT_FAIL;
	}

	/* flipping */
	ret = optic_ll_rx_flipinvert_set ( OPTIC_RX_DATA_LOW, true, invert );

	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_ll_rx_flipinvert: %d",
				ret);
		return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_ll_rx_flipinvert_set ( OPTIC_RX_DATA_HIGH, true, invert );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_ll_rx_flipinvert: %d",
				ret);
		return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_ll_rx_flipinvert_set ( OPTIC_RX_EDGE_FALL, true, invert );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_ll_rx_flipinvert: %d",
				ret);
		return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_ll_rx_flipinvert_set ( OPTIC_RX_EDGE_RISE, true, invert );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_ll_rx_flipinvert: %d",
				ret);
		return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_ll_rx_flipinvert_set ( OPTIC_RX_MONITOR, true, invert );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_ll_rx_flipinvert: %d",
				ret);
		return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_ll_rx_flipinvert_set ( OPTIC_RX_XTALK, false, false );
	if (ret != OPTIC_STATUS_OK) {
		OPTIC_DEBUG_ERR("optic_ll_rx_flipinvert: %d", ret);
		return OPTIC_STATUS_INIT_FAIL;
	}

	temp = abs (*p_rx_offset);

	ret = optic_ll_rx_dac_set ( OPTIC_RX_DATA_LOW,
				    (*p_rx_offset >= 0) ? true : false,
				    (temp >> 8) & 0xFF, temp & 0xFF );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_ll_rx_dac_set: %d", ret);
		return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_ll_rx_dac_set ( OPTIC_RX_DATA_HIGH, true, 0, 0 );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_ll_rx_dac_set: %d", ret);
		return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_ll_rx_dac_sel ( OPTIC_RX_DATA_LOW );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_ll_rx_dac_sel: %d", ret);
		return OPTIC_STATUS_INIT_FAIL;
	}

	/* enable to GTC */
	ret = optic_ll_rx_afectrl_config ( OPTIC_RX_AFECTRL_RTERM,
					   OPTIC_RX_AFECTRL_EMP );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("optic_ll_rx_afectrl_config: %d", ret);
		return OPTIC_STATUS_INIT_FAIL;
	}

	if ((mode == OPTIC_BOSA) && (*p_rx_offset == 0)) {
		/* AFE enable is part of rx offset correction */
		ret = optic_ll_rx_offset_cancel ( rx_mode, p_rx_offset );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_ll_rx_offset_cancel: %d",
					 ret);
			return OPTIC_STATUS_INIT_FAIL;
		}
	} else {
		ret = optic_ll_rx_afectrl_set ( OPTIC_ENABLE, false );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("optic_ll_rx_afectrl_set: %d",
					ret);
			return OPTIC_STATUS_INIT_FAIL;
		}
	}

#if ((OPTIC_DEBUG == ACTIVE) && (OPTIC_DEBUG_PRINTOUT_DUMP_RX == ACTIVE))
	optic_ll_rx_dump ();
#endif

	return ret;
}


/*! @} */

/*! @} */
