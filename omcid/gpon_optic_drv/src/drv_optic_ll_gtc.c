/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, GTC-PMA Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_GTC_PMA_INTERNAL GTC/PMA Interface Module - Internal
   @{
*/


#include "drv_optic_ll_gtc.h"
#include "drv_optic_register.h"

#include "drv_optic_reg_gtc_pma.h"


static enum optic_errorcode optic_ll_gtc_length_set ( const uint8_t length);
static enum optic_errorcode optic_ll_gtc_length_get ( uint8_t *length);
static enum optic_errorcode optic_ll_gtc_pattern_set ( const uint32_t
						       pattern[20] );
static enum optic_errorcode optic_ll_gtc_pattern_get ( uint32_t pattern[20] );

static enum optic_errorcode optic_ll_gtc_length_set ( const uint8_t length)
{
	gtc_pma_w32_mask ( GTC_PMA_LTSC_LEN_MASK,
			   (((length > 78) ? 78 : length)
			    << GTC_PMA_LTSC_LEN_OFFSET) &
			       GTC_PMA_LTSC_LEN_MASK, ltsc);

	return OPTIC_STATUS_OK;
}

static enum optic_errorcode optic_ll_gtc_length_get ( uint8_t *length)
{
	uint32_t reg;

	if (length == NULL)
		return OPTIC_STATUS_ERR;

	reg = gtc_pma_r32 ( ltsc );
	*length = (reg & GTC_PMA_LTSC_LEN_MASK) >> GTC_PMA_LTSC_LEN_OFFSET;

	if (*length > 78)
		*length = 78;

	return OPTIC_STATUS_OK;
}

static enum optic_errorcode optic_ll_gtc_pattern_set ( const uint32_t
                                                       pattern[20] )
{
	uint8_t i;

	if (pattern == NULL)
		return OPTIC_STATUS_ERR;

	for (i=0; i<20; i++)
		gtc_pma_w32(pattern[i], ltsdata[i]);

	return OPTIC_STATUS_OK;
}

static enum optic_errorcode optic_ll_gtc_pattern_get ( uint32_t pattern[20] )
{
	uint8_t i;

	if (pattern == NULL)
		return OPTIC_STATUS_ERR;

	for (i=0; i<20; i++)
		pattern[i] = gtc_pma_r32(ltsdata[i]);

	return OPTIC_STATUS_OK;
}


enum optic_errorcode optic_ll_gtc_set ( const enum optic_activation mode )
{
	gtc_pma_w32_mask ( GTC_PMA_LTSC_EN,
	                   (mode == OPTIC_ENABLE)?
	                   GTC_PMA_LTSC_EN : GTC_PMA_LTSC_EN_DIS,
			   ltsc);

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_gtc_get ( enum optic_activation *mode )
{
	uint32_t reg;

	if (mode == NULL)
		return OPTIC_STATUS_ERR;

	reg = gtc_pma_r32 ( ltsc );
	if ((reg & GTC_PMA_LTSC_EN) == GTC_PMA_LTSC_EN)
		*mode = OPTIC_ENABLE;
	else
		*mode = OPTIC_DISABLE;

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_gtc_pattern_config_set ( const enum
 						       optic_patternmode mode,
 						       const uint32_t
 						       pattern[20],
 						       const uint8_t length )
{
	enum optic_errorcode ret;

	switch (mode) {
	case OPTIC_PATTERNMODE_BERT:
		gtc_pma_w32_mask ( GTC_PMA_LTSC_ENL, GTC_PMA_LTSC_ENL_EN,
			           ltsc);
		break;
	case OPTIC_PATTERNMODE_LTS:
		gtc_pma_w32_mask ( GTC_PMA_LTSC_ENL, GTC_PMA_LTSC_ENL_DIS,
			           ltsc);
		break;
	default:
		return OPTIC_STATUS_POOR;

	}

	ret = optic_ll_gtc_set ( OPTIC_DISABLE );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_gtc_length_set ( length );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_gtc_pattern_set ( pattern );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

enum optic_errorcode optic_ll_gtc_pattern_config_get ( enum
 						       optic_patternmode *mode,
 						       uint32_t pattern[20],
 						       uint8_t *length )
{
	enum optic_errorcode ret;
	uint32_t reg;

	if (mode == NULL)
		return OPTIC_STATUS_ERR;

	reg = gtc_pma_r32 (ltsc);

	if ((reg & GTC_PMA_LTSC_ENL) == GTC_PMA_LTSC_ENL_EN)
		*mode = OPTIC_PATTERNMODE_BERT;
	else
		*mode = OPTIC_PATTERNMODE_LTS;


	ret = optic_ll_gtc_length_get ( length );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_gtc_pattern_get ( pattern );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}
/*! @} */
/*! @} */
