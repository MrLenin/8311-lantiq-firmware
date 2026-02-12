/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_gtc.h
*/
#ifndef _drv_optic_ll_gtc_h
#define _drv_optic_ll_gtc_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"
#include "drv_optic_common.h"



EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_GTC_PMA_INTERNAL GTC/PMA Interface Module - Internal
   @{
*/

enum optic_patternmode
{
	OPTIC_PATTERNMODE_BERT,
	OPTIC_PATTERNMODE_LTS,
};

enum optic_errorcode optic_ll_gtc_set ( const enum optic_activation mode );
enum optic_errorcode optic_ll_gtc_get ( enum optic_activation *mode );
enum optic_errorcode optic_ll_gtc_pattern_config_set ( const enum
 						       optic_patternmode mode,
 						       const uint32_t
 						       pattern[20],
 						       const uint8_t length );
enum optic_errorcode optic_ll_gtc_pattern_config_get ( enum optic_patternmode
						       *mode,
 						       uint32_t pattern[20],
 						       uint8_t *length );



/*! @} */

/*! @} */

EXTERN_C_END

#endif
