/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_fcsi.h
*/
#ifndef _drv_optic_fcsi_h
#define _drv_optic_fcsi_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_FCSI_INTERNAL FCSI Module - Internal
   @{
*/

enum optic_errorcode optic_fcsi_predriver_update ( const enum optic_powerlevel
						   powerlevel,
						   const struct
						   optic_config_fcsi *fcsi );
enum optic_errorcode optic_fcsi_predriver_set ( uint8_t dd_loadn,
						uint8_t dd_bias_en,
						uint8_t dd_loadp,
						uint8_t dd_cm_load,
						uint8_t bd_loadn,
						uint8_t bd_bias_en,
						uint8_t bd_loadp,
						uint8_t bd_cm_load );
enum optic_errorcode optic_fcsi_predriver_get ( uint8_t *dd_loadn,
						uint8_t *dd_bias_en,
						uint8_t *dd_loadp,
						uint8_t *dd_cm_load,
						uint8_t *bd_loadn,
						uint8_t *bd_bias_en,
						uint8_t *bd_loadp,
						uint8_t *bd_cm_load );

/*! @} */

/*! @} */

EXTERN_C_END

#endif
