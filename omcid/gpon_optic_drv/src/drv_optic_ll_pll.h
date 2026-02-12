/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_pll.h
*/
#ifndef _drv_optic_ll_pll_h
#define _drv_optic_ll_pll_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"
#include "drv_optic_common.h"


EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_PLL_INTERNAL PLL Module - Internal
   @{
*/

enum optic_pll_module
{
	OPTIC_PLL_RX,
	OPTIC_PLL_TX,
};

enum optic_errorcode optic_ll_pll_calibrate ( void );
enum optic_errorcode optic_ll_pll_vco_set ( void );
enum optic_errorcode optic_ll_pll_check ( void );
enum optic_errorcode optic_ll_pll_start ( const enum optic_manage_mode mode );
enum optic_errorcode optic_ll_pll_laser_set ( const bool single_ended );
enum optic_errorcode optic_ll_pll_module_set ( const enum optic_pll_module
					       module,
					       const enum optic_activation mode );
enum optic_errorcode optic_ll_pll_module_get ( const enum optic_pll_module
					       module,
                                               enum optic_activation *mode );
enum optic_errorcode optic_ll_pll_rogue (void);

/*! @} */

/*! @} */

EXTERN_C_END

#endif
