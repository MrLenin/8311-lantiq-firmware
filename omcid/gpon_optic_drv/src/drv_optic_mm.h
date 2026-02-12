/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_mm.h
*/
#ifndef _drv_optic_mm_h
#define _drv_optic_mm_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"


EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_MM_INTERNAL MM Module - Internal
   @{
*/


enum optic_errorcode optic_mm_init ( struct optic_control *p_ctrl );

enum optic_errorcode optic_mm_control ( struct optic_control *p_ctrl );
enum optic_errorcode optic_mm_calibrate ( struct optic_control *p_ctrl,
					  uint8_t gain_selector );
enum optic_errorcode optic_mm_temp_int_get ( struct optic_control *p_ctrl );
enum optic_errorcode optic_mm_temp_ext_get ( struct optic_control *p_ctrl );
enum optic_errorcode optic_mm_power_get ( struct optic_control *p_ctrl );
enum optic_errorcode optic_mm_thresh_calc ( struct optic_control *p_ctrl );
enum optic_errorcode optic_mm_thresh_set ( struct optic_control *p_ctrl );



/*! @} */

/*! @} */

EXTERN_C_END

#endif
