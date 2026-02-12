/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_ll_sys_gpon.h
*/
#ifndef _drv_optic_ll_sys_gpon_h
#define _drv_optic_ll_sys_gpon_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"



EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_SYS_GPON_INTERNAL SYS_GPON Module - Internal
   @{
*/


enum optic_errorcode optic_ll_sys_gpon_clockenable ( void );
enum optic_errorcode optic_ll_sys_gpon_clockdisable ( void );
enum optic_errorcode optic_ll_sys_gpon_dump ( void );


/*! @} */

/*! @} */

EXTERN_C_END

#endif
