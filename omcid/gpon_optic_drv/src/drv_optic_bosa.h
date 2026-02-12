/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file drv_optic_bosa.h
*/
#ifndef _drv_optic_bosa_h
#define _drv_optic_bosa_h

#include "drv_optic_std_defs.h"
#include "drv_optic_error.h"

EXTERN_C_BEGIN

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \addtogroup OPTIC_BOSA_INTERNAL BOSA Module - Internal
   @{
*/


enum optic_errorcode optic_bosa_init ( struct optic_control *p_ctrl );
enum optic_errorcode optic_powerlevel_set ( const uint8_t powerlevel );
enum optic_errorcode optic_powerlevel_get ( uint8_t *powerlevel );
enum optic_errorcode optic_bosa_powerlevel_set ( struct optic_control *p_ctrl,
                                                 const enum optic_powerlevel
                                                 powerlevel );
enum optic_errorcode optic_bosa_powerlevel_get ( struct optic_control *p_ctrl,
                                                 enum optic_powerlevel
                                                 *powerlevel );


/*! @} */

/*! @} */

EXTERN_C_END

#endif
