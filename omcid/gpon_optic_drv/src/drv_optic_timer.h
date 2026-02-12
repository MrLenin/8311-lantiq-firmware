/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_optic_timer_h
#define _drv_optic_timer_h

#include "drv_optic_std_defs.h"
/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_TIMER_INTERNAL Timer Interface - Internal
   @{
*/

EXTERN_C_BEGIN

#define OPTIC_TIMER_ID_MEASURE 0
#define OPTIC_TIMER_ID_APD_ADAPT 1
/** Maximum of used timers */
#define OPTIC_TIMER_GLOBAL_MAX  2

extern void optic_timer_start ( const uint32_t timer_no, uint32_t timeout);
extern void optic_timer_stop ( const uint32_t timer_no);

/*! @} */
/*! @} */

EXTERN_C_END

#endif
