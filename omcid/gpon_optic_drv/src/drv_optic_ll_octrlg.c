/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, OCTRLG Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_OCTRLG_INTERNAL OCTRLG Interface Module - Internal
   @{
*/


#include "drv_optic_ll_gtc.h"
#include "drv_optic_register.h"
#include "drv_optic_reg_octrlg.h"

#ifndef OPTIC_LIBRARY
/**
	this function reads total transmitted bytes counter and recalculate
	laser life time. Function has to be called at least each 27 seconds
*/
enum optic_errorcode optic_ll_octrlg_ageupdate ( uint8_t *seconds )
{
	uint32_t reg, diff;
	static uint32_t reg_old = 0;
	static uint32_t last = 0;

	if (seconds == NULL)
		return OPTIC_STATUS_ERR;

#ifndef OPTIC_SIMULATION
	reg = octrlg_r32 ( txtcnt );
#else
	reg = 0;
#endif
	if (reg > reg_old)
		diff = reg - reg_old;
	else
		diff = 0xFFFFFFFF - reg_old + reg + 1;
	/* not clear on read */
#if 1
	reg_old = reg;
#endif
	/* counter = 19440 in 125 us */
	*seconds = diff / (0x9450C00);
	last += (diff % (0x9450C00));
	if (last > 0x9450C00) {
		(*seconds) ++;
		last -= 0x9450C00;
	}

	return OPTIC_STATUS_OK;
}
#endif

/*! @} */
/*! @} */
