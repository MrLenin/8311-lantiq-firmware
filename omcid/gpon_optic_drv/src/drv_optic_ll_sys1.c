/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, SYS1 Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_SYS1_INTERNAL SYS1 Module - Internal
   @{
*/

#include "drv_optic_ll_sys1.h"
#include "drv_optic_common.h"
#include "drv_optic_register.h"
#include "drv_optic_reg_sys1.h"

enum optic_errorcode optic_ll_sys1_ldo_set ( const enum optic_activation mode )
{
	/* init ldo configuration: 1,5 V */
	if (mode == OPTIC_ENABLE) {
		sys1_w32_mask ( INFRAC_LIN1V5C_MASK,
				((0x03 << INFRAC_LIN1V5C_OFFSET) &
					  INFRAC_LIN1V5C_MASK),
				infrac );
	}

	sys1_w32_mask ( INFRAC_LIN1V5EN, (mode == OPTIC_ENABLE)?
			INFRAC_LIN1V5EN_EN : INFRAC_LIN1V5EN_DIS,
			infrac );

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_sys1_ldo_get ( enum optic_activation *mode )
{
	uint32_t reg;
	if (mode == NULL)
		return OPTIC_STATUS_ERR;

	reg = sys1_r32 ( infrac );

	if ((reg & INFRAC_LIN1V5EN) == INFRAC_LIN1V5EN_EN)
		*mode = OPTIC_ENABLE;
	else
		*mode = OPTIC_DISABLE;

	return OPTIC_STATUS_OK;
}

/*! @} */
/*! @} */
