/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, linear LDO Interface - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_LDO_INTERNAL Linear LDO Interface - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_ldo_interface.h"

#include "drv_optic_ll_sys1.h"

enum optic_errorcode ldo_enable ( struct optic_device *p_dev )
{
	(void) p_dev;

	return optic_ll_sys1_ldo_set ( OPTIC_ENABLE );
}

enum optic_errorcode ldo_disable ( struct optic_device *p_dev )
{
	(void) p_dev;

	return optic_ll_sys1_ldo_set ( OPTIC_DISABLE );
}


enum optic_errorcode ldo_status_get ( struct optic_device *p_dev,
                                      struct optic_ldo_status *param )
{
	enum optic_errorcode ret = OPTIC_STATUS_OK;
	enum optic_activation mode;

	(void) p_dev;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_ldo_status) );

	ret = optic_ll_sys1_ldo_get ( &mode );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	param->enable = (mode == OPTIC_ENABLE)? true : false;

	return ret;
}


/* ------------------------------------------------------------------------- */

const struct optic_entry ldo_function_table[OPTIC_LDO_MAX] =
{
/*  0 */  TE0    (FIO_LDO_ENABLE,               ldo_enable),
/*  1 */  TE0    (FIO_LDO_DISABLE,              ldo_disable),
/*  2 */  TE1out (FIO_LDO_STATUS_GET,           sizeof(struct optic_ldo_status),
						ldo_status_get),
};

/*! @} */

/*! @} */
