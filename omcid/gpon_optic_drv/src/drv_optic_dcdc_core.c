/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, DC/DC CORE Interface - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_DCDC_CORE_INTERNAL DC/DC CORE Interface - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_dcdc_core_interface.h"

#include "drv_optic_calc.h"
#include "drv_optic_dcdc_core.h"
#include "drv_optic_ll_dcdc_core.h"


/**
   Read core configuration data into the context.
*/
enum optic_errorcode dcdc_core_cfg_set ( struct optic_device *p_dev,
                                         const struct optic_dcdc_core_config
                                         *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	p_ctrl->config.dcdc_core.v_min              = param->v_min;
	p_ctrl->config.dcdc_core.v_max              = param->v_max;
	p_ctrl->config.dcdc_core.v_tolerance_input  = param->v_tolerance_input;
	p_ctrl->config.dcdc_core.v_tolerance_target = param->v_tolerance_target;

	/** Dead zone timing to avoid switching transistor overlap.
	The absolute value to be used depends on the selected external switching
	transistor types for the NMOS and the PMOS switching transistor.
	The time is given in units of ns.
	The configurable range for each value is from 0 to 31 ns.
	The hardware setting resolution is in steps of 2 ns,
	so the LSB is of no significance.
	The allowed value range is from 0x1 to 0xB. */

#if OPTIC_USE_DCDC_DEADZONE == ACTIVE
	if (param->pmos_on_delay < 0x1 ||
	    param->pmos_on_delay > 0xB ||
	    param->nmos_on_delay < 0x1 ||
	    param->nmos_on_delay > 0xB) {
		return OPTIC_STATUS_ERR;
	} else {
		p_ctrl->config.dcdc_core.pmos_on_delay = param->pmos_on_delay;
		p_ctrl->config.dcdc_core.nmos_on_delay = param->nmos_on_delay;
	}
#else
	p_ctrl->config.dcdc_core.pmos_on_delay = 4;
	p_ctrl->config.dcdc_core.nmos_on_delay = 7;
#endif
	/* ready to read tables & read configs */
	p_ctrl->state.config_read[OPTIC_CONFIGTYPE_DCDC_CORE] = true;
	optic_state_set ( p_ctrl, OPTIC_STATE_CONFIG );

	return OPTIC_STATUS_OK;
}

/**
   Returns core configuration.
*/
enum optic_errorcode dcdc_core_cfg_get ( struct optic_device *p_dev,
				         struct optic_dcdc_core_config *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_dcdc_core_config) );

	param->v_min              = p_ctrl->config.dcdc_core.v_min;
	param->v_max              = p_ctrl->config.dcdc_core.v_max;
	param->v_tolerance_input  = p_ctrl->config.dcdc_core.v_tolerance_input;
	param->v_tolerance_target = p_ctrl->config.dcdc_core.v_tolerance_target;
	param->pmos_on_delay	  = p_ctrl->config.dcdc_core.pmos_on_delay;
	param->nmos_on_delay	  = p_ctrl->config.dcdc_core.nmos_on_delay;


	return OPTIC_STATUS_OK;
}

enum optic_errorcode dcdc_core_enable ( struct optic_device *p_dev )
{
	(void) p_dev;

	return optic_ll_dcdc_core_set ( OPTIC_ENABLE );
}

enum optic_errorcode dcdc_core_disable ( struct optic_device *p_dev )
{
	(void) p_dev;

	return optic_ll_dcdc_core_set ( OPTIC_DISABLE );
}

enum optic_errorcode dcdc_core_status_get ( struct optic_device *p_dev,
                                            struct optic_dcdc_core_status
                                            *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	enum optic_errorcode ret;
	enum optic_activation mode;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset ( param, 0, sizeof(struct optic_dcdc_core_status) );

	ret = optic_ll_dcdc_core_get ( &mode );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	param->enable = (mode == OPTIC_ENABLE)? true : false;

	ret = optic_dcdc_core_voltage_get ( p_ctrl, &(param->voltage) );

	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

/* ----------------------------- NON IOCTL ---------------------------------- */

/**
	set DCDC CORE voltage
*/
enum optic_errorcode optic_dcdc_core_voltage_set ( struct optic_control *p_ctrl,
						   const uint16_t vcore )
{
	struct optic_fuses *fuses = &(p_ctrl->config.fuses);
	enum optic_errorcode ret;

	ret = optic_rangecheck_dcdc ( &(p_ctrl->config.range),
					    OPTIC_DCDC_CORE, vcore);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_ll_dcdc_core_voltage_set ( fuses->offset_dcdc_core,
					             fuses->gain_dcdc_core,
	                                             vcore );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

/**
	read DCDC CORE voltage
*/
enum optic_errorcode optic_dcdc_core_voltage_get ( struct optic_control *p_ctrl,
						   uint16_t *vcore )
{
	struct optic_fuses *fuses = &(p_ctrl->config.fuses);
	enum optic_errorcode ret;

	ret =  optic_ll_dcdc_core_voltage_get ( fuses->offset_dcdc_core,
						      fuses->gain_dcdc_core,
	                                              vcore );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	ret = optic_rangecheck_dcdc ( &(p_ctrl->config.range),
					    OPTIC_DCDC_CORE, *vcore);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

/* ------------------------------------------------------------------------- */

const struct optic_entry dcdc_core_function_table[OPTIC_DCDC_CORE_MAX] =
{
/*  0 */  TE1in  (FIO_DCDC_CORE_CFG_SET,        sizeof(struct optic_dcdc_core_config),
						dcdc_core_cfg_set),
/*  1 */  TE1out (FIO_DCDC_CORE_CFG_GET,        sizeof(struct optic_dcdc_core_config),
						dcdc_core_cfg_get),
/*  2 */  TE0    (FIO_DCDC_CORE_ENABLE,         dcdc_core_enable),
/*  3 */  TE0    (FIO_DCDC_CORE_DISABLE,        dcdc_core_disable),
/*  4 */  TE1out (FIO_DCDC_CORE_STATUS_GET,     sizeof(struct optic_dcdc_core_status),
						dcdc_core_status_get),
};

/*! @} */

/*! @} */
