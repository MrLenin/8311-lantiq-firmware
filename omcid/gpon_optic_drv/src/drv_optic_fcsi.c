/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, FCSI Interface - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_FCSI_INTERNAL FCSI Register Interface - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_fcsi_interface.h"


#include "drv_optic_calc.h"
#include "drv_optic_fcsi.h"
#include "drv_optic_ll_fcsi.h"

/**
   Read fcsi configuration data into the context.
*/
enum optic_errorcode fcsi_cfg_set ( struct optic_device *p_dev,
                                    const struct optic_fcsi_config *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	p_ctrl->config.fcsi.gvs = param->gvs;

	if (is_falcon_chip_a2x()) { /* A21 */
	   	p_ctrl->config.fcsi.dd_loadn[OPTIC_POWERLEVEL_0] =   DD_LOADN_0_A21;
	   	p_ctrl->config.fcsi.dd_bias_en[OPTIC_POWERLEVEL_0] = DD_BIAS_EN_0_A21;
	   	p_ctrl->config.fcsi.dd_loadp[OPTIC_POWERLEVEL_0] =   DD_LOADP_0_A21;
	   	p_ctrl->config.fcsi.dd_cm_load[OPTIC_POWERLEVEL_0] = DD_CM_LOAD_0_A21;
	   	p_ctrl->config.fcsi.bd_loadn[OPTIC_POWERLEVEL_0] =   BD_LOADN_0_A21;
	   	p_ctrl->config.fcsi.bd_bias_en[OPTIC_POWERLEVEL_0] = BD_BIAS_EN_0_A21;
	   	p_ctrl->config.fcsi.bd_loadp[OPTIC_POWERLEVEL_0] =   BD_LOADP_0_A21;
	   	p_ctrl->config.fcsi.bd_cm_load[OPTIC_POWERLEVEL_0] = BD_CM_LOAD_0_A21;

	   	p_ctrl->config.fcsi.dd_loadn[OPTIC_POWERLEVEL_1] =   DD_LOADN_1_A21;
	   	p_ctrl->config.fcsi.dd_bias_en[OPTIC_POWERLEVEL_1] = DD_BIAS_EN_1_A21;
	   	p_ctrl->config.fcsi.dd_loadp[OPTIC_POWERLEVEL_1] =   DD_LOADP_1_A21;
	   	p_ctrl->config.fcsi.dd_cm_load[OPTIC_POWERLEVEL_1] = DD_CM_LOAD_1_A21;
	   	p_ctrl->config.fcsi.bd_loadn[OPTIC_POWERLEVEL_1] =   BD_LOADN_1_A21;
	   	p_ctrl->config.fcsi.bd_bias_en[OPTIC_POWERLEVEL_1] = BD_BIAS_EN_1_A21;
	   	p_ctrl->config.fcsi.bd_loadp[OPTIC_POWERLEVEL_1] =   BD_LOADP_1_A21;
	   	p_ctrl->config.fcsi.bd_cm_load[OPTIC_POWERLEVEL_1] = BD_CM_LOAD_1_A21;

	   	p_ctrl->config.fcsi.dd_loadn[OPTIC_POWERLEVEL_2] =   DD_LOADN_2_A21;
	   	p_ctrl->config.fcsi.dd_bias_en[OPTIC_POWERLEVEL_2] = DD_BIAS_EN_2_A21;
	   	p_ctrl->config.fcsi.dd_loadp[OPTIC_POWERLEVEL_2] =   DD_LOADP_2_A21;
	   	p_ctrl->config.fcsi.dd_cm_load[OPTIC_POWERLEVEL_2] = DD_CM_LOAD_2_A21;
	   	p_ctrl->config.fcsi.bd_loadn[OPTIC_POWERLEVEL_2] =   BD_LOADN_2_A21;
	   	p_ctrl->config.fcsi.bd_bias_en[OPTIC_POWERLEVEL_2] = BD_BIAS_EN_2_A21;
	   	p_ctrl->config.fcsi.bd_loadp[OPTIC_POWERLEVEL_2] =   BD_LOADP_2_A21;
	   	p_ctrl->config.fcsi.bd_cm_load[OPTIC_POWERLEVEL_2] = BD_CM_LOAD_2_A21;

	} else { /* A12 */
		p_ctrl->config.fcsi.dd_loadn[OPTIC_POWERLEVEL_0] =   DD_LOADN_0;
	   	p_ctrl->config.fcsi.dd_bias_en[OPTIC_POWERLEVEL_0] = DD_BIAS_EN_0;
	   	p_ctrl->config.fcsi.dd_loadp[OPTIC_POWERLEVEL_0] =   DD_LOADP_0;
	   	p_ctrl->config.fcsi.dd_cm_load[OPTIC_POWERLEVEL_0] = DD_CM_LOAD_0;
	   	p_ctrl->config.fcsi.bd_loadn[OPTIC_POWERLEVEL_0] =   BD_LOADN_0;
	   	p_ctrl->config.fcsi.bd_bias_en[OPTIC_POWERLEVEL_0] = BD_BIAS_EN_0;
	   	p_ctrl->config.fcsi.bd_loadp[OPTIC_POWERLEVEL_0] =   BD_LOADP_0;
	   	p_ctrl->config.fcsi.bd_cm_load[OPTIC_POWERLEVEL_0] = BD_CM_LOAD_0;

	   	p_ctrl->config.fcsi.dd_loadn[OPTIC_POWERLEVEL_1] =   DD_LOADN_1;
	   	p_ctrl->config.fcsi.dd_bias_en[OPTIC_POWERLEVEL_1] = DD_BIAS_EN_1;
	   	p_ctrl->config.fcsi.dd_loadp[OPTIC_POWERLEVEL_1] =   DD_LOADP_1;
	   	p_ctrl->config.fcsi.dd_cm_load[OPTIC_POWERLEVEL_1] = DD_CM_LOAD_1;
	   	p_ctrl->config.fcsi.bd_loadn[OPTIC_POWERLEVEL_1] =   BD_LOADN_1;
	   	p_ctrl->config.fcsi.bd_bias_en[OPTIC_POWERLEVEL_1] = BD_BIAS_EN_1;
	   	p_ctrl->config.fcsi.bd_loadp[OPTIC_POWERLEVEL_1] =   BD_LOADP_1;
	   	p_ctrl->config.fcsi.bd_cm_load[OPTIC_POWERLEVEL_1] = BD_CM_LOAD_1;

	   	p_ctrl->config.fcsi.dd_loadn[OPTIC_POWERLEVEL_2] =   DD_LOADN_2;
	   	p_ctrl->config.fcsi.dd_bias_en[OPTIC_POWERLEVEL_2] = DD_BIAS_EN_2;
	   	p_ctrl->config.fcsi.dd_loadp[OPTIC_POWERLEVEL_2] =   DD_LOADP_2;
	   	p_ctrl->config.fcsi.dd_cm_load[OPTIC_POWERLEVEL_2] = DD_CM_LOAD_2;
	   	p_ctrl->config.fcsi.bd_loadn[OPTIC_POWERLEVEL_2] =   BD_LOADN_2;
	   	p_ctrl->config.fcsi.bd_bias_en[OPTIC_POWERLEVEL_2] = BD_BIAS_EN_2;
	   	p_ctrl->config.fcsi.bd_loadp[OPTIC_POWERLEVEL_2] =   BD_LOADP_2;
	   	p_ctrl->config.fcsi.bd_cm_load[OPTIC_POWERLEVEL_2] = BD_CM_LOAD_2;
	}

	/* ready to read tables & read configs */
	p_ctrl->state.config_read[OPTIC_CONFIGTYPE_FCSI] = true;
	optic_state_set ( p_ctrl, OPTIC_STATE_CONFIG );

	return OPTIC_STATUS_OK;
}

/**
   Returns fcsi configuration.
*/
enum optic_errorcode fcsi_cfg_get ( struct optic_device *p_dev,
				    struct optic_fcsi_config *param )
{
	struct optic_bfd bfd;
	enum optic_errorcode ret;

	/* unused parameter */
	(void)p_dev;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	ret = optic_ll_fcsi_bfd_get (&bfd);
	if (ret != OPTIC_STATUS_OK)
		return ret;

	param->gvs = bfd.gvs;
	param->ctrl0 = bfd.ctrl0;

	return OPTIC_STATUS_OK;
}

/* ----------------------------- NON IOCTL ---------------------------------- */

/**
	Manages FCSI predriver configuration - dependent on power level
	\remark don't call in debug mode (p_ctrl->config.debug_mode == true)

	\param p_ctrl - control context
	\param powerlevel - power level

	\return
	- OPTIC_STATUS_OK - success,
	- OPTIC_STATUS_FCSI_READTIMEOUT - read failed
	- OPTIC_STATUS_FCSI_WRITETIMEOUT - write failed
*/
enum optic_errorcode optic_fcsi_predriver_update ( const enum optic_powerlevel
						   powerlevel,
						   const struct
						   optic_config_fcsi *fcsi )
{
	if (fcsi == NULL)
		return OPTIC_STATUS_ERR;

	return optic_fcsi_predriver_set ( fcsi->dd_loadn[powerlevel],
					  fcsi->dd_bias_en[powerlevel],
					  fcsi->dd_loadp[powerlevel],
					  fcsi->dd_cm_load[powerlevel],
					  fcsi->bd_loadn[powerlevel],
					  fcsi->bd_bias_en[powerlevel],
					  fcsi->bd_loadp[powerlevel],
					  fcsi->bd_cm_load[powerlevel]);
}

enum optic_errorcode optic_fcsi_predriver_set ( uint8_t dd_loadn,
						uint8_t dd_bias_en,
						uint8_t dd_loadp,
						uint8_t dd_cm_load,
						uint8_t bd_loadn,
						uint8_t bd_bias_en,
						uint8_t bd_loadp,
						uint8_t bd_cm_load )
{
	enum optic_errorcode ret;

#if (OPTIC_FCSI_PREDRIVER_RANGECHECK == ACTIVE)
	ret = optic_check_predriver ( dd_loadn, dd_bias_en,
				      dd_loadp, dd_cm_load,
				      bd_loadn, bd_bias_en,
				      bd_loadp, bd_cm_load );
	if (ret != OPTIC_STATUS_OK)
		return ret;
#endif

	ret = optic_ll_fcsi_predriver_set ( dd_loadn, dd_bias_en,
					    dd_loadp, dd_cm_load,
					    bd_loadn, bd_bias_en,
					    bd_loadp, bd_cm_load );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	return ret;
}

enum optic_errorcode optic_fcsi_predriver_get ( uint8_t *dd_loadn,
						uint8_t *dd_bias_en,
						uint8_t *dd_loadp,
						uint8_t *dd_cm_load,
						uint8_t *bd_loadn,
						uint8_t *bd_bias_en,
						uint8_t *bd_loadp,
						uint8_t *bd_cm_load )
{
	enum optic_errorcode ret;
	ret = optic_ll_fcsi_predriver_get ( dd_loadn, dd_bias_en,
					          dd_loadp, dd_cm_load,
					          bd_loadn, bd_bias_en,
					          bd_loadp, bd_cm_load );
	if (ret != OPTIC_STATUS_OK)
		return ret;

#if (OPTIC_FCSI_PREDRIVER_RANGECHECK == ACTIVE)
	ret = optic_check_predriver ( *dd_loadn, *dd_bias_en,
					    *dd_loadp, *dd_cm_load,
					    *bd_loadn, *bd_bias_en,
					    *bd_loadp, *bd_cm_load );
	if (ret != OPTIC_STATUS_OK)
		return ret;
#endif

	return ret;
}


/* ------------------------------------------------------------------------- */

const struct optic_entry fcsi_function_table[OPTIC_FCSI_MAX] =
{
/*  0 */  TE1in  (FIO_FCSI_CFG_SET,     sizeof(struct optic_fcsi_config),
					fcsi_cfg_set),
/*  1 */  TE1out (FIO_FCSI_CFG_GET,     sizeof(struct optic_fcsi_config),
					fcsi_cfg_get),

};


/*! @} */

/*! @} */
