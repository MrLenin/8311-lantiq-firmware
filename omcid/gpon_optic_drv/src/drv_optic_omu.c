/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, OMU Interface - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_OMU_INTERNAL OMU Interface - Internal
   @{
*/

#include "drv_optic_api.h"
#include "drv_optic_common.h"
#include "drv_optic_omu_interface.h"

#include "drv_optic_rx.h"
#include "drv_optic_tx.h"
#include "drv_optic_ll_bert.h"
#include "drv_optic_ll_pll.h"
#include "drv_optic_ll_tx.h"
#include "drv_optic_ll_rx.h"
#include "drv_optic_ll_mpd.h"
#include "drv_optic_ll_gpio.h"
#include "drv_optic_ll_int.h"
#include "drv_optic_ll_dcdc_apd.h"

/**
	The omu_cfg_set function is used to provide configurations for the
	receive path of the optical module (OMU).

*/
enum optic_errorcode omu_cfg_set ( struct optic_device *p_dev,
                                   const struct optic_omu_config *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	p_ctrl->config.omu.signal_detect_avail = param->signal_detect_avail;
	p_ctrl->config.omu.signal_detect_port  =  param->signal_detect_port;

	if (param->threshold_lol_set > 100)
		return OPTIC_STATUS_POOR;
	if (param->threshold_lol_clear > 100)
		return OPTIC_STATUS_POOR;

	p_ctrl->config.omu.threshold_lol_set   =  param->threshold_lol_set;
	p_ctrl->config.omu.threshold_lol_clear =  param->threshold_lol_clear;


	p_ctrl->config.omu.laser_enable_single_ended =
					param->laser_enable_single_ended;

	/* ready to read tables & read configs */
	p_ctrl->state.config_read[OPTIC_CONFIGTYPE_OMU] = true;
	optic_state_set ( p_ctrl, OPTIC_STATE_CONFIG );

	return OPTIC_STATUS_OK;
}

/**
	The omu_cfg_get function is used to read back the basic configuration
	of the OMU receive path within the GOI module.

*/
enum optic_errorcode omu_cfg_get ( struct optic_device *p_dev,
                                   struct optic_omu_config *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;

	if (param == NULL)
      		return OPTIC_STATUS_ERR;

	memset(param, 0x00, sizeof(struct optic_omu_config));

	param->signal_detect_avail = p_ctrl->config.omu.signal_detect_avail;
	param->signal_detect_port  = p_ctrl->config.omu.signal_detect_port;

	param->threshold_lol_set   = p_ctrl->config.omu.threshold_lol_set;
	param->threshold_lol_clear = p_ctrl->config.omu.threshold_lol_clear;

	param->laser_enable_single_ended =
				p_ctrl->config.omu.laser_enable_single_ended;

	return OPTIC_STATUS_OK;
}

/**
	The omu_rx_enable function switches the receiver on.
*/
enum optic_errorcode omu_rx_enable ( struct optic_device *p_dev )
{
	(void) p_dev;

	return optic_ll_pll_module_set ( OPTIC_PLL_RX, true );
}

/**
	The omu_rx_disable function switches the receiver off.
*/
enum optic_errorcode omu_rx_disable ( struct optic_device *p_dev )
{
	(void) p_dev;

	return optic_ll_pll_module_set ( OPTIC_PLL_RX, false );
}

/**
	The omu_tx_enable function switches the receiver on.
*/
enum optic_errorcode omu_tx_enable ( struct optic_device *p_dev )
{
	(void) p_dev;

	return optic_ll_pll_module_set ( OPTIC_PLL_TX, true );
}

/**
	The omu_tx_disable function switches the receiver off.
*/
enum optic_errorcode omu_tx_disable ( struct optic_device *p_dev )
{
	(void) p_dev;

	return optic_ll_pll_module_set ( OPTIC_PLL_TX, false );
}

/**
	The omu_tx_status_get function provides status information
	that is available for the OMU transmitter.
*/
enum optic_errorcode omu_tx_status_get ( struct optic_device *p_dev,
                                         struct optic_omu_tx_status_get
                                         *param )
{
	enum optic_errorcode ret;
	enum optic_activation mode;

	(void) p_dev;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset(param, 0x00, sizeof(struct optic_omu_tx_status_get));

	/* read omu tx state */
	ret = optic_ll_pll_module_get ( OPTIC_PLL_TX, &mode );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	param->tx_enable = (mode == OPTIC_ENABLE) ? true : false;

	return ret;
}

/**
   The omu_rx_status_get function provides status information
   that is available for the OMU receiver.
*/
enum optic_errorcode omu_rx_status_get ( struct optic_device *p_dev,
                                         struct optic_omu_rx_status_get
                                         *param )
{
	struct optic_control *p_ctrl = p_dev->p_ctrl;
	struct optic_config_omu *omu = &(p_ctrl->config.omu);
	struct optic_interrupts *irq = &(p_ctrl->state.interrupts);
	enum optic_errorcode ret;
	enum optic_activation mode;

	if (param == NULL)
		return OPTIC_STATUS_ERR;

	memset(param, 0x00, sizeof(struct optic_omu_rx_status_get));

	/* read omu rx state */
	ret = optic_ll_pll_module_get ( OPTIC_PLL_RX, &mode );
	if (ret != OPTIC_STATUS_OK)
		return ret;

	param->rx_enable = (mode == OPTIC_ENABLE) ? true : false;

	ret = optic_ll_int_omu_get ( omu->signal_detect_avail, irq,
					   &(param->loss_of_signal),
					   &(param->loss_of_lock) );
		if (ret != OPTIC_STATUS_OK)
			return ret;

	return ret;
}

/* ----------------------------- NON IOCTL ---------------------------------- */

/**
	The omu_init function is used to initialize the optical module (OMU).

	- Make sure that FCSI registers are initialized,
	  to the same values as used for BOSA (part of GOI_init).
	- The measurement unit is not needed. But we enable the module
	  to be able to use it for temperature measurements.
          MM calibration is outside the scope of the OMU init function
          (part of GOI_init).

	1. configure TX FIFO
	2. init CDR (RX)
	3. set LOL thresholds (configure LOL alarm)
	4. set LSB-MSB flip for RX data (low) path ctrl, TX data and bias path ctrl
	5. enable receive data signals to GTC
	6. set & enable receive DAC offset correction
	7. init gpio: signal detect
*/


enum optic_errorcode omu_init ( struct optic_control *p_ctrl )
{
	enum optic_errorcode ret;
	struct optic_config_omu *omu = &(p_ctrl->config.omu);
	bool ignore_error;
	bool single_ended;

	ignore_error = (p_ctrl->config.run_mode &
	                (1<<OPTIC_RUNMODE_ERROR_IGNORE)) ? true : false;
	single_ended = p_ctrl->config.omu.laser_enable_single_ended;

	ret = optic_ll_pll_laser_set ( single_ended );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("omu_init/optic_ll_pll_laser_set: %d",
	 			ret);
		if (! ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	/* disable APD DCDC */
	ret = optic_ll_dcdc_apd_exit ();
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("omu_init/optic_ll_dcdc_apd_exit: %d", ret);
		if (! ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_tx_init (OPTIC_OMU,
				p_ctrl->config.bosa.pi_control,
				p_ctrl->config.delay_tx_enable,
				p_ctrl->config.delay_tx_disable,
				p_ctrl->config.size_tx_fifo,
				p_ctrl->config.bias_polarity_regular,
				p_ctrl->config.mod_polarity_regular);
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("omu_init/optic_ll_tx_init: %d",
	 			ret);
		if (! ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	ret = optic_rx_init ( OPTIC_OMU, false,
			      omu->threshold_lol_clear,
			      omu->threshold_lol_set,
			      p_ctrl->config.rx_polarity_regular,
			      &(p_ctrl->calibrate.rx_offset) );
	if (ret != OPTIC_STATUS_OK) {
	 	OPTIC_DEBUG_ERR("omu_init/optic_ll_rx_init: %d",
	 			ret);
		if (! ignore_error)
			return OPTIC_STATUS_INIT_FAIL;
	}

	if (p_ctrl->config.omu.signal_detect_avail == true) {
		ret = optic_ll_gpio_init ( omu->signal_detect_port,
				     		 &(omu->signal_detect_irq) );
		if (ret != OPTIC_STATUS_OK) {
			OPTIC_DEBUG_ERR("omu_init/optic_ll_gpio_init: %d",
					ret);
			p_ctrl->config.omu.signal_detect_avail = false;
			if (! ignore_error)
				return OPTIC_STATUS_INIT_FAIL;
		}
	}
	optic_irq_omu_init ( p_ctrl->config.omu.signal_detect_irq );

	return OPTIC_STATUS_OK;
}

/* ------------------------------------------------------------------------- */

const struct optic_entry omu_function_table[OPTIC_OMU_MAX] =
{
/*  0 */  TE1in  (FIO_OMU_CFG_SET,       sizeof(struct optic_omu_config),
                                         omu_cfg_set),
/*  1 */  TE1out (FIO_OMU_CFG_GET,       sizeof(struct optic_omu_config),
                                         omu_cfg_get),
/*  2 */  TE0    (FIO_OMU_RX_ENABLE,     omu_rx_enable),
/*  3 */  TE0    (FIO_OMU_RX_DISABLE,    omu_rx_disable),
/*  4 */  TE0    (FIO_OMU_TX_ENABLE,     omu_tx_enable),
/*  5 */  TE0    (FIO_OMU_TX_DISABLE,    omu_tx_disable),
/*  6 */  TE1out (FIO_OMU_RX_STATUS_GET, sizeof(struct optic_omu_rx_status_get),
					 omu_rx_status_get),
/*  7 */  TE1out (FIO_OMU_TX_STATUS_GET, sizeof(struct optic_omu_tx_status_get),
	                                 omu_tx_status_get)
};

/*! @} */

/*! @} */
