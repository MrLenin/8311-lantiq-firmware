/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_onu_dyn_pwr_mngmt_ctrl.h"

/** \addtogroup OMCI_API_ME_ONU_DYN_PWR_MNGMT_CTRL

   @{
*/

enum omci_api_return omci_api_onu_dyn_pwr_mngmt_ctrl_update(
					   struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint8_t pwr_reduction_mngmt_mode,
					   uint32_t max_sleep_interval,
					   uint32_t min_aware_interval,
					   uint16_t min_active_held_interval)
{
	struct gtc_op_mode mode;
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   pwr_reduction_mngmt_mode=0x%X\n"
		  "   max_sleep_interval=%u\n"
		  "   min_aware_interval=%u\n"
		  "   min_active_held_interval=%u\n",
		  __FUNCTION__,
		  me_id,
		  pwr_reduction_mngmt_mode,
		  max_sleep_interval, min_aware_interval,
		  min_active_held_interval));

	(void)max_sleep_interval;
	(void)min_aware_interval;
	(void)min_active_held_interval;

	if (pwr_reduction_mngmt_mode &
		OMCI_API_ONU_DYN_PWR_MNGMT_CTRL_CYCLIC_SLEEP_MODE_MASK) {
		DBG(OMCI_API_ERR, ("Unsupported power reduction mode 0x%X\n",
			pwr_reduction_mngmt_mode));
		return OMCI_API_ERROR;
	}

	mode.gpon_op_mode =
		pwr_reduction_mngmt_mode &
			OMCI_API_ONU_DYN_PWR_MNGMT_CTRL_DOZE_MODE_MASK ?
				GPON_POWER_SAVING_DOZING :
				GPON_POWER_SAVING_MODE_OFF;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GTC_POWER_SAVING_MODE_SET,
		      &mode, sizeof(mode));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

/** @} */
