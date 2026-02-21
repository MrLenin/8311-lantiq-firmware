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

/*
 * v7.5.1 power management: 40-byte struct via /dev/onu, magic 8 (not GTC).
 * Stock replaced FIO_GTC_POWER_SAVING_MODE_SET entirely.
 * GTC cmd 0x0B maps to GTC_IDLE_SET in v7.5.1 (wrong handler).
 * Stock ioctl = 0x80280800 = _IOW(8, 0, 40-byte struct).
 */
#define ONU_PWR_MAGIC	8

struct onu_pwr_mgmt_ctrl {
	uint32_t gpon_op_mode;		/* 0: 0=skip, 1=OFF, 2=DOZE, 4=CYCLIC */
	uint32_t itransinit;		/* 4: not passed by v4.5.0 ME handler */
	uint32_t max_sleep_interval;	/* 8 */
	uint32_t itxinit;		/* 12: not passed by v4.5.0 ME handler */
	uint32_t min_aware_interval;	/* 16 */
	uint32_t min_active_held_interval; /* 20 */
	uint32_t max_sleep_ext;		/* 24: v7.5.1 attr, not in v4.5.0 */
	uint32_t _pad[3];		/* 28-39: zeroed */
};

#define FIO_ONU_PWR_MGMT_CTRL_SET \
	_IOW(ONU_PWR_MAGIC, 0, struct onu_pwr_mgmt_ctrl)

enum omci_api_return omci_api_onu_dyn_pwr_mngmt_ctrl_update(
				   struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint8_t pwr_reduction_mngmt_mode,
				   uint32_t max_sleep_interval,
				   uint32_t min_aware_interval,
				   uint16_t min_active_held_interval)
{
	struct onu_pwr_mgmt_ctrl pwr;

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

	memset(&pwr, 0, sizeof(pwr));

	/* Stock mode mapping: 0x01->1(OFF), 0x02->2(DOZE), 0x04->4(CYCLIC).
	   Any other value -> gpon_op_mode stays 0 (from memset). Stock always
	   calls dev_ctl regardless of mode and ignores the return value. */
	switch (pwr_reduction_mngmt_mode) {
	case 0x01:
		pwr.gpon_op_mode = 1;
		break;
	case 0x02:
		pwr.gpon_op_mode = 2;
		break;
	case 0x04:
		pwr.gpon_op_mode = 4;
		break;
	default:
		break;
	}

	pwr.max_sleep_interval = max_sleep_interval;
	pwr.min_aware_interval = min_aware_interval;
	pwr.min_active_held_interval = (uint32_t)min_active_held_interval;

	/* Stock returns void — never checks dev_ctl result. */
	dev_ctl(ctx->remote, ctx->onu_fd, FIO_ONU_PWR_MGMT_CTRL_SET,
		&pwr, sizeof(pwr));

	return OMCI_API_SUCCESS;
}

/** @} */
