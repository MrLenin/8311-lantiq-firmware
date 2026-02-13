/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_gem_port_pmhd.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_gem_port_pmhd.h"
#include "me/omci_gem_port_network_ctp.h"
#include "me/omci_api_gem_port_pmhd.h"

#ifdef INCLUDE_PM

/** \addtogroup OMCI_ME_GEM_PORT_PMHD
    @{
*/

static enum omci_error me_counters_get(struct omci_context *context,
				       struct me *me,
				       enum omci_pm_interval interval)
{
	struct omci_me_gem_port_pmhd *me_data;
	enum omci_api_return ret;
	uint64_t received_packets;
	uint64_t received_blocks;
	uint64_t transmitted_blocks;

	dbg_in(__func__, "%p, %p, %lu", (void *)context, (void *)me, interval);

	me_data = (struct omci_me_gem_port_pmhd *)me->data;

	me_data->misinserted_packets = 0;
	me_data->impaired_blocks = 0;

	ret = omci_api_gem_port_pmhd_cnt_get(context->api,
					     me->instance_id,
					     false,
					     interval == OMCI_PM_INTERVAL_CURR,
					     NULL,
					     &received_packets,
					     &received_blocks,
					     &transmitted_blocks,
					     &me_data->lost_packets);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't get counters", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	me_data->received_packets_hi = uint64_hi(received_packets);
	me_data->received_packets_lo = uint64_lo(received_packets);

	me_data->received_blocks_hi = uint64_hi(received_blocks);
	me_data->received_blocks_lo = uint64_lo(received_blocks);

	me_data->transmitted_blocks_hi = uint64_hi(transmitted_blocks);
	me_data->transmitted_blocks_lo = uint64_lo(transmitted_blocks);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_thr_set(struct omci_context *context,
				  struct me *me,
				  uint32_t thr[PM_THR_NUM])
{
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p, %p", (void *)context, (void *)me,
	       (void *)thr);

	ret = omci_api_gem_port_pmhd_thr_set(context->api,
					     me->instance_id,
					     /* tx_gem_frames */
					     0,
					     /* rx_gem_frames */
					     thr[2],
					     /* rx_payload_bytes */
					     thr[3],
					     /* tx_payload_bytes */
					     thr[4],
					     /* lost_packets */
					     thr[0]);

	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't set thresholds", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	/* check if related GEM Port Network CTP exists */
	error = mib_me_find(context, OMCI_ME_GEM_PORT_NETWORK_CTP,
			    me->instance_id, NULL);

	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, error);
	return error;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

	dbg_out_ret(__func__, error);
	return error;
}

static struct me_tca tca_table[] = {
	/* 0 Lost packets #1 */
	TCA(0, omci_me_gem_port_pmhd_lost_packets, 1),
	/* 1 Misinserted packets #2 */
	TCA(1, omci_me_gem_port_pmhd_misinserted_packets, 2),
	/* 2 Impaired blocks #3 */
	TCA(2, omci_me_gem_port_pmhd_impaired_blocks, 3),

	TCA(0, 0, 0)
};

/** Managed Entity class */
struct me_class me_gem_port_pmhd_class = {
	/* Class ID */
	OMCI_ME_GEM_PORT_PMHD,
	/* Attributes */
	{
		/* 1. Interval End Time */
		ATTR_UINT("Interval end time",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_gem_port_pmhd,
				   interval_end_time),
			  1,
			  OMCI_ATTR_PROP_RD,
			  pm_interval_end_time_get),
		/* 2. Threshold Data 1/2 ID */
		ATTR_PTR("Threshold data 1/2 id",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_gem_port_pmhd,
				  thr_data_id),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 3. Lost Packet Count */
		ATTR_UINT("Lost packets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_gem_port_pmhd,
				   lost_packets),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 4. Misinserted Packet Count */
		ATTR_UINT("Misinserted packets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_gem_port_pmhd,
				   misinserted_packets),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 5. Received Packet Count */
		ATTR_UINT("Received packets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_gem_port_pmhd,
				   received_packets_hi),
			  5,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 6. Received Block Count */
		ATTR_UINT("Received block",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_gem_port_pmhd,
				   received_blocks_hi),
			  5,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 7. Transmitted Block Count */
		ATTR_UINT("Transmitted blocks",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_gem_port_pmhd,
				   transmitted_blocks_hi),
			  5,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 8. Impaired Block Count */
		ATTR_UINT("Impaired blocks",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_gem_port_pmhd,
				   impaired_blocks),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 9-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
	},
	/* Actions */
	{
		NULL, NULL, NULL, NULL,
		/* Create */
		create_action_handle,
		NULL,
		/* Delete */
		delete_action_handle,
		NULL,
		/* Set */
		set_action_handle,
		/* Get */
		get_action_handle,
		NULL,
		/* Get all alarms */
		NULL,
		/* Get all alarms next */
		NULL,
		/* MIB upload */
		NULL,
		/* MIB upload next */
		NULL,
		/* MIB reset */
		NULL,
		/* Alarm */
		NULL,
		/* Attribute value change */
		NULL,
		/* Test */
		NULL,
		/* Start SW download */
		NULL,
		/* Download section */
		NULL,
		/* End SW download */
		NULL,
		/* Activate software */
		NULL,
		/* Commit software */
		NULL,
		/* Synchronize Time */
		NULL,
		/* Reboot */
		NULL,
		/* Get next */
		NULL,
		/* Test result */
		NULL,
		/* Get current data */
		get_current_data_action_handle
	},
	/* Init Handler */
	me_init,
	/* Shutdown Handler */
	me_shutdown,
	/* Validate Handler */
	default_me_validate,
	/* Update Handler */
	default_me_update,
	/* Table Attribute Copy Handler */
	NULL,
	/* Table Attribute Operations Handler */
	NULL,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	me_counters_get,
	/* Thresholds set Handler */
	me_thr_set,
#endif
	/* TCA Table */
	tca_table,
	/* Data Size */
	sizeof(struct omci_me_gem_port_pmhd),
	/* Properties */
	OMCI_ME_PROP_PM | OMCI_ME_PROP_HAS_ALARMS | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"GEM port PMHD",
		/* Access */
		ME_CREATED_BY_OLT,
		/* Supported alarms */
		NULL,
		/* Supported alarms count */
		0,
		/* Support */
		ME_SUPPORTED},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */

#endif
