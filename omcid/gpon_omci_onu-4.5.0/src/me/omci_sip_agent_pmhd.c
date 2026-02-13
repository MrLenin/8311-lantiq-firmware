/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_sip_agent_pmhd.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_sip_agent_pmhd.h"
#include "me/omci_api_sip_agent_pmhd.h"

#if defined(INCLUDE_PM) && defined(INCLUDE_OMCI_ONU_VOIP)

/** \addtogroup OMCI_SIP_AGENT_PMHD
   @{
*/

static enum omci_error me_counters_get(struct omci_context *context,
				       struct me *me,
				       enum omci_pm_interval interval)
{
	struct omci_me_sip_agent_pmhd *me_data;
	uint32_t  transactions, rx_invite_reqs , rx_invite_retrans,
		  rx_noninvite_reqs, rx_noninvite_retrans, rx_response,
		  rx_response_retrans, tx_invite_reqs, tx_invite_retrans,
		  tx_noninvite_reqs, tx_noninvite_retrans, tx_response,
		  tx_response_retrans;
	enum omci_api_return ret;

	dbg_in(__func__, "%p, %p, %lu", (void *)context, (void *)me, interval);

	me_data = (struct omci_me_sip_agent_pmhd *)me->data;

	ret = omci_api_sip_agent_pmhd_cnt_get(context->api,
					      me->instance_id,
					      &transactions,
					      &rx_invite_reqs,
					      &rx_invite_retrans,
					      &rx_noninvite_reqs,
					      &rx_noninvite_retrans,
					      &rx_response,
					      &rx_response_retrans,
					      &tx_invite_reqs,
					      &tx_invite_retrans,
					      &tx_noninvite_reqs,
					      &tx_noninvite_retrans,
					      &tx_response,
					      &tx_response_retrans);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't get counters", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	me_data->transactions = transactions;
	me_data->rx_invite_reqs = rx_invite_reqs;
	me_data->rx_invite_retrans = rx_invite_retrans;
	me_data->rx_noninvite_reqs = rx_noninvite_reqs;
	me_data->rx_noninvite_retrans = rx_noninvite_retrans;
	me_data->rx_response = rx_response;
	me_data->rx_response_retrans = rx_response_retrans;
	me_data->tx_invite_reqs = tx_invite_reqs;
	me_data->tx_invite_retrans = tx_invite_retrans;
	me_data->tx_noninvite_reqs = tx_noninvite_reqs;
	me_data->tx_noninvite_retrans = tx_noninvite_retrans;
	me_data->tx_response = tx_response;
	me_data->tx_response_retrans = tx_response_retrans;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;

	/* check if related SIP Agent config data exists */
	error = mib_me_find(context, OMCI_ME_SIP_AGENT_CONFIG_DATA,
			    me->instance_id, NULL);
	RETURN_IF_ERROR(error);

	error = default_me_init(context, me, init_data, suppress_avc);
	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}

static struct me_tca tca_table[] = {
	/* 1 Rx invite reqs #1 */
	TCA(1, omci_me_sip_agent_pmhd_rx_invite_reqs, 1),
	/* 2 Rx invite retrans #2 */
	TCA(2, omci_me_sip_agent_pmhd_rx_invite_retrans, 2),
	/* 3 Rx noninvite reqs  #3 */
	TCA(3, omci_me_sip_agent_pmhd_rx_noninvite_reqs, 3),
	/* 4 Rx noninvite retrans #4 */
	TCA(4, omci_me_sip_agent_pmhd_rx_noninvite_retrans, 4),
	/* 5 Rx response #5 */
	TCA(5, omci_me_sip_agent_pmhd_rx_response, 5),
	/* 6 Rx response retransmissions #6 */
	TCA(6, omci_me_sip_agent_pmhd_rx_response_retrans, 6),

	TCA(0, 0, 0)
};

/** Managed Entity class */
struct me_class me_sip_agent_pmhd_class = {
	/* Class ID */
	OMCI_ME_SIP_AGENT_MONITORING_DATA,
	/* Attributes */
	{
		ATTR_UINT("Interval end time",
			ATTR_SUPPORTED,
			0x00,
			0xff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 interval_end_time),
			1,
			OMCI_ATTR_PROP_RD,
			pm_interval_end_time_get),
		ATTR_UINT("Threshold data",
			ATTR_SUPPORTED,
			0x0000,
			0xffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 threshold_data),
			2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			OMCI_ATTR_PROP_SBC,
			NULL),
		ATTR_UINT("Transactions",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 transactions),
			4,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			NULL),
		ATTR_UINT("Rx invite reqs",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 rx_invite_reqs),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Rx invite retrans",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 rx_invite_retrans),
			4,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			NULL),
		ATTR_UINT("Rx noninvite reqs",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 rx_noninvite_reqs),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Rx noninvite retrans",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 rx_noninvite_retrans),
			4,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			NULL),
		ATTR_UINT("Rx response",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 rx_response),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Rx response retrans",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 rx_response_retrans),
			4,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			NULL),
		ATTR_UINT("Tx invite reqs",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 tx_invite_reqs),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Tx invite retrans",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 tx_invite_retrans),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Tx noninvite reqs",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 tx_noninvite_reqs),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Tx noninvite retrans",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 tx_noninvite_retrans),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Tx response",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 tx_response),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Tx response retrans",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_sip_agent_pmhd,
				 tx_response_retrans),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
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
	NULL,
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
	default_me_thr_set,
#endif
	/* TCA Table */
	tca_table,
	/* Data Size */
	sizeof(struct omci_me_sip_agent_pmhd),
	/* Properties */
	OMCI_ME_PROP_PM | OMCI_ME_PROP_PM_INTERNAL | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"SIP agent PMHD",
		/* Access */
		ME_CREATED_BY_OLT,
		/* Supported alarms */
		NULL,
		/* Supported alarms count */
		0,
		/* Support */
		ME_SUPPORTED
	},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */

#endif
