/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_ethernet_ds_pmhd.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_ethernet_ds_pmhd.h"
#include "me/omci_api_ethernet_ds_pmhd.h"

#ifdef INCLUDE_PM

/** \addtogroup OMCI_ME_ETHERNET_PMHD_DS
    @{
*/

static enum omci_error me_counters_get(struct omci_context *context,
				       struct me *me,
				       enum omci_pm_interval interval)
{
	enum omci_api_return ret;
	struct omci_me_ethernet_ds_pmhd *me_data;
	uint64_t drop_events, octets, packets, broadcast_packets,
		 multicast_packets, crc_errored_packets, undersized_packets,
		 oversized_packets, cnt64_octets_packets, cnt127_octets_packets,
		 cnt255_octets_packets, cnt511_octets_packets,
		 cnt1023_octets_packets, cnt1518_octets_packets;

	dbg_in(__func__, "%p, %p, %lu", (void *)context, (void *)me, interval);

	me_data = (struct omci_me_ethernet_ds_pmhd *)me->data;

	ret = omci_api_ethernet_ds_pmhd_cnt_get(context->api, me->instance_id,
						interval ==
							OMCI_PM_INTERVAL_CURR,
						false,
						&drop_events,
						&octets,
						&packets,
						&broadcast_packets,
						&multicast_packets,
						&crc_errored_packets,
						&undersized_packets,
						&oversized_packets,
						&cnt64_octets_packets,
						&cnt127_octets_packets,
						&cnt255_octets_packets,
						&cnt511_octets_packets,
						&cnt1023_octets_packets,
						&cnt1518_octets_packets);
	if (ret != OMCI_API_SUCCESS) {
		me_dbg_err(me, "DRV ERR(%d) Can't get counters", ret);

		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	me_data->drop_event_count = uint64_lo(drop_events);

	if (interval != OMCI_PM_INTERVAL_ABS) {
		me_data->rx_byte_count =
					uint64_lo(octets);
		me_data->rx_packet_count =
					uint64_lo(packets);
		me_data->rx_broadcast_packet_count =
					uint64_lo(broadcast_packets);
		me_data->rx_multicast_packet_count =
					uint64_lo(multicast_packets);
		me_data->fcs_error_count =
					uint64_lo(crc_errored_packets);
		me_data->rx_undersized_packet_count =
					uint64_lo(undersized_packets);
		me_data->rx_oversized_packet_count =
					uint64_lo(oversized_packets);
		me_data->rx_frame64_count =
					uint64_lo(cnt64_octets_packets);
		me_data->rx_frame127_count =
					uint64_lo(cnt127_octets_packets);
		me_data->rx_frame255_count =
					uint64_lo(cnt255_octets_packets);
		me_data->rx_frame511_count =
					uint64_lo(cnt511_octets_packets);
		me_data->rx_frame1023_count =
					uint64_lo(cnt1023_octets_packets);
		me_data->rx_frame1518_count =
					uint64_lo(cnt1518_octets_packets);
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

	/* check if related PPTP Eth UNI exists */
	error = mib_me_find(context, OMCI_ME_PPTP_ETHERNET_UNI,
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
	/* 0 Drop events #1 */
	TCA(0, omci_me_ethernet_ds_pmhd_drop_event_count, 1),
	/* 1 CRC errored packets #2 */
	TCA(1, omci_me_ethernet_ds_pmhd_fcs_error_count, 2),
	/* 2 Undersize packets #3 */
	TCA(2, omci_me_ethernet_ds_pmhd_rx_undersized_packet_count, 3),
	/* 3 Oversize packets #4 */
	TCA(3, omci_me_ethernet_ds_pmhd_rx_oversized_packet_count, 4),

	TCA(0, 0, 0)
};

/** Managed Entity class */
struct me_class me_ethernet_ds_pmhd_class = {
	/* Class ID */
	OMCI_ME_ETHERNET_FRAME_PMHD_DS,
	/* Attributes */
	{
		/* 1. Interval End Time */
		ATTR_UINT("Interval end time",
			  ATTR_SUPPORTED,
			  0x00,
			  0xff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   interval_end_time),
			  1,
			  OMCI_ATTR_PROP_RD,
			  pm_interval_end_time_get),
		/* 2. Threshold Data 1/2 ID */
		ATTR_PTR("Threshold data 1/2 id",
			 ATTR_SUPPORTED,
			 0x0000,
			 0xffff,
			 offsetof(struct omci_me_ethernet_ds_pmhd,
				  thr_data_id),
			 2,
			 OMCI_ATTR_PROP_RD
			 | OMCI_ATTR_PROP_WR | OMCI_ATTR_PROP_SBC,
			 NULL),
		/* 3. Drop Event Count */
		ATTR_UINT("Drop events",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   drop_event_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 4. Received Octet (Byte) Count */
		ATTR_UINT("Octets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   rx_byte_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 5. Received Packet Count */
		ATTR_UINT("Packets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   rx_packet_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 6. Received Broadcast Packet Count  */
		ATTR_UINT("Broadcast packets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   rx_broadcast_packet_count),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 7. Received Multicast Packet Count */
		ATTR_UINT("Multicast packets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   rx_multicast_packet_count),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 8. FCS (CRC) Error Count */
		ATTR_UINT("CRC errored packets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   fcs_error_count),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 9. Received Undersized Packet Count */
		ATTR_UINT("Undersize packets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   rx_undersized_packet_count),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 10. Received Oversized Packet Count */
		ATTR_UINT("Oversize packets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   rx_oversized_packet_count),
			  4,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_TEMPLATE,
			  NULL),
		/* 11. Received Frame Size 64 Byte Count */
		ATTR_UINT("Packets 64 octets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   rx_frame64_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 12. Received Frame Size 65 to 127 Byte Count */
		ATTR_UINT("Packets 65 - 127 octets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   rx_frame127_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 13. Received Frame Size 128 to 255 Byte Count */
		ATTR_UINT("Packets 128 - 255 octets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   rx_frame255_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 14. Received Frame Size 256 to 511 Byte Count */
		ATTR_UINT("Packets 256 - 511 octets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   rx_frame511_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 15. Received Frame Size 512 to 1023 Byte Count */
		ATTR_UINT("Packets 512 - 1023 octets",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   rx_frame1023_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 16. Received Frame Size 1024 to 1518 Byte Count */
		ATTR_UINT("Packets 1024 - 1518 octet",
			  ATTR_SUPPORTED,
			  0x00000000,
			  0xffffffff,
			  offsetof(struct omci_me_ethernet_ds_pmhd,
				   rx_frame1518_count),
			  4,
			  OMCI_ATTR_PROP_RD,
			  NULL)
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
	default_me_thr_set,
#endif
	/* TCA Table */
	tca_table,
	/* Data Size */
	sizeof(struct omci_me_ethernet_ds_pmhd),
	/* Properties */
	OMCI_ME_PROP_PM | OMCI_ME_PROP_PM_INTERNAL | OMCI_ME_PROP_HAS_ALARMS |
	OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"Ethernet frame PMHD DS",
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
