/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "ifxos_memory_alloc.h"
#include "ifxos_time.h"
#include "omci_api_common.h"
#include "omci_api_debug.h"

#define OMCI_API_EVENT_HANDLING_THREAD_PRIO          IFXOS_THREAD_PRIO_NORMAL
#define OMCI_API_EVENT_HANDLING_THREAD_STACKSIZE     IFXOS_DEFAULT_STACK_SIZE
#define OMCI_API_EVENT_HANDLING_THREAD_STOP_TIMEOUT  \
						 IFXOS_THREAD_DOWN_WAIT_POLL_MS

enum omci_api_return error_notify(struct omci_api_ctx *ctx,
				  uint16_t class_id, uint16_t instance_id,
				  enum omci_api_action_type action,
				  enum omci_api_return ret)
{
	return OMCI_API_SUCCESS;
}

static void omci_api_goi_handle(struct omci_api_ctx *ctx)
{
	enum omci_api_return ret;
	struct omci_api_event event;
	struct optic_fifo_data fifo_data;
	bool active = false;

	ret = dev_ctl(ctx->remote, ctx->goi_fd, FIO_OPTIC_EVENT_FIFO,
		      &fifo_data, sizeof(fifo_data));
	if (ret < OMCI_API_SUCCESS) {
		DBG(OMCI_API_WRN, ("optic fifo event get failed\n"));
		return;
	}

	/* NOTE! When RPC is used, event data may come with the wrong
	 * byte order! Here we should care about it! */

	fifo_data.header.id = ONU_OMCI_NTOH32(fifo_data.header.id);
	fifo_data.header.len = ONU_OMCI_NTOH32(fifo_data.header.len);

	switch (fifo_data.header.id) {
	case OPTIC_FIFO_ALARM:
		fifo_data.data.alarm = ONU_OMCI_NTOH32(fifo_data.data.alarm);

		switch (fifo_data.data.alarm) {

		case OPTIC_IRQ_TEMPALARM_YELLOW_SET:
			active = true;
		case OPTIC_IRQ_TEMPALARM_YELLOW_CLEAR:
			/** \todo define a clean place for the G988.4
				  definitions*/
			event.alarm.alarm = 8;
			event.alarm.active = active;
			break;
		case OPTIC_IRQ_TEMPALARM_RED_SET:
			active = true;
		case OPTIC_IRQ_TEMPALARM_RED_CLEAR:
			event.alarm.alarm = 9;
			event.alarm.active = active;
			break;
		default:
			DBG(OMCI_API_MSG, ("GOI ALARM #%u (0x%x)\n",
				ONU_OMCI_NTOH32(fifo_data.data.alarm),
				ONU_OMCI_NTOH32(fifo_data.data.alarm)));
			return;
		}

		event.type = OMCI_API_EVENT_ALARM;
		event.alarm.class_id = 256;
		event.alarm.instance_id = 0;

		ctx->event.cb(ctx->caller, &event);		
		break;
	default:
		DBG(OMCI_API_MSG, ("GOI EVENT #%u (0x%x)\n",
			  ONU_OMCI_NTOH32(fifo_data.header.id),
			  ONU_OMCI_NTOH32(fifo_data.header.id)));
		break;
	}
}

static void omci_api_onu_event_link_state_change(struct omci_api_ctx *ctx,
						 struct onu_fifo_data *fifo_data)
{
	union lan_port_status_get_u port_status;
	struct omci_api_event event;
	uint32_t me_id;
	int ret;

	event.type = OMCI_API_EVENT_LINK_STATE;
	event.link_state.state =
		ONU_OMCI_NTOH32(fifo_data->data.link_state.new);

	port_status.in.index = ONU_OMCI_NTOH32(fifo_data->data.link_state.port);
	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_LAN_PORT_STATUS_GET,
		      &port_status,
		      sizeof(port_status));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Can't get port #%d status "
				   "on link state event\n",
				   ONU_OMCI_NTOH32(fifo_data->data.link_state.
				   port)));
		return;
	}

	switch (port_status.out.link_status) {
		case LAN_PHY_STATUS_10_UP:
			event.link_state.config_ind = 1;
			break;

		case LAN_PHY_STATUS_100_UP:
			event.link_state.config_ind = 2;
			break;

		case LAN_PHY_STATUS_1000_UP:
			event.link_state.config_ind = 3;
			break;

		default:
			event.link_state.config_ind = 0;
			break;
	}

	if (port_status.out.phy_duplex == LAN_PHY_MODE_DUPLEX_HALF)
		event.link_state.config_ind |= 0x10;

	ret = id_get(ctx, MAPPER_PPTPETHUNI_MEID_TO_IDX,
		     &me_id,
		     ONU_OMCI_NTOH32(fifo_data->data.link_state.port));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("Can't get port #%d id "
				   "on link state event\n",
				   ONU_OMCI_NTOH32(fifo_data->data.link_state.
				   port)));
		return;
	}

	event.link_state.instance_id = (uint16_t)me_id;

	DBG(OMCI_API_MSG,
		("port #%d status change: state %d, config %d (meid 0x%x)\n",
		   ONU_OMCI_NTOH32(fifo_data->data.link_state.port),
		   event.link_state.state,
		   event.link_state.config_ind,
		   event.link_state.instance_id));

	ctx->event.cb(ctx->caller, &event);
}

static void omci_api_onu_handle(struct omci_api_ctx *ctx)
{
	struct omci_api_event event;
	struct onu_fifo_data data;

	if (dev_ctl(ctx->remote, ctx->onu_fd_nfc, FIO_ONU_EVENT_FIFO, &data,
		    sizeof(data)) >= 0) {

		/* NOTE! When RPC is used, event data may come with the wrong
		 * byte order! Here we should care about it! */

		data.header.id =
		    ONU_OMCI_NTOH32(data.header.id);
		data.header.len =
		    ONU_OMCI_NTOH32(data.header.len);

		switch (data.header.id) {

		case ONU_EVENT_PLOAM_DS:
			/* disabled */
			break;

		case ONU_EVENT_STATE_CHANGE:
			event.type = OMCI_API_EVENT_PLOAM_STATE;
			event.ploam_state.curr =
				ONU_OMCI_NTOH32(data.data.state.curr_state);
			event.ploam_state.prev =
				ONU_OMCI_NTOH32(data.data.state.previous_state);

			ctx->event.cb(ctx->caller, &event);
			break;

		case ONU_EVENT_OMCI_RECEIVE:
			event.type = OMCI_API_EVENT_OMCI;
			memcpy(event.omci.msg, &data.data.omci_message.
			       message[0], data.data.omci_message.length);
			ctx->event.cb(ctx->caller, &event);
			break;

#ifdef INCLUDE_ONU_GOI_SUPPORT
		case ONU_FIFO_GOI_TX_POWER_LOW:
			event.type = OMCI_API_EVEN_ALARM;
			event.alarm.class_id = 263;
			event.alarm.instance_id = 0;
			event.alarm.alarm = 4;
			event.alarm.active = true;
			ctx->event.cb(ctx->caller, &event);
			/** \todo need some kind of indication
				  about alarm on/off */
			break;
#endif

#if 0
		/** \todo fix in driver:
			  ONU_FIFO_GOI_TX_POWER_HIGH is the
			  same as ONU_FIFO_GOI_TX_POWER_LOW */
		case ONU_FIFO_GOI_TX_POWER_HIGH:
			event.type = OMCI_API_EVENT_ALARM;
			event.alarm.class_id = 263;
			event.alarm.instance_id = 0;
			event.alarm.alarm = 5;
			event.alarm.active = true;
			ctx->event.cb(ctx->caller, &event);
			/** \todo need some kind of indication
				  about alarm on/off */
			break;
#endif

#ifdef INCLUDE_ONU_GOI_SUPPORT
		case ONU_FIFO_GOI_RX_POWER_LOW:
			event.type = OMCI_API_EVENT_ALARM;
			event.alarm.class_id = 263;
			event.alarm.instance_id = 0;
			event.alarm.alarm = 0;
			event.alarm.active = true;
			ctx->event.cb(ctx->caller, &event);
			/** \todo need some kind of indication
				  about alarm on/off */
			break;
#endif

#if 0
		/** \todo fix in driver:
			  ONU_FIFO_GOI_RX_POWER_HIGH is the
			  same as ONU_FIFO_GOI_RX_POWER_LOW */
		case ONU_FIFO_GOI_RX_POWER_HIGH:
			event.type = OMCI_API_EVEN_ALARM;
			event.alarm.class_id = 263;
			event.alarm.instance_id = 0;
			event.alarm.alarm = 1;
			event.alarm.active = true;
			ctx->event.cb(ctx->caller, &event);
			/** \todo need some kind of indication
				  about alarm on/off */
			break;
#endif

		case ONU_EVENT_LINK_STATE_CHANGE:
			omci_api_onu_event_link_state_change(ctx, &data);
			break;

		default:
			DBG(OMCI_API_MSG, ("ONU EVENT #%u (0x%x)\n",
				  ONU_OMCI_NTOH32(data.header.id),
				  ONU_OMCI_NTOH32(data.header.id)));
			break;
		}
	}
}

static int32_t omci_api_event_handling_thread(struct IFXOS_ThreadParams_s
					      *thr_params)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct omci_api_ctx *ctx = (struct omci_api_ctx *)thr_params->nArg1;
	int m = -1;
	uint8_t out[2];

#ifdef LINUX
	DBG(OMCI_API_MSG, ("EventHandling (tid %d)" CRLF, getpid()));
#endif

	if (ctx->onu_fd_nfc > m)
		m = ctx->onu_fd_nfc;
	if (ctx->goi_fd_nfc > m)
		m = ctx->goi_fd_nfc;

	while (thr_params->bRunning == IFX_TRUE &&
	       thr_params->bShutDown == IFX_FALSE) {

		if (event_wait(ctx, m, 5000, &out[0])) {
			if (out[0])
				omci_api_onu_handle(ctx);
			if (out[1])
				omci_api_goi_handle(ctx);
		}
	}
	return 0;
}

enum omci_api_return event_handling_start(struct omci_api_ctx *ctx)
{
	struct onu_event_mask fifo_mask;
	struct event_ctx *event = &ctx->event;
	uint32_t psm_mask;
	enum optic_activation optic_evt;
	struct onu_test_mode test_mode;

	event->init = false;

	/* v7.5.1 stock event mask = 0x00346018. Includes v4.5.0 events plus:
	   bit 14 (15MIN_INTERVAL_END), bit 18/20/21 (v7.5.1-only events). */
	fifo_mask.val = 0x00346018;
	dev_ctl(ctx->remote, ctx->onu_fd_nfc, FIO_ONU_EVENT_ENABLE_SET,
		&fifo_mask, sizeof(fifo_mask));

	/* v7.5.1 stock: psm_fsm_event_mask_set(0xFFFFFFFF) during event init.
	   Enables all PSM FSM event types. Result not checked (fire-and-forget). */
	psm_mask = 0xFFFFFFFF;
	dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_PSM_FSM_EVENT_MASK_SET,
		&psm_mask, sizeof(psm_mask));

	/* v7.5.1 stock: enable optic event FIFO on goi_fd_nfc.
	   Must be the fd the event thread selects on for optic alarms. */
	optic_evt = OPTIC_ENABLE;
	dev_ctl(ctx->remote, ctx->goi_fd_nfc, FIO_OPTIC_EVENT_SET,
		&optic_evt, sizeof(optic_evt));

	/* v7.5.1 stock: "omci_download_enable=1" — enables OMCI SW download. */
	memset(&test_mode, 0, sizeof(test_mode));
	strncpy(test_mode.mode, "omci_download_enable=1", sizeof(test_mode.mode) - 1);
	dev_ctl(ctx->remote, ctx->onu_fd, FIO_ONU_TEST_MODE_SET,
		&test_mode, sizeof(test_mode));

	if (IFXOS_ThreadInit((IFXOS_ThreadCtrl_t *)
			     &event->thread_ctrl,
			     "evthdl",
			     omci_api_event_handling_thread,
			     OMCI_API_EVENT_HANDLING_THREAD_PRIO,
			     OMCI_API_EVENT_HANDLING_THREAD_STACKSIZE,
			     (unsigned long)ctx, 0)) {
		DBG(OMCI_API_ERR, ("Can't start event handling thread\n"));
		return OMCI_API_ERROR;
	}

	event->init = true;

	return OMCI_API_SUCCESS;
}

enum omci_api_return event_handling_stop(struct omci_api_ctx *ctx)
{
	struct event_ctx *event = &ctx->event;

	if (event->init == false)
		return OMCI_API_SUCCESS;

	if (IFXOS_ThreadDelete
	    ((IFXOS_ThreadCtrl_t *) &event->thread_ctrl,
	     OMCI_API_EVENT_HANDLING_THREAD_STOP_TIMEOUT)) {
		DBG(OMCI_API_ERR, ("Can't stop event handling thread\n"));
		return OMCI_API_ERROR;
	}

	return OMCI_API_SUCCESS;
}
