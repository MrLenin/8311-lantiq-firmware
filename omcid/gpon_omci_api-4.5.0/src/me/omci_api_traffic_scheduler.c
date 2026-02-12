/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_traffic_scheduler.h"

enum omci_api_return
omci_api_traffic_scheduler_create(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint16_t tcont_ptr,
				  uint16_t traffic_scheduler_ptr,
				  uint8_t policy,
				  uint8_t priority_weight)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint8_t scheduler_index = (uint8_t)(me_id & 0xFF);
	uint32_t connected_scheduler_index = 0, idx = 0;
	struct gpe_sched_create scheduler_create;
	struct gpe_scheduler_idx scheduler;
	union gpe_scheduler_get_u connected_scheduler;
	struct gpe_epn egress_port;
	struct gpe_token_bucket_shaper tbs;
	bool ani = false;
	uint8_t epn = tcont_ptr & 0xff;

	DBG(OMCI_API_MSG, ("%s"
		  " me_id=%u"
		  " tcont_ptr=0x%x"
		  " traffic_scheduler_ptr=0x%x"
		  " policy=%u"
		  " priority_weight=%u"
		  " scheduler_index=%u\n",
		  __FUNCTION__,
		  me_id, tcont_ptr, traffic_scheduler_ptr, policy,
		  priority_weight, scheduler_index));

	memset(&scheduler_create, 0x00, sizeof(scheduler_create));
	scheduler_create.index = scheduler_index;
	scheduler_create.scheduler_id = me_id;
	scheduler_create.scheduler_policy = (enum gpe_policy) policy;
	scheduler_create.priority_weight = priority_weight;
	scheduler_create.use_tcont = false;
	scheduler_create.level = 0;

	if (traffic_scheduler_ptr != 0x0000 && traffic_scheduler_ptr != 0xffff) {
		scheduler_create.use_regular = 0;
		/* connected to another scheduler */
		scheduler_create.connected_scheduler_index =
						(traffic_scheduler_ptr & 0xFF);
	} else if (tcont_ptr != 0x0000 && tcont_ptr != 0xffff) {
		scheduler_create.use_regular = 0;
		/* connected to TCONT */
		scheduler_create.connected_scheduler_index =
						ONU_GPE_SCHEDULER_INDEX_TCONT + epn;
		ani = true;
	} else {
		scheduler_create.use_regular = 1;
		scheduler_create.port_idx  = scheduler_index;
	}

	if(scheduler_create.use_regular == 0) {
		connected_scheduler.in.index = scheduler_create.connected_scheduler_index;
		/* get the scheduler to be connected */
		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_SCHEDULER_GET,
				  &connected_scheduler,
				  sizeof(connected_scheduler));
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("Can't get scheduler configuration"
			  " me_id=%u"
			  " connected_scheduler.in.index=0x%x\n",
			  me_id, connected_scheduler.in.index));
			return ret;
		}

		/* set next hierarchy level */
		scheduler_create.level = connected_scheduler.out.level + 1;
	}

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_SCHEDULER_CREATE,
		      &scheduler_create, sizeof(scheduler_create));
	if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR, ("Can't create scheduler"
			  " me_id=%u"
			  " scheduler_create.index=0x%x"
			  " connected_scheduler.in.index=0x%x\n",
			  me_id, scheduler_create.index, connected_scheduler.in.index));
			  goto sched_delete;
	}

	if (ani) {
		egress_port.epn = epn;
		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_GPE_EGRESS_PORT_ENABLE,
			      &egress_port, sizeof(egress_port));
		if (ret != OMCI_API_SUCCESS)
			goto sched_delete;
	}

	return OMCI_API_SUCCESS;

sched_delete:
	scheduler.index = scheduler_index;
	dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_SCHEDULER_DELETE,
		&scheduler, sizeof(scheduler));

	return ret;
}

enum omci_api_return
omci_api_traffic_scheduler_destroy(struct omci_api_ctx *ctx,
				   uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint8_t scheduler_index = (uint8_t)(me_id & 0xFF);
	uint32_t idx = 0;
	struct gpe_scheduler_idx scheduler;
	struct gpe_token_bucket_shaper tbs;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	scheduler.index = (uint8_t)scheduler_index;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_SCHEDULER_DELETE,
		      &scheduler, sizeof(scheduler));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return ret;
}

enum omci_api_return
omci_api_traffic_scheduler_update(struct omci_api_ctx *ctx,
				  uint16_t me_id,
				  uint16_t tcont_ptr,
				  uint16_t traffic_scheduler_ptr,
				  uint8_t policy,
				  uint8_t priority_weight)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_scheduler_cfg scheduler_cfg;
	uint8_t scheduler_index = (uint8_t)(me_id & 0xFF);

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   priority_weight=%u\n",
		  __FUNCTION__, me_id, priority_weight));

	scheduler_cfg.index = (uint8_t)scheduler_index;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_SCHEDULER_CFG_GET,
		      &scheduler_cfg, sizeof(scheduler_cfg));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	scheduler_cfg.weight = priority_weight;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_SCHEDULER_CFG_SET,
		      &scheduler_cfg, sizeof(scheduler_cfg));

	if (ret != OMCI_API_SUCCESS)
		return ret;

	return ret;
}
