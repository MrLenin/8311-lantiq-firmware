/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_traffic_descriptor.h"

/** \addtogroup OMCI_API_ME_TRAFFIC_DESCRIPTOR

   @{
*/

/** Maximum possible traffic descriptor ME's */
#define ONU_GPE_MAX_TRAFFIC_DESCRIPTOR		64

/** MAC Bridge configuration data

   \note Store local copy of MAC Bridge
         configuration data for each MAC Bridge
*/
static struct omci_api_traffic_descriptor
			    td[ONU_GPE_MAX_TRAFFIC_DESCRIPTOR] = { 0 };

static enum omci_api_return
omci_api_traffic_descriptor_meter_update(struct omci_api_ctx *ctx,
					 const uint32_t td_idx);

enum omci_api_return
omci_api_meter_set(struct omci_api_ctx *ctx,
		   const uint16_t meter_index,
		   const struct omci_api_traffic_descriptor *td);

enum omci_api_return
omci_api_traffic_descriptor_update(struct omci_api_ctx *ctx,
				   uint16_t me_id,
				   uint32_t cir,
				   uint32_t pir,
				   uint32_t cbs,
				   uint32_t pbs,
				   uint8_t color_mode,
				   uint8_t ingress_color_marking,
				   uint8_t egress_color_marking,
				   uint8_t meter_type)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t td_idx = 0;

	DBG(OMCI_API_MSG, ("%s"
		  " MeId=%u"
		  " Cir=%u"
		  " Pir=%u"
		  " Cbs=%u"
		  " Pbs=%u"
		  " ColorMode=%u"
		  " IngressColorMarking=%u"
		  " EgressColorMarking=%u"
		  " MeterType=%u\n",
		  __FUNCTION__,
		  me_id, cir,
		  pir, cbs,
		  pbs, color_mode,
		  ingress_color_marking, egress_color_marking, meter_type));

	ret = index_get(ctx, MAPPER_TRAFFDESCR_TO_IDX, me_id, &td_idx);
	if (ret == OMCI_API_NOT_FOUND) {
		ret = id_map(ctx, MAPPER_TRAFFDESCR_TO_IDX, me_id, &td_idx);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR,
				("MAPPER_TRAFFDESCR_TO_IDX: can't map %d id\n",
									me_id));
			return OMCI_API_ERROR;
		}
	} else if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("MAPPER_TRAFFDESCR_TO_IDX: failed\n"));
		return OMCI_API_ERROR;
	}

	if (td_idx >= ONU_GPE_MAX_TRAFFIC_DESCRIPTOR) {
		DBG(OMCI_API_ERR,
			("Not enough Traffic Descriptor buffer available\n"));
		return OMCI_API_ERROR;
	}

	td[td_idx].cir = cir;
	td[td_idx].pir = pir;
	td[td_idx].cbs = cbs;
	td[td_idx].pbs = pbs;
	td[td_idx].color_mode = color_mode;
	td[td_idx].ingress_color_marking = ingress_color_marking;
	td[td_idx].egress_color_marking = egress_color_marking;
	td[td_idx].meter_type = meter_type;

	omci_api_traffic_descriptor_meter_update(ctx, td_idx);

	return ret;
}

enum omci_api_return
omci_api_traffic_descriptor_destroy(struct omci_api_ctx *ctx,
				    uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t td_idx = 0, i;

	DBG(OMCI_API_MSG, ("%s MeId=%u\n", __FUNCTION__, me_id));

	ret = index_get(ctx, MAPPER_TRAFFDESCR_TO_IDX, me_id, &td_idx);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR, ("MAPPER_TRAFFDESCR_TO_IDX: failed\n"));
		return OMCI_API_ERROR;
	}

	ret = omci_api_shaper_clean(ctx, td_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	for(i=0;i<MAX_TD_SHAPER;i++)
		td[td_idx].shaper[i].enable = 0;

	for(i=0;i<MAX_TD_METER;i++)
		td[td_idx].meter[i].enable = 0;

	ret = index_remove(ctx, MAPPER_TRAFFDESCR_TO_IDX, td_idx);
	if (ret != OMCI_API_SUCCESS) {
		(void)error_notify(ctx, 47, me_id,
				   OMCI_API_ACTION_DESTROY, ret);
		return OMCI_API_ERROR;
	}

	return ret;
}

enum omci_api_return
omci_api_traffic_descriptor_get(struct omci_api_ctx *ctx,
				const uint32_t td_idx,
				struct omci_api_traffic_descriptor *dest)
{
	if (td_idx >= ONU_GPE_MAX_TRAFFIC_DESCRIPTOR)
		return OMCI_API_ERROR;

	memcpy(dest, &td[td_idx], sizeof(struct omci_api_traffic_descriptor));

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_traffic_descriptor_meter_attach(struct omci_api_ctx *ctx,
					 const uint32_t td_idx,
					 uint8_t meter_idx)
{
	int i;

	if (td_idx >= ONU_GPE_MAX_TRAFFIC_DESCRIPTOR)
		return OMCI_API_ERROR;

	for(i=0;i<MAX_TD_METER;i++) {
		if(td[td_idx].meter[i].enable)
			continue;
		td[td_idx].meter[i].enable = 1;
		td[td_idx].meter[i].index = meter_idx;
		break;
	}
	if (i == MAX_TD_METER)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_traffic_descriptor_meter_detach(struct omci_api_ctx *ctx,
					 const uint32_t td_idx,
					 const uint8_t meter_idx)
{
	int i;

	if (td_idx >= ONU_GPE_MAX_TRAFFIC_DESCRIPTOR)
		return OMCI_API_ERROR;

	for(i=0;i<MAX_TD_METER;i++) {
		if(td[td_idx].meter[i].enable == 0)
			continue;
		if(td[td_idx].meter[i].index != meter_idx)
			continue;
		td[td_idx].meter[i].index = 0;
		td[td_idx].meter[i].enable = 0;
	}
	if (i == MAX_TD_METER)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

static enum omci_api_return
omci_api_traffic_descriptor_meter_update(struct omci_api_ctx *ctx,
					 const uint32_t td_idx)
{
	int i;

	if (td_idx >= ONU_GPE_MAX_TRAFFIC_DESCRIPTOR)
		return OMCI_API_ERROR;

	for(i=0;i<MAX_TD_METER;i++) {
		if(td[td_idx].meter[i].enable)
			continue;
		omci_api_meter_set(ctx, td[td_idx].meter[i].index, &td[td_idx]);
		break;
	}
	if (i == MAX_TD_METER)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}


enum omci_api_return
omci_api_traffic_descriptor_shaper_attach(struct omci_api_ctx *ctx,
					  const uint32_t td_idx,
					  const uint32_t shaper_idx)
{
	int i;

	if (td_idx >= ONU_GPE_MAX_TRAFFIC_DESCRIPTOR)
		return OMCI_API_ERROR;

	for(i=0;i<MAX_TD_SHAPER;i++) {
		if(td[td_idx].shaper[i].enable)
			continue;
		td[td_idx].shaper[i].enable = 1;
		td[td_idx].shaper[i].index = shaper_idx;
		break;
	}
	if (i == MAX_TD_SHAPER)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_traffic_descriptor_shaper_detach(struct omci_api_ctx *ctx,
					  const uint32_t td_idx)
{
	int i;

	if (td_idx >= ONU_GPE_MAX_TRAFFIC_DESCRIPTOR)
		return OMCI_API_ERROR;

	for(i=0;i<MAX_TD_SHAPER;i++) {
		if(td[td_idx].shaper[i].enable == 0)
			continue;
		td[td_idx].shaper[i].enable = 0;
	}
	if (i == MAX_TD_SHAPER)
		return OMCI_API_ERROR;

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_shaper_update(struct omci_api_ctx *ctx,
		    const uint32_t shaper_index)
{
	enum omci_api_return ret;
	struct gpe_token_bucket_shaper_cfg shaper;
	int i,k;

	/* find all TD which are pointing to the given shaper */
	memset(&shaper, 0, sizeof(shaper));
	for(k=0;k<ONU_GPE_MAX_TRAFFIC_DESCRIPTOR;k++) {
		for(i=0;i<MAX_TD_SHAPER;i++) {
			if(td[k].shaper[i].enable == 0)
				continue;
			if(td[k].shaper[i].index != shaper_index)
				continue;
			/* get the maximum values */
			shaper.cir = MAX(td[k].cir, shaper.cir);
			shaper.pir = MAX(td[k].pir, shaper.pir);
			shaper.cbs = MAX(td[k].cbs, shaper.cbs);
			shaper.pbs = MAX(td[k].pbs, shaper.pbs);
			break;
		}
	}

	shaper.index = shaper_index;
	shaper.mode = td->meter_type;
	shaper.enable = 1;

	ret = dev_ctl(ctx->remote, ctx->onu_fd,
		      FIO_GPE_TOKEN_BUCKET_SHAPER_CFG_SET,
		      &shaper, sizeof(shaper));
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("shaper %u failed on cfg set, ret=%d\n",
					shaper.index, ret));
		return ret;
	}

	return ret;
}

enum omci_api_return omci_api_shaper_clean(struct omci_api_ctx *ctx,
					   const uint32_t td_idx)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_token_bucket_shaper_cfg shaper;
	int i;

	memset(&shaper, 0, sizeof(shaper));
	shaper.cir = ONU_GPE_TBS_CIR_DEF;
	shaper.pir = ONU_GPE_TBS_PIR_DEF;
	shaper.cbs = ONU_GPE_TBS_CBS_DEF;
	shaper.pbs = ONU_GPE_TBS_PBS_DEF;

	for(i=0;i<MAX_TD_SHAPER;i++) {
		if(td[td_idx].shaper[i].enable == 0)
			continue;
		shaper.index = td[td_idx].shaper[i].index;
		dev_ctl(ctx->remote, ctx->onu_fd,
			  FIO_GPE_TOKEN_BUCKET_SHAPER_CFG_SET,
			  &shaper, sizeof(shaper));
	}

	return ret;
}

/** @} */
