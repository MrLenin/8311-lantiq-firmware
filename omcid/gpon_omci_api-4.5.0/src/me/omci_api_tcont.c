/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_tcont.h"

/** \addtogroup OMCI_API_ME_TCONT

   @{
*/

enum omci_api_return omci_api_tcont_create(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint16_t policy)
{
	enum omci_api_return ret = OMCI_API_ERROR;
	struct gpe_tcont_cfg tcont;

	if (ret != OMCI_API_SUCCESS) {
		tcont.epn = me_id & 0xff;
		tcont.policy = policy != 0 ? policy : 1;
		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TCONT_CREATE,
			      &tcont, sizeof(tcont));
	}

	return ret;
}

static enum omci_api_return omci_api_tcont_set(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint16_t alloc_id)
{
	enum omci_api_return ret = OMCI_API_ERROR;
	struct gpe_tcont tcont;
	uint8_t i, first_free = 0xff;
	uint32_t tcont_idx = 0;

	memset(&tcont, 0, sizeof(tcont));

	ret = index_get(ctx, MAPPER_TCONT_MEID_TO_IDX, me_id, &tcont_idx);
	if (ret == OMCI_API_SUCCESS) {
		/* Already mapped: set tcont_idx for GET/SET path below.
		   v4.5.0 SDK bug: missed this, left tcont_idx=0 from memset.
		   Stock (FUN_00441b9c) does: local_40 = mapper_result. */
		tcont.tcont_idx = tcont_idx;
	} else {
		for (i = 0; i < ONU_GPE_MAX_TCONT; i++) {
			tcont.tcont_idx = i;
			ret = dev_ctl(ctx->remote, ctx->onu_fd,
					  FIO_GPE_TCONT_GET,
					  &tcont, sizeof(tcont));
			if (ret != OMCI_API_SUCCESS) {
				DBG(OMCI_API_ERR,
					("FIO_GPE_TCONT_GET failed\n"));
				break;
			}
			if (tcont.alloc_id == alloc_id) {
				first_free = 0xff;
				ret = explicit_map(ctx,
						   MAPPER_TCONT_MEID_TO_IDX,
						   me_id, i);
				if (ret != OMCI_API_SUCCESS) {
					DBG(OMCI_API_ERR, ("MAPPER_TCONT_MEID_TO_IDX: map failed %d -> %d\n", me_id, i));
					return ret;
				}
				break;
			} else if (tcont.alloc_id == 0xff &&
				   first_free == 0xff) {
				first_free = i;
			}
		}
	}
	if (first_free != 0xff) {
		/* no set yet - use the first free tcont */
		ret = explicit_map(ctx, MAPPER_TCONT_MEID_TO_IDX,
				   me_id, first_free);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR,
				("MAPPER_TCONT_MEID_TO_IDX:"
				 " map failed %d -> %d (2)\n", me_id, i));
			return ret;
		}
		tcont.tcont_idx = first_free;
		tcont.alloc_id = alloc_id;
	}
	if (ret == OMCI_API_SUCCESS) {
		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TCONT_GET,
			      &tcont, sizeof(tcont));
		/* add data epn */
		tcont.reg_egress_port = me_id & 0xff;
		/* set alloc id */
		tcont.alloc_id = alloc_id;
		ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TCONT_SET,
			      &tcont, sizeof(tcont));
		if (ret != OMCI_API_SUCCESS)
			DBG(OMCI_API_ERR, ("FIO_GPE_TCONT_SET failed\n"));
	}

	return ret;
}

static enum omci_api_return omci_api_tcont_delete(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint16_t alloc_id)
{
	struct gpe_tcont tcont;
	enum omci_api_return ret = OMCI_API_SUCCESS;
	uint32_t tcont_idx = 0;

	ret = index_get(ctx, MAPPER_TCONT_MEID_TO_IDX, me_id, &tcont_idx);
	if (ret != OMCI_API_SUCCESS) {
		if (ret == OMCI_API_NOT_FOUND)
			return OMCI_API_SUCCESS;
		return ret;
	}

	tcont.tcont_idx = tcont_idx;
	dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TCONT_DELETE,
			  &tcont, sizeof(tcont));

	ret = id_remove(ctx, MAPPER_TCONT_MEID_TO_IDX, me_id);
	if (ret != OMCI_API_SUCCESS) {
		(void)error_notify(ctx, 262, me_id,
				   OMCI_API_ACTION_DESTROY, ret);
		return ret;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return omci_api_tcont_update(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint16_t alloc_id)
{
	if(alloc_id == 0xff || alloc_id == 0xffff)
		return omci_api_tcont_delete(ctx, me_id, alloc_id);
	else
		return omci_api_tcont_set(ctx, me_id, alloc_id);
}

enum omci_api_return omci_api_tcont_destroy(struct omci_api_ctx *ctx,
					    uint16_t me_id,
					    uint16_t alloc_id)
{
	enum omci_api_return ret;
	uint32_t tcont_idx;

	ret = index_get(ctx, MAPPER_TCONT_MEID_TO_IDX, me_id, &tcont_idx);
	if (ret == OMCI_API_SUCCESS)
		id_remove(ctx, MAPPER_TCONT_MEID_TO_IDX, me_id);

	return OMCI_API_SUCCESS;
}

/** @} */
