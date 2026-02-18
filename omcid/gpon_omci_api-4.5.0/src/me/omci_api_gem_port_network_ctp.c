/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_gem_port_network_ctp.h"
#include "me/omci_api_tcont.h"
#include "me/omci_api_priority_queue.h"


/** \addtogroup OMCI_API_ME_GEM_PORT_NETWORK_CTP

   @{
*/

enum omci_api_return
omci_api_gem_port_network_ctp_update(struct omci_api_ctx *ctx,
				     uint16_t me_id,
				     uint16_t gem_port_id,
				     uint16_t tcont_ptr,
				     uint8_t direction,
				     uint16_t us_priority_queue_ptr,
				     uint8_t us_priority_queue_drop_precedence_color_marking,
				     uint8_t us_traffic_descriptor_egress_color_marking,
				     uint16_t us_traffic_descriptor_profile_ptr,
				     uint16_t ds_priority_queue_ptr,
				     uint16_t ds_traffic_descriptor_profile_ptr)
{
	struct gpe_gem_port gem_port;
	uint32_t gpix = 0xffffffff;
#if defined(INCLUDE_OMCI_API_MCC)
	uint32_t exc_mask = 1 << ONU_GPE_EXCEPTION_OFFSET_IGMP_MLD;
#else
	uint32_t exc_mask = 0;
#endif
	enum omci_api_return ret = OMCI_API_ERROR;
	struct gpe_equeue_cfg cfg;
	union gpe_equeue_get_u gpe_equeue;
	union gpe_equeue_path_get_u gpe_equeue_path;

	DBG(OMCI_API_MSG, ("gem port ctp:"
		  " me_id=%u"
		  " gem_port_id=%u"
		  " tcont_ptr=%u"
		  " direction=%u"
		  " us_priority_queue_ptr=%u"
		  " us_traffic_descriptor_profile_ptr=%u"
		  " ds_priority_queue_ptr=%u"
		  " ds_traffic_descriptor_profile_ptr=%u\n",
		  me_id,
		  gem_port_id,
		  tcont_ptr,
		  direction,
		  us_priority_queue_ptr,
		  us_traffic_descriptor_profile_ptr,
		  ds_priority_queue_ptr,
		  ds_traffic_descriptor_profile_ptr));

	memset(&gem_port, 0x00, sizeof(gem_port));
	if (index_get(ctx, MAPPER_GEMPORTCTP_MEID_TO_IDX,
		      me_id, &gpix) != OMCI_API_SUCCESS) {

		/* try retrieve gem port index from known gem port id */
		gem_port.gem_port_id = gem_port_id;
		if (dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_GEM_PORT_GET,
			    &gem_port, sizeof(gem_port)) != 0) {

			/* gem port id doesn't exist so far, add it and
			   retrieve the gpix */
			memset(&gem_port, 0x00, sizeof(gem_port));
			gem_port.gem_port_id = gem_port_id;
			gem_port.data_direction = direction;
			gem_port.encryption_enable = false;
			/* v7.5.1: removed me_id==0x200 (host2lan) special
			   case that used GEM_PORT_SET with SW_GPIX.
			   Always use GEM_PORT_ADD. */
			if (dev_ctl(ctx->remote, ctx->onu_fd,
				    FIO_GPE_GEM_PORT_ADD, &gem_port,
				    sizeof(gem_port)) != 0) {

				DBG(OMCI_API_ERR,
					("FIO_GPE_GEM_PORT_ADD %d "
					 "failed\n", gem_port_id));
				goto err;
			}
		} else {
			DBG(OMCI_API_ERR,
				("gem_port_id %d already defined (gpix %d)\n",
					gem_port_id, gem_port.gem_port_index));
		}
		gpix = gem_port.gem_port_index;
		ret = explicit_map(ctx, MAPPER_GEMPORTCTP_MEID_TO_IDX,
				   me_id, (gem_port_id << 16) | gpix);
		if (ret != OMCI_API_SUCCESS)
			goto err;
	} else {
		gpix = gpix & 0xFFFF;
		/* redefine the gem port id for a given gpix */
		DBG(OMCI_API_ERR,
			("map gem_port_id %d - gpix %d already defined\n",
							gem_port_id, gpix));
		gem_port.gem_port_index = gpix;
		gem_port.gem_port_id = gem_port_id;
		gem_port.data_direction = direction;
		if (dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_GEM_PORT_SET,
			    &gem_port, sizeof(gem_port)) != 0) {
			DBG(OMCI_API_ERR, ("FIO_GPE_GEM_PORT_SET %d\n",
							gem_port_id));
			goto err;
		}
	}
	
	if ((gpix != 0xffffffff) && (direction & GPE_DIRECTION_UPSTREAM)) {
		/* for all upstream directions write the firmware table */
		ret = omci_api_gem_port_us_add(ctx, gpix,
					       us_priority_queue_ptr & 0xff);
		if (ret != OMCI_API_SUCCESS)
			DBG(OMCI_API_ERR,
				("ONU_GPE_US_GEM_PORT_TABLE_ID ret=%d\n", ret));

		ret = ani_exception_setup(ctx, gpix,
					 OMCI_API_GEM_PORT_DIRECTION_UPSTREAM,
					 ONU_GPE_EXCEPTION_PROFILE_GEM_US,
					 0x0, 0x0, exc_mask, 0x0);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR,
				("GEM port %d US exc profile set failed, %d\n",
								gpix, ret));
			return ret;
		}
	}

	if ((gpix != 0xffffffff) && (direction & GPE_DIRECTION_DOWNSTREAM)) {
		/* set fixed Ingress color marking mode for downstream */
		ret = omci_api_gem_port_ds_ingress_color_marking_modify(ctx,
									gpix,
									1);
		if (ret != OMCI_API_SUCCESS)
			DBG(OMCI_API_ERR,
				("ONU_GPE_DS_GEM_PORT_TABLE_ID ret=%d\n", ret));

		ret = ani_exception_setup(ctx, gpix,
					 OMCI_API_GEM_PORT_DIRECTION_DOWNSTREAM,
					 ONU_GPE_EXCEPTION_PROFILE_GEM_DS,
					 exc_mask, 0x0, 0x0, 0x0);
		if (ret != OMCI_API_SUCCESS) {
			DBG(OMCI_API_ERR,
				("GEM port %d DS exc profile set failed, %d\n",
								gpix, ret));
			return ret;
		}
		ret = omci_api_gemport_meter_add(ctx, gpix, me_id, 
					   ds_traffic_descriptor_profile_ptr);
	}

	if (direction & GPE_DIRECTION_UPSTREAM &&
	    us_priority_queue_ptr != 0x0000 &&
	    us_priority_queue_ptr != 0xFFFF)  {
			omci_api_gem_port_shaper_add(ctx, gpix, 
					   us_priority_queue_ptr,
					   us_traffic_descriptor_profile_ptr);
	}

	/* v7.5.1: guard against invalid ds_priority_queue_ptr and always
	   call prio_selection_modify (reset when no valid queue). */
	if (gpix != 0xffffffff &&
	    ds_priority_queue_ptr != 0x0000 &&
	    ds_priority_queue_ptr != 0xFFFF) {
		cfg.index = ds_priority_queue_ptr;
		ret = dev_ctl(ctx->remote, ctx->onu_fd,
			      FIO_GPE_EGRESS_QUEUE_CFG_GET,
			      &cfg, sizeof(cfg));
		if (ret == OMCI_API_SUCCESS) {
			if (!cfg.enable)
				return OMCI_API_SUCCESS;

			gpe_equeue_path.in.index = ds_priority_queue_ptr;
			ret = dev_ctl(ctx->remote, ctx->onu_fd,
				      FIO_GPE_EGRESS_QUEUE_PATH_GET,
				      &gpe_equeue_path,
				      sizeof(gpe_equeue_path));
			if (ret != OMCI_API_SUCCESS)
				return OMCI_API_SUCCESS;

			if (gpe_equeue_path.out.epn >= 64 &&
			    gpe_equeue_path.out.epn < 68) {
				/* v7.5.1: queue_selection_mode always
				   false, only egress_queue_offset set */
				omci_api_gem_port_ds_prio_selection_modify(
					ctx, gpix, false,
					gpe_equeue_path.out.info[0].leaf);
				return OMCI_API_SUCCESS;
			}
			return OMCI_API_SUCCESS;
		}
	}

	/* Reset prio selection when no valid DS queue */
	if (gpix != 0xffffffff)
		omci_api_gem_port_ds_prio_selection_modify(ctx, gpix,
							   false, 0);

	return OMCI_API_SUCCESS;
err:
	if (gpix != 0xffffffff) {
		ret = id_remove(ctx, MAPPER_GEMPORTCTP_MEID_TO_IDX, me_id);
		if (ret != OMCI_API_SUCCESS) {
			(void)error_notify(ctx, 262, me_id,
					   OMCI_API_ACTION_DESTROY, ret);
			return ret;
		}
	}

	return OMCI_API_ERROR;

}

enum omci_api_return
omci_api_gem_port_network_ctp_destroy(struct omci_api_ctx *ctx,
				      uint16_t me_id,
				      uint16_t gem_port_id,
				      uint16_t td_ptr)
{
	enum omci_api_return ret = OMCI_API_ERROR;
	struct gpe_gem_port gem_port;
	uint32_t gpix = 0xffffffff;

	if (index_get(ctx, MAPPER_GEMPORTCTP_MEID_TO_IDX, me_id, &gpix)
		!= OMCI_API_SUCCESS) {
		return OMCI_API_SUCCESS;
	}

	gpix = gpix & 0xFFFF;
	omci_api_gemport_meter_delete(ctx, gpix, me_id, td_ptr);
	omci_api_gemport_shaper_delete(ctx, gpix, td_ptr);
	omci_api_gem_port_us_delete(ctx, gpix);
	omci_api_gem_port_ds_delete(ctx, gpix);

	/* remove gem port */
	gem_port.gem_port_id = gem_port_id;
	dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_GEM_PORT_DELETE,
		&gem_port, sizeof(gem_port));

	ret = id_remove(ctx, MAPPER_GEMPORTCTP_MEID_TO_IDX, me_id);
	if (ret != OMCI_API_SUCCESS) {
		(void)error_notify(ctx, 262, me_id,
				   OMCI_API_ACTION_DESTROY, ret);
		return ret;
	}
	return OMCI_API_SUCCESS;
}

/** @} */
