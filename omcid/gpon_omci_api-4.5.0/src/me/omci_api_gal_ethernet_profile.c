/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_gal_ethernet_profile.h"

/** \addtogroup OMCI_API_ME_GAL_ETHERNET_PROFILE

   @{
*/

static uint16_t gn_gem_payload_size_max = 4095;

enum omci_api_return
omci_api_gal_ethernet_profile_update(struct omci_api_ctx *ctx,
				     uint16_t me_id,
				     uint16_t gem_payload_size_max)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gpe_cfg gpe_cfg;

	if (gem_payload_size_max > gn_gem_payload_size_max)
		return ret;
	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_CFG_GET,
		      &gpe_cfg, sizeof(gpe_cfg));
	if (ret == OMCI_API_SUCCESS)
		return ret;

	gpe_cfg.gem_payload_size_max = gem_payload_size_max;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_CFG_SET,
		      &gpe_cfg, sizeof(gpe_cfg));
	if (ret == OMCI_API_SUCCESS)
		gn_gem_payload_size_max = gem_payload_size_max;

	return ret;
}

enum omci_api_return
omci_api_gal_ethernet_profile_destroy(struct omci_api_ctx *ctx,
				      uint16_t me_id)
{
	return OMCI_API_SUCCESS;
}

/** @} */
