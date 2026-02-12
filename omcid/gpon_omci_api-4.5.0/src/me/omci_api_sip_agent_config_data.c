/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include <assert.h>

#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_sip_agent_config_data.h"

#ifdef INCLUDE_OMCI_API_VOIP

/** \addtogroup OMCI_API_ME_SIP_AGENT_CONFIG_DATA

   @{
*/

enum omci_api_return
omci_api_sip_agent_config_data_update(struct omci_api_ctx *ctx,
				      uint16_t me_id,
				      char *proxy_addr,
				      uint32_t primary_dns,
				      uint32_t secondary_dns,
				      uint32_t agent_ip,
				      uint32_t agent_proto,
				      uint32_t agent_port,
				      uint32_t reg_exp_time,
				      uint32_t rereg_head_start,
				      char *host_part_uri,
				      char *registrar)
{
	enum omci_api_return ret;
	uint32_t agt_idx;
	struct sip_agent agt;

#if 0
	printf("%s:\n"
	       "\tproxy_addr=%s\n"
	       "\tpr_dns=0x%x\n"
	       "\tsec_dns=0x%x\n"
	       "\tagent_ip=0x%x\n"
	       "\tagent_proto=0x%x\n"
	       "\tagent_port=0x%x\n"
	       "\treg_exp_time=0x%x\n"
	       "\trereg_head_start=0x%x\n"
	       "\thost_port_uri=%s\n"
	       "\tregistrar=%s\n",
	       __FUNCTION__,
	       proxy_addr,
	       primary_dns,
	       secondary_dns,
	       agent_ip,
	       agent_proto,
	       agent_port,
	       reg_exp_time,
	       rereg_head_start,
	       host_part_uri,
	       registrar);
#endif

	ret = index_get(ctx, MAPPER_SIP_AGT_TO_IDX, me_id, &agt_idx);
	if (ret != OMCI_API_SUCCESS) {
		ret = id_map(ctx, MAPPER_SIP_AGT_TO_IDX, me_id, &agt_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret; /* no free sip agents */
	}

#if 0
	printf("%s: using agt_idx=%u\n", __FUNCTION__, agt_idx);
#endif

	if (agent_proto == 0 && agent_ip == 0 && agent_port == 0)
		return OMCI_API_SUCCESS;

	ret = omci_api_voip_agent_cfg_get(ctx, &agt);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	agt.agent_ip = agent_ip;
	agt.agent_proto = agent_proto;
	agt.agent_port = agent_port;
	strncpy(agt.registrar, registrar, sizeof(agt.registrar));
	strncpy(agt.proxy, proxy_addr, sizeof(agt.proxy));
	agt.reg_exp_time = reg_exp_time;

	ret = omci_api_voip_agent_cfg_set(ctx, &agt);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return omci_api_voip_agent_update(ctx);
}

enum omci_api_return
omci_api_sip_agent_config_data_destroy(struct omci_api_ctx *ctx,
				       uint16_t me_id)
{
	enum omci_api_return ret;
	uint32_t agt_idx;

	ret = index_get(ctx, MAPPER_SIP_AGT_TO_IDX, me_id, &agt_idx);
	if (ret != OMCI_API_SUCCESS)
		return OMCI_API_SUCCESS;

	(void)index_remove(ctx, MAPPER_SIP_AGT_TO_IDX, agt_idx);

	return omci_api_voip_agent_destroy(ctx);
}

enum omci_api_return
omci_api_sip_status_get(struct omci_api_ctx *ctx,
			uint16_t me_id,
			uint8_t *status)
{
	return OMCI_API_SUCCESS;
}

/** @} */

#endif
