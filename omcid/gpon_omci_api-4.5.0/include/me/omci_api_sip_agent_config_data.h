/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_api_me_sip_agent_config_data
#define _omci_api_me_sip_agent_config_data

#include "omci_api.h"

__BEGIN_DECLS

/** \addtogroup OMCI_API_ME

   @{
*/

/** \defgroup OMCI_API_ME_SIP_AGENT_CONFIG_DATA SIP agent config data

    The SIP agent config data managed entity models a SIP signalling agent. It
    defines the configuration necessary to establish communication for
    signalling between the SIP user agent and a SIP server.

    Note – If a non-OMCI interface is used to manage SIP for VoIP, this ME is
    unnecessary. The non-OMCI interface supplies the necessary data, which may
    be read back to the OLT via the SIP config portal ME.

    Instances of this managed entity are created and deleted by the OLT.

   @{
*/

/** Update SIP agent config data ME resources

   \param[in] ctx                   OMCI API context pointer
   \param[in] me_id                 Managed Entity identifier
   \param[in] proxy_addr            Proxy server address pointer
   \param[in] primary_dns           Primary SIP DNS
   \param[in] secondary_dns         Secondary SIP DNS
   \param[in] agent_ip              SIP agent IP (taken from linked TCP/UDP
                                    pointer)
   \param[in] agent_proto           SIP signaling protocol (taken from linked
                                    TCP/UDP pointer)
   \param[in] agent_port            SIP agent port (taken from linked TCP/UDP
                                    pointer)
   \param[in] reg_exp_time          SIP reg exp time
   \param[in] rereg_head_start      SIP rereg head start time
   \param[in] host_part_uri         Host part URI
   \param[in] registrar             SIP registrar
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
				      char *registrar);

/** Cleanup SIP agent config data ME resources

   \param[in] ctx                   OMCI API context pointer
   \param[in] me_id                 Managed Entity identifier
*/
enum omci_api_return
omci_api_sip_agent_config_data_destroy(struct omci_api_ctx *ctx,
				       uint16_t me_id);

/** Retrieve SIP status

   \param[in]  ctx    OMCI API context pointer
   \param[in]  me_id  Managed Entity identifier
   \param[out] status SIP status
*/
enum omci_api_return
omci_api_sip_status_get(struct omci_api_ctx *ctx,
			uint16_t me_id,
			uint8_t *status);

/** @} */

/** @} */

__END_DECLS

#endif
