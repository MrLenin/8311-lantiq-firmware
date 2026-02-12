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
#include "me/omci_api_sip_user_data.h"

#ifdef INCLUDE_OMCI_API_VOIP

/** \addtogroup OMCI_API_ME_SIP_USER_DATA

   @{
*/

enum omci_api_return
omci_api_sip_user_data_update(struct omci_api_ctx *ctx,
			      uint16_t me_id,
			      uint16_t agent_ptr,
			      char *user_part_aor,
			      char *username,
			      char *password,
			      char *realm,
			      uint8_t validation_scheme,
			      uint16_t pptp_ptr,
			      uint32_t ip_addr)
{
	enum omci_api_return ret;
	uint32_t usr_idx, agt_idx;
	struct sip_user usr;

#if 0
	printf("%s:\n"
	       "\tagent_ptr=0x%x\n"
	       "\tuser_part_aor=%s\n"
	       "\tusername=%s\n"
	       "\tpassword=%s\n"
	       "\tpptp_ptr=0x%x\n",
	       __FUNCTION__,
	       agent_ptr,
	       user_part_aor,
	       username,
	       password,
	       pptp_ptr);
#endif

	ret = index_get(ctx, MAPPER_SIP_AGT_TO_IDX, agent_ptr, &agt_idx);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	ret = index_get(ctx, MAPPER_SIP_USR_TO_IDX, me_id, &usr_idx);
	if (ret != OMCI_API_SUCCESS) {
		ret = id_map(ctx, MAPPER_SIP_USR_TO_IDX, me_id, &usr_idx);
		if (ret != OMCI_API_SUCCESS)
			return ret; /* no free sip users */
	}

#if 0
	printf("%s: using agt_idx=%u, usr_idx=%u\n", __FUNCTION__,
	       agt_idx, usr_idx);
#endif

	ret = omci_api_voip_user_cfg_get(ctx, usr_idx, &usr);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	strcpy(usr.username, username);
	strcpy(usr.password, password);

	usr.user_ip = ip_addr;

	if (validation_scheme == 0) {
		strcpy(usr.realm, "*");
	} else if (validation_scheme == 1) {
		strcpy(usr.realm, realm);
	} else {
		DBG(OMCI_API_ERR, ("sip: unsupported validation_scheme=%u\n",
			validation_scheme));
		return OMCI_API_ERROR;
	}

	ret = omci_api_voip_user_cfg_set(ctx, usr_idx, &usr);
	if (ret != OMCI_API_SUCCESS)
		return ret;
	
	if (usr.user_ip && strlen(usr.username))
		if (omci_api_voip_user_register(ctx, usr_idx)
							!= OMCI_API_SUCCESS)
			DBG(OMCI_API_WRN, ("sip: user %s register failed\n",
								usr.username));

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_sip_user_data_destroy(struct omci_api_ctx *ctx,
			       uint16_t me_id)
{
	return OMCI_API_SUCCESS;
}

/** @} */

#endif
