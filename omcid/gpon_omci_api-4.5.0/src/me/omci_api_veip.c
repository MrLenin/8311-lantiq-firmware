/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_api_veip.c
   v7.5.1 Virtual Ethernet Interface Point API — mapper registration
   and port lock/unlock for VEIP.

   Reverse-engineered from stock omcid v7.5.1:
     FUN_0043fa50 = omci_api_veip_create  (uni2lan + explicit_map 0x1e)
     FUN_0043fabc = omci_api_veip_destroy (id_remove 0x1e)
     FUN_0043f1a8 = lock_port   (index_get + lan_port_enable 0)
     FUN_0043f25c = unlock_port (index_get + lan_port_enable 1)
*/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_veip.h"
#include "me/omci_api_table_access.h"

enum omci_api_return
omci_api_veip_create(struct omci_api_ctx *ctx,
		     uint16_t me_id)
{
	enum omci_api_return ret;
	uint8_t lan_port;

	DBG(OMCI_API_MSG, ("%s me_id=%u\n", __FUNCTION__, me_id));

	ret = omci_api_uni2lan(ctx, me_id, &lan_port);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("%s uni2lan failed for me_id=%u, ret=%d\n",
			 __FUNCTION__, me_id, ret));
		return ret;
	}

	ret = explicit_map(ctx, MAPPER_VEIP_MEID_TO_IDX,
			   me_id, lan_port);
	if (ret != OMCI_API_SUCCESS) {
		DBG(OMCI_API_ERR,
			("%s explicit_map failed, ret=%d\n",
			 __FUNCTION__, ret));
		return ret;
	}

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_veip_destroy(struct omci_api_ctx *ctx,
		      uint16_t me_id)
{
	DBG(OMCI_API_MSG, ("%s me_id=%u\n", __FUNCTION__, me_id));

	return id_remove(ctx, MAPPER_VEIP_MEID_TO_IDX, me_id);
}

enum omci_api_return
omci_api_veip_lock(struct omci_api_ctx *ctx,
		   uint16_t me_id)
{
	enum omci_api_return ret;
	uint32_t lan_port;

	ret = index_get(ctx, MAPPER_VEIP_MEID_TO_IDX, me_id, &lan_port);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return omci_api_lan_port_enable(ctx, lan_port, 0);
}

enum omci_api_return
omci_api_veip_unlock(struct omci_api_ctx *ctx,
		     uint16_t me_id)
{
	enum omci_api_return ret;
	uint32_t lan_port;

	ret = index_get(ctx, MAPPER_VEIP_MEID_TO_IDX, me_id, &lan_port);
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return omci_api_lan_port_enable(ctx, lan_port, 1);
}
