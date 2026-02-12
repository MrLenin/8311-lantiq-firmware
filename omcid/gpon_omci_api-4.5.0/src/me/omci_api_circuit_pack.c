/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_circuit_pack.h"

/** \addtogroup OMCI_API_ME_CIRCUIT_PACK

   @{
*/

enum omci_api_return
omci_api_circuit_pack_create(struct omci_api_ctx *ctx,
			     uint16_t me_id,
			     uint8_t type,
			     uint8_t port_num,
			     uint8_t bridged_or_ip_ind,
			     uint8_t card_configuration,
			     uint32_t power_shed_override)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   type=%u\n"
		  "   port_num=%u\n"
		  "   bridged_or_ip_ind=%u\n"
		  "   card_configuration=%u\n"
		  "   power_shed_override=%u\n",
		  __FUNCTION__,
		  me_id,
		  type,
		  port_num, bridged_or_ip_ind, card_configuration,
		  power_shed_override));

	return ret;
}

enum omci_api_return omci_api_circuit_pack_destroy(struct omci_api_ctx *ctx,
						   uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	return ret;
}

enum omci_api_return omci_api_circuit_pack_update(struct omci_api_ctx *ctx,
						  uint16_t me_id,
						  uint8_t bridged_or_ip_ind,
						  uint8_t card_configuration,
						  uint32_t power_shed_override)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   bridged_or_ip_ind=%u\n"
		  "   card_configuration=%u\n"
		  "   power_shed_override=%u\n",
		  __FUNCTION__,
		  me_id, bridged_or_ip_ind, card_configuration,
		  power_shed_override));

	return ret;
}

/** @} */
