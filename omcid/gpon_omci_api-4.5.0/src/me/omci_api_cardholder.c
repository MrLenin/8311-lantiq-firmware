/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_cardholder.h"

/** \addtogroup OMCI_API_ME_CARDHOLDER

@{
*/

enum omci_api_return
omci_api_cardholder_create(struct omci_api_ctx *ctx,
			   uint16_t me_id,
			   uint8_t expected_plug_in_unit_type,
			   uint8_t expected_port_count,
			   const uint8_t expected_equipment_id
			   [OMCI_API_CARDHOLDER_EQUIPMENTID_SIZE],
			   uint8_t invoke_protection_switch)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   expected_plug_in_unit_type=%u\n"
		  "   expected_port_count=%u\n"
		  "   expected_equipment_id=(too long)\n"
		  "   invoke_protection_switch=%u\n",
		  __FUNCTION__,
		  me_id,
		  expected_plug_in_unit_type,
		  expected_port_count, invoke_protection_switch));

	return ret;
}

enum omci_api_return omci_api_cardholder_destroy(struct omci_api_ctx *ctx,
						 uint16_t me_id)
{
	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	return OMCI_API_SUCCESS;
}

enum omci_api_return
omci_api_cardholder_update(struct omci_api_ctx *ctx,
			   uint16_t me_id,
			   uint8_t expected_plug_in_unit_type,
			   uint8_t expected_port_count,
			   const uint8_t expected_equipment_id
			   [OMCI_API_CARDHOLDER_EQUIPMENTID_SIZE],
			   uint8_t invoke_protection_switch)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   expected_plug_in_unit_type=%u\n"
		  "   expected_port_count=%u\n"
		  "   expected_equipment_id=(too long)\n"
		  "   invoke_protection_switch=%u\n",
		  __FUNCTION__,
		  me_id,
		  expected_plug_in_unit_type,
		  expected_port_count, invoke_protection_switch));

	return ret;
}

/** @} */
