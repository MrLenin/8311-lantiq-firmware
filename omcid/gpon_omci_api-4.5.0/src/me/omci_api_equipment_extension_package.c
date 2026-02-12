/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_equipment_extension_package.h"

/** \addtogroup OMCI_API_ME_EQUIPMENT_EXTENSION_PACKAGE

   @{
*/

enum omci_api_return
omci_api_equipment_extension_package_create(struct omci_api_ctx *ctx,
					    uint16_t me_id,
					    uint16_t environmental_sense,
					    uint16_t contact_closure_output)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   environmental_sense=%u\n"
		  "   contact_closure_output=%u\n",
		  __FUNCTION__,
		  me_id, environmental_sense, contact_closure_output));

	/** \todo related HW values need to be identified */

	return ret;
}

enum omci_api_return
omci_api_equipment_extension_package_destroy(struct omci_api_ctx *ctx,
					     uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

   /** \todo add implementation */

	return ret;
}

enum omci_api_return
omci_api_equipment_extension_package_update(struct omci_api_ctx *ctx,
					    uint16_t me_id,
					    uint16_t environmental_sense,
					    uint16_t contact_closure_output)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   environmental_sense=%u\n"
		  "   contact_closure_output=%u\n",
		  __FUNCTION__,
		  me_id, environmental_sense, contact_closure_output));

	/** \todo related HW values need to be identified */

	return ret;
}

/** @} */
