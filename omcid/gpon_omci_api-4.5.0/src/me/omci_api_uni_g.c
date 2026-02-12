/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_uni_g.h"

/** \addtogroup OMCI_API_ME_UNI_G

   @{
*/

enum omci_api_return omci_api_uni_g_create(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint16_t config_option_status)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   config_option_status=%u\n",
		  __FUNCTION__, me_id, config_option_status));

	/** \todo add implementation of Me ID mapping to driver Index */
	/** \todo Related HW registers should be defined. */

	return ret;
}

enum omci_api_return omci_api_uni_g_destroy(struct omci_api_ctx *ctx,
					    uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	/** \todo add implementation of Me ID mapping to driver Index */
	/** \todo Related HW registers should be defined. */

	return ret;
}

enum omci_api_return omci_api_uni_g_update(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint16_t config_option_status)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   config_option_status=%u\n",
		  __FUNCTION__, me_id, config_option_status));

	/** \todo Related HW registers should be defined. */

	return ret;
}

/** @} */
