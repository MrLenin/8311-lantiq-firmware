/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_onu2_g.h"

/** \addtogroup OMCI_API_ME_ONU2_G

   @{
*/

#if 0 

/* place holder
   - currently all values are readonly
   - the sys uptime is reported directly from the omci stack
*/

enum omci_api_return omci_api_onu2_g_create(struct omci_api_ctx *ctx,
					    uint16_t me_id,
					    uint8_t security_mode)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   security_mode=%u\n",
		  __FUNCTION__, me_id, security_mode));

	/** \todo add implementation. */

	return ret;
}

enum omci_api_return omci_api_onu2_g_destroy(struct omci_api_ctx *ctx,
					     uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	/** \todo add implementation. */

	return ret;
}

enum omci_api_return omci_api_onu2_g_update(struct omci_api_ctx *ctx,
					    uint16_t me_id,
					    uint8_t security_mode)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   security_mode=%u\n",
		  __FUNCTION__, me_id, security_mode));

	/** \todo Related HW values should be defined. */

	return ret;
}
#endif

/** @} */
