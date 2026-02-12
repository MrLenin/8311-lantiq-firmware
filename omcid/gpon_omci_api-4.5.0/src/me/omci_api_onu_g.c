/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_onu_g.h"

/** \addtogroup OMCI_API_ME_ONU_G

   @{
*/

enum omci_api_return omci_api_onu_g_serial_number_get(struct omci_api_ctx *ctx,
						       uint16_t me_id,
						       uint8_t *serial_number)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;
	struct gtc_serial_num serial;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GTC_SERIAL_NUMBER_GET,
		      &serial, sizeof(serial));

	if (ret == OMCI_API_SUCCESS)
		memcpy(serial_number, &serial, 8);

	return ret;
}

enum omci_api_return omci_api_onu_g_create(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint8_t battery_backup,
					   uint8_t traff_mgmt_opt)
{
	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   battery_backup=%u\n",
		  __FUNCTION__, me_id, battery_backup));

	return omci_api_onu_g_update(ctx, me_id, battery_backup,
				     traff_mgmt_opt);
}

enum omci_api_return omci_api_onu_g_destroy(struct omci_api_ctx *ctx,
					    uint16_t me_id)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n" "   me_id=%u\n", __FUNCTION__, me_id));

	/** \todo add implementation. */

	return ret;
}

enum omci_api_return omci_api_onu_g_update(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint8_t battery_backup,
					   uint8_t traff_mgmt_opt)
{
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n" "   battery_backup=%u\n",
		  __FUNCTION__, me_id, battery_backup));

	ctx->traff_mgmt_opt = traff_mgmt_opt;

	/** \todo Related HW values should be defined. */

	return ret;
}

/** @} */
