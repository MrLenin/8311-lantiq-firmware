/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "omci_api_common.h"
#include "omci_api_debug.h"
#include "me/omci_api_olt_g.h"

/** \addtogroup OMCI_API_ME_OLT_G

   @{
*/

enum omci_api_return omci_api_olt_g_update(struct omci_api_ctx *ctx,
					   uint16_t me_id,
					   uint32_t multiframe_count,
					   uint32_t tod_extended_seconds,
					   uint32_t tod_seconds,
					   uint32_t tod_nano_seconds)
{
	struct gpe_tod_sync tod_sync;
	enum omci_api_return ret = OMCI_API_SUCCESS;

	DBG(OMCI_API_MSG, ("%s\n"
		  "   me_id=%u\n"
		  "   multiframe_count=%u\n"
		  "   tod_extended_seconds=%u\n"
		  "   tod_seconds=%u\n"
		  "   tod_nano_seconds=%u\n",
		  __FUNCTION__,
		  me_id,
		  multiframe_count,
		  tod_extended_seconds, tod_seconds, tod_nano_seconds));

	tod_sync.multiframe_count = multiframe_count;
	tod_sync.tod_seconds = tod_seconds;
	tod_sync.tod_extended_seconds = (uint16_t)tod_extended_seconds;
	tod_sync.tod_nano_seconds = tod_nano_seconds;

	ret = dev_ctl(ctx->remote, ctx->onu_fd, FIO_GPE_TOD_SYNC_SET,
		      &tod_sync, sizeof(tod_sync));
	if (ret != OMCI_API_SUCCESS)
		return ret;

	return OMCI_API_SUCCESS;
}

/** @} */
