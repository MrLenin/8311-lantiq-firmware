/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include <stdio.h>
#ifdef LINUX
#include <unistd.h>
#endif

#define OMCI_DBG_MODULE OMCI_DBG_MODULE_CORE

#include "omci_core.h"
#include "omci_debug.h"

/** \addtogroup OMCI_DEBUG
   @{
*/

#ifndef OMCI_DEBUG_DISABLE
struct dbg_module_level dbg_modules[OMCI_DBG_MODULE_NUM] =
{
	/* OMCI_DBG_MODULE_NO */
	{ OMCI_DBG_OFF, "-    " },

	/* OMCI_DBG_MODULE_CORE */
	{ OMCI_DBG_PRN, "CORE " },

	/* OMCI_DBG_MODULE_API */
	{ OMCI_DBG_PRN, "API  " },

	/* OMCI_DBG_MODULE_MIB */
	{ OMCI_DBG_PRN, "MIB  " },

	/* OMCI_DBG_MODULE_ME */
	{ OMCI_DBG_PRN, "ME   " },

	/* OMCI_DBG_MODULE_MSG_DUMP */
	{ OMCI_DBG_OFF, "MSG  " },

	/* OMCI_DBG_MODULE_PM */
	{ OMCI_DBG_PRN, "PM   " },

	/* OMCI_DBG_MODULE_MIB_RESET */
	{ OMCI_DBG_OFF, "MIBRS" },

	/* OMCI_DBG_MODULE_IFXOS */
	{ OMCI_DBG_OFF, "IFXOS" },

	/* OMCI_DBG_MODULE_VOIP */
	{ OMCI_DBG_OFF, "VOIP" }
};

char *dbg_levels[OMCI_DBG_LVL_NUM] = {
	/* OMCI_DBG_MSG */
	"MSG",

	/* OMCI_DBG_PRN */
	"PRN",

	/* OMCI_DBG_WRN */
	"WRN",

	/* OMCI_DBG_ERR */
	"ERR",

	/* OMCI_DBG_OFF */
	"OFF",
};

void omci_hook(void *context, const char *cmd, const uint32_t class_id,
	       const uint32_t instance_id)
{
	char run[64];
	(void)context;
	sprintf(run, "/opt/lantiq/bin/omci_hook.sh %s %d %d",
						   cmd, class_id, instance_id);
	system(run);
}

#endif

/** @} */
