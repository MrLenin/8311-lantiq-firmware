/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
 *  \file omci_config_api.c
 *
 *  Config API for LOID/LPWD credential getters and interface-to-ME mapping.
 *
 *  The shipping v7.5.1 binary uses context->uboot_get() callbacks passed
 *  at init time to read firmware environment variables. Our implementation
 *  reads them directly via popen("fw_printenv"), consistent with the rest
 *  of our codebase.
 *
 *  Shipping functions: FUN_0040a4ac (omci_cfg_logical_onu_id_get, 70B)
 *                      FUN_0040a504 (omci_cfg_logical_password_get, 70B)
 */

#define OMCI_DBG_MODULE OMCI_DBG_MODULE_CORE

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_config_api.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

/** Read a firmware environment variable via fw_printenv.
 *
 *  Returns 0 on success, -1 if not found or error.
 */
static int fwenv_read(const char *name, char *value, size_t value_size)
{
	FILE *fp;
	char cmd[128];
	char buf[256];
	char *ptr;
	size_t len;

	if (snprintf(cmd, sizeof(cmd), "fw_printenv %s 2>/dev/null", name)
	    >= (int)sizeof(cmd))
		return -1;

	fp = popen(cmd, "r");
	if (!fp)
		return -1;

	len = fread(buf, 1, sizeof(buf) - 1, fp);
	(void)pclose(fp);

	if (len == 0)
		return -1;

	buf[len] = '\0';

	/* fw_printenv output is "name=value\n" — find the '=' */
	ptr = strchr(buf, '=');
	if (!ptr)
		return -1;
	ptr++;

	/* strip trailing newline */
	len = strlen(ptr);
	if (len > 0 && ptr[len - 1] == '\n')
		ptr[len - 1] = '\0';

	strncpy(value, ptr, value_size);
	return 0;
}

enum omci_error omci_cfg_logical_onu_id_get(struct omci_context *context,
					    struct me *me,
					    void *data,
					    size_t data_size)
{
	char loid[256];

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       data, data_size);

	assert(data_size == OMCI_CFG_LOID_LEN);

	if (fwenv_read(OMCI_CFG_UBOOT_LOID_NAME, loid, sizeof(loid)) == 0) {
		strncpy(data, loid, OMCI_CFG_LOID_LEN);
	}
	/* If not found, return success with existing (zeroed) data — matches
	 * shipping behavior where -0x10 (RESOURCE_NOT_FOUND) maps to 0 */

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

enum omci_error omci_cfg_logical_password_get(struct omci_context *context,
					      struct me *me,
					      void *data,
					      size_t data_size)
{
	char lpwd[256];

	dbg_in(__func__, "%p, %p, %p, %lu", (void *)context, (void *)me,
	       data, data_size);

	assert(data_size == OMCI_CFG_LPWD_LEN);

	if (fwenv_read(OMCI_CFG_UBOOT_LPWD_NAME, lpwd, sizeof(lpwd)) == 0) {
		strncpy(data, lpwd, OMCI_CFG_LPWD_LEN);
	}

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

uint16_t omci_cfg_ip_host_me_id_get(const char *ifname)
{
	if (strcmp(ifname, "host") == 0)
		return 0;
	else if (strcmp(ifname, "lan") == 0)
		return 1;
	else
		return 0xFFFF;
}
