/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_onu_remote_debug.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_onu_remote_debug.h"

#ifdef INCLUDE_CLI_SUPPORT

/** \addtogroup OMCI_ME_REMOTE_DEBUG
   @{
*/

/** Buffer for command result.

   It should be noted that OLT should not try to execute two or more
   command simultaneously; Only the last command result will be returned.
*/
static char cmd_result[0x8000 - 1] = { 0 };

/** Size of the command result */
static size_t cmd_result_size;

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	char cmd[26];
	char *arg;
	IFXOS_File_t *cli_file;
	enum omci_error ret;

	struct omci_me_onu_remote_debug *upd_data;
	struct omci_me_onu_remote_debug *me_data;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	upd_data = (struct omci_me_onu_remote_debug *) data;
	me_data = (struct omci_me_onu_remote_debug *) me->data;

	if (!me->is_initialized) {
		memset(me_data->cmd, 0, sizeof(me_data->cmd));

		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	/* open memory file for CLI */
	cli_file = IFXOS_FMemOpen(cmd_result, sizeof(cmd_result),
				  IFXOS_OPEN_MODE_WRITE IFXOS_OPEN_MODE_READ);
	if (!cli_file) {
		me_dbg_err(me, "ERROR(%d): Can't open cmd_result with "
			   "IFXOS_FMemOpen", OMCI_ERROR);

		dbg_out_ret(__func__, OMCI_ERROR);
		return OMCI_ERROR;
	}

	/* execute command */
	memcpy(cmd, upd_data->cmd, 25);
	cmd[25] = 0;
	arg = cmd;

	while (*arg) {
		if (*arg == ' ') {
			*arg = 0;
			arg++;
			break;
		}

		arg++;
	}

	if (context->cli_on_exec) {
		ret = context->cli_on_exec(context, cmd, arg, cli_file);
		if (ret != OMCI_SUCCESS) {
			me_dbg_wrn(me, "WARNING command '%s' with "
				   "arguments '%s' execution failed", cmd, arg);
	
		}
	} else {
		me_dbg_wrn(me, "WARNING command '%s' with "
			   "arguments '%s' execution failed, no CLI handler "
			   "installed", cmd, arg);
		ret = OMCI_ERROR;
	}

	if (ret != OMCI_SUCCESS) {
		(void)IFXOS_FMemClose(cli_file);
	
		dbg_out_ret(__func__, OMCI_ERROR);
		return ret;
	}

	(void)IFXOS_FWrite("\0", 1, 1, cli_file);
	(void)IFXOS_FFlush(cli_file);

	cmd_result_size = strlen(cmd_result);

	/* close memory file */
	(void)IFXOS_FMemClose(cli_file);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)init_data, suppress_avc);

	RETURN_IF_PTR_NULL(init_data);

	/* only one instance with id=0 may be created */
	if (me->instance_id != 0) {
		dbg_out_ret(__func__, OMCI_ERROR_INVALID_ME_ID);
		return OMCI_ERROR_INVALID_ME_ID;
	}

	error = me_data_write(context, me, init_data,
			      me->class->data_size,
			      ~me->class->inv_attr_mask, suppress_avc);
	RETURN_IF_ERROR(error);

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_tbl_copy(struct omci_context *context,
				   struct me *me,
				   unsigned int attr,
				   struct tbl_copy_entry *tbl_copy)
{
	enum omci_error error = OMCI_SUCCESS;

	dbg_in(__func__, "%p, %p, %u, %p", (void *)context, (void *)me, attr,
	       (void *)tbl_copy);

	switch (attr) {
	case 3:
		tbl_copy->free_data = false;
		tbl_copy->data = (uint8_t *)cmd_result;
		tbl_copy->data_size = cmd_result_size;
		break;

	default:
		error = OMCI_ERROR_INVALID_ME_ATTR;
		break;
	}

	dbg_out_ret(__func__, error);
	return error;
}

static uint16_t cmd_format_cp[] = { 0 };

/** Managed Entity class */
struct me_class me_onu_remote_debug_class = {
	/* Class ID */
	OMCI_ME_ONU_REMOTE_DEBUG,
	/* Attributes */
	{
		/* 1. Command Format */
		ATTR_ENUM("Command format",
			  ATTR_SUPPORTED,
			  cmd_format_cp,
			  offsetof(struct omci_me_onu_remote_debug,
				   cmd_format),
			  1,
			  OMCI_ATTR_PROP_RD,
			  NULL),
		/* 2. Command */
		ATTR_STR("Command",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_onu_remote_debug,
				  cmd),
			 25,
			 OMCI_ATTR_PROP_WR,
			 NULL),
		/* 3. Reply Table */
		ATTR_TBL("Reply table",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_onu_remote_debug,
				  cmd_format),
			 1,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 4-16. Doesn't exist */
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF(),
		ATTR_NOT_DEF()
	},
	/* Actions */
	{
		NULL, NULL, NULL, NULL,
		/* Create */
		NULL,
		NULL,
		/* Delete */
		NULL,
		NULL,
		/* Set */
		set_action_handle,
		/* Get */
		get_action_handle,
		NULL,
		/* Get all alarms */
		NULL,
		/* Get all alarms next */
		NULL,
		/* MIB upload */
		NULL,
		/* MIB upload next */
		NULL,
		/* MIB reset */
		NULL,
		/* Alarm */
		NULL,
		/* Attribute value change */
		NULL,
		/* Test */
		NULL,
		/* Start SW download */
		NULL,
		/* Download section */
		NULL,
		/* End SW download */
		NULL,
		/* Activate software */
		NULL,
		/* Commit software */
		NULL,
		/* Synchronize Time */
		NULL,
		/* Reboot */
		NULL,
		/* Get next */
		get_next_action_handle,
		/* Test result */
		NULL,
		/* Get current data */
		NULL
	},
	/* Init Handler */
	me_init,
	/* Shutdown Handler */
	NULL,
	/* Validate Handler */
	NULL,
	/* Update Handler */
	me_update,
	/* Table Attribute Copy Handler */
	me_tbl_copy,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	NULL,
	/* Thresholds set Handler */
	NULL,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_me_onu_remote_debug),
	/* Properties */
	OMCI_ME_PROP_NO_UPLOAD | OMCI_ME_PROP_REVIEW,
#  ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"ONU remote debug",
		/* Access */
		ME_CREATED_BY_ONT,
		/* Supported alarms */
		NULL,
		/* Supported alarms count */
		0,
		/* Support */
		ME_SUPPORTED
	},
#  endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */

#endif
