/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_std_defs.h"
#include "drv_onu_error.h"
#include "drv_onu_interface.h"
#include "drv_onu_api.h"
#include "drv_onu_cli_core.h"
#include "drv_onu_common_interface.h"
#include "drv_onu_ploam_interface.h"
#include "drv_onu_ploam_api.h"
#include "drv_onu_gtc_interface.h"
#include "drv_onu_gtc_api.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_gpe_api.h"
#include "drv_onu_gpe_tables_interface.h"
#include "drv_onu_gpe_tables_api.h"
#include "drv_onu_lan_interface.h"
#include "drv_onu_lan_api.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_event_api.h"
#include "drv_onu_tse_config.h"
#include "drv_onu_ll_sce.h"

#ifdef INCLUDE_CLI_SUPPORT

extern int onu_cli_check_help(
	const char *p_cmd,
	const char *p_usage,
	const uint32_t bufsize_max,
	char *p_out);

/** \addtogroup ONU_CLI_COMMANDS
   @{
*/

/** Generic handler for table set/get/read/write/add/delete commands

   \param[in] usage     Command help information
   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
   \param[in] set       Hander intended for set-like (set/write/add/delete)
                        operations
   \param[in] get       Hander intended for get-like (get/read) operations
*/
static int cli_gpe_table_op(
	const char *usage,
	struct onu_device *p_dev,
	bool get_instance,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out,
	enum onu_errorcode (*set)(struct onu_device *p_dev,
				  struct gpe_table_entry *param),
	enum onu_errorcode (*get)(struct onu_device *p_dev,
				  const struct gpe_table *in,
				  struct gpe_table_entry *out),
	bool input_data)
{
	int ret = 0;
	uint32_t i;
	enum onu_errorcode fct_ret = (enum onu_errorcode) 0;
	uint32_t data_count = 0;
	uint32_t *data;
	union gpe_table_entry_u entry;
	char copybuf[255];
	char *str;
	char *tok;

	if ((ret = onu_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0)
		return ret;

	strncpy(copybuf, p_cmd, sizeof(copybuf));
	str = copybuf;

	memset(&entry, 0, sizeof(entry));

	if (get_instance) {
		/* instance */
		tok = onu_strsep(&str, " ");
		if (!tok)
			return onu_cli_check_help("-h", usage, bufsize_max, p_out);
		entry.in.instance = onu_strtoul(tok, NULL, 10);
	}
	/* id */
	tok = onu_strsep(&str, " ");
	if (!tok)
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);

	entry.in.id = onu_strtoul(tok, NULL, 10);

	/* index */

	tok = onu_strsep(&str, " ");
	if (!tok)
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);

	entry.in.index = onu_strtoul(tok, NULL, 10);

	tok = onu_strsep(&str, " ");

	if (input_data && tok) {
		/* data_count */

		data_count = onu_strtoul(tok, NULL, 10);

		if (data_count > sizeof(union gpe_table_data) / 4)
			return onu_cli_check_help("-h", usage, bufsize_max,
						  p_out);

		/* data */

		data = (uint32_t *)&entry.in.data;

		for (i = 0; i < data_count; i++) {
			tok = onu_strsep(&str, " ");
			if (!tok)
				return onu_cli_check_help("-h", usage,
							  bufsize_max, p_out);

			data[i] = onu_strtoul(tok, NULL, 10);
		}
	}

	/* COP tables require key for GET command; ensure that we get it */
	if (get == gpe_table_entry_get && !GPE_IS_PE_TABLE(entry.in.id))
		if (data_count == 0 && cop_tbl_cfg[entry.in.id].key_len)
			return sprintf(p_out, "Key data is not specified!");

	if (set) {
		if (get_instance == false)
			entry.in.instance = 255;

		fct_ret = set(p_dev, (struct gpe_table_entry*)&entry);

		return sprintf(p_out, "errorcode=%d" ONU_CRLF, (int)fct_ret);
	} else if (get) {
		if (get_instance == false) {
			if (GPE_IS_PE_TABLE(entry.in.id)) {
			entry.in.instance = 1;
			}
			else {
				entry.in.instance = 0;
			}
		}

		fct_ret = get(p_dev, &entry.in, &entry.out);

		if (fct_ret)
			return sprintf(p_out, "errorcode=%d" ONU_CRLF,
				       (int)fct_ret);

		ret = sprintf(p_out, "errorcode=%d data=", (int)fct_ret);

		if (GPE_IS_PE_TABLE(entry.out.id))
			data_count = pe_tbl_cfg[GPE_TABLE_ID(entry.out.id)].
				entry_width / 32;
		else
			data_count = cop_tbl_cfg[entry.out.id].entry_width / 32;

		/* workaround for bit fields and other small PE tables */
		if (data_count == 0)
			data_count = 1;

		data = (uint32_t *)&entry.out.data;

		for (i = 0; i < data_count; i++)
			ret += sprintf(ret + p_out, "%08x ", data[i]);

		return ret + sprintf(ret + p_out, ONU_CRLF);
	} else {
		return sprintf(p_out, "errorcode=%d" ONU_CRLF, (int)-1);
	}
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_table_set(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_table_set" ONU_CRLF
		"Short Form: gpets" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t data_count" ONU_CRLF
		"- uint32_t data_word[8]" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, false, p_cmd, bufsize_max, p_out,
				gpe_table_entry_set,
				NULL,
				true);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_table_get(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_table_get" ONU_CRLF
		"Short Form: gpetg" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t data_count (optional)" ONU_CRLF
		"- uint32_t data_word[8] (optional)" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, false, p_cmd, bufsize_max, p_out,
				NULL,
				gpe_table_entry_get,
				true);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_pe_table_set(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_pe_table_set" ONU_CRLF
		"Short Form: gpets" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t instance" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t data_count" ONU_CRLF
		"- uint32_t data_word[8]" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, true, p_cmd, bufsize_max, p_out,
				gpe_table_entry_set,
				NULL,
				true);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_pe_table_get(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_table_get" ONU_CRLF
		"Short Form: gpetg" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t instance" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t data_count (optional)" ONU_CRLF
		"- uint32_t data_word[8] (optional)" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, true, p_cmd, bufsize_max, p_out,
				NULL,
				gpe_table_entry_get,
				true);
}
/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_table_write(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_table_write" ONU_CRLF
		"Short Form: gpetw" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t data_count" ONU_CRLF
		"- uint32_t data_word[8]" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, false, p_cmd, bufsize_max, p_out,
				gpe_table_entry_write,
				NULL,
				true);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_table_read(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_table_read" ONU_CRLF
		"Short Form: gpetr" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, false, p_cmd, bufsize_max, p_out,
				NULL,
				gpe_table_entry_read,
				false);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_table_add(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_table_add" ONU_CRLF
		"Short Form: gpeta" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t data_count" ONU_CRLF
		"- uint32_t data_word[8]" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, false, p_cmd, bufsize_max, p_out,
				gpe_table_entry_add,
				NULL,
				true);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_table_delete(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_table_delete" ONU_CRLF
		"Short Form: gpetd" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t data_count" ONU_CRLF
		"- uint32_t data_word[8]" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, false, p_cmd, bufsize_max, p_out,
				gpe_table_entry_delete,
				NULL,
				true);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_table_search(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_table_search" ONU_CRLF
		"Short Form: gpesrch" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t data_count" ONU_CRLF
		"- uint32_t data_word[8]" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, false, p_cmd, bufsize_max, p_out,
				gpe_table_entry_search,
				NULL,
				true);
}


/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_short_fwd_add(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_short_fwd_add" ONU_CRLF
		"Short Form: gpesfwda" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t data_count" ONU_CRLF
		"- uint32_t data_word[8]" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, false, p_cmd, bufsize_max, p_out,
				gpe_short_fwd_add,
				NULL,
				true);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_short_fwd_relearn(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: cli_gpe_short_fwd_relearn" ONU_CRLF
		"Short Form: gpesfwdr" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t data_count" ONU_CRLF
		"- uint32_t data_word[8]" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, false, p_cmd, bufsize_max, p_out,
				gpe_short_fwd_relearn,
				NULL,
				true);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_short_fwd_forward(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: cli_gpe_short_fwd_forward" ONU_CRLF
		"Short Form: gpesfwdfwd" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t data_count" ONU_CRLF
		"- uint32_t data_word[8]" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, false, p_cmd, bufsize_max, p_out,
				gpe_short_fwd_forward,
				NULL,
				true);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_short_fwd_delete(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_short_fwd_delete" ONU_CRLF
		"Short Form: gpesfwdd" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t data_count" ONU_CRLF
		"- uint32_t data_word[8]" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, false, p_cmd, bufsize_max, p_out,
				gpe_short_fwd_delete,
				NULL,
				true);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_age_get(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum onu_errorcode fct_ret = (enum onu_errorcode) 0;
	struct gpe_table_entry in;
	struct sce_mac_entry_age out;

#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_age_get" ONU_CRLF
		"Short Form: gpeageg" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t key_word[0]" ONU_CRLF
		"- uint32_t key_word[1]" ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		"- uint16_t age" ONU_CRLF
		"- uint16_t ticks" ONU_CRLF
		ONU_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = onu_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}

	ret = onu_cli_sscanf(p_cmd, "%u %u %u", &in.index, &in.data.message.data[0], &in.data.message.data[1]);
	if (ret != 3) {
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);
	}
	in.id = 10;

	fct_ret = gpe_age_get(p_dev, &in, &out);
	return sprintf(p_out, "errorcode=%d age=%u sec. (ticks=%u)" ONU_CRLF, (int)fct_ret, out.age, out.ticks);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_age(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum onu_errorcode fct_ret = (enum onu_errorcode) 0;
	struct gpe_table_entry in;

#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_age" ONU_CRLF
		"Short Form: gpeage" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = onu_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}

	ret = onu_cli_sscanf(p_cmd, "%u", &in.index);
	if (ret != 1) {
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);
	}
	in.id = 10;

	fct_ret = gpe_age(p_dev, &in);
	return sprintf(p_out, "errorcode=%d" ONU_CRLF, (int)fct_ret);
}


/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_fid_add(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum onu_errorcode fct_ret = (enum onu_errorcode) 0;
	struct gpe_table_entry in;

#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_fid_add" ONU_CRLF
		"Short Form: gpefa" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32t key \n  " ONU_CRLF
		"- uint32_t data \n  " ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = onu_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}
	ret = onu_cli_sscanf(p_cmd, "%u %u", &in.data.message.data[0], &in.data.message.data[1]);

	if (ret != 2) {
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);
	}
	fct_ret = gpe_fid_add(p_dev, &in);
	return sprintf(p_out, "errorcode=%d " ONU_CRLF, (int)fct_ret);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_fid_delete(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum onu_errorcode fct_ret = (enum onu_errorcode) 0;
	struct gpe_table_entry in;

#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_fid_delete" ONU_CRLF
		"Short Form: gpefd" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t key \n  " ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = onu_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}
	ret = onu_cli_sscanf(p_cmd, "%u", &in.data.message.data[0]);
	if (ret != 1) {
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);
	}
	fct_ret = gpe_fid_delete(p_dev, &in);
	return sprintf(p_out, "errorcode=%d " ONU_CRLF, (int)fct_ret);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_long_fwd_add(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum onu_errorcode fct_ret = (enum onu_errorcode) 0;
	struct gpe_table_entry in;

#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_long_fwd_add" ONU_CRLF
		"Short Form: gpelfwda" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32t key[5] \n  " ONU_CRLF
		"- uint32_t data[3] \n  " ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = onu_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}
	ret = onu_cli_sscanf(p_cmd, "%u %u %u %u %u %u %u %u",
			&in.data.message.data[0], &in.data.message.data[1],
			&in.data.message.data[2], &in.data.message.data[3],
			&in.data.message.data[4], &in.data.message.data[5],
			&in.data.message.data[6], &in.data.message.data[7]);

	if (ret != 8) {
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);
	}
	fct_ret = gpe_long_fwd_add(p_dev, &in);
	return sprintf(p_out, "errorcode=%d " ONU_CRLF, (int)fct_ret);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_long_fwd_delete(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum onu_errorcode fct_ret = (enum onu_errorcode) 0;
	struct gpe_table_entry in;

#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_long_fwd_delete" ONU_CRLF
		"Short Form: gpelfwdd" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t key[5] \n  " ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = onu_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}
	ret = onu_cli_sscanf(p_cmd, "%u %u %u %u %u",
			&in.data.message.data[0],
			&in.data.message.data[1],
			&in.data.message.data[2],
			&in.data.message.data[3],
			&in.data.message.data[4]);

	if (ret != 5) {
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);
	}
	fct_ret = gpe_long_fwd_delete(p_dev, &in);
	return sprintf(p_out, "errorcode=%d " ONU_CRLF, (int)fct_ret);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_long_fwd_forward(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: cli_gpe_long_fwd_forward" ONU_CRLF
		"Short Form: gpelfwdfwd" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t id" ONU_CRLF
		"- uint32_t index" ONU_CRLF
		"- uint32_t data_count" ONU_CRLF
		"- uint32_t data_word[8]" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
	const char usage[] = "";
#endif

	return cli_gpe_table_op(usage, p_dev, false, p_cmd, bufsize_max, p_out,
				gpe_long_fwd_forward,
				NULL,
				true);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_table_reinit(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum onu_errorcode fct_ret = (enum onu_errorcode) 0;
	struct gpe_reinit_table reinit_table;

#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_table_reinit" ONU_CRLF
		"Short Form: gpetri" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t table_id \n  " ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = onu_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}
	ret = onu_cli_sscanf(p_cmd, "%u ", &reinit_table.table_id);

	if (ret != 1) {
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);
	}
	fct_ret = gpe_table_reinit(p_dev, &reinit_table);
	return sprintf(p_out, "errorcode=%d " ONU_CRLF, (int)fct_ret);
}


/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_extvlan_translate(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum onu_errorcode fct_ret = (enum onu_errorcode) 0;
	struct gpe_table_entry in;
	struct gpe_table_entry out;

#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_extvlan_translate" ONU_CRLF
		"Short Form: gpeet" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t index \n  " ONU_CRLF
		"- uint32_t key0 \n  " ONU_CRLF
		"- uint32_t key1 \n  " ONU_CRLF
		"- uint32_t key2 \n  " ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		"- uint32_t index \n" ONU_CRLF
		"- uint32_t data0 \n  " ONU_CRLF
		"- uint32_t data1 \n  " ONU_CRLF
		"- uint32_t data2 \n  " ONU_CRLF
		"- uint32_t data3 \n  " ONU_CRLF
		ONU_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = onu_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}
	ret = onu_cli_sscanf(p_cmd, "%u %u %u %u", &in.index, &in.data.message.data[0], &in.data.message.data[1], &in.data.message.data[2]);

	if (ret != 4) {
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);
	}
	fct_ret = gpe_ext_vlan_do(p_dev, &in, &out);
	return sprintf(p_out, "errorcode=%d index=%u data0=0x%08x data1=0x%08x data2=0x%08x data3=0x%08x" ONU_CRLF,
			(int)fct_ret,
			out.index,
			out.data.message.data[0],
			out.data.message.data[1],
			out.data.message.data[2],
			out.data.message.data[3] );
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_gpe_tr181_counter_get(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum onu_errorcode fct_ret = ONU_STATUS_OK;
	struct gpe_tr181_counters_cfg in;
	struct gpe_tr181_counters out;
	char *tok, *str;
	uint8_t i;

#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: gpe_tr181_counter_get" ONU_CRLF
		"Short Form: " CLI_EMPTY_CMD_HELP ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint8_t us_egress_queue_num" ONU_CRLF
		"- us_egress_queue_list[" _MKSTR(ONU_GPE_MAX_QUEUE) "]" ONU_CRLF
		"- uint8_t ds_egress_queue_num" ONU_CRLF
		"- ds_egress_queue_list[" _MKSTR(ONU_GPE_MAX_QUEUE) "]" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		"- uint64_t bytes_sent" ONU_CRLF
		"- uint64_t bytes_received" ONU_CRLF
		"- uint64_t packets_sent" ONU_CRLF
		"- uint64_t packets_received" ONU_CRLF
		"- uint32_t errors_sent" ONU_CRLF
		"- uint32_t errors_received" ONU_CRLF
		"- uint32_t discard_packets_sent" ONU_CRLF
		"- uint32_t discard_packets_received" ONU_CRLF
		ONU_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = onu_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0)
		return ret;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	strncpy(p_out, p_cmd, bufsize_max);
	str = p_out;

	tok = onu_strsep(&str, " ");
	if (!tok)
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);

	in.us_egress_queue_num = (uint8_t)onu_strtoul(tok, NULL, 10);

	if (in.us_egress_queue_num >= ARRAY_SIZE(in.us_egress_queue_list))
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);

	for (i = 0; i < in.us_egress_queue_num; i++) {
		tok = onu_strsep(&str, " ");
		if (!tok)
			return onu_cli_check_help("-h", usage,
						  bufsize_max, p_out);

		in.us_egress_queue_list[i] = (uint8_t)onu_strtoul(tok,NULL,10);
	}

	tok = onu_strsep(&str, " ");
	if (!tok)
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);

	in.ds_egress_queue_num = (uint8_t)onu_strtoul(tok, NULL, 10);

	if (in.ds_egress_queue_num >= ARRAY_SIZE(in.ds_egress_queue_list))
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);

	for (i = 0; i < in.ds_egress_queue_num; i++) {
		tok = onu_strsep(&str, " ");
		if (!tok)
			return onu_cli_check_help("-h", usage,
						  bufsize_max, p_out);

		in.ds_egress_queue_list[i] = (uint8_t)onu_strtoul(tok,NULL,10);
	}

	fct_ret = gpe_tr181_counter_get(p_dev, &in, &out);
	return sprintf(p_out, "errorcode=%d bytes_sent=%llu "
			      "bytes_received=%llu packets_sent=%llu "
			      "packets_received=%llu errors_sent=%u "
			      "errors_received=%u discard_packets_sent=%u "
			      "discard_packets_received=%u" ONU_CRLF,
				(int)fct_ret, out.bytes_sent,
				out.bytes_received, out.packets_sent,
				out.packets_received, out.errors_sent,
				out.errors_received, out.discard_packets_sent,
				out.discard_packets_received);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_sce_reg_print(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum onu_errorcode fct_ret = (enum onu_errorcode) 0;
	struct sce_thread param;
	uint32_t val;
	unsigned int i;
	static const char reg_map[] = {
		REG_R0, REG_R4, REG_R8,  REG_R12, REG_L0, REG_L4, REG_PC,
		REG_R1, REG_R5, REG_R9,  REG_FP,  REG_L1, REG_L5, REG_SP,
		REG_R2, REG_R6, REG_R10, REG_GP,  REG_L2, REG_L6, REG_T,
		REG_R3, REG_R7, REG_R11, REG_ST,  REG_L3, REG_L7 };
	static const char *format[]= {
		"R0: %08X  ", "R4: %08X  ", "R8 : %08X  ","R12: %08X  ",
		"L0: %04X  ", "L4: %04X  ", "PC: %04X  ",
		"R1: %08X  ", "R5: %08X  ", "R9 : %08X  ","FP : %08X  ",
		"L1: %04X  ", "L5: %04X  ", "SP: %d  ",
		"R2: %08X  ", "R6: %08X  ", "R10: %08X  ","GP : %08X  ",
		"L2: %04X  ", "L6: %04X  ", "T : %d  ",
		"R3: %08X  ", "R7: %08X  ", "R11: %08X  ","ST : %08X  ",
		"L3: %04X  ", "L7: %04X  " };

#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: sce_reg_print" ONU_CRLF
		"Short Form: scerp" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t tid" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = onu_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}
	ret = onu_cli_sscanf(p_cmd, "%u", &param.tid);
	if (ret != 1) {
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);
	}

	p_out[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(reg_map); i++) {
#if defined(INCLUDE_SCE_DEBUG)
		ret = sce_fw_pe_reg_get(param.tid, reg_map[i], &val);
#else
		ret = -1;
#endif		
		if (ret != 0)
			val = 0xeeeeeeee;

		sprintf(p_out + strlen(p_out), format[i], val);
		if ((i % 7) == 6)
			sprintf(p_out + strlen(p_out), "\n");
	}
	sprintf(p_out + strlen(p_out), "\n");

	return strlen(p_out) + sprintf(p_out + strlen(p_out),
				       "errorcode=%d" ONU_CRLF, (int)fct_ret);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_sce_break_print(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
	enum onu_errorcode fct_ret = (enum onu_errorcode) 0;
	struct sce_thread param;
	int i;

#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: sce_break_print" ONU_CRLF
		"Short Form: scebp" ONU_CRLF
		ONU_CRLF
		"Input Parameter" ONU_CRLF
		"- uint32_t tid" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		ONU_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = onu_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}
	ret = onu_cli_sscanf(p_cmd, "%u", &param.tid);
	if (ret != 1) {
		return onu_cli_check_help("-h", usage, bufsize_max, p_out);
	}

	p_out[0] = '\0';
	for (i = 0; i < SCE_MAX_BREAKPOINTS; i++) {
#if defined(INCLUDE_SCE_DEBUG)
		uint32_t addr;

		if (!sce_fw_breakpoint_get(param.tid, i, &addr))
			sprintf(p_out + strlen(p_out), "Breakpoint #%u at 0x%08X\n", i, addr);
#else
		ret = -1;
#endif
	}
	return strlen(p_out) + sprintf(p_out + strlen(p_out),
				       "errorcode=%d" ONU_CRLF, (int)fct_ret);
}

/** Handle command

   \param[in] p_dev     ONU device pointer
   \param[in] p_cmd     Input commands
   \param[in] p_out     Output FD
*/
static int cli_sce_break_check(
	struct onu_device *p_dev,
	const char *p_cmd,
	const uint32_t bufsize_max,
	char *p_out)
{
	int ret = 0;
#if defined(INCLUDE_SCE_DEBUG)
	enum onu_errorcode fct_ret = (enum onu_errorcode) 0;
	struct sce_thread_mask out;
	int tid;
	struct onu_control *ctrl = (struct onu_control *)p_dev->ctrl;
#endif

#ifndef ONU_DEBUG_DISABLE
	static const char usage[] =
		"Long Form: sce_break_check" ONU_CRLF
		"Short Form: scebc" ONU_CRLF
		ONU_CRLF
		"Output Parameter" ONU_CRLF
		"- enum onu_errorcode errorcode" ONU_CRLF
		"- uint32_t mask" ONU_CRLF
		ONU_CRLF;
#else
#undef usage
#define usage ""
#endif

	if ((ret = onu_cli_check_help(p_cmd, usage, bufsize_max, p_out)) >= 0) {
		return ret;
	}
	p_out[0] = '\0';
#if defined(INCLUDE_SCE_DEBUG)
	fct_ret = sce_break_check(p_dev, &out);

	p_out[0] = '\0';
	if (out.mask > 0) {
		for (tid = 0; tid < ctrl->num_pe*4; tid++) {
			if (out.mask & (1<<tid)) {
				sprintf(p_out + strlen(p_out),
					"Reached breakpoint "
					"on tid %d\n",
					tid);
			}
		}
	}
	return strlen(p_out) + sprintf(p_out + strlen(p_out),
				       "errorcode=%d mask=0x%x " ONU_CRLF,
				       (int)fct_ret, out.mask);
#else
	return sprintf(p_out, "errorcode=-1 " ONU_CRLF);
#endif		

}

/** Register misc commands */
void onu_cli_misc_register(
	void)
{
onu_cli_command_add("gpets", "gpe_table_set", cli_gpe_table_set);
onu_cli_command_add("gpetg", "gpe_table_get", cli_gpe_table_get);
onu_cli_command_add("gpetw", "gpe_table_write", cli_gpe_table_write);
onu_cli_command_add("gpetr", "gpe_table_read", cli_gpe_table_read);
onu_cli_command_add("gpeta", "gpe_table_add", cli_gpe_table_add);
onu_cli_command_add("gpetd", "gpe_table_delete", cli_gpe_table_delete);
onu_cli_command_add("gpetsrch", "gpe_table_search", cli_gpe_table_search);
onu_cli_command_add("gpesfwda", "gpe_short_fwd_add", cli_gpe_short_fwd_add);
onu_cli_command_add("gpesfwdd", "gpe_short_fwd_delete", cli_gpe_short_fwd_delete);
onu_cli_command_add("gpesfwdr", "gpe_short_fwd_relearn", cli_gpe_short_fwd_relearn);
onu_cli_command_add("gpeageg", "gpe_age_get", cli_gpe_age_get);
onu_cli_command_add("gpeage", "gpe_age", cli_gpe_age);
onu_cli_command_add("gpesfwdfwd", "gpe_short_fwd_forward", cli_gpe_short_fwd_forward);
onu_cli_command_add("gpefa", "gpe_fid_add", cli_gpe_fid_add);
onu_cli_command_add("gpefd", "gpe_fid_delete", cli_gpe_fid_delete);
onu_cli_command_add("gpelfwda", "gpe_long_fwd_add", cli_gpe_long_fwd_add);
onu_cli_command_add("gpelfwdd", "gpe_long_fwd_delete", cli_gpe_long_fwd_delete);
onu_cli_command_add("gpelfwdfwd", "gpe_long_fwd_forward", cli_gpe_long_fwd_forward);
onu_cli_command_add("gpetri", "gpe_table_reinit", cli_gpe_table_reinit);
onu_cli_command_add("gpeet", "gpe_extvlan_translate", cli_gpe_extvlan_translate);
onu_cli_command_add(CLI_EMPTY_CMD, "gpe_tr181_counter_get", cli_gpe_tr181_counter_get);
onu_cli_command_add("scerp", "sce_reg_print", cli_sce_reg_print);
onu_cli_command_add("scebp", "sce_break_print", cli_sce_break_print);
onu_cli_command_add("scebc", "sce_break_check", cli_sce_break_check);
onu_cli_command_add("gpepts", "gpe_pe_table_set", cli_gpe_pe_table_set);
onu_cli_command_add("gpeptg", "gpe_pe_table_get", cli_gpe_pe_table_get);
}

/*! @} */

#endif
