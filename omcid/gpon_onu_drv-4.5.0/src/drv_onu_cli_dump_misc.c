/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "drv_onu_std_defs.h"
#include "drv_onu_api.h"

#ifdef INCLUDE_CLI_DUMP_SUPPORT


/** \addtogroup ONU_CLI_DUMP_COMMANDS
   @{
*/

int dump_NULL(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_onu_reset(char *p_out, const void *p_data_in)
{
	(void)p_data_in;
	return sprintf(p_out, "onu_reset" ONU_CRLF);
}

static int dump_gpe_table_entry(char *p_out, const void *p_data_in,
				const char *cmd)
{
	int cnt;
	uint32_t i, *data;
	struct gpe_table *param;

	param = (struct gpe_table *)p_data_in;
	data = (uint32_t*)&param->data;

	cnt = sprintf(	p_out, "%s %u %u %u ",
			cmd, param->id, param->index,
			(unsigned int)sizeof(union gpe_table_data)/4);

	/** all tables are 32-bit aligned*/
	for (i = 0; i < sizeof(union gpe_table_data)/4; i++)
		cnt += sprintf(p_out + cnt, "0x%08x ", data[i]);

	cnt += sprintf(p_out + cnt, "%s", ONU_CRLF);

	return cnt;
}


int dump_gpe_table_reinit(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_table_entry_set(char *p_out, const void *p_data_in)
{
	return dump_gpe_table_entry(p_out, p_data_in,"gpe_table_set");
}

int dump_gpe_table_entry_get(char *p_out, const void *p_data_in)
{
	return dump_gpe_table_entry(p_out, p_data_in,"gpe_table_get");
}

int dump_gpe_table_entry_add(char *p_out, const void *p_data_in)
{
	return dump_gpe_table_entry(p_out, p_data_in,
				    "gpe_table_add");
}

int dump_gpe_table_entry_delete(char *p_out, const void *p_data_in)
{
	return dump_gpe_table_entry(p_out, p_data_in,
				    "gpe_table_delete");
}

int dump_gpe_table_entry_search(char *p_out, const void *p_data_in)
{
	return dump_gpe_table_entry(p_out, p_data_in,
				    "gpe_table_entry_search");
}

int dump_gpe_table_entry_read(char *p_out, const void *p_data_in)
{
	struct gpe_table *param;
	const char *cmd = "gpe_table_read";

	param = (struct gpe_table *)p_data_in;

	return sprintf(	p_out, "%s %u %u" ONU_CRLF,
			cmd, param->id, param->index);
}

int dump_gpe_table_entry_write(char *p_out, const void *p_data_in)
{
	return dump_gpe_table_entry(p_out, p_data_in,
				    "gpe_table_write");
}

int dump_gpe_bridge_port_cfg_set(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_ext_vlan_get(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_ext_vlan_set(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_ext_vlan_do(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_fid_add(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_fid_delete(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_long_fwd_forward(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_long_fwd_add(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_long_fwd_delete(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_tagging_filter_get(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_tagging_filter_set(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_tagging_filter_do(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_cop_table0_read(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_short_fwd_add(char *p_out, const void *p_data_in)
{
	return dump_gpe_table_entry(p_out, p_data_in,
				    "gpe_short_fwd_add");
}

int dump_gpe_short_fwd_delete(char *p_out, const void *p_data_in)
{
	return dump_gpe_table_entry(p_out, p_data_in,
				    "gpe_short_fwd_delete");
}

int dump_gpe_short_fwd_relearn(char *p_out, const void *p_data_in)
{
	return dump_gpe_table_entry(p_out, p_data_in,
				    "gpe_short_fwd_relearn");
}

int dump_gpe_short_fwd_forward(char *p_out, const void *p_data_in)
{
	return dump_gpe_table_entry(p_out, p_data_in,
				    "gpe_short_fwd_forward");
}

int dump_gpe_age_get(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_age(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;;
}

int dump_gpe_ext_vlan_custom_set(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_ext_vlan_custom_get(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_ploam_ds_insert(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_ploam_ds_extract(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_ploam_us_insert(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_ploam_us_extract(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_activity_get(char *p_out, const void *p_data_in)
{
	(void)p_out;
	(void)p_data_in;
	return 0;
}

int dump_gpe_iqueue_write_debug(char *p_out, const void *p_data_in)
{
	(void)p_data_in;

	return sprintf(p_out, "dump_ssb_iqueue_write" ONU_CRLF);
}

int dump_gpe_tr181_counter_get(char *p_out, const void *p_data_in)
{
	(void)p_data_in;

	return sprintf(p_out, "gpe_tr181_counter_get" ONU_CRLF);
}

/*! @} */

#endif
