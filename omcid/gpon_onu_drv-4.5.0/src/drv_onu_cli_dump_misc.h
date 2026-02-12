/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file "LICENSE" in the root folder of
  this software module.

******************************************************************************/
#ifndef _drv_onu_cli_dump_misc_h
#define _drv_onu_cli_dump_misc_h

/** \addtogroup ONU_CLI_DUMP_COMMANDS
   @{
*/

int dump_NULL(char *p_out, const void *p_data_in);
int dump_onu_reset(char *p_out, const void *p_data_in);
int dump_gpe_table_reinit(char *p_out, const void *p_data_in);
int dump_gpe_table_entry_set(char *p_out, const void *p_data_in);
int dump_gpe_table_entry_get(char *p_out, const void *p_data_in);
int dump_gpe_table_entry_add(char *p_out, const void *p_data_in);
int dump_gpe_table_entry_delete(char *p_out, const void *p_data_in);
int dump_gpe_table_entry_search(char *p_out, const void *p_data_in);
int dump_gpe_table_entry_read(char *p_out, const void *p_data_in);
int dump_gpe_table_entry_write(char *p_out, const void *p_data_in);
int dump_gpe_bridge_port_cfg_set(char *p_out, const void *p_data_in);
int dump_gpe_ext_vlan_get(char *p_out, const void *p_data_in);
int dump_gpe_ext_vlan_set(char *p_out, const void *p_data_in);
int dump_gpe_ext_vlan_do(char *p_out, const void *p_data_in);
int dump_gpe_fid_add(char *p_out, const void *p_data_in);
int dump_gpe_fid_delete(char *p_out, const void *p_data_in);
int dump_gpe_long_fwd_add(char *p_out, const void *p_data_in);
int dump_gpe_long_fwd_delete(char *p_out, const void *p_data_in);
int dump_gpe_long_fwd_forward(char *p_out, const void *p_data_in);
int dump_gpe_tagging_filter_get(char *p_out, const void *p_data_in);
int dump_gpe_tagging_filter_set(char *p_out, const void *p_data_in);
int dump_gpe_tagging_filter_do(char *p_out, const void *p_data_in);
int dump_gpe_cop_table0_read(char *p_out, const void *p_data_in);
int dump_gpe_short_fwd_add(char *p_out, const void *p_data_in);
int dump_gpe_short_fwd_delete(char *p_out, const void *p_data_in);
int dump_gpe_short_fwd_relearn(char *p_out, const void *p_data_in);
int dump_gpe_short_fwd_forward(char *p_out, const void *p_data_in);
int dump_gpe_ext_vlan_custom_set(char *p_out, const void *p_data_in);
int dump_gpe_ext_vlan_custom_get(char *p_out, const void *p_data_in);
int dump_ploam_ds_insert(char *p_out, const void *p_data_in);
int dump_ploam_ds_extract(char *p_out, const void *p_data_in);
int dump_ploam_us_insert(char *p_out, const void *p_data_in);
int dump_ploam_us_extract(char *p_out, const void *p_data_in);
int dump_gpe_age_get(char *p_out, const void *p_data_in);
int dump_gpe_age(char *p_out, const void *p_data_in);
int dump_gpe_activity_get(char *p_out, const void *p_data_in);
int dump_gpe_iqueue_write_debug(char *p_out, const void *p_data_in);
int dump_gpe_tr181_counter_get(char *p_out, const void *p_data_in);

/*! @} */

#endif
