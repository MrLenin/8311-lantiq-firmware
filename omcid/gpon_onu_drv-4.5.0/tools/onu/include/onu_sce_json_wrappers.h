/******************************************************************************

                               Copyright (c) 2013
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* attention, this file was automatically generated
   by update_sce.py at 31 Jan 2013 08:25:50 +000 */

#ifndef __sce_wrappers_json_h
#define __sce_wrappers_json_h

int json_gpe_ds_gem_port_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_us_gem_port_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_fwd_id_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_fwd_id_hash_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_bridge_port_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_tagging_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_vlan_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_extended_vlan_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_vlan_rule_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_vlan_treatment_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_pmapper_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_short_fwd_hash_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_short_fwd_table_mac_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_short_fwd_table_mac_mc_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_short_fwd_table_ipv4_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_short_fwd_table_ipv4_mc_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_long_fwd_hash_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_long_fwd_table_ipv6_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_long_fwd_table_ipv6_mc_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_ds_mc_ipv4_source_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_ds_mc_ipv6_source_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_learning_limitation_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_lan_port_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_pcp_decoding_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_dscp_decoding_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_pcp_encoding_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_dscp_encoding_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_exception_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_redirection_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_mac_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_acl_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_acl_filter_table2_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_bridge_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_ethertype_exception_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_ethertype_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_enqueue_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_counter_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_status_table_get(FILE *f, int onu_fd, uint8_t instance, int index);
int json_gpe_constants_table_get(FILE *f, int onu_fd, uint8_t instance, int index);

int json_table_by_id_get(FILE *f, uint32_t table_id, int onu_id, uint8_t instance, int index);
int json_table_by_name_get(FILE *f, const char *table_name, int onu_id, uint8_t instance, int index);

#endif
