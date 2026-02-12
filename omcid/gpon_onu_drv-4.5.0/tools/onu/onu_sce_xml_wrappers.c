/******************************************************************************

                               Copyright (c) 2013
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/* attention, this file was automatically generated
   by update_sce.py at 31 Jan 2013 08:25:50 +000 */

#include "onu_sce_wrappers_common.h"

typedef int (table_get)(FILE *f, int onu_fd, uint8_t instance, int index);

struct table_by_id {
	uint32_t id;
	table_get *handler;
};

struct table_by_name {
	const char *name;
	table_get *handler;
};

int xml_gpe_ds_gem_port_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 256 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_ds_gem_port_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_DS_GEM_PORT_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.ds_gem_port), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.ds_gem_port.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='bridge_port_index0' type='uint32_t' width='7'>0x%x</field>\n", entry.data.ds_gem_port.bridge_port_index0);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.unused1);
		fprintf(f, "\t\t<field name='bridge_port_index1' type='uint32_t' width='7'>0x%x</field>\n", entry.data.ds_gem_port.bridge_port_index1);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.unused2);
		fprintf(f, "\t\t<field name='bridge_port_index2' type='uint32_t' width='7'>0x%x</field>\n", entry.data.ds_gem_port.bridge_port_index2);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.unused3);
		fprintf(f, "\t\t<field name='bridge_port_index3' type='uint32_t' width='7'>0x%x</field>\n", entry.data.ds_gem_port.bridge_port_index3);
		fprintf(f, "\t\t<field name='unused4' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.unused4);
		fprintf(f, "\t\t<field name='bridge_port_index4' type='uint32_t' width='7'>0x%x</field>\n", entry.data.ds_gem_port.bridge_port_index4);
		fprintf(f, "\t\t<field name='unused5' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.unused5);
		fprintf(f, "\t\t<field name='bridge_port_index5' type='uint32_t' width='7'>0x%x</field>\n", entry.data.ds_gem_port.bridge_port_index5);
		fprintf(f, "\t\t<field name='unused6' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.unused6);
		fprintf(f, "\t\t<field name='bridge_port_index6' type='uint32_t' width='7'>0x%x</field>\n", entry.data.ds_gem_port.bridge_port_index6);
		fprintf(f, "\t\t<field name='unused7' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.unused7);
		fprintf(f, "\t\t<field name='bridge_port_index7' type='uint32_t' width='7'>0x%x</field>\n", entry.data.ds_gem_port.bridge_port_index7);
		fprintf(f, "\t\t<field name='unused8' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.unused8);
		fprintf(f, "\t\t<field name='ds_gem_meter_id' type='uint32_t' width='9'>0x%x</field>\n", entry.data.ds_gem_port.ds_gem_meter_id);
		fprintf(f, "\t\t<field name='ds_gem_meter_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.ds_gem_meter_enable);
		fprintf(f, "\t\t<field name='ext_vlan_ingress_mode' type='uint32_t' width='2'>0x%x</field>\n", entry.data.ds_gem_port.ext_vlan_ingress_mode);
		fprintf(f, "\t\t<field name='unused10' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.unused10);
		fprintf(f, "\t\t<field name='ext_vlan_index' type='uint32_t' width='7'>0x%x</field>\n", entry.data.ds_gem_port.ext_vlan_index);
		fprintf(f, "\t\t<field name='ext_vlan_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.ext_vlan_enable);
		fprintf(f, "\t\t<field name='exception_profile' type='uint32_t' width='3'>0x%x</field>\n", entry.data.ds_gem_port.exception_profile);
		fprintf(f, "\t\t<field name='unused11' type='uint32_t' width='2'>0x%x</field>\n", entry.data.ds_gem_port.unused11);
		fprintf(f, "\t\t<field name='ingress_color_marking' type='uint32_t' width='3'>0x%x</field>\n", entry.data.ds_gem_port.ingress_color_marking);
		fprintf(f, "\t\t<field name='dscp_table_pointer' type='uint32_t' width='3'>0x%x</field>\n", entry.data.ds_gem_port.dscp_table_pointer);
		fprintf(f, "\t\t<field name='interworking_option' type='uint32_t' width='3'>0x%x</field>\n", entry.data.ds_gem_port.interworking_option);
		fprintf(f, "\t\t<field name='egress_queue_offset' type='uint32_t' width='3'>0x%x</field>\n", entry.data.ds_gem_port.egress_queue_offset);
		fprintf(f, "\t\t<field name='unused12' type='uint32_t' width='6'>0x%x</field>\n", entry.data.ds_gem_port.unused12);
		fprintf(f, "\t\t<field name='max_bridge_index' type='uint32_t' width='3'>0x%x</field>\n", entry.data.ds_gem_port.max_bridge_index);
		fprintf(f, "\t\t<field name='unused13' type='uint32_t' width='2'>0x%x</field>\n", entry.data.ds_gem_port.unused13);
		fprintf(f, "\t\t<field name='lan_port_index' type='uint32_t' width='3'>0x%x</field>\n", entry.data.ds_gem_port.lan_port_index);
		fprintf(f, "\t\t<field name='gem_port_type' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.gem_port_type);
		fprintf(f, "\t\t<field name='queue_selection_mode' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.queue_selection_mode);
		fprintf(f, "\t\t<field name='napt_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.napt_enable);
		fprintf(f, "\t\t<field name='pppoe_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.pppoe_enable);
		fprintf(f, "\t\t<field name='fid_mask_vido' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.fid_mask_vido);
		fprintf(f, "\t\t<field name='fid_mask_vidi' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.fid_mask_vidi);
		fprintf(f, "\t\t<field name='fid_mask_pcpo' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.fid_mask_pcpo);
		fprintf(f, "\t\t<field name='fid_mask_pcpi' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.fid_mask_pcpi);
		fprintf(f, "\t\t<field name='gem_loopback_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.gem_loopback_enable);
		fprintf(f, "\t\t<field name='gem_mac_swap_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.gem_mac_swap_enable);
		fprintf(f, "\t\t<field name='unused15' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.unused15);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_gem_port.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_us_gem_port_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 256 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_us_gem_port_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_US_GEM_PORT_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.us_gem_port), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.us_gem_port.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='egress_queue_index' type='uint32_t' width='8'>0x%x</field>\n", entry.data.us_gem_port.egress_queue_index);
		fprintf(f, "\t\t<field name='ext_vlan_index' type='uint32_t' width='7'>0x%x</field>\n", entry.data.us_gem_port.ext_vlan_index);
		fprintf(f, "\t\t<field name='ext_vlan_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.us_gem_port.ext_vlan_enable);
		fprintf(f, "\t\t<field name='egress_color_marking' type='uint32_t' width='3'>0x%x</field>\n", entry.data.us_gem_port.egress_color_marking);
		fprintf(f, "\t\t<field name='ext_vlan_incremental_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.us_gem_port.ext_vlan_incremental_enable);
		fprintf(f, "\t\t<field name='ext_vlan_egress_mode' type='uint32_t' width='2'>0x%x</field>\n", entry.data.us_gem_port.ext_vlan_egress_mode);
		fprintf(f, "\t\t<field name='queue_marking_mode' type='uint32_t' width='3'>0x%x</field>\n", entry.data.us_gem_port.queue_marking_mode);
		fprintf(f, "\t\t<field name='dscp_table_pointer' type='uint32_t' width='3'>0x%x</field>\n", entry.data.us_gem_port.dscp_table_pointer);
		fprintf(f, "\t\t<field name='exception_profile' type='uint32_t' width='3'>0x%x</field>\n", entry.data.us_gem_port.exception_profile);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.us_gem_port.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_fwd_id_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 256 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_fwd_id_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_FID_ASSIGNMENT_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.fwd_id), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.fwd_id.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='vid_outer' type='uint32_t' width='12'>0x%x</field>\n", entry.data.fwd_id.vid_outer);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='1'>0x%x</field>\n", entry.data.fwd_id.unused1);
		fprintf(f, "\t\t<field name='prio_outer' type='uint32_t' width='3'>0x%x</field>\n", entry.data.fwd_id.prio_outer);
		fprintf(f, "\t\t<field name='vid_inner' type='uint32_t' width='12'>0x%x</field>\n", entry.data.fwd_id.vid_inner);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='1'>0x%x</field>\n", entry.data.fwd_id.unused2);
		fprintf(f, "\t\t<field name='prio_inner' type='uint32_t' width='3'>0x%x</field>\n", entry.data.fwd_id.prio_inner);
		fprintf(f, "\t\t<field name='fid' type='uint32_t' width='8'>0x%x</field>\n", entry.data.fwd_id.fid);
		fprintf(f, "\t\t<field name='cross_connect' type='uint32_t' width='1'>0x%x</field>\n", entry.data.fwd_id.cross_connect);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='7'>0x%x</field>\n", entry.data.fwd_id.unused3);
		fprintf(f, "\t\t<field name='next_entry' type='uint32_t' width='14'>0x%x</field>\n", entry.data.fwd_id.next_entry);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.fwd_id.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.fwd_id.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_fwd_id_hash_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_fwd_id_hash_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_FID_HASH_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.fwd_id_hash), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.fwd_id_hash.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='16'>0x%x</field>\n", entry.data.fwd_id_hash.unused1);
		fprintf(f, "\t\t<field name='fwd_id_assignent_table_pointer' type='uint32_t' width='14'>0x%x</field>\n", entry.data.fwd_id_hash.fwd_id_assignent_table_pointer);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='1'>0x%x</field>\n", entry.data.fwd_id_hash.unused2);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.fwd_id_hash.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_bridge_port_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 128 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_bridge_port_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_BRIDGE_PORT_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.bridge_port), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.bridge_port.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='learning_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge_port.learning_enable);
		fprintf(f, "\t\t<field name='port_lock_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge_port.port_lock_enable);
		fprintf(f, "\t\t<field name='local_switching_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge_port.local_switching_enable);
		fprintf(f, "\t\t<field name='uuc_flood_disable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge_port.uuc_flood_disable);
		fprintf(f, "\t\t<field name='tagging_filter_ingress_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge_port.tagging_filter_ingress_enable);
		fprintf(f, "\t\t<field name='tagging_filter_egress_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge_port.tagging_filter_egress_enable);
		fprintf(f, "\t\t<field name='meter_ingress_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge_port.meter_ingress_enable);
		fprintf(f, "\t\t<field name='meter_egress_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge_port.meter_egress_enable);
		fprintf(f, "\t\t<field name='umc_flood_disable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge_port.umc_flood_disable);
		fprintf(f, "\t\t<field name='forwarding_method' type='uint32_t' width='4'>0x%x</field>\n", entry.data.bridge_port.forwarding_method);
		fprintf(f, "\t\t<field name='bridge_index' type='uint32_t' width='3'>0x%x</field>\n", entry.data.bridge_port.bridge_index);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge_port.unused2);
		fprintf(f, "\t\t<field name='port_state' type='uint32_t' width='2'>0x%x</field>\n", entry.data.bridge_port.port_state);
		fprintf(f, "\t\t<field name='sa_filter_mode' type='uint32_t' width='2'>0x%x</field>\n", entry.data.bridge_port.sa_filter_mode);
		fprintf(f, "\t\t<field name='da_filter_mode' type='uint32_t' width='2'>0x%x</field>\n", entry.data.bridge_port.da_filter_mode);
		fprintf(f, "\t\t<field name='ingress_color_marking' type='uint32_t' width='3'>0x%x</field>\n", entry.data.bridge_port.ingress_color_marking);
		fprintf(f, "\t\t<field name='egress_color_marking' type='uint32_t' width='3'>0x%x</field>\n", entry.data.bridge_port.egress_color_marking);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='3'>0x%x</field>\n", entry.data.bridge_port.unused3);
		fprintf(f, "\t\t<field name='sa_filter_pointer' type='uint32_t' width='8'>0x%x</field>\n", entry.data.bridge_port.sa_filter_pointer);
		fprintf(f, "\t\t<field name='da_filter_pointer' type='uint32_t' width='8'>0x%x</field>\n", entry.data.bridge_port.da_filter_pointer);
		fprintf(f, "\t\t<field name='tagging_filter_ingress' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge_port.tagging_filter_ingress);
		fprintf(f, "\t\t<field name='meter_id_ingress' type='uint32_t' width='9'>0x%x</field>\n", entry.data.bridge_port.meter_id_ingress);
		fprintf(f, "\t\t<field name='tagging_filter_egress' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge_port.tagging_filter_egress);
		fprintf(f, "\t\t<field name='meter_id_egress' type='uint32_t' width='9'>0x%x</field>\n", entry.data.bridge_port.meter_id_egress);
		fprintf(f, "\t\t<field name='egress_filter_mask' type='uint32_t' width='10'>0x%x</field>\n", entry.data.bridge_port.egress_filter_mask);
		fprintf(f, "\t\t<field name='dscp_table_pointer' type='uint32_t' width='3'>0x%x</field>\n", entry.data.bridge_port.dscp_table_pointer);
		fprintf(f, "\t\t<field name='unused4' type='uint32_t' width='3'>0x%x</field>\n", entry.data.bridge_port.unused4);
		fprintf(f, "\t\t<field name='tp_pointer' type='uint32_t' width='8'>0x%x</field>\n", entry.data.bridge_port.tp_pointer);
		fprintf(f, "\t\t<field name='tp_type' type='uint32_t' width='2'>0x%x</field>\n", entry.data.bridge_port.tp_type);
		fprintf(f, "\t\t<field name='unused5' type='uint32_t' width='21'>0x%x</field>\n", entry.data.bridge_port.unused5);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge_port.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_tagging_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 128 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_tagging_filter_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_TAGGING_FILTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.tagging_filter), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.tagging_filter.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='tci_mask' type='uint32_t' width='16'>0x%x</field>\n", entry.data.tagging_filter.tci_mask);
		fprintf(f, "\t\t<field name='untagged_drop_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.tagging_filter.untagged_drop_enable);
		fprintf(f, "\t\t<field name='tagged_pass_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.tagging_filter.tagged_pass_enable);
		fprintf(f, "\t\t<field name='tagged_drop_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.tagging_filter.tagged_drop_enable);
		fprintf(f, "\t\t<field name='pass_on_match_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.tagging_filter.pass_on_match_enable);
		fprintf(f, "\t\t<field name='unused0' type='uint32_t' width='1'>0x%x</field>\n", entry.data.tagging_filter.unused0);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='11'>0x%x</field>\n", entry.data.tagging_filter.unused1);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='16'>0x%x</field>\n", entry.data.tagging_filter.unused2);
		fprintf(f, "\t\t<field name='vlan_table_index' type='uint32_t' width='14'>0x%x</field>\n", entry.data.tagging_filter.vlan_table_index);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='1'>0x%x</field>\n", entry.data.tagging_filter.unused3);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.tagging_filter.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_vlan_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_vlan_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_VLAN_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.vlan), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.vlan.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='tci' type='uint32_t' width='16'>0x%x</field>\n", entry.data.vlan.tci);
		fprintf(f, "\t\t<field name='unused' type='uint32_t' width='14'>0x%x</field>\n", entry.data.vlan.unused);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_extended_vlan_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 128 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_extended_vlan_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_EXTENDED_VLAN_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.extended_vlan), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.extended_vlan.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='input_tpid' type='uint32_t' width='16'>0x%x</field>\n", entry.data.extended_vlan.input_tpid);
		fprintf(f, "\t\t<field name='output_tpid' type='uint32_t' width='16'>0x%x</field>\n", entry.data.extended_vlan.output_tpid);
		fprintf(f, "\t\t<field name='dscp_table_pointer' type='uint32_t' width='3'>0x%x</field>\n", entry.data.extended_vlan.dscp_table_pointer);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='13'>0x%x</field>\n", entry.data.extended_vlan.unused1);
		fprintf(f, "\t\t<field name='vlan_rule_table_pointer' type='uint32_t' width='14'>0x%x</field>\n", entry.data.extended_vlan.vlan_rule_table_pointer);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='1'>0x%x</field>\n", entry.data.extended_vlan.unused2);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.extended_vlan.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_vlan_rule_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_vlan_rule_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_VLAN_RULE_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.vlan_rule), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.vlan_rule.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='zero_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.zero_enable);
		fprintf(f, "\t\t<field name='one_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.one_enable);
		fprintf(f, "\t\t<field name='two_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.two_enable);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='5'>0x%x</field>\n", entry.data.vlan_rule.unused1);
		fprintf(f, "\t\t<field name='outer_priority_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.outer_priority_enable);
		fprintf(f, "\t\t<field name='outer_priority_filter' type='uint32_t' width='3'>0x%x</field>\n", entry.data.vlan_rule.outer_priority_filter);
		fprintf(f, "\t\t<field name='outer_vid_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.outer_vid_enable);
		fprintf(f, "\t\t<field name='outer_vid_filter' type='uint32_t' width='12'>0x%x</field>\n", entry.data.vlan_rule.outer_vid_filter);
		fprintf(f, "\t\t<field name='outer_input_tpid_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.outer_input_tpid_enable);
		fprintf(f, "\t\t<field name='outer_reg_tpid_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.outer_reg_tpid_enable);
		fprintf(f, "\t\t<field name='outer_de_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.outer_de_enable);
		fprintf(f, "\t\t<field name='outer_de_filter' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.outer_de_filter);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='3'>0x%x</field>\n", entry.data.vlan_rule.unused2);
		fprintf(f, "\t\t<field name='inner_priority_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.inner_priority_enable);
		fprintf(f, "\t\t<field name='inner_priority_filter' type='uint32_t' width='3'>0x%x</field>\n", entry.data.vlan_rule.inner_priority_filter);
		fprintf(f, "\t\t<field name='inner_vid_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.inner_vid_enable);
		fprintf(f, "\t\t<field name='inner_vid_filter' type='uint32_t' width='12'>0x%x</field>\n", entry.data.vlan_rule.inner_vid_filter);
		fprintf(f, "\t\t<field name='inner_input_tpid_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.inner_input_tpid_enable);
		fprintf(f, "\t\t<field name='inner_reg_tpid_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.inner_reg_tpid_enable);
		fprintf(f, "\t\t<field name='inner_de_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.inner_de_enable);
		fprintf(f, "\t\t<field name='inner_de_filter' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.inner_de_filter);
		fprintf(f, "\t\t<field name='ethertype_filter1_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.ethertype_filter1_enable);
		fprintf(f, "\t\t<field name='ethertype_filter2_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.ethertype_filter2_enable);
		fprintf(f, "\t\t<field name='ethertype_filter3_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.ethertype_filter3_enable);
		fprintf(f, "\t\t<field name='ethertype_filter4_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.ethertype_filter4_enable);
		fprintf(f, "\t\t<field name='ethertype_filter5_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.ethertype_filter5_enable);
		fprintf(f, "\t\t<field name='spare_filter1_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.spare_filter1_enable);
		fprintf(f, "\t\t<field name='spare_filter2_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.spare_filter2_enable);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.unused3);
		fprintf(f, "\t\t<field name='def' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.def);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_rule.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_vlan_treatment_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_vlan_treatment_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_VLAN_TREATMENT_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.vlan_treatment), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.vlan_treatment.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='tagb_treatment' type='uint32_t' width='4'>0x%x</field>\n", entry.data.vlan_treatment.tagb_treatment);
		fprintf(f, "\t\t<field name='tagb_vid_treatment' type='uint32_t' width='13'>0x%x</field>\n", entry.data.vlan_treatment.tagb_vid_treatment);
		fprintf(f, "\t\t<field name='tagb_tpid_treatment' type='uint32_t' width='3'>0x%x</field>\n", entry.data.vlan_treatment.tagb_tpid_treatment);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='12'>0x%x</field>\n", entry.data.vlan_treatment.unused1);
		fprintf(f, "\t\t<field name='taga_treatment' type='uint32_t' width='4'>0x%x</field>\n", entry.data.vlan_treatment.taga_treatment);
		fprintf(f, "\t\t<field name='taga_vid_treatment' type='uint32_t' width='13'>0x%x</field>\n", entry.data.vlan_treatment.taga_vid_treatment);
		fprintf(f, "\t\t<field name='taga_tpid_treatment' type='uint32_t' width='3'>0x%x</field>\n", entry.data.vlan_treatment.taga_tpid_treatment);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='4'>0x%x</field>\n", entry.data.vlan_treatment.unused2);
		fprintf(f, "\t\t<field name='discard_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_treatment.discard_enable);
		fprintf(f, "\t\t<field name='outer_not_generate' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_treatment.outer_not_generate);
		fprintf(f, "\t\t<field name='inner_not_generate' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_treatment.inner_not_generate);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='4'>0x%x</field>\n", entry.data.vlan_treatment.unused3);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.vlan_treatment.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_pmapper_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 32 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_pmapper_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_PMAPPER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.pmapper), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.pmapper.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='itp_id0' type='uint32_t' width='8'>0x%x</field>\n", entry.data.pmapper.itp_id0);
		fprintf(f, "\t\t<field name='itp_id1' type='uint32_t' width='8'>0x%x</field>\n", entry.data.pmapper.itp_id1);
		fprintf(f, "\t\t<field name='itp_id2' type='uint32_t' width='8'>0x%x</field>\n", entry.data.pmapper.itp_id2);
		fprintf(f, "\t\t<field name='itp_id3' type='uint32_t' width='8'>0x%x</field>\n", entry.data.pmapper.itp_id3);
		fprintf(f, "\t\t<field name='itp_id4' type='uint32_t' width='8'>0x%x</field>\n", entry.data.pmapper.itp_id4);
		fprintf(f, "\t\t<field name='itp_id5' type='uint32_t' width='8'>0x%x</field>\n", entry.data.pmapper.itp_id5);
		fprintf(f, "\t\t<field name='itp_id6' type='uint32_t' width='8'>0x%x</field>\n", entry.data.pmapper.itp_id6);
		fprintf(f, "\t\t<field name='itp_id7' type='uint32_t' width='8'>0x%x</field>\n", entry.data.pmapper.itp_id7);
		fprintf(f, "\t\t<field name='dscp_table_pointer' type='uint32_t' width='3'>0x%x</field>\n", entry.data.pmapper.dscp_table_pointer);
		fprintf(f, "\t\t<field name='default_pcp' type='uint32_t' width='3'>0x%x</field>\n", entry.data.pmapper.default_pcp);
		fprintf(f, "\t\t<field name='meter_id_pmapper_bc' type='uint32_t' width='9'>0x%x</field>\n", entry.data.pmapper.meter_id_pmapper_bc);
		fprintf(f, "\t\t<field name='meter_id_pmapper_mc' type='uint32_t' width='9'>0x%x</field>\n", entry.data.pmapper.meter_id_pmapper_mc);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='4'>0x%x</field>\n", entry.data.pmapper.unused3);
		fprintf(f, "\t\t<field name='meter_pmapper_bcen' type='uint32_t' width='1'>0x%x</field>\n", entry.data.pmapper.meter_pmapper_bcen);
		fprintf(f, "\t\t<field name='meter_pmapper_mcen' type='uint32_t' width='1'>0x%x</field>\n", entry.data.pmapper.meter_pmapper_mcen);
		fprintf(f, "\t\t<field name='unmarked_frame_option' type='uint32_t' width='1'>0x%x</field>\n", entry.data.pmapper.unmarked_frame_option);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.pmapper.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_short_fwd_hash_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_short_fwd_hash_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_SHORT_FWD_HASH_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.short_fwd_hash), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.short_fwd_hash.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='16'>0x%x</field>\n", entry.data.short_fwd_hash.unused1);
		fprintf(f, "\t\t<field name='fwd_table_pointer' type='uint32_t' width='14'>0x%x</field>\n", entry.data.short_fwd_hash.fwd_table_pointer);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_hash.unused2);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_hash.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_short_fwd_table_mac_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_short_fwd_table_mac'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_SHORT_FWD_TABLE_MAC_ID, TABLE_ENTRY_SIZE(entry.data.short_fwd_table_mac), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.short_fwd_table_mac.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='mac_address_low' type='uint32_t' width='32'>0x%x</field>\n", entry.data.short_fwd_table_mac.mac_address_low);
		fprintf(f, "\t\t<field name='mac_address_high' type='uint32_t' width='16'>0x%x</field>\n", entry.data.short_fwd_table_mac.mac_address_high);
		fprintf(f, "\t\t<field name='fid' type='uint32_t' width='8'>0x%x</field>\n", entry.data.short_fwd_table_mac.fid);
		fprintf(f, "\t\t<field name='bridge_index' type='uint32_t' width='3'>0x%x</field>\n", entry.data.short_fwd_table_mac.bridge_index);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac.unused1);
		fprintf(f, "\t\t<field name='key_code' type='uint32_t' width='4'>0x%x</field>\n", entry.data.short_fwd_table_mac.key_code);
		fprintf(f, "\t\t<field name='bridge_port_index' type='uint32_t' width='7'>0x%x</field>\n", entry.data.short_fwd_table_mac.bridge_port_index);
		fprintf(f, "\t\t<field name='zero_port_map_indicator' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac.zero_port_map_indicator);
		fprintf(f, "\t\t<field name='activity' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac.activity);
		fprintf(f, "\t\t<field name='limitation' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac.limitation);
		fprintf(f, "\t\t<field name='dynamic_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac.dynamic_enable);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac.unused2);
		fprintf(f, "\t\t<field name='dummy_encapsulation_index' type='uint32_t' width='9'>0x%x</field>\n", entry.data.short_fwd_table_mac.dummy_encapsulation_index);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='3'>0x%x</field>\n", entry.data.short_fwd_table_mac.unused3);
		fprintf(f, "\t\t<field name='learning_time_stamp' type='uint32_t' width='8'>0x%x</field>\n", entry.data.short_fwd_table_mac.learning_time_stamp);
		fprintf(f, "\t\t<field name='unused4' type='uint32_t' width='16'>0x%x</field>\n", entry.data.short_fwd_table_mac.unused4);
		fprintf(f, "\t\t<field name='next_entry' type='uint32_t' width='14'>0x%x</field>\n", entry.data.short_fwd_table_mac.next_entry);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_short_fwd_table_mac_mc_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 0 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_short_fwd_table_mac_mc'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_SHORT_FWD_TABLE_MAC_MC_ID, TABLE_ENTRY_SIZE(entry.data.short_fwd_table_mac_mc), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.short_fwd_table_mac_mc.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='mac_address_low' type='uint32_t' width='32'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.mac_address_low);
		fprintf(f, "\t\t<field name='mac_address_high' type='uint32_t' width='16'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.mac_address_high);
		fprintf(f, "\t\t<field name='fid' type='uint32_t' width='8'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.fid);
		fprintf(f, "\t\t<field name='bridge_index' type='uint32_t' width='3'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.bridge_index);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.unused1);
		fprintf(f, "\t\t<field name='key_code' type='uint32_t' width='4'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.key_code);
		fprintf(f, "\t\t<field name='include_enable' type='uint32_t' width='7'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.include_enable);
		fprintf(f, "\t\t<field name='one_port_map_indicator' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.one_port_map_indicator);
		fprintf(f, "\t\t<field name='activity' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.activity);
		fprintf(f, "\t\t<field name='zero_limitation' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.zero_limitation);
		fprintf(f, "\t\t<field name='dynamic_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.dynamic_enable);
		fprintf(f, "\t\t<field name='msf_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.msf_enable);
		fprintf(f, "\t\t<field name='source_filter_pointer' type='uint32_t' width='9'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.source_filter_pointer);
		fprintf(f, "\t\t<field name='igmp' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.igmp);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='2'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.unused2);
		fprintf(f, "\t\t<field name='dummy_learning_time_stamp' type='uint32_t' width='8'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.dummy_learning_time_stamp);
		fprintf(f, "\t\t<field name='port_map' type='uint32_t' width='16'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.port_map);
		fprintf(f, "\t\t<field name='next_entry' type='uint32_t' width='14'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.next_entry);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_mac_mc.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_short_fwd_table_ipv4_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 0 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_short_fwd_table_ipv4'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_SHORT_FWD_TABLE_IPV4_ID, TABLE_ENTRY_SIZE(entry.data.short_fwd_table_ipv4), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.short_fwd_table_ipv4.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='ip_address' type='uint32_t' width='32'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.ip_address);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='16'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.unused1);
		fprintf(f, "\t\t<field name='fid' type='uint32_t' width='8'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.fid);
		fprintf(f, "\t\t<field name='bridge_index' type='uint32_t' width='3'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.bridge_index);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.unused2);
		fprintf(f, "\t\t<field name='key_code' type='uint32_t' width='4'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.key_code);
		fprintf(f, "\t\t<field name='bridge_port_index' type='uint32_t' width='7'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.bridge_port_index);
		fprintf(f, "\t\t<field name='zero_port_map_indicator' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.zero_port_map_indicator);
		fprintf(f, "\t\t<field name='activity' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.activity);
		fprintf(f, "\t\t<field name='zero_limitation' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.zero_limitation);
		fprintf(f, "\t\t<field name='zero_dynamic_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.zero_dynamic_enable);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.unused3);
		fprintf(f, "\t\t<field name='encapsulation_index' type='uint32_t' width='9'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.encapsulation_index);
		fprintf(f, "\t\t<field name='unused4' type='uint32_t' width='3'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.unused4);
		fprintf(f, "\t\t<field name='dummy_learning_time_stamp' type='uint32_t' width='8'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.dummy_learning_time_stamp);
		fprintf(f, "\t\t<field name='unused5' type='uint32_t' width='16'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.unused5);
		fprintf(f, "\t\t<field name='next_entry' type='uint32_t' width='14'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.next_entry);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_short_fwd_table_ipv4_mc_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 0 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_short_fwd_table_ipv4_mc'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ID, TABLE_ENTRY_SIZE(entry.data.short_fwd_table_ipv4_mc), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.short_fwd_table_ipv4_mc.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='ip_address' type='uint32_t' width='32'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.ip_address);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='16'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.unused1);
		fprintf(f, "\t\t<field name='fid' type='uint32_t' width='8'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.fid);
		fprintf(f, "\t\t<field name='bridge_index' type='uint32_t' width='3'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.bridge_index);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.unused2);
		fprintf(f, "\t\t<field name='key_code' type='uint32_t' width='4'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.key_code);
		fprintf(f, "\t\t<field name='include_enable' type='uint32_t' width='7'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.include_enable);
		fprintf(f, "\t\t<field name='one_port_map_indicator' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.one_port_map_indicator);
		fprintf(f, "\t\t<field name='activity' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.activity);
		fprintf(f, "\t\t<field name='zero_limitation' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.zero_limitation);
		fprintf(f, "\t\t<field name='zero_dynamic_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.zero_dynamic_enable);
		fprintf(f, "\t\t<field name='msf_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.msf_enable);
		fprintf(f, "\t\t<field name='source_filter_pointer' type='uint32_t' width='9'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.source_filter_pointer);
		fprintf(f, "\t\t<field name='igmp' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.igmp);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='2'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.unused3);
		fprintf(f, "\t\t<field name='dummy_learning_time_stamp' type='uint32_t' width='8'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.dummy_learning_time_stamp);
		fprintf(f, "\t\t<field name='port_map' type='uint32_t' width='16'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.port_map);
		fprintf(f, "\t\t<field name='next_entry' type='uint32_t' width='14'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.next_entry);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.short_fwd_table_ipv4_mc.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_long_fwd_hash_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_long_fwd_hash_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_LONG_FWD_HASH_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.long_fwd_hash), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.long_fwd_hash.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='16'>0x%x</field>\n", entry.data.long_fwd_hash.unused1);
		fprintf(f, "\t\t<field name='fwd_table_pointer' type='uint32_t' width='14'>0x%x</field>\n", entry.data.long_fwd_hash.fwd_table_pointer);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_hash.unused2);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_hash.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_long_fwd_table_ipv6_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 128 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_long_fwd_table_ipv6'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_LONG_FWD_TABLE_IPV6_ID, TABLE_ENTRY_SIZE(entry.data.long_fwd_table_ipv6), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.long_fwd_table_ipv6.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='ip_address0' type='uint32_t' width='32'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.ip_address0);
		fprintf(f, "\t\t<field name='ip_address1' type='uint32_t' width='32'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.ip_address1);
		fprintf(f, "\t\t<field name='ip_address2' type='uint32_t' width='32'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.ip_address2);
		fprintf(f, "\t\t<field name='ip_address3' type='uint32_t' width='32'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.ip_address3);
		fprintf(f, "\t\t<field name='zero0' type='uint32_t' width='16'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.zero0);
		fprintf(f, "\t\t<field name='fid' type='uint32_t' width='8'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.fid);
		fprintf(f, "\t\t<field name='bridge_index' type='uint32_t' width='3'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.bridge_index);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.unused1);
		fprintf(f, "\t\t<field name='key_code' type='uint32_t' width='4'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.key_code);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='32'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.unused2);
		fprintf(f, "\t\t<field name='bridge_port_index' type='uint32_t' width='7'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.bridge_port_index);
		fprintf(f, "\t\t<field name='zero_port_map_indicator' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.zero_port_map_indicator);
		fprintf(f, "\t\t<field name='dummy_mc_group_active' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.dummy_mc_group_active);
		fprintf(f, "\t\t<field name='zero_limitation' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.zero_limitation);
		fprintf(f, "\t\t<field name='zero_dynamic_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.zero_dynamic_enable);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.unused3);
		fprintf(f, "\t\t<field name='encapsulation_index' type='uint32_t' width='9'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.encapsulation_index);
		fprintf(f, "\t\t<field name='unused4' type='uint32_t' width='3'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.unused4);
		fprintf(f, "\t\t<field name='dummy_learning_time_stamp' type='uint32_t' width='8'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.dummy_learning_time_stamp);
		fprintf(f, "\t\t<field name='unused5' type='uint32_t' width='16'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.unused5);
		fprintf(f, "\t\t<field name='next_entry' type='uint32_t' width='14'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.next_entry);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_long_fwd_table_ipv6_mc_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 0 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_long_fwd_table_ipv6_mc'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_LONG_FWD_TABLE_IPV6_MC_ID, TABLE_ENTRY_SIZE(entry.data.long_fwd_table_ipv6_mc), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.long_fwd_table_ipv6_mc.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='ip_address0' type='uint32_t' width='32'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.ip_address0);
		fprintf(f, "\t\t<field name='ip_address1' type='uint32_t' width='32'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.ip_address1);
		fprintf(f, "\t\t<field name='ip_address2' type='uint32_t' width='32'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.ip_address2);
		fprintf(f, "\t\t<field name='ip_address3' type='uint32_t' width='32'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.ip_address3);
		fprintf(f, "\t\t<field name='zero0' type='uint32_t' width='16'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.zero0);
		fprintf(f, "\t\t<field name='fid' type='uint32_t' width='8'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.fid);
		fprintf(f, "\t\t<field name='bridge_index' type='uint32_t' width='3'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.bridge_index);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.unused1);
		fprintf(f, "\t\t<field name='key_code' type='uint32_t' width='4'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.key_code);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='32'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.unused2);
		fprintf(f, "\t\t<field name='include_enable' type='uint32_t' width='7'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.include_enable);
		fprintf(f, "\t\t<field name='one_port_map_indicator' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.one_port_map_indicator);
		fprintf(f, "\t\t<field name='mc_group_active' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.mc_group_active);
		fprintf(f, "\t\t<field name='zero_limitation' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.zero_limitation);
		fprintf(f, "\t\t<field name='zero_dynamic_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.zero_dynamic_enable);
		fprintf(f, "\t\t<field name='msf_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.msf_enable);
		fprintf(f, "\t\t<field name='source_filter_pointer' type='uint32_t' width='9'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.source_filter_pointer);
		fprintf(f, "\t\t<field name='igmp' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.igmp);
		fprintf(f, "\t\t<field name='unused4' type='uint32_t' width='2'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.unused4);
		fprintf(f, "\t\t<field name='dummy_learning_time_stamp' type='uint32_t' width='8'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.dummy_learning_time_stamp);
		fprintf(f, "\t\t<field name='port_map' type='uint32_t' width='16'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.port_map);
		fprintf(f, "\t\t<field name='next_entry' type='uint32_t' width='14'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.next_entry);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.long_fwd_table_ipv6_mc.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_ds_mc_ipv4_source_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 512 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_ds_mc_ipv4_source_filter_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.ds_mc_ipv4_source_filter), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.ds_mc_ipv4_source_filter.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='ip_address' type='uint32_t' width='32'>0x%x</field>\n", entry.data.ds_mc_ipv4_source_filter.ip_address);
		fprintf(f, "\t\t<field name='port_map' type='uint32_t' width='4'>0x%x</field>\n", entry.data.ds_mc_ipv4_source_filter.port_map);
		fprintf(f, "\t\t<field name='unused' type='uint32_t' width='26'>0x%x</field>\n", entry.data.ds_mc_ipv4_source_filter.unused);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_mc_ipv4_source_filter.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_mc_ipv4_source_filter.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_ds_mc_ipv6_source_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 128 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_ds_mc_ipv6_source_filter_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.ds_mc_ipv6_source_filter), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.ds_mc_ipv6_source_filter.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='ip_address0' type='uint32_t' width='32'>0x%x</field>\n", entry.data.ds_mc_ipv6_source_filter.ip_address0);
		fprintf(f, "\t\t<field name='ip_address1' type='uint32_t' width='32'>0x%x</field>\n", entry.data.ds_mc_ipv6_source_filter.ip_address1);
		fprintf(f, "\t\t<field name='ip_address2' type='uint32_t' width='32'>0x%x</field>\n", entry.data.ds_mc_ipv6_source_filter.ip_address2);
		fprintf(f, "\t\t<field name='ip_address3' type='uint32_t' width='32'>0x%x</field>\n", entry.data.ds_mc_ipv6_source_filter.ip_address3);
		fprintf(f, "\t\t<field name='port_map' type='uint32_t' width='4'>0x%x</field>\n", entry.data.ds_mc_ipv6_source_filter.port_map);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='28'>0x%x</field>\n", entry.data.ds_mc_ipv6_source_filter.unused1);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='32'>0x%x</field>\n", entry.data.ds_mc_ipv6_source_filter.unused2);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='32'>0x%x</field>\n", entry.data.ds_mc_ipv6_source_filter.unused3);
		fprintf(f, "\t\t<field name='unused4' type='uint32_t' width='30'>0x%x</field>\n", entry.data.ds_mc_ipv6_source_filter.unused4);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_mc_ipv6_source_filter.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ds_mc_ipv6_source_filter.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_learning_limitation_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 128 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_learning_limitation_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_LEARNING_LIMITATION_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.learning_limitation), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='association_count' type='uint32_t' width='16'>0x%x</field>\n", entry.data.learning_limitation.association_count);
		fprintf(f, "\t\t<field name='learning_limit' type='uint32_t' width='16'>0x%x</field>\n", entry.data.learning_limitation.learning_limit);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_lan_port_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 8 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_lan_port_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_LAN_PORT_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.lan_port), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.lan_port.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='interworking_index' type='uint32_t' width='7'>0x%x</field>\n", entry.data.lan_port.interworking_index);
		fprintf(f, "\t\t<field name='interworking_option' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.interworking_option);
		fprintf(f, "\t\t<field name='base_queue_index' type='uint32_t' width='8'>0x%x</field>\n", entry.data.lan_port.base_queue_index);
		fprintf(f, "\t\t<field name='cfm_meter_id' type='uint32_t' width='9'>0x%x</field>\n", entry.data.lan_port.cfm_meter_id);
		fprintf(f, "\t\t<field name='cfm_meter_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.cfm_meter_enable);
		fprintf(f, "\t\t<field name='pppoe_filter_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.pppoe_filter_enable);
		fprintf(f, "\t\t<field name='ext_vlan_mc_enable_egress' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.ext_vlan_mc_enable_egress);
		fprintf(f, "\t\t<field name='fid_mask_vido' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.fid_mask_vido);
		fprintf(f, "\t\t<field name='fid_mask_vidi' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.fid_mask_vidi);
		fprintf(f, "\t\t<field name='fid_mask_pcpo' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.fid_mask_pcpo);
		fprintf(f, "\t\t<field name='fid_mask_pcpi' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.fid_mask_pcpi);
		fprintf(f, "\t\t<field name='ext_vlan_index_ingress' type='uint32_t' width='7'>0x%x</field>\n", entry.data.lan_port.ext_vlan_index_ingress);
		fprintf(f, "\t\t<field name='ext_vlan_enable_ingress' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.ext_vlan_enable_ingress);
		fprintf(f, "\t\t<field name='ext_vlan_index_egress' type='uint32_t' width='7'>0x%x</field>\n", entry.data.lan_port.ext_vlan_index_egress);
		fprintf(f, "\t\t<field name='ext_vlan_enable_egress' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.ext_vlan_enable_egress);
		fprintf(f, "\t\t<field name='ext_vlan_egress_mode' type='uint32_t' width='2'>0x%x</field>\n", entry.data.lan_port.ext_vlan_egress_mode);
		fprintf(f, "\t\t<field name='ext_vlan_ingress_mode' type='uint32_t' width='2'>0x%x</field>\n", entry.data.lan_port.ext_vlan_ingress_mode);
		fprintf(f, "\t\t<field name='ext_vlan_incremental_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.ext_vlan_incremental_enable);
		fprintf(f, "\t\t<field name='ethertype_filter_pointer' type='uint32_t' width='6'>0x%x</field>\n", entry.data.lan_port.ethertype_filter_pointer);
		fprintf(f, "\t\t<field name='ethertype_filter_mode' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.ethertype_filter_mode);
		fprintf(f, "\t\t<field name='ethertype_filter_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.ethertype_filter_enable);
		fprintf(f, "\t\t<field name='lan_loopback_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.lan_loopback_enable);
		fprintf(f, "\t\t<field name='lan_mac_swap_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.lan_mac_swap_enable);
		fprintf(f, "\t\t<field name='ext_vlan_mc_enable_ingress' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.ext_vlan_mc_enable_ingress);
		fprintf(f, "\t\t<field name='queue_marking_mode' type='uint32_t' width='3'>0x%x</field>\n", entry.data.lan_port.queue_marking_mode);
		fprintf(f, "\t\t<field name='dscp_table_pointer' type='uint32_t' width='3'>0x%x</field>\n", entry.data.lan_port.dscp_table_pointer);
		fprintf(f, "\t\t<field name='acl_filter_mode' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.acl_filter_mode);
		fprintf(f, "\t\t<field name='acl_filter_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.acl_filter_enable);
		fprintf(f, "\t\t<field name='acl_filter_index' type='uint32_t' width='8'>0x%x</field>\n", entry.data.lan_port.acl_filter_index);
		fprintf(f, "\t\t<field name='exception_profile' type='uint32_t' width='3'>0x%x</field>\n", entry.data.lan_port.exception_profile);
		fprintf(f, "\t\t<field name='igmp_except_meter_id' type='uint32_t' width='9'>0x%x</field>\n", entry.data.lan_port.igmp_except_meter_id);
		fprintf(f, "\t\t<field name='igmp_except_meter_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.igmp_except_meter_enable);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='3'>0x%x</field>\n", entry.data.lan_port.unused3);
		fprintf(f, "\t\t<field name='uni_except_meter_id' type='uint32_t' width='9'>0x%x</field>\n", entry.data.lan_port.uni_except_meter_id);
		fprintf(f, "\t\t<field name='uni_except_meter_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.uni_except_meter_enable);
		fprintf(f, "\t\t<field name='policer_threshold' type='uint32_t' width='21'>0x%x</field>\n", entry.data.lan_port.policer_threshold);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.lan_port.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_pcp_decoding_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 32 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_pcp_decoding_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_PCP_DECODING_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.pcp_decoding), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='priority' type='uint8_t' width='3'>0x%x</field>\n", entry.data.pcp_decoding.priority);
		fprintf(f, "\t\t<field name='de' type='uint8_t' width='1'>0x%x</field>\n", entry.data.pcp_decoding.de);
		fprintf(f, "\t\t<field name='color' type='uint8_t' width='2'>0x%x</field>\n", entry.data.pcp_decoding.color);
		fprintf(f, "\t\t<field name='unused' type='uint8_t' width='2'>0x%x</field>\n", entry.data.pcp_decoding.unused);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_dscp_decoding_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 512 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_dscp_decoding_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_DSCP_DECODING_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.dscp_decoding), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='pcp' type='uint8_t' width='3'>0x%x</field>\n", entry.data.dscp_decoding.pcp);
		fprintf(f, "\t\t<field name='de' type='uint8_t' width='1'>0x%x</field>\n", entry.data.dscp_decoding.de);
		fprintf(f, "\t\t<field name='color' type='uint8_t' width='2'>0x%x</field>\n", entry.data.dscp_decoding.color);
		fprintf(f, "\t\t<field name='unused' type='uint8_t' width='2'>0x%x</field>\n", entry.data.dscp_decoding.unused);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_pcp_encoding_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 64 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_pcp_encoding_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_PCP_ENCODING_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.pcp_encoding), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='pcp' type='uint8_t' width='3'>0x%x</field>\n", entry.data.pcp_encoding.pcp);
		fprintf(f, "\t\t<field name='unused' type='uint8_t' width='5'>0x%x</field>\n", entry.data.pcp_encoding.unused);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_dscp_encoding_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 32 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_dscp_encoding_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_DSCP_ENCODING_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.dscp_encoding), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='dscp' type='uint8_t' width='6'>0x%x</field>\n", entry.data.dscp_encoding.dscp);
		fprintf(f, "\t\t<field name='unused' type='uint8_t' width='2'>0x%x</field>\n", entry.data.dscp_encoding.unused);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_exception_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 8 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_exception_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_EXCEPTION_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.exception), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='ingress_exception_flag_mask' type='uint32_t' width='32'>0x%x</field>\n", entry.data.exception.ingress_exception_flag_mask);
		fprintf(f, "\t\t<field name='egress_exception_flag_mask' type='uint32_t' width='32'>0x%x</field>\n", entry.data.exception.egress_exception_flag_mask);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_redirection_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 32 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_redirection_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_REDIRECTION_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.redirection), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='redirection_queue_index' type='uint32_t' width='8'>0x%x</field>\n", entry.data.redirection.redirection_queue_index);
		fprintf(f, "\t\t<field name='snooping_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.redirection.snooping_enable);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='7'>0x%x</field>\n", entry.data.redirection.unused1);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='16'>0x%x</field>\n", entry.data.redirection.unused2);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_mac_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 256 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_mac_filter_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_MAC_FILTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.mac_filter), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.mac_filter.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='mac_address_low' type='uint32_t' width='32'>0x%x</field>\n", entry.data.mac_filter.mac_address_low);
		fprintf(f, "\t\t<field name='mac_address_high' type='uint32_t' width='16'>0x%x</field>\n", entry.data.mac_filter.mac_address_high);
		fprintf(f, "\t\t<field name='key_code' type='uint32_t' width='3'>0x%x</field>\n", entry.data.mac_filter.key_code);
		fprintf(f, "\t\t<field name='unused' type='uint32_t' width='11'>0x%x</field>\n", entry.data.mac_filter.unused);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.mac_filter.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.mac_filter.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_acl_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 32 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_acl_filter_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_ACL_FILTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.acl_filter), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.acl_filter.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='parameter10' type='uint32_t' width='32'>0x%x</field>\n", entry.data.acl_filter.parameter10);
		fprintf(f, "\t\t<field name='parameter11' type='uint32_t' width='32'>0x%x</field>\n", entry.data.acl_filter.parameter11);
		fprintf(f, "\t\t<field name='parameter12' type='uint32_t' width='32'>0x%x</field>\n", entry.data.acl_filter.parameter12);
		fprintf(f, "\t\t<field name='parameter13' type='uint32_t' width='32'>0x%x</field>\n", entry.data.acl_filter.parameter13);
		fprintf(f, "\t\t<field name='parameter200' type='uint32_t' width='32'>0x%x</field>\n", entry.data.acl_filter.parameter200);
		fprintf(f, "\t\t<field name='parameter21' type='uint32_t' width='16'>0x%x</field>\n", entry.data.acl_filter.parameter21);
		fprintf(f, "\t\t<field name='parameter201' type='uint32_t' width='16'>0x%x</field>\n", entry.data.acl_filter.parameter201);
		fprintf(f, "\t\t<field name='parameter_mask1' type='uint32_t' width='32'>0x%x</field>\n", entry.data.acl_filter.parameter_mask1);
		fprintf(f, "\t\t<field name='fid' type='uint32_t' width='8'>0x%x</field>\n", entry.data.acl_filter.fid);
		fprintf(f, "\t\t<field name='layer2_disable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.layer2_disable);
		fprintf(f, "\t\t<field name='fid_disable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.fid_disable);
		fprintf(f, "\t\t<field name='layer3_disable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.layer3_disable);
		fprintf(f, "\t\t<field name='layer4_disable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.layer4_disable);
		fprintf(f, "\t\t<field name='layer2_compare' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.layer2_compare);
		fprintf(f, "\t\t<field name='layer2_mac_address_compare' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.layer2_mac_address_compare);
		fprintf(f, "\t\t<field name='layer3_compare' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.layer3_compare);
		fprintf(f, "\t\t<field name='layer3_ip_address_compare' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.layer3_ip_address_compare);
		fprintf(f, "\t\t<field name='layer4_port_compare' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.layer4_port_compare);
		fprintf(f, "\t\t<field name='layer4_tcp_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.layer4_tcp_enable);
		fprintf(f, "\t\t<field name='layer4_udp_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.layer4_udp_enable);
		fprintf(f, "\t\t<field name='ingress_port_lan0' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.ingress_port_lan0);
		fprintf(f, "\t\t<field name='ingress_port_lan1' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.ingress_port_lan1);
		fprintf(f, "\t\t<field name='ingress_port_lan2' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.ingress_port_lan2);
		fprintf(f, "\t\t<field name='ingress_port_lan3' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.ingress_port_lan3);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='7'>0x%x</field>\n", entry.data.acl_filter.unused1);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_acl_filter_table2_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 32 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_acl_filter_table2'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_ACL_FILTER_TABLE_2_ID, TABLE_ENTRY_SIZE(entry.data.acl_filter_table2), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.acl_filter_table2.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='parameter10' type='uint32_t' width='32'>0x%x</field>\n", entry.data.acl_filter_table2.parameter10);
		fprintf(f, "\t\t<field name='parameter11' type='uint32_t' width='32'>0x%x</field>\n", entry.data.acl_filter_table2.parameter11);
		fprintf(f, "\t\t<field name='parameter12' type='uint32_t' width='32'>0x%x</field>\n", entry.data.acl_filter_table2.parameter12);
		fprintf(f, "\t\t<field name='parameter13' type='uint32_t' width='32'>0x%x</field>\n", entry.data.acl_filter_table2.parameter13);
		fprintf(f, "\t\t<field name='parameter200' type='uint32_t' width='32'>0x%x</field>\n", entry.data.acl_filter_table2.parameter200);
		fprintf(f, "\t\t<field name='parameter21' type='uint32_t' width='16'>0x%x</field>\n", entry.data.acl_filter_table2.parameter21);
		fprintf(f, "\t\t<field name='parameter201' type='uint32_t' width='16'>0x%x</field>\n", entry.data.acl_filter_table2.parameter201);
		fprintf(f, "\t\t<field name='parameter_mask1' type='uint32_t' width='32'>0x%x</field>\n", entry.data.acl_filter_table2.parameter_mask1);
		fprintf(f, "\t\t<field name='fid' type='uint32_t' width='8'>0x%x</field>\n", entry.data.acl_filter_table2.fid);
		fprintf(f, "\t\t<field name='layer2_disable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.layer2_disable);
		fprintf(f, "\t\t<field name='fid_disable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.fid_disable);
		fprintf(f, "\t\t<field name='layer3_disable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.layer3_disable);
		fprintf(f, "\t\t<field name='layer4_disable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.layer4_disable);
		fprintf(f, "\t\t<field name='layer2_compare' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.layer2_compare);
		fprintf(f, "\t\t<field name='layer2_mac_address_compare' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.layer2_mac_address_compare);
		fprintf(f, "\t\t<field name='layer3_compare' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.layer3_compare);
		fprintf(f, "\t\t<field name='layer3_ip_address_compare' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.layer3_ip_address_compare);
		fprintf(f, "\t\t<field name='layer4_port_compare' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.layer4_port_compare);
		fprintf(f, "\t\t<field name='layer4_tcp_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.layer4_tcp_enable);
		fprintf(f, "\t\t<field name='layer4_udp_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.layer4_udp_enable);
		fprintf(f, "\t\t<field name='ingress_port_lan0' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.ingress_port_lan0);
		fprintf(f, "\t\t<field name='ingress_port_lan1' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.ingress_port_lan1);
		fprintf(f, "\t\t<field name='ingress_port_lan2' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.ingress_port_lan2);
		fprintf(f, "\t\t<field name='ingress_port_lan3' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.ingress_port_lan3);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='7'>0x%x</field>\n", entry.data.acl_filter_table2.unused1);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.acl_filter_table2.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_bridge_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 8 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_bridge_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_BRIDGE_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.bridge), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='uuc_meter_id' type='uint32_t' width='9'>0x%x</field>\n", entry.data.bridge.uuc_meter_id);
		fprintf(f, "\t\t<field name='unused1' type='uint32_t' width='6'>0x%x</field>\n", entry.data.bridge.unused1);
		fprintf(f, "\t\t<field name='uuc_meter_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.uuc_meter_enable);
		fprintf(f, "\t\t<field name='mc_meter_id' type='uint32_t' width='9'>0x%x</field>\n", entry.data.bridge.mc_meter_id);
		fprintf(f, "\t\t<field name='unused2' type='uint32_t' width='6'>0x%x</field>\n", entry.data.bridge.unused2);
		fprintf(f, "\t\t<field name='mc_meter_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.mc_meter_enable);
		fprintf(f, "\t\t<field name='bc_meter_id' type='uint32_t' width='9'>0x%x</field>\n", entry.data.bridge.bc_meter_id);
		fprintf(f, "\t\t<field name='unused3' type='uint32_t' width='6'>0x%x</field>\n", entry.data.bridge.unused3);
		fprintf(f, "\t\t<field name='bc_meter_enable' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.bc_meter_enable);
		fprintf(f, "\t\t<field name='flooding_bridge_port_enable' type='uint32_t' width='16'>0x%x</field>\n", entry.data.bridge.flooding_bridge_port_enable);
		fprintf(f, "\t\t<field name='egress_bridge_port_index0' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index0);
		fprintf(f, "\t\t<field name='unused10' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused10);
		fprintf(f, "\t\t<field name='egress_bridge_port_index1' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index1);
		fprintf(f, "\t\t<field name='unused11' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused11);
		fprintf(f, "\t\t<field name='egress_bridge_port_index2' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index2);
		fprintf(f, "\t\t<field name='unused12' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused12);
		fprintf(f, "\t\t<field name='egress_bridge_port_index3' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index3);
		fprintf(f, "\t\t<field name='unused13' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused13);
		fprintf(f, "\t\t<field name='egress_bridge_port_index4' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index4);
		fprintf(f, "\t\t<field name='unused14' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused14);
		fprintf(f, "\t\t<field name='egress_bridge_port_index5' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index5);
		fprintf(f, "\t\t<field name='unused15' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused15);
		fprintf(f, "\t\t<field name='egress_bridge_port_index6' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index6);
		fprintf(f, "\t\t<field name='unused16' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused16);
		fprintf(f, "\t\t<field name='egress_bridge_port_index7' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index7);
		fprintf(f, "\t\t<field name='unused17' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused17);
		fprintf(f, "\t\t<field name='egress_bridge_port_index8' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index8);
		fprintf(f, "\t\t<field name='unused18' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused18);
		fprintf(f, "\t\t<field name='egress_bridge_port_index9' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index9);
		fprintf(f, "\t\t<field name='unused19' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused19);
		fprintf(f, "\t\t<field name='egress_bridge_port_index10' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index10);
		fprintf(f, "\t\t<field name='unused20' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused20);
		fprintf(f, "\t\t<field name='egress_bridge_port_index11' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index11);
		fprintf(f, "\t\t<field name='unused21' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused21);
		fprintf(f, "\t\t<field name='egress_bridge_port_index12' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index12);
		fprintf(f, "\t\t<field name='unused22' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused22);
		fprintf(f, "\t\t<field name='egress_bridge_port_index13' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index13);
		fprintf(f, "\t\t<field name='unused23' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused23);
		fprintf(f, "\t\t<field name='egress_bridge_port_index14' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index14);
		fprintf(f, "\t\t<field name='unused24' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused24);
		fprintf(f, "\t\t<field name='egress_bridge_port_index15' type='uint32_t' width='7'>0x%x</field>\n", entry.data.bridge.egress_bridge_port_index15);
		fprintf(f, "\t\t<field name='unused25' type='uint32_t' width='1'>0x%x</field>\n", entry.data.bridge.unused25);
		fprintf(f, "\t\t<field name='unused26' type='uint32_t' width='32'>0x%x</field>\n", entry.data.bridge.unused26);
		fprintf(f, "\t\t<field name='unused27' type='uint32_t' width='32'>0x%x</field>\n", entry.data.bridge.unused27);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_ethertype_exception_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 8 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_ethertype_exception_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_ETHERTYPE_EXCEPTION_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.ethertype_exception), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='spec_ethertype' type='uint16_t' width='16'>0x%x</field>\n", entry.data.ethertype_exception.spec_ethertype);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_ethertype_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 64 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_ethertype_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_ETHERTYPE_FILTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.ethertype), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.ethertype.valid == 0)
			continue;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='ethertype' type='uint32_t' width='16'>0x%x</field>\n", entry.data.ethertype.ethertype);
		fprintf(f, "\t\t<field name='unused' type='uint32_t' width='14'>0x%x</field>\n", entry.data.ethertype.unused);
		fprintf(f, "\t\t<field name='end' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ethertype.end);
		fprintf(f, "\t\t<field name='valid' type='uint32_t' width='1'>0x%x</field>\n", entry.data.ethertype.valid);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_enqueue_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 8 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_enqueue_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_ENQUEUE_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.enqueue), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='enable' type='uint32_t' width='32'>0x%x</field>\n", entry.data.enqueue.enable);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_counter_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 704 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_counter_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_COUNTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.counter), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='counter_value' type='uint32_t' width='32'>0x%x</field>\n", entry.data.counter.counter_value);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_status_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 25 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_status_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_STATUS_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.status), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='entry_data' type='uint32_t' width='32'>0x%x</field>\n", entry.data.status.entry_data);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_gpe_constants_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 18 - 1;
	uint32_t i;

	fprintf(f, "<table name='gpe_constants_table'>\n");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_CONSTANTS_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.constants), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, "\t<entry index='%u'>\n", i);
		fprintf(f, "\t\t<field name='entry_data' type='uint32_t' width='32'>0x%x</field>\n", entry.data.constants.entry_data);
		fprintf(f, "\t</entry>\n");
	}

	fprintf(f, "</table>\n");

	return 0;
}

int xml_table_by_id_get(FILE *f, uint32_t table_id, int onu_id, uint8_t instance, int index)
{
	unsigned int i;
	struct table_by_id tables[] = {
		{ ONU_GPE_DS_GEM_PORT_TABLE_ID, xml_gpe_ds_gem_port_table_get },
		{ ONU_GPE_US_GEM_PORT_TABLE_ID, xml_gpe_us_gem_port_table_get },
		{ ONU_GPE_FID_ASSIGNMENT_TABLE_ID, xml_gpe_fwd_id_table_get },
		{ ONU_GPE_FID_HASH_TABLE_ID, xml_gpe_fwd_id_hash_table_get },
		{ ONU_GPE_BRIDGE_PORT_TABLE_ID, xml_gpe_bridge_port_table_get },
		{ ONU_GPE_TAGGING_FILTER_TABLE_ID, xml_gpe_tagging_filter_table_get },
		{ ONU_GPE_VLAN_TABLE_ID, xml_gpe_vlan_table_get },
		{ ONU_GPE_EXTENDED_VLAN_TABLE_ID, xml_gpe_extended_vlan_table_get },
		{ ONU_GPE_VLAN_RULE_TABLE_ID, xml_gpe_vlan_rule_table_get },
		{ ONU_GPE_VLAN_TREATMENT_TABLE_ID, xml_gpe_vlan_treatment_table_get },
		{ ONU_GPE_PMAPPER_TABLE_ID, xml_gpe_pmapper_table_get },
		{ ONU_GPE_SHORT_FWD_HASH_TABLE_ID, xml_gpe_short_fwd_hash_table_get },
		{ ONU_GPE_SHORT_FWD_TABLE_MAC_ID, xml_gpe_short_fwd_table_mac_get },
		{ ONU_GPE_SHORT_FWD_TABLE_MAC_MC_ID, xml_gpe_short_fwd_table_mac_mc_get },
		{ ONU_GPE_SHORT_FWD_TABLE_IPV4_ID, xml_gpe_short_fwd_table_ipv4_get },
		{ ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ID, xml_gpe_short_fwd_table_ipv4_mc_get },
		{ ONU_GPE_LONG_FWD_HASH_TABLE_ID, xml_gpe_long_fwd_hash_table_get },
		{ ONU_GPE_LONG_FWD_TABLE_IPV6_ID, xml_gpe_long_fwd_table_ipv6_get },
		{ ONU_GPE_LONG_FWD_TABLE_IPV6_MC_ID, xml_gpe_long_fwd_table_ipv6_mc_get },
		{ ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_ID, xml_gpe_ds_mc_ipv4_source_filter_table_get },
		{ ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_ID, xml_gpe_ds_mc_ipv6_source_filter_table_get },
		{ ONU_GPE_LEARNING_LIMITATION_TABLE_ID, xml_gpe_learning_limitation_table_get },
		{ ONU_GPE_LAN_PORT_TABLE_ID, xml_gpe_lan_port_table_get },
		{ ONU_GPE_PCP_DECODING_TABLE_ID, xml_gpe_pcp_decoding_table_get },
		{ ONU_GPE_DSCP_DECODING_TABLE_ID, xml_gpe_dscp_decoding_table_get },
		{ ONU_GPE_PCP_ENCODING_TABLE_ID, xml_gpe_pcp_encoding_table_get },
		{ ONU_GPE_DSCP_ENCODING_TABLE_ID, xml_gpe_dscp_encoding_table_get },
		{ ONU_GPE_EXCEPTION_TABLE_ID, xml_gpe_exception_table_get },
		{ ONU_GPE_REDIRECTION_TABLE_ID, xml_gpe_redirection_table_get },
		{ ONU_GPE_MAC_FILTER_TABLE_ID, xml_gpe_mac_filter_table_get },
		{ ONU_GPE_ACL_FILTER_TABLE_ID, xml_gpe_acl_filter_table_get },
		{ ONU_GPE_ACL_FILTER_TABLE_2_ID, xml_gpe_acl_filter_table2_get },
		{ ONU_GPE_BRIDGE_TABLE_ID, xml_gpe_bridge_table_get },
		{ ONU_GPE_ETHERTYPE_EXCEPTION_TABLE_ID, xml_gpe_ethertype_exception_table_get },
		{ ONU_GPE_ETHERTYPE_FILTER_TABLE_ID, xml_gpe_ethertype_table_get },
		{ ONU_GPE_ENQUEUE_TABLE_ID, xml_gpe_enqueue_table_get },
		{ ONU_GPE_COUNTER_TABLE_ID, xml_gpe_counter_table_get },
		{ ONU_GPE_STATUS_TABLE_ID, xml_gpe_status_table_get },
		{ ONU_GPE_CONSTANTS_TABLE_ID, xml_gpe_constants_table_get },
	};

	for (i = 0; i < ARRAY_SIZE(tables); i++)
		if (tables[i].id == table_id)
			return tables[i].handler(f, onu_id, instance, index);

	return -1;
}

int xml_table_by_name_get(FILE *f, const char *table_name, int onu_id, uint8_t instance, int index)
{
	unsigned int i;
	struct table_by_name tables[] = {
		{ "gpe_ds_gem_port_table", xml_gpe_ds_gem_port_table_get },
		{ "gpe_us_gem_port_table", xml_gpe_us_gem_port_table_get },
		{ "gpe_fwd_id_table", xml_gpe_fwd_id_table_get },
		{ "gpe_fwd_id_hash_table", xml_gpe_fwd_id_hash_table_get },
		{ "gpe_bridge_port_table", xml_gpe_bridge_port_table_get },
		{ "gpe_tagging_filter_table", xml_gpe_tagging_filter_table_get },
		{ "gpe_vlan_table", xml_gpe_vlan_table_get },
		{ "gpe_extended_vlan_table", xml_gpe_extended_vlan_table_get },
		{ "gpe_vlan_rule_table", xml_gpe_vlan_rule_table_get },
		{ "gpe_vlan_treatment_table", xml_gpe_vlan_treatment_table_get },
		{ "gpe_pmapper_table", xml_gpe_pmapper_table_get },
		{ "gpe_short_fwd_hash_table", xml_gpe_short_fwd_hash_table_get },
		{ "gpe_short_fwd_table_mac", xml_gpe_short_fwd_table_mac_get },
		{ "gpe_short_fwd_table_mac_mc", xml_gpe_short_fwd_table_mac_mc_get },
		{ "gpe_short_fwd_table_ipv4", xml_gpe_short_fwd_table_ipv4_get },
		{ "gpe_short_fwd_table_ipv4_mc", xml_gpe_short_fwd_table_ipv4_mc_get },
		{ "gpe_long_fwd_hash_table", xml_gpe_long_fwd_hash_table_get },
		{ "gpe_long_fwd_table_ipv6", xml_gpe_long_fwd_table_ipv6_get },
		{ "gpe_long_fwd_table_ipv6_mc", xml_gpe_long_fwd_table_ipv6_mc_get },
		{ "gpe_ds_mc_ipv4_source_filter_table", xml_gpe_ds_mc_ipv4_source_filter_table_get },
		{ "gpe_ds_mc_ipv6_source_filter_table", xml_gpe_ds_mc_ipv6_source_filter_table_get },
		{ "gpe_learning_limitation_table", xml_gpe_learning_limitation_table_get },
		{ "gpe_lan_port_table", xml_gpe_lan_port_table_get },
		{ "gpe_pcp_decoding_table", xml_gpe_pcp_decoding_table_get },
		{ "gpe_dscp_decoding_table", xml_gpe_dscp_decoding_table_get },
		{ "gpe_pcp_encoding_table", xml_gpe_pcp_encoding_table_get },
		{ "gpe_dscp_encoding_table", xml_gpe_dscp_encoding_table_get },
		{ "gpe_exception_table", xml_gpe_exception_table_get },
		{ "gpe_redirection_table", xml_gpe_redirection_table_get },
		{ "gpe_mac_filter_table", xml_gpe_mac_filter_table_get },
		{ "gpe_acl_filter_table", xml_gpe_acl_filter_table_get },
		{ "gpe_acl_filter_table2", xml_gpe_acl_filter_table2_get },
		{ "gpe_bridge_table", xml_gpe_bridge_table_get },
		{ "gpe_ethertype_exception_table", xml_gpe_ethertype_exception_table_get },
		{ "gpe_ethertype_table", xml_gpe_ethertype_table_get },
		{ "gpe_enqueue_table", xml_gpe_enqueue_table_get },
		{ "gpe_counter_table", xml_gpe_counter_table_get },
		{ "gpe_status_table", xml_gpe_status_table_get },
		{ "gpe_constants_table", xml_gpe_constants_table_get },
	};

	for (i = 0; i < ARRAY_SIZE(tables); i++)
		if (strcmp(tables[i].name, table_name) == 0)
			return tables[i].handler(f, onu_id, instance, index);

	return -1;
}
