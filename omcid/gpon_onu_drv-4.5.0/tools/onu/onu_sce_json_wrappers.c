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

int json_gpe_ds_gem_port_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 256 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_ds_gem_port_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_DS_GEM_PORT_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.ds_gem_port), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.ds_gem_port.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"bridge_port_index0\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.bridge_port_index0);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.unused1);
		fprintf(f, ",\n\t\t\"bridge_port_index1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.bridge_port_index1);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.unused2);
		fprintf(f, ",\n\t\t\"bridge_port_index2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.bridge_port_index2);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.unused3);
		fprintf(f, ",\n\t\t\"bridge_port_index3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.bridge_port_index3);
		fprintf(f, ",\n\t\t\"unused4\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.unused4);
		fprintf(f, ",\n\t\t\"bridge_port_index4\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.bridge_port_index4);
		fprintf(f, ",\n\t\t\"unused5\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.unused5);
		fprintf(f, ",\n\t\t\"bridge_port_index5\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.bridge_port_index5);
		fprintf(f, ",\n\t\t\"unused6\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.unused6);
		fprintf(f, ",\n\t\t\"bridge_port_index6\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.bridge_port_index6);
		fprintf(f, ",\n\t\t\"unused7\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.unused7);
		fprintf(f, ",\n\t\t\"bridge_port_index7\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.bridge_port_index7);
		fprintf(f, ",\n\t\t\"unused8\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.unused8);
		fprintf(f, ",\n\t\t\"ds_gem_meter_id\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.ds_gem_meter_id);
		fprintf(f, ",\n\t\t\"ds_gem_meter_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.ds_gem_meter_enable);
		fprintf(f, ",\n\t\t\"ext_vlan_ingress_mode\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.ext_vlan_ingress_mode);
		fprintf(f, ",\n\t\t\"unused10\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.unused10);
		fprintf(f, ",\n\t\t\"ext_vlan_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.ext_vlan_index);
		fprintf(f, ",\n\t\t\"ext_vlan_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.ext_vlan_enable);
		fprintf(f, ",\n\t\t\"exception_profile\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.exception_profile);
		fprintf(f, ",\n\t\t\"unused11\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.unused11);
		fprintf(f, ",\n\t\t\"ingress_color_marking\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.ingress_color_marking);
		fprintf(f, ",\n\t\t\"dscp_table_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.dscp_table_pointer);
		fprintf(f, ",\n\t\t\"interworking_option\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.interworking_option);
		fprintf(f, ",\n\t\t\"egress_queue_offset\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.egress_queue_offset);
		fprintf(f, ",\n\t\t\"unused12\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"6\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.unused12);
		fprintf(f, ",\n\t\t\"max_bridge_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.max_bridge_index);
		fprintf(f, ",\n\t\t\"unused13\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.unused13);
		fprintf(f, ",\n\t\t\"lan_port_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.lan_port_index);
		fprintf(f, ",\n\t\t\"gem_port_type\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.gem_port_type);
		fprintf(f, ",\n\t\t\"queue_selection_mode\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.queue_selection_mode);
		fprintf(f, ",\n\t\t\"napt_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.napt_enable);
		fprintf(f, ",\n\t\t\"pppoe_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.pppoe_enable);
		fprintf(f, ",\n\t\t\"fid_mask_vido\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.fid_mask_vido);
		fprintf(f, ",\n\t\t\"fid_mask_vidi\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.fid_mask_vidi);
		fprintf(f, ",\n\t\t\"fid_mask_pcpo\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.fid_mask_pcpo);
		fprintf(f, ",\n\t\t\"fid_mask_pcpi\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.fid_mask_pcpi);
		fprintf(f, ",\n\t\t\"gem_loopback_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.gem_loopback_enable);
		fprintf(f, ",\n\t\t\"gem_mac_swap_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.gem_mac_swap_enable);
		fprintf(f, ",\n\t\t\"unused15\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.unused15);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_gem_port.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_us_gem_port_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 256 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_us_gem_port_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_US_GEM_PORT_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.us_gem_port), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.us_gem_port.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"egress_queue_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.us_gem_port.egress_queue_index);
		fprintf(f, ",\n\t\t\"ext_vlan_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.us_gem_port.ext_vlan_index);
		fprintf(f, ",\n\t\t\"ext_vlan_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.us_gem_port.ext_vlan_enable);
		fprintf(f, ",\n\t\t\"egress_color_marking\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.us_gem_port.egress_color_marking);
		fprintf(f, ",\n\t\t\"ext_vlan_incremental_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.us_gem_port.ext_vlan_incremental_enable);
		fprintf(f, ",\n\t\t\"ext_vlan_egress_mode\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.us_gem_port.ext_vlan_egress_mode);
		fprintf(f, ",\n\t\t\"queue_marking_mode\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.us_gem_port.queue_marking_mode);
		fprintf(f, ",\n\t\t\"dscp_table_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.us_gem_port.dscp_table_pointer);
		fprintf(f, ",\n\t\t\"exception_profile\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.us_gem_port.exception_profile);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.us_gem_port.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_fwd_id_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 256 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_fwd_id_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_FID_ASSIGNMENT_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.fwd_id), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.fwd_id.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"vid_outer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"12\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id.vid_outer);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id.unused1);
		fprintf(f, ",\n\t\t\"prio_outer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id.prio_outer);
		fprintf(f, ",\n\t\t\"vid_inner\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"12\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id.vid_inner);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id.unused2);
		fprintf(f, ",\n\t\t\"prio_inner\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id.prio_inner);
		fprintf(f, ",\n\t\t\"fid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id.fid);
		fprintf(f, ",\n\t\t\"cross_connect\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id.cross_connect);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id.unused3);
		fprintf(f, ",\n\t\t\"next_entry\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id.next_entry);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_fwd_id_hash_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_fwd_id_hash_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_FID_HASH_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.fwd_id_hash), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.fwd_id_hash.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id_hash.unused1);
		fprintf(f, ",\n\t\t\"fwd_id_assignent_table_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id_hash.fwd_id_assignent_table_pointer);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id_hash.unused2);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.fwd_id_hash.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_bridge_port_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 128 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_bridge_port_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_BRIDGE_PORT_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.bridge_port), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.bridge_port.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"learning_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.learning_enable);
		fprintf(f, ",\n\t\t\"port_lock_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.port_lock_enable);
		fprintf(f, ",\n\t\t\"local_switching_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.local_switching_enable);
		fprintf(f, ",\n\t\t\"uuc_flood_disable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.uuc_flood_disable);
		fprintf(f, ",\n\t\t\"tagging_filter_ingress_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.tagging_filter_ingress_enable);
		fprintf(f, ",\n\t\t\"tagging_filter_egress_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.tagging_filter_egress_enable);
		fprintf(f, ",\n\t\t\"meter_ingress_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.meter_ingress_enable);
		fprintf(f, ",\n\t\t\"meter_egress_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.meter_egress_enable);
		fprintf(f, ",\n\t\t\"umc_flood_disable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.umc_flood_disable);
		fprintf(f, ",\n\t\t\"forwarding_method\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.forwarding_method);
		fprintf(f, ",\n\t\t\"bridge_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.bridge_index);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.unused2);
		fprintf(f, ",\n\t\t\"port_state\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.port_state);
		fprintf(f, ",\n\t\t\"sa_filter_mode\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.sa_filter_mode);
		fprintf(f, ",\n\t\t\"da_filter_mode\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.da_filter_mode);
		fprintf(f, ",\n\t\t\"ingress_color_marking\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.ingress_color_marking);
		fprintf(f, ",\n\t\t\"egress_color_marking\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.egress_color_marking);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.unused3);
		fprintf(f, ",\n\t\t\"sa_filter_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.sa_filter_pointer);
		fprintf(f, ",\n\t\t\"da_filter_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.da_filter_pointer);
		fprintf(f, ",\n\t\t\"tagging_filter_ingress\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.tagging_filter_ingress);
		fprintf(f, ",\n\t\t\"meter_id_ingress\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.meter_id_ingress);
		fprintf(f, ",\n\t\t\"tagging_filter_egress\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.tagging_filter_egress);
		fprintf(f, ",\n\t\t\"meter_id_egress\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.meter_id_egress);
		fprintf(f, ",\n\t\t\"egress_filter_mask\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"10\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.egress_filter_mask);
		fprintf(f, ",\n\t\t\"dscp_table_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.dscp_table_pointer);
		fprintf(f, ",\n\t\t\"unused4\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.unused4);
		fprintf(f, ",\n\t\t\"tp_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.tp_pointer);
		fprintf(f, ",\n\t\t\"tp_type\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.tp_type);
		fprintf(f, ",\n\t\t\"unused5\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"21\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.unused5);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge_port.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_tagging_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 128 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_tagging_filter_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_TAGGING_FILTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.tagging_filter), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.tagging_filter.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"tci_mask\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.tagging_filter.tci_mask);
		fprintf(f, ",\n\t\t\"untagged_drop_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.tagging_filter.untagged_drop_enable);
		fprintf(f, ",\n\t\t\"tagged_pass_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.tagging_filter.tagged_pass_enable);
		fprintf(f, ",\n\t\t\"tagged_drop_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.tagging_filter.tagged_drop_enable);
		fprintf(f, ",\n\t\t\"pass_on_match_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.tagging_filter.pass_on_match_enable);
		fprintf(f, ",\n\t\t\"unused0\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.tagging_filter.unused0);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"11\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.tagging_filter.unused1);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.tagging_filter.unused2);
		fprintf(f, ",\n\t\t\"vlan_table_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.tagging_filter.vlan_table_index);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.tagging_filter.unused3);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.tagging_filter.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_vlan_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_vlan_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_VLAN_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.vlan), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.vlan.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"tci\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan.tci);
		fprintf(f, ",\n\t\t\"unused\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan.unused);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_extended_vlan_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 128 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_extended_vlan_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_EXTENDED_VLAN_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.extended_vlan), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.extended_vlan.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"input_tpid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.extended_vlan.input_tpid);
		fprintf(f, ",\n\t\t\"output_tpid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.extended_vlan.output_tpid);
		fprintf(f, ",\n\t\t\"dscp_table_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.extended_vlan.dscp_table_pointer);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"13\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.extended_vlan.unused1);
		fprintf(f, ",\n\t\t\"vlan_rule_table_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.extended_vlan.vlan_rule_table_pointer);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.extended_vlan.unused2);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.extended_vlan.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_vlan_rule_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_vlan_rule_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_VLAN_RULE_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.vlan_rule), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.vlan_rule.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"zero_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.zero_enable);
		fprintf(f, ",\n\t\t\"one_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.one_enable);
		fprintf(f, ",\n\t\t\"two_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.two_enable);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"5\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.unused1);
		fprintf(f, ",\n\t\t\"outer_priority_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.outer_priority_enable);
		fprintf(f, ",\n\t\t\"outer_priority_filter\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.outer_priority_filter);
		fprintf(f, ",\n\t\t\"outer_vid_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.outer_vid_enable);
		fprintf(f, ",\n\t\t\"outer_vid_filter\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"12\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.outer_vid_filter);
		fprintf(f, ",\n\t\t\"outer_input_tpid_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.outer_input_tpid_enable);
		fprintf(f, ",\n\t\t\"outer_reg_tpid_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.outer_reg_tpid_enable);
		fprintf(f, ",\n\t\t\"outer_de_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.outer_de_enable);
		fprintf(f, ",\n\t\t\"outer_de_filter\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.outer_de_filter);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.unused2);
		fprintf(f, ",\n\t\t\"inner_priority_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.inner_priority_enable);
		fprintf(f, ",\n\t\t\"inner_priority_filter\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.inner_priority_filter);
		fprintf(f, ",\n\t\t\"inner_vid_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.inner_vid_enable);
		fprintf(f, ",\n\t\t\"inner_vid_filter\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"12\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.inner_vid_filter);
		fprintf(f, ",\n\t\t\"inner_input_tpid_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.inner_input_tpid_enable);
		fprintf(f, ",\n\t\t\"inner_reg_tpid_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.inner_reg_tpid_enable);
		fprintf(f, ",\n\t\t\"inner_de_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.inner_de_enable);
		fprintf(f, ",\n\t\t\"inner_de_filter\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.inner_de_filter);
		fprintf(f, ",\n\t\t\"ethertype_filter1_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.ethertype_filter1_enable);
		fprintf(f, ",\n\t\t\"ethertype_filter2_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.ethertype_filter2_enable);
		fprintf(f, ",\n\t\t\"ethertype_filter3_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.ethertype_filter3_enable);
		fprintf(f, ",\n\t\t\"ethertype_filter4_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.ethertype_filter4_enable);
		fprintf(f, ",\n\t\t\"ethertype_filter5_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.ethertype_filter5_enable);
		fprintf(f, ",\n\t\t\"spare_filter1_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.spare_filter1_enable);
		fprintf(f, ",\n\t\t\"spare_filter2_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.spare_filter2_enable);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.unused3);
		fprintf(f, ",\n\t\t\"def\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.def);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_rule.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_vlan_treatment_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_vlan_treatment_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_VLAN_TREATMENT_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.vlan_treatment), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.vlan_treatment.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"tagb_treatment\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_treatment.tagb_treatment);
		fprintf(f, ",\n\t\t\"tagb_vid_treatment\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"13\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_treatment.tagb_vid_treatment);
		fprintf(f, ",\n\t\t\"tagb_tpid_treatment\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_treatment.tagb_tpid_treatment);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"12\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_treatment.unused1);
		fprintf(f, ",\n\t\t\"taga_treatment\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_treatment.taga_treatment);
		fprintf(f, ",\n\t\t\"taga_vid_treatment\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"13\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_treatment.taga_vid_treatment);
		fprintf(f, ",\n\t\t\"taga_tpid_treatment\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_treatment.taga_tpid_treatment);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_treatment.unused2);
		fprintf(f, ",\n\t\t\"discard_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_treatment.discard_enable);
		fprintf(f, ",\n\t\t\"outer_not_generate\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_treatment.outer_not_generate);
		fprintf(f, ",\n\t\t\"inner_not_generate\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_treatment.inner_not_generate);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_treatment.unused3);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.vlan_treatment.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_pmapper_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 32 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_pmapper_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_PMAPPER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.pmapper), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.pmapper.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"itp_id0\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.itp_id0);
		fprintf(f, ",\n\t\t\"itp_id1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.itp_id1);
		fprintf(f, ",\n\t\t\"itp_id2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.itp_id2);
		fprintf(f, ",\n\t\t\"itp_id3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.itp_id3);
		fprintf(f, ",\n\t\t\"itp_id4\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.itp_id4);
		fprintf(f, ",\n\t\t\"itp_id5\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.itp_id5);
		fprintf(f, ",\n\t\t\"itp_id6\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.itp_id6);
		fprintf(f, ",\n\t\t\"itp_id7\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.itp_id7);
		fprintf(f, ",\n\t\t\"dscp_table_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.dscp_table_pointer);
		fprintf(f, ",\n\t\t\"default_pcp\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.default_pcp);
		fprintf(f, ",\n\t\t\"meter_id_pmapper_bc\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.meter_id_pmapper_bc);
		fprintf(f, ",\n\t\t\"meter_id_pmapper_mc\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.meter_id_pmapper_mc);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.unused3);
		fprintf(f, ",\n\t\t\"meter_pmapper_bcen\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.meter_pmapper_bcen);
		fprintf(f, ",\n\t\t\"meter_pmapper_mcen\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.meter_pmapper_mcen);
		fprintf(f, ",\n\t\t\"unmarked_frame_option\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.unmarked_frame_option);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pmapper.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_short_fwd_hash_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_short_fwd_hash_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_SHORT_FWD_HASH_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.short_fwd_hash), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.short_fwd_hash.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_hash.unused1);
		fprintf(f, ",\n\t\t\"fwd_table_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_hash.fwd_table_pointer);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_hash.unused2);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_hash.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_short_fwd_table_mac_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_short_fwd_table_mac\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_SHORT_FWD_TABLE_MAC_ID, TABLE_ENTRY_SIZE(entry.data.short_fwd_table_mac), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.short_fwd_table_mac.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"mac_address_low\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.mac_address_low);
		fprintf(f, ",\n\t\t\"mac_address_high\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.mac_address_high);
		fprintf(f, ",\n\t\t\"fid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.fid);
		fprintf(f, ",\n\t\t\"bridge_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.bridge_index);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.unused1);
		fprintf(f, ",\n\t\t\"key_code\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.key_code);
		fprintf(f, ",\n\t\t\"bridge_port_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.bridge_port_index);
		fprintf(f, ",\n\t\t\"zero_port_map_indicator\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.zero_port_map_indicator);
		fprintf(f, ",\n\t\t\"activity\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.activity);
		fprintf(f, ",\n\t\t\"limitation\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.limitation);
		fprintf(f, ",\n\t\t\"dynamic_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.dynamic_enable);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.unused2);
		fprintf(f, ",\n\t\t\"dummy_encapsulation_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.dummy_encapsulation_index);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.unused3);
		fprintf(f, ",\n\t\t\"learning_time_stamp\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.learning_time_stamp);
		fprintf(f, ",\n\t\t\"unused4\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.unused4);
		fprintf(f, ",\n\t\t\"next_entry\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.next_entry);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_short_fwd_table_mac_mc_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 0 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_short_fwd_table_mac_mc\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_SHORT_FWD_TABLE_MAC_MC_ID, TABLE_ENTRY_SIZE(entry.data.short_fwd_table_mac_mc), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.short_fwd_table_mac_mc.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"mac_address_low\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.mac_address_low);
		fprintf(f, ",\n\t\t\"mac_address_high\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.mac_address_high);
		fprintf(f, ",\n\t\t\"fid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.fid);
		fprintf(f, ",\n\t\t\"bridge_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.bridge_index);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.unused1);
		fprintf(f, ",\n\t\t\"key_code\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.key_code);
		fprintf(f, ",\n\t\t\"include_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.include_enable);
		fprintf(f, ",\n\t\t\"one_port_map_indicator\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.one_port_map_indicator);
		fprintf(f, ",\n\t\t\"activity\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.activity);
		fprintf(f, ",\n\t\t\"zero_limitation\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.zero_limitation);
		fprintf(f, ",\n\t\t\"dynamic_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.dynamic_enable);
		fprintf(f, ",\n\t\t\"msf_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.msf_enable);
		fprintf(f, ",\n\t\t\"source_filter_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.source_filter_pointer);
		fprintf(f, ",\n\t\t\"igmp\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.igmp);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.unused2);
		fprintf(f, ",\n\t\t\"dummy_learning_time_stamp\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.dummy_learning_time_stamp);
		fprintf(f, ",\n\t\t\"port_map\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.port_map);
		fprintf(f, ",\n\t\t\"next_entry\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.next_entry);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_mac_mc.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_short_fwd_table_ipv4_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 0 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_short_fwd_table_ipv4\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_SHORT_FWD_TABLE_IPV4_ID, TABLE_ENTRY_SIZE(entry.data.short_fwd_table_ipv4), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.short_fwd_table_ipv4.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"ip_address\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.ip_address);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.unused1);
		fprintf(f, ",\n\t\t\"fid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.fid);
		fprintf(f, ",\n\t\t\"bridge_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.bridge_index);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.unused2);
		fprintf(f, ",\n\t\t\"key_code\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.key_code);
		fprintf(f, ",\n\t\t\"bridge_port_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.bridge_port_index);
		fprintf(f, ",\n\t\t\"zero_port_map_indicator\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.zero_port_map_indicator);
		fprintf(f, ",\n\t\t\"activity\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.activity);
		fprintf(f, ",\n\t\t\"zero_limitation\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.zero_limitation);
		fprintf(f, ",\n\t\t\"zero_dynamic_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.zero_dynamic_enable);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.unused3);
		fprintf(f, ",\n\t\t\"encapsulation_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.encapsulation_index);
		fprintf(f, ",\n\t\t\"unused4\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.unused4);
		fprintf(f, ",\n\t\t\"dummy_learning_time_stamp\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.dummy_learning_time_stamp);
		fprintf(f, ",\n\t\t\"unused5\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.unused5);
		fprintf(f, ",\n\t\t\"next_entry\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.next_entry);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_short_fwd_table_ipv4_mc_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 0 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_short_fwd_table_ipv4_mc\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ID, TABLE_ENTRY_SIZE(entry.data.short_fwd_table_ipv4_mc), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.short_fwd_table_ipv4_mc.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"ip_address\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.ip_address);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.unused1);
		fprintf(f, ",\n\t\t\"fid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.fid);
		fprintf(f, ",\n\t\t\"bridge_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.bridge_index);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.unused2);
		fprintf(f, ",\n\t\t\"key_code\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.key_code);
		fprintf(f, ",\n\t\t\"include_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.include_enable);
		fprintf(f, ",\n\t\t\"one_port_map_indicator\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.one_port_map_indicator);
		fprintf(f, ",\n\t\t\"activity\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.activity);
		fprintf(f, ",\n\t\t\"zero_limitation\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.zero_limitation);
		fprintf(f, ",\n\t\t\"zero_dynamic_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.zero_dynamic_enable);
		fprintf(f, ",\n\t\t\"msf_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.msf_enable);
		fprintf(f, ",\n\t\t\"source_filter_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.source_filter_pointer);
		fprintf(f, ",\n\t\t\"igmp\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.igmp);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.unused3);
		fprintf(f, ",\n\t\t\"dummy_learning_time_stamp\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.dummy_learning_time_stamp);
		fprintf(f, ",\n\t\t\"port_map\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.port_map);
		fprintf(f, ",\n\t\t\"next_entry\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.next_entry);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.short_fwd_table_ipv4_mc.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_long_fwd_hash_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 1024 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_long_fwd_hash_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_LONG_FWD_HASH_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.long_fwd_hash), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.long_fwd_hash.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_hash.unused1);
		fprintf(f, ",\n\t\t\"fwd_table_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_hash.fwd_table_pointer);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_hash.unused2);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_hash.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_long_fwd_table_ipv6_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 128 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_long_fwd_table_ipv6\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_LONG_FWD_TABLE_IPV6_ID, TABLE_ENTRY_SIZE(entry.data.long_fwd_table_ipv6), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.long_fwd_table_ipv6.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"ip_address0\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.ip_address0);
		fprintf(f, ",\n\t\t\"ip_address1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.ip_address1);
		fprintf(f, ",\n\t\t\"ip_address2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.ip_address2);
		fprintf(f, ",\n\t\t\"ip_address3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.ip_address3);
		fprintf(f, ",\n\t\t\"zero0\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.zero0);
		fprintf(f, ",\n\t\t\"fid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.fid);
		fprintf(f, ",\n\t\t\"bridge_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.bridge_index);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.unused1);
		fprintf(f, ",\n\t\t\"key_code\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.key_code);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.unused2);
		fprintf(f, ",\n\t\t\"bridge_port_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.bridge_port_index);
		fprintf(f, ",\n\t\t\"zero_port_map_indicator\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.zero_port_map_indicator);
		fprintf(f, ",\n\t\t\"dummy_mc_group_active\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.dummy_mc_group_active);
		fprintf(f, ",\n\t\t\"zero_limitation\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.zero_limitation);
		fprintf(f, ",\n\t\t\"zero_dynamic_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.zero_dynamic_enable);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.unused3);
		fprintf(f, ",\n\t\t\"encapsulation_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.encapsulation_index);
		fprintf(f, ",\n\t\t\"unused4\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.unused4);
		fprintf(f, ",\n\t\t\"dummy_learning_time_stamp\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.dummy_learning_time_stamp);
		fprintf(f, ",\n\t\t\"unused5\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.unused5);
		fprintf(f, ",\n\t\t\"next_entry\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.next_entry);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_long_fwd_table_ipv6_mc_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 0 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_long_fwd_table_ipv6_mc\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_LONG_FWD_TABLE_IPV6_MC_ID, TABLE_ENTRY_SIZE(entry.data.long_fwd_table_ipv6_mc), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.long_fwd_table_ipv6_mc.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"ip_address0\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.ip_address0);
		fprintf(f, ",\n\t\t\"ip_address1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.ip_address1);
		fprintf(f, ",\n\t\t\"ip_address2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.ip_address2);
		fprintf(f, ",\n\t\t\"ip_address3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.ip_address3);
		fprintf(f, ",\n\t\t\"zero0\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.zero0);
		fprintf(f, ",\n\t\t\"fid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.fid);
		fprintf(f, ",\n\t\t\"bridge_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.bridge_index);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.unused1);
		fprintf(f, ",\n\t\t\"key_code\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.key_code);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.unused2);
		fprintf(f, ",\n\t\t\"include_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.include_enable);
		fprintf(f, ",\n\t\t\"one_port_map_indicator\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.one_port_map_indicator);
		fprintf(f, ",\n\t\t\"mc_group_active\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.mc_group_active);
		fprintf(f, ",\n\t\t\"zero_limitation\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.zero_limitation);
		fprintf(f, ",\n\t\t\"zero_dynamic_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.zero_dynamic_enable);
		fprintf(f, ",\n\t\t\"msf_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.msf_enable);
		fprintf(f, ",\n\t\t\"source_filter_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.source_filter_pointer);
		fprintf(f, ",\n\t\t\"igmp\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.igmp);
		fprintf(f, ",\n\t\t\"unused4\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.unused4);
		fprintf(f, ",\n\t\t\"dummy_learning_time_stamp\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.dummy_learning_time_stamp);
		fprintf(f, ",\n\t\t\"port_map\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.port_map);
		fprintf(f, ",\n\t\t\"next_entry\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.next_entry);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.long_fwd_table_ipv6_mc.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_ds_mc_ipv4_source_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 512 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_ds_mc_ipv4_source_filter_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.ds_mc_ipv4_source_filter), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.ds_mc_ipv4_source_filter.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"ip_address\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv4_source_filter.ip_address);
		fprintf(f, ",\n\t\t\"port_map\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv4_source_filter.port_map);
		fprintf(f, ",\n\t\t\"unused\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"26\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv4_source_filter.unused);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv4_source_filter.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv4_source_filter.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_ds_mc_ipv6_source_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 128 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_ds_mc_ipv6_source_filter_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.ds_mc_ipv6_source_filter), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.ds_mc_ipv6_source_filter.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"ip_address0\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv6_source_filter.ip_address0);
		fprintf(f, ",\n\t\t\"ip_address1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv6_source_filter.ip_address1);
		fprintf(f, ",\n\t\t\"ip_address2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv6_source_filter.ip_address2);
		fprintf(f, ",\n\t\t\"ip_address3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv6_source_filter.ip_address3);
		fprintf(f, ",\n\t\t\"port_map\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"4\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv6_source_filter.port_map);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"28\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv6_source_filter.unused1);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv6_source_filter.unused2);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv6_source_filter.unused3);
		fprintf(f, ",\n\t\t\"unused4\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"30\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv6_source_filter.unused4);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv6_source_filter.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ds_mc_ipv6_source_filter.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_learning_limitation_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 128 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_learning_limitation_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_LEARNING_LIMITATION_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.learning_limitation), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"association_count\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.learning_limitation.association_count);
		fprintf(f, ",\n\t\t\"learning_limit\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.learning_limitation.learning_limit);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_lan_port_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 8 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_lan_port_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_LAN_PORT_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.lan_port), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.lan_port.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"interworking_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.interworking_index);
		fprintf(f, ",\n\t\t\"interworking_option\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.interworking_option);
		fprintf(f, ",\n\t\t\"base_queue_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.base_queue_index);
		fprintf(f, ",\n\t\t\"cfm_meter_id\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.cfm_meter_id);
		fprintf(f, ",\n\t\t\"cfm_meter_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.cfm_meter_enable);
		fprintf(f, ",\n\t\t\"pppoe_filter_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.pppoe_filter_enable);
		fprintf(f, ",\n\t\t\"ext_vlan_mc_enable_egress\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.ext_vlan_mc_enable_egress);
		fprintf(f, ",\n\t\t\"fid_mask_vido\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.fid_mask_vido);
		fprintf(f, ",\n\t\t\"fid_mask_vidi\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.fid_mask_vidi);
		fprintf(f, ",\n\t\t\"fid_mask_pcpo\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.fid_mask_pcpo);
		fprintf(f, ",\n\t\t\"fid_mask_pcpi\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.fid_mask_pcpi);
		fprintf(f, ",\n\t\t\"ext_vlan_index_ingress\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.ext_vlan_index_ingress);
		fprintf(f, ",\n\t\t\"ext_vlan_enable_ingress\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.ext_vlan_enable_ingress);
		fprintf(f, ",\n\t\t\"ext_vlan_index_egress\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.ext_vlan_index_egress);
		fprintf(f, ",\n\t\t\"ext_vlan_enable_egress\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.ext_vlan_enable_egress);
		fprintf(f, ",\n\t\t\"ext_vlan_egress_mode\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.ext_vlan_egress_mode);
		fprintf(f, ",\n\t\t\"ext_vlan_ingress_mode\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.ext_vlan_ingress_mode);
		fprintf(f, ",\n\t\t\"ext_vlan_incremental_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.ext_vlan_incremental_enable);
		fprintf(f, ",\n\t\t\"ethertype_filter_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"6\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.ethertype_filter_pointer);
		fprintf(f, ",\n\t\t\"ethertype_filter_mode\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.ethertype_filter_mode);
		fprintf(f, ",\n\t\t\"ethertype_filter_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.ethertype_filter_enable);
		fprintf(f, ",\n\t\t\"lan_loopback_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.lan_loopback_enable);
		fprintf(f, ",\n\t\t\"lan_mac_swap_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.lan_mac_swap_enable);
		fprintf(f, ",\n\t\t\"ext_vlan_mc_enable_ingress\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.ext_vlan_mc_enable_ingress);
		fprintf(f, ",\n\t\t\"queue_marking_mode\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.queue_marking_mode);
		fprintf(f, ",\n\t\t\"dscp_table_pointer\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.dscp_table_pointer);
		fprintf(f, ",\n\t\t\"acl_filter_mode\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.acl_filter_mode);
		fprintf(f, ",\n\t\t\"acl_filter_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.acl_filter_enable);
		fprintf(f, ",\n\t\t\"acl_filter_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.acl_filter_index);
		fprintf(f, ",\n\t\t\"exception_profile\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.exception_profile);
		fprintf(f, ",\n\t\t\"igmp_except_meter_id\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.igmp_except_meter_id);
		fprintf(f, ",\n\t\t\"igmp_except_meter_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.igmp_except_meter_enable);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.unused3);
		fprintf(f, ",\n\t\t\"uni_except_meter_id\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.uni_except_meter_id);
		fprintf(f, ",\n\t\t\"uni_except_meter_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.uni_except_meter_enable);
		fprintf(f, ",\n\t\t\"policer_threshold\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"21\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.policer_threshold);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.lan_port.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_pcp_decoding_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 32 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_pcp_decoding_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_PCP_DECODING_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.pcp_decoding), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"priority\" : {\n\t\t\t\"type\" : \"uint8_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pcp_decoding.priority);
		fprintf(f, ",\n\t\t\"de\" : {\n\t\t\t\"type\" : \"uint8_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pcp_decoding.de);
		fprintf(f, ",\n\t\t\"color\" : {\n\t\t\t\"type\" : \"uint8_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pcp_decoding.color);
		fprintf(f, ",\n\t\t\"unused\" : {\n\t\t\t\"type\" : \"uint8_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pcp_decoding.unused);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_dscp_decoding_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 512 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_dscp_decoding_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_DSCP_DECODING_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.dscp_decoding), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"pcp\" : {\n\t\t\t\"type\" : \"uint8_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.dscp_decoding.pcp);
		fprintf(f, ",\n\t\t\"de\" : {\n\t\t\t\"type\" : \"uint8_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.dscp_decoding.de);
		fprintf(f, ",\n\t\t\"color\" : {\n\t\t\t\"type\" : \"uint8_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.dscp_decoding.color);
		fprintf(f, ",\n\t\t\"unused\" : {\n\t\t\t\"type\" : \"uint8_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.dscp_decoding.unused);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_pcp_encoding_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 64 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_pcp_encoding_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_PCP_ENCODING_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.pcp_encoding), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"pcp\" : {\n\t\t\t\"type\" : \"uint8_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pcp_encoding.pcp);
		fprintf(f, ",\n\t\t\"unused\" : {\n\t\t\t\"type\" : \"uint8_t\",\n\t\t\t\"width\" : \"5\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.pcp_encoding.unused);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_dscp_encoding_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 32 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_dscp_encoding_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_DSCP_ENCODING_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.dscp_encoding), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"dscp\" : {\n\t\t\t\"type\" : \"uint8_t\",\n\t\t\t\"width\" : \"6\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.dscp_encoding.dscp);
		fprintf(f, ",\n\t\t\"unused\" : {\n\t\t\t\"type\" : \"uint8_t\",\n\t\t\t\"width\" : \"2\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.dscp_encoding.unused);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_exception_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 8 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_exception_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_EXCEPTION_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.exception), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"ingress_exception_flag_mask\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.exception.ingress_exception_flag_mask);
		fprintf(f, ",\n\t\t\"egress_exception_flag_mask\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.exception.egress_exception_flag_mask);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_redirection_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 32 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_redirection_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_REDIRECTION_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.redirection), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"redirection_queue_index\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.redirection.redirection_queue_index);
		fprintf(f, ",\n\t\t\"snooping_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.redirection.snooping_enable);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.redirection.unused1);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.redirection.unused2);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_mac_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 256 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_mac_filter_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_MAC_FILTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.mac_filter), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.mac_filter.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"mac_address_low\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.mac_filter.mac_address_low);
		fprintf(f, ",\n\t\t\"mac_address_high\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.mac_filter.mac_address_high);
		fprintf(f, ",\n\t\t\"key_code\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"3\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.mac_filter.key_code);
		fprintf(f, ",\n\t\t\"unused\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"11\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.mac_filter.unused);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.mac_filter.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.mac_filter.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_acl_filter_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 32 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_acl_filter_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_ACL_FILTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.acl_filter), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.acl_filter.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"parameter10\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.parameter10);
		fprintf(f, ",\n\t\t\"parameter11\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.parameter11);
		fprintf(f, ",\n\t\t\"parameter12\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.parameter12);
		fprintf(f, ",\n\t\t\"parameter13\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.parameter13);
		fprintf(f, ",\n\t\t\"parameter200\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.parameter200);
		fprintf(f, ",\n\t\t\"parameter21\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.parameter21);
		fprintf(f, ",\n\t\t\"parameter201\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.parameter201);
		fprintf(f, ",\n\t\t\"parameter_mask1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.parameter_mask1);
		fprintf(f, ",\n\t\t\"fid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.fid);
		fprintf(f, ",\n\t\t\"layer2_disable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.layer2_disable);
		fprintf(f, ",\n\t\t\"fid_disable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.fid_disable);
		fprintf(f, ",\n\t\t\"layer3_disable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.layer3_disable);
		fprintf(f, ",\n\t\t\"layer4_disable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.layer4_disable);
		fprintf(f, ",\n\t\t\"layer2_compare\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.layer2_compare);
		fprintf(f, ",\n\t\t\"layer2_mac_address_compare\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.layer2_mac_address_compare);
		fprintf(f, ",\n\t\t\"layer3_compare\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.layer3_compare);
		fprintf(f, ",\n\t\t\"layer3_ip_address_compare\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.layer3_ip_address_compare);
		fprintf(f, ",\n\t\t\"layer4_port_compare\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.layer4_port_compare);
		fprintf(f, ",\n\t\t\"layer4_tcp_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.layer4_tcp_enable);
		fprintf(f, ",\n\t\t\"layer4_udp_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.layer4_udp_enable);
		fprintf(f, ",\n\t\t\"ingress_port_lan0\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.ingress_port_lan0);
		fprintf(f, ",\n\t\t\"ingress_port_lan1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.ingress_port_lan1);
		fprintf(f, ",\n\t\t\"ingress_port_lan2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.ingress_port_lan2);
		fprintf(f, ",\n\t\t\"ingress_port_lan3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.ingress_port_lan3);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.unused1);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_acl_filter_table2_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 32 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_acl_filter_table2\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_ACL_FILTER_TABLE_2_ID, TABLE_ENTRY_SIZE(entry.data.acl_filter_table2), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.acl_filter_table2.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"parameter10\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.parameter10);
		fprintf(f, ",\n\t\t\"parameter11\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.parameter11);
		fprintf(f, ",\n\t\t\"parameter12\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.parameter12);
		fprintf(f, ",\n\t\t\"parameter13\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.parameter13);
		fprintf(f, ",\n\t\t\"parameter200\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.parameter200);
		fprintf(f, ",\n\t\t\"parameter21\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.parameter21);
		fprintf(f, ",\n\t\t\"parameter201\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.parameter201);
		fprintf(f, ",\n\t\t\"parameter_mask1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.parameter_mask1);
		fprintf(f, ",\n\t\t\"fid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"8\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.fid);
		fprintf(f, ",\n\t\t\"layer2_disable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.layer2_disable);
		fprintf(f, ",\n\t\t\"fid_disable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.fid_disable);
		fprintf(f, ",\n\t\t\"layer3_disable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.layer3_disable);
		fprintf(f, ",\n\t\t\"layer4_disable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.layer4_disable);
		fprintf(f, ",\n\t\t\"layer2_compare\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.layer2_compare);
		fprintf(f, ",\n\t\t\"layer2_mac_address_compare\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.layer2_mac_address_compare);
		fprintf(f, ",\n\t\t\"layer3_compare\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.layer3_compare);
		fprintf(f, ",\n\t\t\"layer3_ip_address_compare\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.layer3_ip_address_compare);
		fprintf(f, ",\n\t\t\"layer4_port_compare\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.layer4_port_compare);
		fprintf(f, ",\n\t\t\"layer4_tcp_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.layer4_tcp_enable);
		fprintf(f, ",\n\t\t\"layer4_udp_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.layer4_udp_enable);
		fprintf(f, ",\n\t\t\"ingress_port_lan0\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.ingress_port_lan0);
		fprintf(f, ",\n\t\t\"ingress_port_lan1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.ingress_port_lan1);
		fprintf(f, ",\n\t\t\"ingress_port_lan2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.ingress_port_lan2);
		fprintf(f, ",\n\t\t\"ingress_port_lan3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.ingress_port_lan3);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.unused1);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.acl_filter_table2.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_bridge_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 8 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_bridge_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_BRIDGE_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.bridge), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"uuc_meter_id\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.uuc_meter_id);
		fprintf(f, ",\n\t\t\"unused1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"6\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused1);
		fprintf(f, ",\n\t\t\"uuc_meter_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.uuc_meter_enable);
		fprintf(f, ",\n\t\t\"mc_meter_id\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.mc_meter_id);
		fprintf(f, ",\n\t\t\"unused2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"6\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused2);
		fprintf(f, ",\n\t\t\"mc_meter_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.mc_meter_enable);
		fprintf(f, ",\n\t\t\"bc_meter_id\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"9\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.bc_meter_id);
		fprintf(f, ",\n\t\t\"unused3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"6\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused3);
		fprintf(f, ",\n\t\t\"bc_meter_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.bc_meter_enable);
		fprintf(f, ",\n\t\t\"flooding_bridge_port_enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.flooding_bridge_port_enable);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index0\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index0);
		fprintf(f, ",\n\t\t\"unused10\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused10);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index1\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index1);
		fprintf(f, ",\n\t\t\"unused11\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused11);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index2\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index2);
		fprintf(f, ",\n\t\t\"unused12\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused12);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index3\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index3);
		fprintf(f, ",\n\t\t\"unused13\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused13);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index4\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index4);
		fprintf(f, ",\n\t\t\"unused14\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused14);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index5\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index5);
		fprintf(f, ",\n\t\t\"unused15\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused15);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index6\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index6);
		fprintf(f, ",\n\t\t\"unused16\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused16);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index7\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index7);
		fprintf(f, ",\n\t\t\"unused17\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused17);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index8\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index8);
		fprintf(f, ",\n\t\t\"unused18\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused18);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index9\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index9);
		fprintf(f, ",\n\t\t\"unused19\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused19);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index10\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index10);
		fprintf(f, ",\n\t\t\"unused20\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused20);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index11\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index11);
		fprintf(f, ",\n\t\t\"unused21\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused21);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index12\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index12);
		fprintf(f, ",\n\t\t\"unused22\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused22);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index13\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index13);
		fprintf(f, ",\n\t\t\"unused23\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused23);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index14\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index14);
		fprintf(f, ",\n\t\t\"unused24\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused24);
		fprintf(f, ",\n\t\t\"egress_bridge_port_index15\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"7\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.egress_bridge_port_index15);
		fprintf(f, ",\n\t\t\"unused25\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused25);
		fprintf(f, ",\n\t\t\"unused26\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused26);
		fprintf(f, ",\n\t\t\"unused27\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.bridge.unused27);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_ethertype_exception_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 8 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_ethertype_exception_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_ETHERTYPE_EXCEPTION_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.ethertype_exception), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"spec_ethertype\" : {\n\t\t\t\"type\" : \"uint16_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ethertype_exception.spec_ethertype);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_ethertype_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 64 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_ethertype_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_ETHERTYPE_FILTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.ethertype), instance, i, &entry);
		if (ret)
			return ret;

		if (index < 0 && entry.data.ethertype.valid == 0)
			continue;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"ethertype\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"16\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ethertype.ethertype);
		fprintf(f, ",\n\t\t\"unused\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"14\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ethertype.unused);
		fprintf(f, ",\n\t\t\"end\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ethertype.end);
		fprintf(f, ",\n\t\t\"valid\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"1\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.ethertype.valid);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_enqueue_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 8 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_enqueue_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_ENQUEUE_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.enqueue), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"enable\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.enqueue.enable);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_counter_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 704 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_counter_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_COUNTER_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.counter), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"counter_value\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.counter.counter_value);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_status_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 25 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_status_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_STATUS_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.status), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"entry_data\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.status.entry_data);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_gpe_constants_table_get(FILE *f, int onu_fd, uint8_t instance, int index)
{
	struct gpe_table_entry entry;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : 18 - 1;
	uint32_t i;

	fprintf(f, "{\n\t\"name\" : \"gpe_constants_table\"");

	for (i = index_begin; i <= index_end; i++) {
		ret = table_read(onu_fd, ONU_GPE_CONSTANTS_TABLE_ID, TABLE_ENTRY_SIZE(entry.data.constants), instance, i, &entry);
		if (ret)
			return ret;

		fprintf(f, ",\n\t\"%u\" : {", i);
		fprintf(f, "\n\t\t\"entry_data\" : {\n\t\t\t\"type\" : \"uint32_t\",\n\t\t\t\"width\" : \"32\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", entry.data.constants.entry_data);
		fprintf(f, "\n\t}");
	}

	fprintf(f, "\n}\n");

	return 0;
}

int json_table_by_id_get(FILE *f, uint32_t table_id, int onu_id, uint8_t instance, int index)
{
	unsigned int i;
	struct table_by_id tables[] = {
		{ ONU_GPE_DS_GEM_PORT_TABLE_ID, json_gpe_ds_gem_port_table_get },
		{ ONU_GPE_US_GEM_PORT_TABLE_ID, json_gpe_us_gem_port_table_get },
		{ ONU_GPE_FID_ASSIGNMENT_TABLE_ID, json_gpe_fwd_id_table_get },
		{ ONU_GPE_FID_HASH_TABLE_ID, json_gpe_fwd_id_hash_table_get },
		{ ONU_GPE_BRIDGE_PORT_TABLE_ID, json_gpe_bridge_port_table_get },
		{ ONU_GPE_TAGGING_FILTER_TABLE_ID, json_gpe_tagging_filter_table_get },
		{ ONU_GPE_VLAN_TABLE_ID, json_gpe_vlan_table_get },
		{ ONU_GPE_EXTENDED_VLAN_TABLE_ID, json_gpe_extended_vlan_table_get },
		{ ONU_GPE_VLAN_RULE_TABLE_ID, json_gpe_vlan_rule_table_get },
		{ ONU_GPE_VLAN_TREATMENT_TABLE_ID, json_gpe_vlan_treatment_table_get },
		{ ONU_GPE_PMAPPER_TABLE_ID, json_gpe_pmapper_table_get },
		{ ONU_GPE_SHORT_FWD_HASH_TABLE_ID, json_gpe_short_fwd_hash_table_get },
		{ ONU_GPE_SHORT_FWD_TABLE_MAC_ID, json_gpe_short_fwd_table_mac_get },
		{ ONU_GPE_SHORT_FWD_TABLE_MAC_MC_ID, json_gpe_short_fwd_table_mac_mc_get },
		{ ONU_GPE_SHORT_FWD_TABLE_IPV4_ID, json_gpe_short_fwd_table_ipv4_get },
		{ ONU_GPE_SHORT_FWD_TABLE_IPV4_MC_ID, json_gpe_short_fwd_table_ipv4_mc_get },
		{ ONU_GPE_LONG_FWD_HASH_TABLE_ID, json_gpe_long_fwd_hash_table_get },
		{ ONU_GPE_LONG_FWD_TABLE_IPV6_ID, json_gpe_long_fwd_table_ipv6_get },
		{ ONU_GPE_LONG_FWD_TABLE_IPV6_MC_ID, json_gpe_long_fwd_table_ipv6_mc_get },
		{ ONU_GPE_DS_MC_IPV4_SOURCE_FILTER_TABLE_ID, json_gpe_ds_mc_ipv4_source_filter_table_get },
		{ ONU_GPE_DS_MC_IPV6_SOURCE_FILTER_TABLE_ID, json_gpe_ds_mc_ipv6_source_filter_table_get },
		{ ONU_GPE_LEARNING_LIMITATION_TABLE_ID, json_gpe_learning_limitation_table_get },
		{ ONU_GPE_LAN_PORT_TABLE_ID, json_gpe_lan_port_table_get },
		{ ONU_GPE_PCP_DECODING_TABLE_ID, json_gpe_pcp_decoding_table_get },
		{ ONU_GPE_DSCP_DECODING_TABLE_ID, json_gpe_dscp_decoding_table_get },
		{ ONU_GPE_PCP_ENCODING_TABLE_ID, json_gpe_pcp_encoding_table_get },
		{ ONU_GPE_DSCP_ENCODING_TABLE_ID, json_gpe_dscp_encoding_table_get },
		{ ONU_GPE_EXCEPTION_TABLE_ID, json_gpe_exception_table_get },
		{ ONU_GPE_REDIRECTION_TABLE_ID, json_gpe_redirection_table_get },
		{ ONU_GPE_MAC_FILTER_TABLE_ID, json_gpe_mac_filter_table_get },
		{ ONU_GPE_ACL_FILTER_TABLE_ID, json_gpe_acl_filter_table_get },
		{ ONU_GPE_ACL_FILTER_TABLE_2_ID, json_gpe_acl_filter_table2_get },
		{ ONU_GPE_BRIDGE_TABLE_ID, json_gpe_bridge_table_get },
		{ ONU_GPE_ETHERTYPE_EXCEPTION_TABLE_ID, json_gpe_ethertype_exception_table_get },
		{ ONU_GPE_ETHERTYPE_FILTER_TABLE_ID, json_gpe_ethertype_table_get },
		{ ONU_GPE_ENQUEUE_TABLE_ID, json_gpe_enqueue_table_get },
		{ ONU_GPE_COUNTER_TABLE_ID, json_gpe_counter_table_get },
		{ ONU_GPE_STATUS_TABLE_ID, json_gpe_status_table_get },
		{ ONU_GPE_CONSTANTS_TABLE_ID, json_gpe_constants_table_get },
	};

	for (i = 0; i < ARRAY_SIZE(tables); i++)
		if (tables[i].id == table_id)
			return tables[i].handler(f, onu_id, instance, index);

	return -1;
}

int json_table_by_name_get(FILE *f, const char *table_name, int onu_id, uint8_t instance, int index)
{
	unsigned int i;
	struct table_by_name tables[] = {
		{ "gpe_ds_gem_port_table", json_gpe_ds_gem_port_table_get },
		{ "gpe_us_gem_port_table", json_gpe_us_gem_port_table_get },
		{ "gpe_fwd_id_table", json_gpe_fwd_id_table_get },
		{ "gpe_fwd_id_hash_table", json_gpe_fwd_id_hash_table_get },
		{ "gpe_bridge_port_table", json_gpe_bridge_port_table_get },
		{ "gpe_tagging_filter_table", json_gpe_tagging_filter_table_get },
		{ "gpe_vlan_table", json_gpe_vlan_table_get },
		{ "gpe_extended_vlan_table", json_gpe_extended_vlan_table_get },
		{ "gpe_vlan_rule_table", json_gpe_vlan_rule_table_get },
		{ "gpe_vlan_treatment_table", json_gpe_vlan_treatment_table_get },
		{ "gpe_pmapper_table", json_gpe_pmapper_table_get },
		{ "gpe_short_fwd_hash_table", json_gpe_short_fwd_hash_table_get },
		{ "gpe_short_fwd_table_mac", json_gpe_short_fwd_table_mac_get },
		{ "gpe_short_fwd_table_mac_mc", json_gpe_short_fwd_table_mac_mc_get },
		{ "gpe_short_fwd_table_ipv4", json_gpe_short_fwd_table_ipv4_get },
		{ "gpe_short_fwd_table_ipv4_mc", json_gpe_short_fwd_table_ipv4_mc_get },
		{ "gpe_long_fwd_hash_table", json_gpe_long_fwd_hash_table_get },
		{ "gpe_long_fwd_table_ipv6", json_gpe_long_fwd_table_ipv6_get },
		{ "gpe_long_fwd_table_ipv6_mc", json_gpe_long_fwd_table_ipv6_mc_get },
		{ "gpe_ds_mc_ipv4_source_filter_table", json_gpe_ds_mc_ipv4_source_filter_table_get },
		{ "gpe_ds_mc_ipv6_source_filter_table", json_gpe_ds_mc_ipv6_source_filter_table_get },
		{ "gpe_learning_limitation_table", json_gpe_learning_limitation_table_get },
		{ "gpe_lan_port_table", json_gpe_lan_port_table_get },
		{ "gpe_pcp_decoding_table", json_gpe_pcp_decoding_table_get },
		{ "gpe_dscp_decoding_table", json_gpe_dscp_decoding_table_get },
		{ "gpe_pcp_encoding_table", json_gpe_pcp_encoding_table_get },
		{ "gpe_dscp_encoding_table", json_gpe_dscp_encoding_table_get },
		{ "gpe_exception_table", json_gpe_exception_table_get },
		{ "gpe_redirection_table", json_gpe_redirection_table_get },
		{ "gpe_mac_filter_table", json_gpe_mac_filter_table_get },
		{ "gpe_acl_filter_table", json_gpe_acl_filter_table_get },
		{ "gpe_acl_filter_table2", json_gpe_acl_filter_table2_get },
		{ "gpe_bridge_table", json_gpe_bridge_table_get },
		{ "gpe_ethertype_exception_table", json_gpe_ethertype_exception_table_get },
		{ "gpe_ethertype_table", json_gpe_ethertype_table_get },
		{ "gpe_enqueue_table", json_gpe_enqueue_table_get },
		{ "gpe_counter_table", json_gpe_counter_table_get },
		{ "gpe_status_table", json_gpe_status_table_get },
		{ "gpe_constants_table", json_gpe_constants_table_get },
	};

	for (i = 0; i < ARRAY_SIZE(tables); i++)
		if (strcmp(tables[i].name, table_name) == 0)
			return tables[i].handler(f, onu_id, instance, index);

	return -1;
}
