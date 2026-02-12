/******************************************************************************

                               Copyright (c) 2010
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "gtop.h"
#include "gpe_counter.h"

#include <stdio.h>
#include <sys/time.h>

#include <sys/ioctl.h>
#include "drv_onu_resource.h"
#include "drv_onu_common_interface.h"
#include "drv_onu_ploam_interface.h"
#include "drv_onu_gpe_interface.h"
#include "drv_onu_event_interface.h"
#include "drv_onu_gpe_tables_interface.h"
#include "common.h"

static struct {
	struct gpe_gem_port gpe_gem_port;
} *table;

static struct {
	uint32_t gem_port_id;
	uint32_t gem_port_index;
	struct gpe_cnt_gem_val gpe_cnt_gem_val;
} *counter;

static struct {
	uint32_t gem_port_id;
	uint32_t gem_port_index;
	uint32_t queue_id;
	uint32_t queue_id_valid;
	uint32_t scheduler_input;
	uint32_t epn;
	uint32_t tcix;
	uint32_t alloc_id;
} *upstream_flow;

static struct {
	uint32_t alloc_id;
	uint32_t repn;
	uint32_t pepn;
} tcont_array[ONU_GPE_MAX_TCONT];

static union gpe_bridge_port_counter_get_u bridge_port_cnt[32];
static union gpe_meter_cfg_get_u gpe_meter_cfg[32];
static union gpe_meter_status_get_u gpe_meter_status[32];

void gpe_group_init(bool init)
{
	if (init) {
		table = malloc(sizeof(*table) * g_capability.max_gpix);
		counter = malloc(sizeof(*counter) * g_capability.max_gpix);
		upstream_flow = malloc(sizeof(*upstream_flow) * g_capability.max_gpix);

		if (!table || !counter || !upstream_flow) {
			fprintf(stderr, "No free memory\n");
			exit(2);
		}
	} else {
		free(table);
		free(counter);
		free(upstream_flow);
	}
}


char *gpe_capability_entry_get(const int entry, char *text)
{
	switch (entry) {
	case -1:
		sprintf(text, "%-50s %s", "OPTION", "VALUE");
		break;
	case 0:
		sprintf(text, "%-50s %u", "Max meter", g_capability.max_meter);
		break;
	case 1:
		sprintf(text, "%-50s %u", "Max GPIX", g_capability.max_gpix);
		break;
	case 2:
		sprintf(text, "%-50s %u", "Max ETH UNI",
			g_capability.max_eth_uni);
		break;
	case 3:
		sprintf(text, "%-50s %u", "Max POTS UNI",
			g_capability.max_pots_uni);
		break;
	case 4:
		sprintf(text, "%-50s %u", "Max bridge port",
			g_capability.max_bridge_port);
		break;
	};

	return NULL;
}

int gpe_capability_table_get(const int fd, const char *dummy)
{
	return 4 + 1;
}

int gpe_table_get(const int fd, const char *dummy)
{
	unsigned int i,k;
	union gpe_gem_port_get_u port_id;

	for (i=0, k=0; i<ONU_GPE_MAX_GEM_PORT_ID && k<g_capability.max_gpix; i++) {
		port_id.in.val = i;
		if (onu_iocmd(fd, FIO_GPE_GEM_PORT_GET, &port_id,  sizeof(port_id)) != 0)
			continue;
		memcpy(&table[k].gpe_gem_port, &port_id.out, sizeof(struct gpe_gem_port));
		k++;
	}

	return k;
}

char *gpe_table_entry_get(const int entry, char *text)
{
	if (entry == -1) {
		sprintf(text, "GEM PORT ID  GEM PORT IDX  OMCI  MC  ENCRYPT  DIR");
	} else {
		sprintf(text, "%11d  %12d  %4d  %2d  %7d  %3d",
			table[entry].gpe_gem_port.gem_port_id,
			table[entry].gpe_gem_port.gem_port_index,
			table[entry].gpe_gem_port.gem_port_is_omci,
			table[entry].gpe_gem_port.gem_port_is_mc,
			table[entry].gpe_gem_port.encryption_enable,
			table[entry].gpe_gem_port.data_direction);
	}

	return NULL;
}

int gpem_port_table_get(const int fd, const char *dummy)
{
	unsigned int i,k;
	union gpe_gem_counter_get_u counter_id;
	union gpe_gem_port_get_u port_id;

	for (i=0, k=0; i<ONU_GPE_MAX_GEM_PORT_ID && k<g_capability.max_gpix; i++) {
		port_id.in.val = i;

		if (onu_iocmd(fd, FIO_GPE_GEM_PORT_GET, &port_id, sizeof(port_id)) != 0)
			continue;
		counter_id.in.gem_port_index = port_id.out.gem_port_index;
		counter_id.in.reset_mask = 0;
		counter_id.in.curr = true;

		if (onu_iocmd(fd, FIO_GPE_GEM_COUNTER_GET, &counter_id, sizeof(counter_id)) != 0)
			continue;
		counter[k].gem_port_index = port_id.out.gem_port_index;
		counter[k].gem_port_id = i;
		memcpy(&counter[k].gpe_cnt_gem_val, &counter_id.out.cnt_val,
						sizeof(struct gpe_cnt_gem_val));
		k++;
	}

	return k;
}

char *gem_port_entry_get(const int entry, char *text)
{
	if (entry == -1) {
		sprintf(text,   "GEM PORT ID  "\
				"GEM PORT IDX  "\
				"TX FRAMES  "\
				"TX BYTES   "\
				"RX FRAMES  "\
				"RX BYTES   "
				);
		return NULL;
	}
	sprintf(text, "%11d  %12d  %9llu  %9llu  %9llu  %9llu",
		counter[entry].gem_port_id,
		counter[entry].gem_port_index,
		(long long unsigned int)counter[entry].gpe_cnt_gem_val.tx.tx_frames,
		(long long unsigned int)counter[entry].gpe_cnt_gem_val.tx.tx_bytes,
		(long long unsigned int)counter[entry].gpe_cnt_gem_val.rx.rx_frames,
		(long long unsigned int)counter[entry].gpe_cnt_gem_val.rx.rx_bytes);

	return NULL;
}

int alloc_id_table_get(const int fd, const char *dummy)
{
	int i;
	struct gpe_tcont tcont;

	for(i=0;i<ONU_GPE_MAX_TCONT;i++) {
		tcont_array[i].alloc_id= 0xffffffff;
		tcont.tcont_idx = i;
		if(onu_iocmd(fd, FIO_GPE_TCONT_GET, &tcont, sizeof(tcont)) != 0)
			continue;
		tcont_array[i].alloc_id = tcont.alloc_id;
		tcont_array[i].repn = tcont.reg_egress_port;
		tcont_array[i].pepn = tcont.pre_egress_port;
	}

	return ONU_GPE_MAX_TCONT;
}

char *alloc_id_entry_get(const int entry, char *text)
{
	if (entry == -1) {
		sprintf(text,   "TCIX  "\
				"Alloc ID      REPN      PEPN"
				);
		return NULL;
	}
	sprintf(text, "%4u  %8u  %8u  %8u", entry,
		tcont_array[entry].alloc_id,
		tcont_array[entry].repn,
		tcont_array[entry].pepn);

	return NULL;
}

int us_flow_table_get(const int fd, const char *dummy)
{
	unsigned int i,k,m;
	union gpe_gem_port_get_u port_id;
	union gpe_equeue_get_u gpe_equeue;
	struct gpe_table_entry entry;
	struct gpe_tcont tcont;

	for (i=0, k=0; i<ONU_GPE_MAX_GEM_PORT_ID && k<g_capability.max_gpix; i++) {
		port_id.in.val = i;
		if (onu_iocmd(fd, FIO_GPE_GEM_PORT_GET, &port_id, sizeof(port_id)) != 0)
			continue;
		memset(&upstream_flow[k], 0, sizeof(upstream_flow[k]));
		upstream_flow[k].gem_port_id = i;
		upstream_flow[k].gem_port_index = port_id.out.gem_port_index;
		memset(&entry.data, 0x00, sizeof(struct gpe_us_gem_port_table));
		if(upstream_flow[k].gem_port_index != 255) {
			table_read(fd, ONU_GPE_US_GEM_PORT_TABLE_ID,
					port_id.out.gem_port_index,
					sizeof(struct gpe_us_gem_port_table), &entry);
			upstream_flow[k].queue_id = entry.data.us_gem_port.egress_queue_index;
			upstream_flow[k].queue_id_valid = entry.data.us_gem_port.valid;
		} else {
			upstream_flow[k].queue_id = ONU_GPE_QUEUE_INDEX_OMCI_HI_US;
			upstream_flow[k].queue_id_valid = 1;
		}
		if(upstream_flow[k].queue_id_valid) {
			gpe_equeue.in.index = upstream_flow[k].queue_id;
			if(onu_iocmd(fd, FIO_GPE_EGRESS_QUEUE_GET, &gpe_equeue, sizeof(gpe_equeue)) == 0) {
				upstream_flow[k].scheduler_input = gpe_equeue.out.scheduler_input;
				upstream_flow[k].epn = gpe_equeue.out.egress_port_number;
				for(m=0;m<ONU_GPE_MAX_TCONT;m++) {
					tcont.tcont_idx = m;
					if(onu_iocmd(fd, FIO_GPE_TCONT_GET, &tcont, sizeof(tcont)) != 0)
						continue;
					if(gpe_equeue.out.egress_port_number != tcont.reg_egress_port &&
						gpe_equeue.out.egress_port_number != tcont.pre_egress_port)
						continue;
					upstream_flow[k].tcix = m;
					upstream_flow[k].alloc_id = tcont.alloc_id;
				}
			}
		}
		k++;
	}

	return k;
}

char *us_flow_entry_get(const int entry, char *text)
{
	if (entry == -1) {
		sprintf(text,   "GEM PORT ID  "\
				"GEM PORT IDX  "\
				"V  "\
				"QUEUE ID  "\
				"SBIN       "\
				"EPN  "\
				"TCIX  "\
				"ALLOC ID  ");
		return NULL;
	}
	sprintf(text, "%11u  %12u  %s  %8u  %9u  %3u  %4u  %8u",
		upstream_flow[entry].gem_port_id,
		upstream_flow[entry].gem_port_index,
		upstream_flow[entry].queue_id_valid ? "V" : " ",
		upstream_flow[entry].queue_id,
		upstream_flow[entry].scheduler_input,
		upstream_flow[entry].epn,
		upstream_flow[entry].tcix,
		upstream_flow[entry].alloc_id);

	return NULL;
}

int bridge_port_counter_table_get(const int fd, const char *dummy)
{
	unsigned int i,k;
	int ret;

	for(i=0,k=0;k<ARRAY_SIZE(bridge_port_cnt) &&
				i<ONU_GPE_MAX_BRIDGE_PORT;i++) {
		bridge_port_cnt[k].in.index = i;
		bridge_port_cnt[k].in.reset_mask = 0;
		bridge_port_cnt[k].in.curr = 1;
		ret = onu_iocmd(fd, FIO_GPE_BRIDGE_PORT_COUNTER_GET,
				&bridge_port_cnt[k], sizeof(bridge_port_cnt[0]));
		if(ret == 0) {
			k++;
		}
	}

	return k;
}

char *bridge_port_counter_entry_get(const int entry, char *text)
{
	if (entry == -1) {
		sprintf(text,   "IDX  "\
				"IBP GOOD  "\
				"IBP DISCARD  "\
				"LEARNING DISCARD  "\
				"EBP GOOD  "\
				"EBP DISCARD  ");
		return NULL;
	}
	sprintf(text, "%3u  %8llu  %11llu  %16llu  %8llu  %10llu",
		bridge_port_cnt[entry].out.ctrl.index,
		bridge_port_cnt[entry].out.val.ibp_good,
		bridge_port_cnt[entry].out.val.ibp_discard,
		bridge_port_cnt[entry].out.val.learning_discard,
		bridge_port_cnt[entry].out.val.ebp_good,
		bridge_port_cnt[entry].out.val.ebp_discard);

	return NULL;
}

int meter_table_get(const int fd, const char *dummy)
{
	unsigned int i,k;
	int ret;

	for(i=0,k=0;k<ARRAY_SIZE(gpe_meter_cfg) && i<ONU_GPE_MAX_TBM;i+=2) {
		gpe_meter_cfg[k].in.index = i;
		ret = onu_iocmd(fd, FIO_GPE_METER_CFG_GET,
				&gpe_meter_cfg[k], sizeof(gpe_meter_cfg[0]));
		if(ret == 0) {
			gpe_meter_status[k].in.index = i;
			onu_iocmd(fd, FIO_GPE_METER_STATUS_GET,
					&gpe_meter_status[k], sizeof(gpe_meter_status[0]));
			k++;
		}
	}

	return k;
}

char *meter_entry_get(const int entry, char *text)
{
	if (entry == -1) {
		sprintf(text, "IDX  "\
				"CIR       "\
				"PIR       "\
				"CBS       "\
				"PBS       "\
				"Mode      "\
				"Color Aware  "\
				"TBC       "\
				"LTS       "\
				"ETS       "\
				"VTS     ");
		return NULL;
	}
	sprintf(text, "%3u  %8u  %8u  %8u  %8u  %8u  %11u  %8u  %8u  %8u  %8u",
		gpe_meter_cfg[entry].out.index,
		gpe_meter_cfg[entry].out.cir,
		gpe_meter_cfg[entry].out.pir,
		gpe_meter_cfg[entry].out.cbs,
		gpe_meter_cfg[entry].out.pbs,
		gpe_meter_cfg[entry].out.mode,
		gpe_meter_cfg[entry].out.color_aware,
		gpe_meter_status[entry].out.tbc,
		gpe_meter_status[entry].out.lts,
		gpe_meter_status[entry].out.ets,
		gpe_meter_status[entry].out.vts );

	return NULL;
}
