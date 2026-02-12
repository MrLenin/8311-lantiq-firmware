/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#include "drv_onu_error.h"

#include "onu_sce_wrappers_common.h"

typedef int (wrapper_get)(FILE *f, int onu_fd, enum output_type type, int index);

struct wrapper_by_name {
	const char *name;
	wrapper_get *handler;
};

static void error_log(FILE *f, int ret)
{
	fprintf(f, "ERROR: ioctl returned %d\n", ret);
}

int gpe_egress_queue_get(FILE *f, int onu_fd, enum output_type type, int index)
{
	union gpe_equeue_cfg_get_u queue_cfg;
	union gpe_equeue_get_u queue;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : ONU_GPE_MAX_EGRESS_QUEUES - 1;
	uint32_t i;

	wrapper_begin(type, f, "gpe_egress_queue");

	for (i = index_begin; i <= index_end; i++) {
		queue.in.index = i;
		ret = onu_iocmd(onu_fd, FIO_GPE_EGRESS_QUEUE_GET, &queue, sizeof(queue));
		if (ret) {
			error_log(f, ret);
			return ret;
		}

		queue_cfg.in.index = i;
		ret = onu_iocmd(onu_fd, FIO_GPE_EGRESS_QUEUE_CFG_GET, &queue_cfg, sizeof(queue_cfg));
		if (ret) {
			error_log(f, ret);
			return ret;
		}

		wrapper_entry_begin(type, f, i);

		wrapper_field(type, f, true, "index", "uint8_t", queue.out.index);
		wrapper_field(type, f, false, "egress_port_number", "uint8_t", queue.out.egress_port_number);
		wrapper_field(type, f, false, "scheduler_input", "uint16_t", queue.out.scheduler_input);

		wrapper_field(type, f, false, "enable", "bool", queue_cfg.out.enable);
		wrapper_field(type, f, false, "sbin_enable", "bool", queue_cfg.out.sbin_enable);
		wrapper_field(type, f, false, "weight", "uint8_t", queue_cfg.out.weight);
		wrapper_field(type, f, false, "wred_enable", "bool", queue_cfg.out.wred_enable);
		wrapper_field(type, f, false, "avg_weight", "uint8_t", queue_cfg.out.avg_weight);
		wrapper_field(type, f, false, "size", "uint16_t", queue_cfg.out.size);
		wrapper_field(type, f, false, "reservation_threshold", "uint16_t", queue_cfg.out.reservation_threshold);
		wrapper_field(type, f, false, "drop_threshold_red", "uint16_t", queue_cfg.out.drop_threshold_red);
		wrapper_field(type, f, false, "drop_threshold_green_max", "uint16_t", queue_cfg.out.drop_threshold_green_max);
		wrapper_field(type, f, false, "drop_threshold_green_min", "uint16_t", queue_cfg.out.drop_threshold_green_min);
		wrapper_field(type, f, false, "drop_threshold_yellow_max", "uint16_t", queue_cfg.out.drop_threshold_yellow_max);
		wrapper_field(type, f, false, "drop_threshold_yellow_min", "uint16_t", queue_cfg.out.drop_threshold_yellow_min);
		wrapper_field(type, f, false, "drop_probability_green", "uint8_t", queue_cfg.out.drop_probability_green);
		wrapper_field(type, f, false, "drop_probability_yellow", "uint8_t", queue_cfg.out.drop_probability_yellow);
		wrapper_field(type, f, false, "coloring_mode", "enum gpe_coloring_mode", queue_cfg.out.coloring_mode);

		wrapper_entry_end(type, f);
	}

	wrapper_end(type, f);

	return 0;
}

int gpe_egress_port_get(FILE *f, int onu_fd, enum output_type type, int index)
{
	union gpe_egress_port_cfg_get_u port_cfg;
	union gpe_eport_get_u port;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : ONU_GPE_MAX_EGRESS_PORT - 1;
	uint32_t i;

	wrapper_begin(type, f, "gpe_egress_port");

	for (i = index_begin; i <= index_end; i++) {
		port_cfg.in.epn = i;
		ret = onu_iocmd(onu_fd, FIO_GPE_EGRESS_PORT_CFG_GET, &port_cfg, sizeof(port_cfg));
		if (ret) {
			error_log(f, ret);
			return ret;
		}

		port.in.epn = i;
		ret = onu_iocmd(onu_fd, FIO_GPE_EGRESS_PORT_GET, &port, sizeof(port));
		if (ret) {
			error_log(f, ret);
			return ret;
		}

		wrapper_entry_begin(type, f, i);

		wrapper_field(type, f, true, "epn", "uint8_t", port_cfg.out.epn);
		wrapper_field(type, f, false, "enable", "bool", port_cfg.out.enable);
		wrapper_field(type, f, false, "egress_port_threshold_max", "uint16_t", port_cfg.out.egress_port_threshold_max);
		wrapper_field(type, f, false, "egress_port_threshold_green", "uint16_t", port_cfg.out.egress_port_threshold_green);
		wrapper_field(type, f, false, "egress_port_threshold_yellow", "uint16_t", port_cfg.out.egress_port_threshold_yellow);
		wrapper_field(type, f, false, "egress_port_threshold_red", "uint16_t", port_cfg.out.egress_port_threshold_red);

		wrapper_field(type, f, false, "port_index", "uint8_t", port.out.index);
		wrapper_field(type, f, false, "is_uni", "bool", port.out.is_uni);
		wrapper_field(type, f, false, "regular_epn", "uint8_t", port.out.regular_epn);
		wrapper_field(type, f, false, "regular_sbid", "uint8_t", port.out.regular_sbid);
		wrapper_field(type, f, false, "preempting_epn", "uint8_t", port.out.preempting_epn);
		wrapper_field(type, f, false, "preempting_sbid", "uint8_t", port.out.preempting_sbid);

		wrapper_entry_end(type, f);
	}

	wrapper_end(type, f);

	return 0;
}

int gpe_scheduler_get(FILE *f, int onu_fd, enum output_type type, int index)
{
	union gpe_scheduler_cfg_get_u sched_cfg;
	union gpe_scheduler_get_u sched;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : ONU_GPE_MAX_SCHEDULER - 1;
	uint32_t i;

	wrapper_begin(type, f, "gpe_scheduler");

	for (i = index_begin; i <= index_end; i++) {
		sched.in.index = i;
		ret = onu_iocmd(onu_fd, FIO_GPE_SCHEDULER_GET, &sched, sizeof(sched));
		if (ret) {
			error_log(f, ret);
			return ret;
		}

		sched_cfg.in.index = i;
		ret = onu_iocmd(onu_fd, FIO_GPE_SCHEDULER_CFG_GET, &sched_cfg, sizeof(sched_cfg));
		if (ret) {
			error_log(f, ret);
			return ret;
		}

		wrapper_entry_begin(type, f, i);

		wrapper_field(type, f, true, "index", "uint8_t", sched.out.index);
		wrapper_field(type, f, false, "use_tcont", "bool", sched.out.use_tcont);
		wrapper_field(type, f, false, "level", "uint8_t", sched.out.level);
		wrapper_field(type, f, false, "scheduler_id", "uint32_t", sched.out.scheduler_id);
		wrapper_field(type, f, false, "port_idx", "uint8_t", sched.out.port_idx);
		wrapper_field(type, f, false, "connected_scheduler_index", "uint16_t", sched.out.connected_scheduler_index);
		wrapper_field(type, f, false, "use_regular", "bool", sched.out.use_regular);
		wrapper_field(type, f, false, "scheduler_policy", "enum gpe_policy", sched.out.scheduler_policy);
		wrapper_field(type, f, false, "priority_weight", "uint16_t", sched.out.priority_weight);

		wrapper_field(type, f, false, "output_enable", "bool", sched_cfg.out.output_enable);
		wrapper_field(type, f, false, "weight", "uint16_t", sched_cfg.out.weight);

		wrapper_entry_end(type, f);
	}

	wrapper_end(type, f);

	return 0;
}

int gpe_token_bucket_shaper_get(FILE *f, int onu_fd, enum output_type type, int index)
{
	union gpe_token_bucket_shaper_cfg_get_u shaper_cfg;
	union gpe_token_bucket_shaper_get_u shaper;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : ONU_GPE_MAX_SHAPER - 1;
	uint32_t i;

	wrapper_begin(type, f, "gpe_token_bucket_shaper");

	for (i = index_begin; i <= index_end; i++) {
		shaper.in.index = i;
		ret = onu_iocmd(onu_fd, FIO_GPE_TOKEN_BUCKET_SHAPER_GET, &shaper, sizeof(shaper));
		if (ret) {
			error_log(f, ret);
			return ret;
		}

		shaper_cfg.in.index = i;
		ret = onu_iocmd(onu_fd, FIO_GPE_TOKEN_BUCKET_SHAPER_CFG_GET, &shaper_cfg, sizeof(shaper_cfg));
		if (ret) {
			error_log(f, ret);
			return ret;
		}

		wrapper_entry_begin(type, f, i);

		wrapper_field(type, f, true, "index", "uint16_t", shaper.out.index);
		wrapper_field(type, f, true, "scheduler_block_input", "uint16_t", shaper.out.tbs_scheduler_block_input);

		wrapper_field(type, f, false, "enable", "bool", shaper_cfg.out.enable);
		wrapper_field(type, f, false, "mode", "uint8_t", shaper_cfg.out.mode);
		wrapper_field(type, f, false, "cir", "uint32_t", shaper_cfg.out.cir);
		wrapper_field(type, f, false, "pir", "uint32_t", shaper_cfg.out.pir);
		wrapper_field(type, f, false, "cbs", "uint32_t", shaper_cfg.out.cbs);
		wrapper_field(type, f, false, "pbs", "uint32_t", shaper_cfg.out.pbs);

		wrapper_entry_end(type, f);
	}

	wrapper_end(type, f);

	return 0;
}

int gpe_gem_port_id_get(FILE *f, int onu_fd, enum output_type type, int index)
{
	union gpe_gem_port_get_u port_id;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : ONU_GPE_MAX_GEM_PORT_ID - 1;
	uint32_t i;

	wrapper_begin(type, f, "gpe_gem_port_id");

	for (i = index_begin; i <= index_end; i++) {
		port_id.in.val = i;
		ret = onu_iocmd(onu_fd, FIO_GPE_GEM_PORT_GET, &port_id, sizeof(port_id));
		if (ret && ret != GPE_STATUS_NOT_AVAILABLE) {
			error_log(f, ret);
			return ret;
		}

		if (index < 0 && ret != ONU_STATUS_OK)
			continue;

		wrapper_entry_begin(type, f, i);

		wrapper_field(type, f, true, "index", "uint32_t", port_id.out.gem_port_index);
		wrapper_field(type, f, false, "valid", "uint32_t", ret == ONU_STATUS_OK);

		wrapper_entry_end(type, f);
	}

	wrapper_end(type, f);

	return 0;
}

int gpe_tcont_get(FILE *f, int onu_fd, enum output_type type, int index)
{
	struct gpe_tcont tcont;
	int ret;
	uint32_t index_begin = index >= 0 ? index : 0;
	uint32_t index_end = index >= 0 ? index : ONU_GPE_MAX_TCONT - 1;
	uint32_t i;

	wrapper_begin(type, f, "gpe_tcont");

	for (i = index_begin; i <= index_end; i++) {
		tcont.tcont_idx = i;
		ret = onu_iocmd(onu_fd, FIO_GPE_TCONT_GET, &tcont, sizeof(tcont));
		if (ret && ret != GPE_STATUS_NOT_AVAILABLE) {
			error_log(f, ret);
			return ret;
		}

		if (index < 0 && ret != ONU_STATUS_OK)
			continue;

		wrapper_entry_begin(type, f, i);

		wrapper_field(type, f, true, "alloc_id", "uint32_t", tcont.alloc_id);
		wrapper_field(type, f, true, "reg_egress_port", "uint32_t", tcont.reg_egress_port);
		wrapper_field(type, f, true, "pre_egress_port", "uint32_t", tcont.pre_egress_port);

		wrapper_entry_end(type, f);
	}

	wrapper_end(type, f);

	return 0;
}

int wrapper_by_name_get(FILE *f, const char *wrapper_name, int onu_id, enum output_type type, int index)
{
	unsigned int i;
	struct wrapper_by_name wrappers[] = {
		{ "gpe_egress_queue", gpe_egress_queue_get },
		{ "gpe_egress_port", gpe_egress_port_get },
		{ "gpe_scheduler", gpe_scheduler_get },
		{ "gpe_token_bucket_shaper", gpe_token_bucket_shaper_get },
		{ "gpe_gem_port_id", gpe_gem_port_id_get },
		{ "gpe_tcont", gpe_tcont_get },
	};

	for (i = 0; i < ARRAY_SIZE(wrappers); i++)
		if (strcmp(wrappers[i].name, wrapper_name) == 0)
			return wrappers[i].handler(f, onu_id, type, index);

	return -1;
}
