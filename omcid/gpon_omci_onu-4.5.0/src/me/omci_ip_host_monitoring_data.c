/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_ip_host_monitoring_data.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_ip_host_config_data.h"
#include "me/omci_ip_host_monitoring_data.h"

#ifdef INCLUDE_PM

#ifdef INCLUDE_OMCI_ONU_UCI
#include "uci/omci_uci_config.h"
#endif

#ifdef LINUX
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#endif


/** \addtogroup OMCI_IP_HOST_MONITORING_DATA
   @{
*/

#define ICMP_STATS_PATH				"/proc/net/snmp"
#define ICMP_STATS_PREFIX			"Icmp:"
#define ICMP_STATS_IN_ERRORS_OFFSET		1

#define TCPEXT_STATS_PATH			"/proc/net/netstat"
#define TCPEXT_STATS_PREFIX			"TcpExt:"
#define TCPEXT_STATS_ABORT_ON_MEMORY_OFFSET	60

static int proc_net_counter_get(const char *path,
				const char *entry_prefix,
				const uint8_t cnt_offset,
				uint32_t *cnt)
{
	int ret = 0;
#ifdef LINUX
	FILE *in = fopen(path, "r");
	char buf[32];
	bool header = false;
	int i, prefix_len = strlen(entry_prefix);
	unsigned long stats = 0;

	if (!in || prefix_len + 1 > sizeof(buf)) {
		ret = -1;
		goto get_error;
	}

	while (buf == fgets(buf, prefix_len + 1, in)) {
		if (strncmp(buf, entry_prefix, prefix_len))
			continue;

		if (!header) {
			header = true;
			continue;
		}

		for (i = 0; i <= cnt_offset; i++) {
			if (fscanf(in, "%lu", &stats) <= 0) {
				ret = -1;
				break;
			}
		}

		break;
	}

get_error:
	if (in)
		fclose(in);
	*cnt = (unsigned int)stats;
#endif
	return ret;
}

static int ip_host_counters_get(const char *ifname,
				uint32_t *icmp_errors,
				uint32_t *dns_errors,
				uint32_t *dhcp_timeouts,
				uint32_t *ip_addr_conflicts,
				uint32_t *out_of_memory,
				uint32_t *internal_error)
{
	int ret = 0;
#ifdef INCLUDE_OMCI_ONU_UCI
	char uci_opt[OMCI_UCI_PARAM_STR_MAX_SIZE],
	     path[OMCI_UCI_PARAM_STR_MAX_SIZE];
#endif
	if (!ifname)
		return -1;

	/** \todo add appropriate handling*/
	*dns_errors = 0;
	*internal_error = 0;
	*ip_addr_conflicts = 0;
	*dhcp_timeouts = 0;

	ret = proc_net_counter_get(ICMP_STATS_PATH, ICMP_STATS_PREFIX,
				   ICMP_STATS_IN_ERRORS_OFFSET,
				   icmp_errors);
	if (ret != 0) {
		dbg_err("ICM error counter get failed, ret=%d", ret);
		return ret;
	}

	ret = proc_net_counter_get(TCPEXT_STATS_PATH, TCPEXT_STATS_PREFIX,
				   TCPEXT_STATS_ABORT_ON_MEMORY_OFFSET,
				   out_of_memory);
	if (ret != 0) {
		dbg_err("Out of Memory error counter get failed, ret=%d", ret);
		return ret;
	}

#ifdef INCLUDE_OMCI_ONU_UCI
	ret = omci_uci_config_get("omci", "default", "status_file", path);
	if (ret != 0) {
		dbg_err("OMCI uci config get failed, ret=%d", ret);
		return ret;
	}

	ret = omci_uci_config_get(path, "ip_conflicts", ifname, uci_opt);
	if (ret != 0)
		dbg_msg("IP conflicts counter get failed, ret=%d", ret);
	else
		*ip_addr_conflicts = (uint32_t)strtoul(uci_opt, NULL, 10);

	ret = omci_uci_config_get(path, "dhcp_timeouts", ifname, uci_opt);
	if (ret != 0)
		dbg_msg("DHCP timeouts counter get failed, ret=%d", ret);
	else
		*dhcp_timeouts = (uint32_t)strtoul(uci_opt, NULL, 10);
#endif

	return 0;
}

static enum omci_error me_counters_get(struct omci_context *context,
				       struct me *me,
				       enum omci_pm_interval interval)
{
	struct omci_me_ip_host_monitoring_data *me_data;
	uint32_t icmp_errors;
	uint32_t dns_errors;
	uint32_t dhcp_timeouts;
	uint32_t ip_addr_conflicts;
	uint32_t out_of_memory;
	uint32_t internal_error;
	int ret;

	dbg_in(__func__, "%p, %p, %lu", (void *)context, (void *)me, interval);

	me_data = (struct omci_me_ip_host_monitoring_data *)me->data;

	ret = ip_host_counters_get(ip_host_ifname_get(me->instance_id),
				   &icmp_errors,
				   &dns_errors,
				   &dhcp_timeouts,
				   &ip_addr_conflicts,
				   &out_of_memory,
				   &internal_error);

	if (ret) {
		dbg_out_ret(__func__, OMCI_ERROR_DRV);
		return OMCI_ERROR_DRV;
	}

	me_data->icmp_errors = icmp_errors;
	me_data->dns_errors = dns_errors;
	me_data->dhcp_timeouts = (uint16_t)dhcp_timeouts;
	me_data->ip_address_conflict = (uint16_t)ip_addr_conflicts;
	me_data->out_of_memory = (uint16_t)out_of_memory;
	me_data->internal_error = (uint16_t)internal_error;

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	enum omci_error error;

	/* check if related IP Host Config exists */
	error = mib_me_find(context, OMCI_ME_IP_HOST_CONFIG_DATA,
			    me->instance_id, NULL);
	RETURN_IF_ERROR(error);

	error = default_me_init(context, me, init_data, suppress_avc);
	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}

static struct me_tca tca_table[] = {
	/* 1 IPNPM ICMP error #1 */
	TCA(1, omci_me_ip_host_monitoring_data_icmp_errors, 1),
	/* 2 IPNPM DNS error #2 */
	TCA(2, omci_me_ip_host_monitoring_data_dns_errors, 2),
	/* 3 DHCP timeout #3 */
	TCA(3, omci_me_ip_host_monitoring_data_dhcp_timeouts, 3),
	/* 4 IP address conflict #4 */
	TCA(4, omci_me_ip_host_monitoring_data_ip_address_conflict, 4),
	/* 5 Out of memory #5 */
	TCA(5, omci_me_ip_host_monitoring_data_out_of_memory, 5),
	/* 6 Internal error #6 */
	TCA(6, omci_me_ip_host_monitoring_data_internal_error, 6),

	TCA(0, 0, 0)
};

/** Managed Entity class */
struct me_class me_ip_host_monitoring_data_class = {
	/* Class ID */
	OMCI_ME_IP_HOST_MONITORING_DATA,
	/* Attributes */
	{
		ATTR_UINT("Interval end time",
			ATTR_SUPPORTED,
			0x00,
			0xff,
			offsetof(struct omci_me_ip_host_monitoring_data,
				 interval_end_time),
			1,
			OMCI_ATTR_PROP_RD,
			pm_interval_end_time_get),
		ATTR_UINT("Threshold data",
			ATTR_SUPPORTED,
			0x0000,
			0xffff,
			offsetof(struct omci_me_ip_host_monitoring_data,
				 threshold_data),
			2,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			OMCI_ATTR_PROP_SBC,
			NULL),
		ATTR_UINT("ICMP errors",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_ip_host_monitoring_data,
				 icmp_errors),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("DNS errors",
			ATTR_SUPPORTED,
			0x00000000,
			0xffffffff,
			offsetof(struct omci_me_ip_host_monitoring_data,
				 dns_errors),
			4,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("DHCP timeouts",
			ATTR_SUPPORTED,
			0x0000,
			0xffff,
			offsetof(struct omci_me_ip_host_monitoring_data,
				 dhcp_timeouts),
			2,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("IP address conflict",
			ATTR_SUPPORTED,
			0x0000,
			0xffff,
			offsetof(struct omci_me_ip_host_monitoring_data,
				 ip_address_conflict),
			2,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Out of memory",
			ATTR_SUPPORTED,
			0x0000,
			0xffff,
			offsetof(struct omci_me_ip_host_monitoring_data,
				 out_of_memory),
			2,
			OMCI_ATTR_PROP_RD,
			NULL),
		ATTR_UINT("Internal error",
			ATTR_SUPPORTED,
			0x0000,
			0xffff,
			offsetof(struct omci_me_ip_host_monitoring_data,
				 internal_error),
			2,
			OMCI_ATTR_PROP_RD,
			NULL),
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
		create_action_handle,
		NULL,
		/* Delete */
		delete_action_handle,
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
		NULL,
		/* Test result */
		NULL,
		/* Get current data */
		get_current_data_action_handle
	},
	/* Init Handler */
	me_init,
	/* Shutdown Handler */
	NULL,
	/* Validate Handler */
	default_me_validate,
	/* Update Handler */
	default_me_update,
	/* Table Attribute Copy Handler */
	NULL,
	/* Table Attribute Operations Handler */
	NULL,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	me_counters_get,
	/* Thresholds set Handler */
	default_me_thr_set,
#endif
	/* TCA Table */
	tca_table,
	/* Data Size */
	sizeof(struct omci_me_ip_host_monitoring_data),
	/* Properties */
	OMCI_ME_PROP_PM | OMCI_ME_PROP_PM_INTERNAL | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"IP host monitoring data",
		/* Access */
		ME_CREATED_BY_OLT,
		/* Supported alarms */
		NULL,
		/* Supported alarms count */
		0,
		/* Support */
		ME_SUPPORTED
	},
#endif
	/* dynamically calculated */
	0, 0, 0, 0, 0, 0
};

/** @} */

#endif
