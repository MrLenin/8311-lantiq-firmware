/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_ip_host_config_data.c
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_ip_host_config_data.h"
#include "omci_api_usock.h"

#ifdef INCLUDE_OMCI_ONU_UCI
#include "uci/omci_uci_config.h"
#endif

#ifdef INCLUDE_OMCI_ONU_VOIP
/** Timeout between IP host ME update and actual SIP reconfiguration.
   Required, because IP configuration is not applied immediately. */
#define OMCI_SIP_RECONFIGURE_TIMEOUT				3000
/** Maximum number of intermediate entities that can be processed */
#define OMCI_SIP_RECONFIGURE_ME_MAX				10

#include "me/omci_sip_agent_config_data.h"
#include "me/omci_sip_user_data.h"
#include "me/omci_tcp_udp_config_data.h"
#endif

#ifdef LINUX
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#endif


/** \addtogroup OMCI_IP_HOST_CONFIG_DATA
   @{
*/

const char *ip_host_ifname_get(uint16_t instance_id)
{
	/* let ME instance 0 be the wan interface */
	static const char *net_name[2] = {"wan", "lan"};

	assert(instance_id < 2);

	return net_name[instance_id];
}

static int mac_address_get(const char *name, char *mac_address)
{
#ifdef LINUX
	int fd, i;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, name, IFNAMSIZ-1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	close(fd);
	for (i = 0; i < 6; i++)
		mac_address[i] = ifr.ifr_hwaddr.sa_data[i];
#endif

	return 0;
}

static int ip_address_get(const char *name, char *ip_address)
{
#ifdef LINUX
	int fd;
	struct ifreq ifr;
	struct sockaddr_in *sa;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, name, IFNAMSIZ-1);
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	sa = (struct sockaddr_in *)&ifr.ifr_addr;
	switch (sa->sin_family) {
	case AF_INET6:
		break;
	default:
		memcpy(ip_address, &sa->sin_addr.s_addr, 4);
		break;
	}
	close(fd);
#endif

	return 0;
}

static void copy_ipv4_address(uint8_t *dest, uint8_t *src)
{
	dest[0] = src[0];
	dest[1] = src[1];
	dest[2] = src[2];
	dest[3] = src[3];
}

static enum omci_error mac_get(struct omci_context *context,
			       struct me *me, void *data, size_t data_size)
{
	assert(data_size == 6);

	mac_address_get(ip_host_ifname_get(me->instance_id), data);

	return OMCI_SUCCESS;
}

static enum omci_error current_address_get(struct omci_context *context,
					   struct me *me, void *data,
					   size_t data_size)
{
#ifdef INCLUDE_OMCI_ONU_UCI
	struct uci_network *net = NULL;
#endif
	assert(data_size == 4);

#ifdef INCLUDE_OMCI_ONU_UCI
	if (omci_uci_init() == 0) {
		net = uci_network_get(ip_host_ifname_get(me->instance_id));
		if (net) {
			if (net->ipaddr) {
				memcpy(data, net->ipaddr, data_size);
			} else {
				if (ip_address_get(
					ip_host_ifname_get(me->instance_id),
					data) != 0)
					memset(data, 0, data_size);
			}
		}
		omci_uci_free();
	}
#endif

	return OMCI_SUCCESS;
}

static enum omci_error current_mask_get(struct omci_context *context,
					 struct me *me,
					 void *data,
					 size_t data_size)
{
#ifdef INCLUDE_OMCI_ONU_UCI
	struct uci_network *net = NULL;
#endif
	assert(data_size == 4);

#ifdef INCLUDE_OMCI_ONU_UCI
	if (omci_uci_init() == 0) {
		net = uci_network_get(ip_host_ifname_get(me->instance_id));
		if (net) {
			if (net->netmask)
				memcpy(data, net->netmask, data_size);
			else
				memset(data, 0, data_size);
		}
		omci_uci_free();
	}
#endif

	return OMCI_SUCCESS;
}

static enum omci_error current_gateway_get(struct omci_context *context,
					 struct me *me,
					 void *data,
					 size_t data_size)
{
#ifdef INCLUDE_OMCI_ONU_UCI
	struct uci_network *net = NULL;
#endif
	assert(data_size == 4);

#ifdef INCLUDE_OMCI_ONU_UCI
	if (omci_uci_init() == 0) {
		net = uci_network_get(ip_host_ifname_get(me->instance_id));
		if (net) {
			if (net->gateway)
				memcpy(data, net->gateway, data_size);
			else
				memset(data, 0, data_size);
		}
		omci_uci_free();
	}
#endif

	return OMCI_SUCCESS;
}

#ifdef INCLUDE_OMCI_ONU_VOIP
static enum omci_error sip_config_update_timeout_handler(struct omci_context
							 *context,
							 struct timeout
							 *timeout)
{
	struct me *tcp_udp_data_me[OMCI_SIP_RECONFIGURE_ME_MAX];
	size_t tcp_udp_data_found;
	struct me *sip_agent_me[OMCI_SIP_RECONFIGURE_ME_MAX];
	size_t sip_agent_me_found;
	struct me *sip_user_me[OMCI_SIP_RECONFIGURE_ME_MAX];
	size_t sip_user_me_found;
	int i, j, k;
	enum omci_error error;

	mib_lock_read(context);

	dbg_prn("SIP configuration update");

	error = mib_me_find_where(context,
				  OMCI_ME_TCP_UDP_CONFIG_DATA,
				  omci_me_tcp_udp_config_data_ip_host_ptr,
				  &timeout->instance_id,
				  sizeof(timeout->instance_id),
				  &tcp_udp_data_me[0], sizeof(tcp_udp_data_me),
				  &tcp_udp_data_found);
	if (error != OMCI_SUCCESS)
		goto exit;

	for (i = 0; i < tcp_udp_data_found; i++) {
		error = mib_me_find_where(context,
					  OMCI_ME_SIP_AGENT_CONFIG_DATA,
					  omci_sip_agent_config_data_tcp_udp_ptr,
					  &tcp_udp_data_me[i]->instance_id,
					  sizeof(tcp_udp_data_me[i]->instance_id),
					  &sip_agent_me[0],
					  sizeof(sip_agent_me),
					  &sip_agent_me_found);
		if (error != OMCI_SUCCESS)
			continue;

		for (j = 0; j < sip_agent_me_found; j++) {
			me_dbg_prn(sip_agent_me[j], "Refresh agent");
			me_lock(context, sip_agent_me[j]);
			error = me_refresh(context, sip_agent_me[j]);
			me_unlock(context, sip_agent_me[j]);
			if (error != OMCI_SUCCESS) {
				me_dbg_err(sip_agent_me[j], "Refresh error %d",
					   error);
				continue;
			}

			error = mib_me_find_where(context,
						  OMCI_ME_SIP_USER_DATA,
						  omci_sip_user_data_sip_agent_ptr,
						  &sip_agent_me[j]->instance_id,
						  sizeof(sip_agent_me[j]->instance_id),
						  &sip_user_me[0],
						  sizeof(sip_user_me),
						  &sip_user_me_found);
			if (error != OMCI_SUCCESS)
				continue;

			for (k = 0; k < sip_user_me_found; k++) {
				me_dbg_prn(sip_user_me[k], "Refresh user");
				me_lock(context, sip_user_me[k]);
				error = me_refresh(context, sip_user_me[k]);
				me_unlock(context, sip_user_me[k]);
				if (error != OMCI_SUCCESS) {
					me_dbg_err(sip_user_me[k],
						   "Refresh error %d", error);
					continue;
				}
			}
		}
	}

exit:
	mib_unlock(context);
	return error;
}
#endif

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	struct omci_me_ip_host_config_data *upd_data;
#ifdef INCLUDE_OMCI_ONU_UCI
	struct uci_network *net = NULL;
	char *proto;
	char sys_cmd[128];
#endif
#ifdef INCLUDE_OMCI_ONU_VOIP
	enum omci_error error;
#endif

	dbg_in(__func__, "%p, %p, %p, 0x%04x", (void *)context, (void *)me,
	       (void *)data, attr_mask);

	if (me->instance_id >= 2) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	upd_data = (struct omci_me_ip_host_config_data *)data;

#ifdef INCLUDE_OMCI_ONU_UCI
	/* requested static configuration with ip 0.0.0.0 (don't apply) */
	if ((upd_data->ip_options & 1) == 0 &&
	    *(uint32_t *)upd_data->ip_address == 0) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	if (omci_uci_init() == 0) {
		net = uci_network_get(ip_host_ifname_get(me->instance_id));
		if (net == NULL) {
			omci_uci_free();

			dbg_out_ret(__func__, OMCI_SUCCESS);
			return OMCI_SUCCESS;
		}

		uci_network_opt_set(net, (void**)&net->host_name,
				    upd_data->host_name,
				    strlen(upd_data->host_name));

		uci_network_opt_set(net, (void**)&net->client_id,
				    upd_data->ont_id,
				    strlen(upd_data->ont_id));

		if (upd_data->ip_options & 1) {
			proto = "dhcp";
		} else {
			proto = "static";

			uci_network_opt_set(net, (void**)&net->ipaddr,
					    upd_data->ip_address,
					    sizeof(upd_data->ip_address));

			uci_network_opt_set(net, (void**)&net->netmask,
					    upd_data->mask,
					    sizeof(upd_data->mask));

			uci_network_opt_set(net, (void**)&net->gateway,
					    upd_data->gateway,
					    sizeof(upd_data->gateway));
		}

		uci_network_opt_set(net, (void**)&net->proto,
				    proto, strlen(proto));

		uci_network_set(net);

		sprintf(sys_cmd, "ifup %s > /dev/null \n",
			ip_host_ifname_get(me->instance_id));

		if (omci_api_scmd_run(context->api, sys_cmd) != OMCI_SUCCESS)
			me_dbg_err(me, "SYS ERR shell cmd failed!");

#ifdef INCLUDE_OMCI_ONU_VOIP
		/* suppose that the IP configuration is changed; so we run
		   timeout handler in \ref OMCI_SIP_RECONFIGURE_TIMEOUT ms
		   to update SIP agent configurations */
		error = timeout_event_add(context,
				  NULL,
				  OMCI_SIP_RECONFIGURE_TIMEOUT,
				  sip_config_update_timeout_handler,
				  me->class->class_id,
				  me->instance_id,
				  0, 0, 0);
		if (error != OMCI_SUCCESS) {
			me_dbg_err(me, "ERROR(%d) Can't add timeout handler "
				   "for SIP configuration update!", error);
		}
#endif

		omci_uci_free();
	}
#endif

	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	struct omci_me_ip_host_config_data data;
	enum omci_error error;
#ifdef INCLUDE_OMCI_ONU_UCI
	struct uci_network *net = NULL;
#endif

	memset(&data, 0, sizeof(data));

	if (me->instance_id < 2) {
#ifdef INCLUDE_OMCI_ONU_UCI
		if (omci_uci_init() == 0) {
			net = uci_network_get(ip_host_ifname_get(me->instance_id));
			if (net) {
				if (net->ipaddr)
					copy_ipv4_address(&data.ip_address[0],
							  net->ipaddr);
				if (net->netmask)
					copy_ipv4_address(&data.mask[0],
							  net->netmask);

				if (net->gateway)
					copy_ipv4_address(&data.gateway[0],
							  net->gateway);

				if (net->host_name)
					strcpy(data.host_name,
					       net->host_name);

				if (net->client_id)
					strcpy(data.ont_id, net->client_id);

				if (net->proto) {
					if (strcmp("dhcp", net->proto) == 0)
						data.ip_options |= 1;
				}
				/* ping is possible */
				data.ip_options |= 2;
			}
			omci_uci_free();
		}
#endif
	}

	error = me_data_write(context, me, &data, sizeof(data),
			      ~me->class->inv_attr_mask, suppress_avc);
	RETURN_IF_ERROR(error);

	return OMCI_SUCCESS;
}

static enum omci_error me_shutdown(struct omci_context *context,
				   struct me *me)
{
	dbg_in(__func__, "%p, %p", (void *)context, (void *)me);

#ifdef INCLUDE_OMCI_ONU_UCI
	if (uci_network_revert() != 0)
		me_dbg_wrn(me, "uci network revert failed");
#endif
	dbg_out_ret(__func__, OMCI_SUCCESS);
	return OMCI_SUCCESS;
}

static enum omci_error test_action_handle(struct omci_context *context,
					  struct me *me,
					  const union omci_msg *msg,
					  union omci_msg *rsp)
{
	return OMCI_SUCCESS;
}

/** Managed Entity class */
struct me_class me_ip_host_config_data_class = {
	/* Class ID */
	OMCI_ME_IP_HOST_CONFIG_DATA,
	/* Attributes */
	{
		/* 1. IP options */
		ATTR_BF("IP options",
			ATTR_SUPPORTED,
			0x7,
			offsetof(struct omci_me_ip_host_config_data,
				 ip_options),
			1,
			OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			OMCI_ATTR_PROP_PARTLY,
			NULL),
		/* 2. MAC address */
		ATTR_STR("MAC address",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  mac_address),
			 6,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 mac_get),
		/* 3. Ont identifier */
		ATTR_STR("ONT identifier",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  ont_id),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 4. IP address */
		ATTR_STR("IP address",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  ip_address),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 5. Mask */
		ATTR_STR("Mask",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  mask),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 6. Gateway */
		ATTR_STR("Gateway",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  gateway),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 7. Primary DNS */
		ATTR_STR("Primary DNS",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  primary_dns),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 8. Secondary DNS */
		ATTR_STR("Secondary DNS",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  secondary_dns),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 9. Current address */
		ATTR_STR("Current address",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  current_address),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			 OMCI_ATTR_PROP_OPTIONAL,
			 current_address_get),
		/* 10. Current mask */
		ATTR_STR("Current mask",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  current_mask),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			 OMCI_ATTR_PROP_OPTIONAL,
			 current_mask_get),
		/* 11. Current gateway */
		ATTR_STR("Current gateway",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  current_gateway),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			 OMCI_ATTR_PROP_OPTIONAL,
			 current_gateway_get),
		/* 12. Current primary DNS */
		ATTR_STR("Current primary DNS",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  current_primary_dns),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			 OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 13. Current secondary DNS */
		ATTR_STR("Current secondary DNS",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  current_secondary_dns),
			 4,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			 OMCI_ATTR_PROP_OPTIONAL | OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 14. Domain name */
		ATTR_STR("Domain name",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  domain_name),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			 OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 15. Host name */
		ATTR_STR("Host name",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ip_host_config_data,
				  host_name),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_AVC |
			 OMCI_ATTR_PROP_TEMPLATE,
			 NULL),
		/* 16. Doesn't exist */
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
		test_action_handle,
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
		NULL
	},
	/* Init Handler */
	me_init,
	/* Shutdown Handler */
	me_shutdown,
	/* Validate Handler */
	default_me_validate,
	/* Update Handler */
	me_update,
	/* Table Attribute Copy Handler */
	NULL,
#ifdef INCLUDE_PM
	/* Counters get Handler */
	NULL,
	/* Thresholds set Handler */
	NULL,
#endif
	/* TCA Table */
	NULL,
	/* Data Size */
	sizeof(struct omci_me_ip_host_config_data),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"IP host config data",
		/* Access */
		ME_CREATED_BY_ONT,
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
