/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_net.c

   Network utility functions and interface state callback for OMCI.
   Provides MAC address retrieval and IP Host Config Data (ME 134)
   refresh on interface state changes.
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_net.h"
#include "omci_config_api.h"
#include "omci_mib.h"
#include "omci_me.h"
#include "me/omci_ip_host_config_data.h"

#ifdef LINUX
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

int omci_net_mac_get(const char *if_name, uint8_t mac[MAC_ADDR_LEN])
{
#ifdef LINUX
	int fd, i;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	close(fd);
	for (i = 0; i < MAC_ADDR_LEN; i++)
		mac[i] = ifr.ifr_hwaddr.sa_data[i];

	return 0;
#else
	memset(mac, 0, MAC_ADDR_LEN);
	return -1;
#endif
}

enum omci_error omci_net_iface_state_cb(struct omci_context *context,
					const char *iface_name,
					const bool iface_up)
{
	enum omci_error error = OMCI_SUCCESS;
	uint16_t ip_host_meid;
	struct me *ip_host_me;
	struct omci_me_ip_host_config_data me_data;

	dbg_in(__func__, "%p, %s, %s", (void *)context, iface_name,
	       iface_up ? "true" : "false");

	if (context == NULL || iface_name == NULL) {
		dbg_out_ret(__func__, OMCI_ERROR_INVALID_PTR);
		return OMCI_ERROR_INVALID_PTR;
	}

	/* Handle only UP state — DOWN doesn't change DHCP-acquired values */
	if (!iface_up) {
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	/* Map interface name to IP Host Config Data ME instance ID */
	ip_host_meid = omci_cfg_ip_host_me_id_get(iface_name);
	if (ip_host_meid == 0xFFFF) {
		dbg_wrn("Unknown interface '%s', ignoring", iface_name);
		dbg_out_ret(__func__, OMCI_SUCCESS);
		return OMCI_SUCCESS;
	}

	mib_lock_read(context);

	/* Find the IP Host Config Data ME */
	error = mib_me_find(context, OMCI_ME_IP_HOST_CONFIG_DATA,
			    ip_host_meid, &ip_host_me);
	if (error != OMCI_SUCCESS)
		goto _mib_unlock;

	me_lock(context, ip_host_me);

	/* Read current ME data */
	memcpy(&me_data, ip_host_me->data, sizeof(me_data));

	/* Only refresh if DHCP is enabled (bit 0 of ip_options) */
	if (!(me_data.ip_options & 1))
		goto _me_unlock;

	dbg_prn("Interface '%s' up, refreshing IP Host ME %u",
		iface_name, ip_host_meid);

	/* The attribute getter callbacks will be invoked on the next OLT Get
	   request, returning live data from socket ioctls and file parsing.
	   For proactive AVC generation, we would need to read each attribute's
	   current value, compare with stored, and send AVCs for changes.
	   This requires me_attr_read + me_data_write which handles AVC
	   comparison internally. */

	/* Write the current data back — me_data_write will detect changes
	   via getter callbacks and send AVCs as appropriate */
	error = me_data_write(context, ip_host_me, &me_data, sizeof(me_data),
			      omci_attr2mask(omci_me_ip_host_config_data_current_address) |
			      omci_attr2mask(omci_me_ip_host_config_data_current_mask) |
			      omci_attr2mask(omci_me_ip_host_config_data_current_gateway) |
			      omci_attr2mask(omci_me_ip_host_config_data_current_primary_dns) |
			      omci_attr2mask(omci_me_ip_host_config_data_current_secondary_dns) |
			      omci_attr2mask(omci_me_ip_host_config_data_domain_name) |
			      omci_attr2mask(omci_me_ip_host_config_data_host_name),
			      0);

_me_unlock:
	me_unlock(context, ip_host_me);
_mib_unlock:
	mib_unlock(context);

	dbg_out_ret(__func__, error);
	return error;
}
