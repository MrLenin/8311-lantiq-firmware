/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
/**
   \file omci_ipv6_host_config_data.c

   IPv6 Host Config Data ME (class 347).
   Backported from gpon_omci_onu-8.6.3 to v4.5.0 framework.

   This is a minimal implementation suitable for SFP ONUs that don't run
   a full IPv6 stack. It stores all writable attributes, returns MAC address
   and DUID via computed getters, and reports empty tables.
*/
#define OMCI_DBG_MODULE   OMCI_DBG_MODULE_ME

#include "omci_core.h"
#include "omci_debug.h"
#include "omci_me_handlers.h"
#include "me/omci_ipv6_host_config_data.h"

#ifdef LINUX
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#endif

/** \addtogroup OMCI_ME_IPV6_HOST_CONFIG_DATA
   @{
*/

#define IPV6_HOST_IFNAME "host"

/** Read MAC address from a network interface via ioctl. */
static int ipv6_mac_address_get(const char *name, uint8_t *mac)
{
#ifdef LINUX
	int fd, i;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	close(fd);
	for (i = 0; i < 6; i++)
		mac[i] = (uint8_t)ifr.ifr_hwaddr.sa_data[i];
#endif
	return 0;
}

/** Attribute getter: MAC address (attr 2). */
static enum omci_error mac_addr_get(struct omci_context *context,
				    struct me *me, void *data,
				    size_t data_size)
{
	assert(data_size == 6);

	if (ipv6_mac_address_get(IPV6_HOST_IFNAME, (uint8_t *)data) < 0) {
		memset(data, 0, data_size);
		return OMCI_ERROR_DRV;
	}

	return OMCI_SUCCESS;
}

/** Attribute getter: DUID (attr 12).
    Returns DUID-LL (type 3) derived from MAC address per RFC 3315. */
static enum omci_error duid_get(struct omci_context *context,
				struct me *me, void *data,
				size_t data_size)
{
	uint8_t duid[10] = {
		0, 3, /* DUID-LL */
		0, 1, /* Hardware type: Ethernet */
		0, 0, 0, 0, 0, 0 /* MAC */
	};

	assert(data_size == 25);

	memset(data, 0, data_size);

	if (ipv6_mac_address_get(IPV6_HOST_IFNAME, &duid[4]) == 0)
		memcpy(data, duid, sizeof(duid));

	return OMCI_SUCCESS;
}

/** Table copy handler: all four table attributes return empty tables. */
static enum omci_error me_tbl_copy(struct omci_context *context,
				   struct me *me,
				   unsigned int attr,
				   struct tbl_copy_entry *tbl_copy)
{
	/* All table attributes are empty on this SFP ONU (no IPv6 stack).
	   Return size 0 which the framework reports as an empty table. */
	tbl_copy->data_size = 0;
	tbl_copy->data = NULL;

	return OMCI_SUCCESS;
}

static enum omci_error me_update(struct omci_context *context,
				 struct me *me,
				 void *data,
				 uint16_t attr_mask)
{
	/* No hardware actions needed on this SFP ONU.
	   Attribute data is stored by the framework. */
	return OMCI_SUCCESS;
}

static enum omci_error me_init(struct omci_context *context,
			       struct me *me,
			       void *init_data,
			       uint16_t suppress_avc)
{
	return default_me_init(context, me, init_data, suppress_avc);
}

/** Managed Entity class */
struct me_class me_ipv6_host_config_data_class = {
	/* Class ID */
	OMCI_ME_IPV6_CONFIG_DATA,
	/* Attributes */
	{
		/* 1. IP options */
		ATTR_UINT("IP options",
			  ATTR_SUPPORTED,
			  0,
			  15,
			  offsetof(struct omci_me_ipv6_host_config_data,
				   ip_options),
			  1,
			  OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			  OMCI_ATTR_PROP_PARTLY,
			  NULL),
		/* 2. MAC address */
		ATTR_STR("MAC address",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ipv6_host_config_data,
				  mac_addr),
			 6,
			 OMCI_ATTR_PROP_RD,
			 mac_addr_get),
		/* 3. ONU identifier */
		ATTR_STR("ONU identifier",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ipv6_host_config_data,
				  onu_id),
			 25,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 4. IPv6 link local address */
		ATTR_STR("IPv6 link local addr",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ipv6_host_config_data,
				  ipv6_link_local_addr),
			 16,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 5. IPv6 address */
		ATTR_STR("IPv6 address",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ipv6_host_config_data,
				  ipv6_addr),
			 16,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 6. Default router */
		ATTR_STR("Default router",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ipv6_host_config_data,
				  default_router),
			 16,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 7. Primary DNS */
		ATTR_STR("Primary DNS",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ipv6_host_config_data,
				  primary_dns),
			 16,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 8. Secondary DNS */
		ATTR_STR("Secondary DNS",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ipv6_host_config_data,
				  secondary_dns),
			 16,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR,
			 NULL),
		/* 9. Current address table */
		ATTR_TBL("Current address tbl",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ipv6_host_config_data,
				  current_addr_table),
			 24,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 10. Current default router table */
		ATTR_TBL("Current def rtr tbl",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ipv6_host_config_data,
				  current_default_router_table),
			 16,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 11. Current DNS table */
		ATTR_TBL("Current DNS tbl",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ipv6_host_config_data,
				  current_dns_table),
			 16,
			 OMCI_ATTR_PROP_RD,
			 NULL),
		/* 12. DUID */
		ATTR_STR("DUID",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ipv6_host_config_data,
				  duid),
			 25,
			 OMCI_ATTR_PROP_RD,
			 duid_get),
		/* 13. On-link prefix */
		ATTR_STR("On-link prefix",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ipv6_host_config_data,
				  on_link_prefix),
			 17,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_WR |
			 OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 14. Current on-link prefix table */
		ATTR_TBL("Curr on-link pfx tbl",
			 ATTR_SUPPORTED,
			 offsetof(struct omci_me_ipv6_host_config_data,
				  current_on_link_prefix_table),
			 26,
			 OMCI_ATTR_PROP_RD | OMCI_ATTR_PROP_OPTIONAL,
			 NULL),
		/* 15-16. Not defined */
		ATTR_NOT_DEF(),
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
		get_next_action_handle,
		/* Test result */
		NULL,
		/* Get current data */
		NULL
	},
	/* Init Handler */
	me_init,
	/* Shutdown Handler */
	NULL,
	/* Validate Handler */
	default_me_validate,
	/* Update Handler */
	me_update,
	/* Table Attribute Copy Handler */
	me_tbl_copy,
	/* Table Attribute Operations Handler */
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
	sizeof(struct omci_me_ipv6_host_config_data),
	/* Properties */
	OMCI_ME_PROP_NONE | OMCI_ME_PROP_REVIEW,
#ifdef INCLUDE_OMCI_SELF_DESCRIPTION
	{
		/* Name */
		"IPv6 Host Config Data",
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
