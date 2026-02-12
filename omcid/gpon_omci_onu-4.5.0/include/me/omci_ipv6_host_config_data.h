/******************************************************************************

                              Copyright (c) 2012
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_ipv6_host_config_data_h
#define _omci_ipv6_host_config_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_ME_IPV6_HOST_CONFIG_DATA IPv6 Host Config Data Managed Entity

    The IPv6 host config data configures IPv6 based services offered on the ONU.
    The ONU automatically creates instances of this ME if IPv6 host services
    are available.

    @{
*/

/** IPv6 address length in bytes. */
#define OMCI_IPV6_ADDR_LEN 16

/** IP Option flags. */
#define OMCI_ME_IPV6_HOST_IP_OPT_UNLOCKED    0x01
#define OMCI_ME_IPV6_HOST_IP_OPT_ENABLE_RS   0x02
#define OMCI_ME_IPV6_HOST_IP_OPT_ENABLE_DHCPV6 0x04
#define OMCI_ME_IPV6_HOST_IP_OPT_ENABLE_ICMPV6 0x08

/** Current address table entry (24 bytes). */
struct ipv6_current_addr_table {
	uint8_t ip_addr[OMCI_IPV6_ADDR_LEN];
	uint32_t preferred_lifetime_remaining;
	uint32_t valid_lifetime_remaining;
} __PACKED__;

/** Current default router table entry (16 bytes). */
struct ipv6_current_default_router_table {
	uint8_t ip_addr[OMCI_IPV6_ADDR_LEN];
} __PACKED__;

/** Current DNS table entry (16 bytes). */
struct ipv6_current_dns_table {
	uint8_t ip_addr[OMCI_IPV6_ADDR_LEN];
} __PACKED__;

/** Current on-link prefix table entry (26 bytes). */
struct ipv6_current_on_link_prefix_table {
	uint8_t prefix_length;
	uint8_t addr_conf_flag;
	uint8_t prefix[16];
	uint32_t preferred_lifetime;
	uint32_t valid_lifetime;
} __PACKED__;

/** This structure holds the attributes of the IPv6 Host Config Data ME. */
struct omci_me_ipv6_host_config_data {
	/** 1. IP options (R, W) (1 byte) */
	uint8_t ip_options;
	/** 2. MAC address (R) (6 bytes) */
	uint8_t mac_addr[6];
	/** 3. ONU identifier (R, W) (25 bytes) */
	uint8_t onu_id[25];
	/** 4. IPv6 link local address (R) (16 bytes) */
	uint8_t ipv6_link_local_addr[OMCI_IPV6_ADDR_LEN];
	/** 5. IPv6 address (R, W) (16 bytes) */
	uint8_t ipv6_addr[OMCI_IPV6_ADDR_LEN];
	/** 6. Default router (R, W) (16 bytes) */
	uint8_t default_router[OMCI_IPV6_ADDR_LEN];
	/** 7. Primary DNS (R, W) (16 bytes) */
	uint8_t primary_dns[OMCI_IPV6_ADDR_LEN];
	/** 8. Secondary DNS (R, W) (16 bytes) */
	uint8_t secondary_dns[OMCI_IPV6_ADDR_LEN];
	/** 9. Current address table (R) (24*N bytes) */
	struct ipv6_current_addr_table current_addr_table;
	/** 10. Current default router table (R) (16*N bytes) */
	struct ipv6_current_default_router_table current_default_router_table;
	/** 11. Current DNS table (R) (16*N bytes) */
	struct ipv6_current_dns_table current_dns_table;
	/** 12. DUID (R) (25 bytes) */
	uint8_t duid[25];
	/** 13. On-link prefix (R, W) (17 bytes) */
	uint8_t on_link_prefix[17];
	/** 14. Current on-link prefix table (R) (26*N bytes) */
	struct ipv6_current_on_link_prefix_table current_on_link_prefix_table;
} __PACKED__;

/** Attribute number enums. */
enum {
	omci_me_ipv6_host_config_data_ip_options = 1,
	omci_me_ipv6_host_config_data_mac_addr = 2,
	omci_me_ipv6_host_config_data_onu_id = 3,
	omci_me_ipv6_host_config_data_ipv6_link_local_addr = 4,
	omci_me_ipv6_host_config_data_ipv6_addr = 5,
	omci_me_ipv6_host_config_default_router = 6,
	omci_me_ipv6_host_config_primary_dns = 7,
	omci_me_ipv6_host_config_secondary_dns = 8,
	omci_me_ipv6_host_config_current_addr_table = 9,
	omci_me_ipv6_host_config_current_default_router_table = 10,
	omci_me_ipv6_host_config_current_dns_table = 11,
	omci_me_ipv6_host_config_duid = 12,
	omci_me_ipv6_host_config_on_link_prefix = 13,
	omci_me_ipv6_host_config_current_on_link_prefix_table = 14
};

/** @} */

/** @} */

__END_DECLS

#endif
