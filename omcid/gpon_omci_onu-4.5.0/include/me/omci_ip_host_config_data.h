/******************************************************************************

                              Copyright (c) 2011
                            Lantiq Deutschland GmbH
                     Am Campeon 3; 85579 Neubiberg, Germany

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef _omci_ip_host_config_data_h
#define _omci_ip_host_config_data_h

#ifndef SWIG
#include "omci_interface.h"
#endif

__BEGIN_DECLS

/** \addtogroup OMCI_ME
   @{
*/

/** \defgroup OMCI_IP_HOST_CONFIG_DATA IP Host Config Data Managed Entity

    The IP host config data configures IP based services offered on the ONT.
    The ONT automatically creates instances of this Managed Entity if IP host
    services are available.

    @{
*/

/** This structure holds the attributes of the IP Host Config Data Managed
   Entity. */
struct omci_me_ip_host_config_data {
	/** IP Options
	    This attribute is a bit map that enables or disables IP related
	    options.
	    The value 0b1 enables the option while 0b0 disables it.
	    - Bit 0 (0x01): Enable DHCP
	    - Bit 1 (0x02): Respond to "Ping"
	    - Bit 2 (0x04): Respond to traceroute messages
	    - Bit 3 (0x08): Reserved
	    - Bit 4 (0x10): Reserved
	    - Bit 5 (0x20): Reserved
	    - Bit 6 (0x40): Reserved
	    - Bit 7 (0x80): Reserved
	    This parameter is readable and writable by the OLT.
	    The default value is 0x00.
	*/
	uint8_t ip_options;

	/** MAC Address
	    This attribute indicates the MAC address used by the IP node.
	    This parameter is read-only by the OLT.
	    The value is read from an external non-volatile memory.
	*/
	uint8_t mac_address[6];

	/** ONT Identifier
	    A unique ONT identifier string. If set to a non-null value, this
	    string is used instead of the MAC address in retrieving DHCP
	    parameters.  If the string is shorter than 25 characters, it must
	    be null terminated.
	    Its default value is 25 null bytes.
	    This parameter is readable and writable by the OLT.
	*/
	uint8_t ont_id[25];

	/** IPv4 Address
	    This is the address used for IP host services, the attribute has
	    the default value 0x0000 0000 (not set). If this value is set, it
	    overrides any values returned in DHCP.
	    This parameter is readable and writable by the OLT.
	*/
	uint8_t ip_address[4];

	/** IPv4 Address Mask
	    This is the subnet mask for IP host services, the attribute has the
	    default value 0x0000 0000 (not set). If this value is set, it
	    overrides any values returned in DHCP.
	    This parameter is readable and writable by the OLT.
	*/
	uint8_t mask[4];

	/** Gateway IP Address
	    This is the default gateway address used for IP host services, this
	    attribute has the default value 0x0000 0000 (not set). If this value
	    is set, it overrides any values returned in DHCP.
	    This parameter is readable and writable by the OLT.
	*/
	uint8_t gateway[4];

	/** Primary DNS Address
	    This is the address of the primary DNS server, the attribute has the
	    default value 0x0000 0000 (not set). If this value is set, it
	    overrides any values returned in DHCP.
	    This parameter is readable and writable by the OLT.
	*/
	uint8_t primary_dns[4];

	/** Secondary DNS Address
	    This is the address of the secondary DNS server, the attribute has
	    the default value 0x0000 0000 (not set). If this value is set, it
	    overrides any values returned in DHCP.
	    This parameter is readable and writable by the OLT.
	*/
	uint8_t secondary_dns[4];

	/** Current Address
	    This is the current address of the IP host service. The ONT updates
	    this attribute if DHCP assigns a new address.
	    This parameter is read-only by the OLT.
	*/
	uint8_t current_address[4];

	/** Current Address Mask
	    This is the current subnet mask for the IP host service. The ONT
	    updates this attribute if DHCP assigns a new mask.
	    This parameter is read-only by the OLT.
	*/
	uint8_t current_mask[4];

	/** Current Gateway
	    This is the current default gateway address for the IP host service.
	    The ONT updates this attribute if DHCP assigns a new gateway.
	    This parameter is read-only by the OLT.
	*/
	uint8_t current_gateway[4];

	/** Current Primary DNS Address
	    This is the current primary DNS server address. The ONT updates this
	    attribute if DHCP assigns a new address.
	    This parameter is read-only by the OLT.
	*/
	uint8_t current_primary_dns[4];

	/** Current Secondary DNS Address
	    This is the current secondary DNS server address. The ONT updates
	    this attribute if DHCP assigns a new address.
	    This parameter is read-only by the OLT.
	*/
	uint8_t current_secondary_dns[4];

	/** Domain Name
	    If DHCP indicates a domain name, it is presented here. If no domain
	    name is indicated, this attribute is set to a null string. If the
	    string is shorter than 25 byte, it must be null terminated.
	    The default value is 25 null bytes.
	    This parameter is read-only by the OLT.
	*/
	uint8_t domain_name[25];

	/** Host Name
	    If DHCP indicates a host name, it is presented here. If no host name
	    is indicated, this attribute is set to a null string. If the string
	    is shorter than 25 byte, it must be null terminated.
	    The default value is 25 null bytes.
	    This parameter is read-only by the OLT.
	*/
	uint8_t host_name[25];

} __PACKED__;

/** This enumerator holds the attribute numbers of the IP Host Config Data
   Managed Entity.
*/
enum {
	omci_me_ip_host_config_data_ip_options = 1,
	omci_me_ip_host_config_data_mac_address = 2,
	omci_me_ip_host_config_data_ont_id = 3,
	omci_me_ip_host_config_data_ip_address = 4,
	omci_me_ip_host_config_data_mask = 5,
	omci_me_ip_host_config_data_gateway = 6,
	omci_me_ip_host_config_data_primary_dns = 7,
	omci_me_ip_host_config_data_secondary_dns = 8,
	omci_me_ip_host_config_data_current_address = 9,
	omci_me_ip_host_config_data_current_mask = 10,
	omci_me_ip_host_config_data_current_gateway = 11,
	omci_me_ip_host_config_data_current_primary_dns = 12,
	omci_me_ip_host_config_data_current_secondary_dns = 13,
	omci_me_ip_host_config_data_domain_name = 14,
	omci_me_ip_host_config_data_host_name = 15
};

/** Return interface name depending on IP host instance id

   \param[in] instance_id IP host ME instance id

   \return interface name
*/
const char *ip_host_ifname_get(uint16_t instance_id);

/** @} */

/** @} */

__END_DECLS

#endif
