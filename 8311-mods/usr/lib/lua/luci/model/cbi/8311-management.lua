--[[
LuCI - Lua Configuration Interface

Network Addresses (Management) CBI Form
=========================================
Edits the UCI config file /etc/config/network to configure the two
network interfaces used by the 8311 module:

  host  - IP Host interface (WAN-facing): only the MAC address is
          configurable here; the OLT provisions the IP via OMCI.
  lct   - Local Craft Terminal interface (LAN-facing): IP, subnet,
          gateway, DNS, and MAC address for management access to
          the module over the SFP cage host.

On commit, config_onu.sh setip applies the new addresses to the
running network configuration.

Copyright 2011 Ralph Hempel <ralph.hempel@lantiq.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

]]--

require("luci.tools.gpon")

local network_map = Map("network")

local host_config = network_map:section(NamedSection, "host", "interface", "IP Host Interface (WAN)")

local host_mac =
    host_config:option(Value, "macaddr", translate("MAC Address"))

host_mac.datatype = "macaddr"
host_mac.rmempty = false

local lct_config = network_map:section(NamedSection, "lct", "interface", "LCT Interface (LAN)")

local lct_ipaddr =
    lct_config:option(Value, "ipaddr", translate("IP Address"),
    translate("Management IP address. Defaults to 192.168.1.10"))

lct_ipaddr.datatype = "ip4addr"
lct_ipaddr.default = "192.168.1.10"
lct_ipaddr.rmempty = false

local lct_netmask =
    lct_config:option(Value, "netmask", translate("Subnet Mask"),
    translate("Management subnet mask. Defaults to 255.255.255.0"))

lct_netmask.datatype = "ip4addr"
lct_netmask.default = "255.255.255.0"
lct_netmask.rmempty = false

local lct_gateway =
    lct_config:option(Value, "gateway", translate("Gateway"),
    translate("Management gateway. Defaults to the IP address (ie. no default gateway)"))

lct_gateway.datatype = "ip4addr"
lct_gateway.default = "" -- current IP addr
lct_gateway.rmempty = false

local dns_server =
    lct_config:option(Value, "dns", translate("DNS Server"),
    translate("Management DNS server."))

dns_server.datatype = "ip4addr"
dns_server.rmempty = false

local lct_macaddr =
    lct_config:option(Value, "macaddr", translate("LCT MAC Address"),
    translate("MAC address of the LCT management interface (XX:XX:XX:XX:XX:XX format)."))

lct_macaddr.datatype = "macaddr"
lct_macaddr.default = "" -- current IP addr
lct_macaddr.rmempty = false

function network_map.on_after_commit(map)
    luci.sys.call("/opt/lantiq/bin/config_onu.sh setip")
end

return network_map
