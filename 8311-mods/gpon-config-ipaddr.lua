--[[
LuCI - Lua Configuration Interface

Copyright 2011 Ralph Hempel <ralph.hempel@lantiq.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

]]--

require("luci.tools.gpon")

m = Map("network", translate("IP/MAC Addresses"))

s = m:section(NamedSection, "host", "HOST", "Test")
s.anonymous = true
s.addremove = false

v = s:option(Value, "macaddr", translate("HOST Interface (WAN) MAC Address"), translate("HOST interface MAC address (only applicable where MAC address authentication is used)."))
v.addremove = true
v.rmempty = false
v.datatype = "macaddr"

s = m:section(NamedSection, "lct", "LCT")
s.anonymous = true
s.addremove = false

v = s:option(Value, "ipaddr", translate("LCT Interface (LAN) IP Address"), translate("LCT interface IP address."))
v.addremove = true
v.rmempty = false
v.datatype = "ip4addr"

v = s:option(Value, "gateway", translate("LCT Interface (LAN) Gateway Address"), translate("LCT interface gateway address."))
v.addremove = true
v.rmempty = false
v.datatype = "ip4addr"

v = s:option(Value, "macaddr", translate("LCT Interface (LAN) MAC Address"), translate("LCT interface MAC address."))
v.addremove = true
v.rmempty = false
v.datatype = "macaddr"

function m.on_after_commit(map)
    luci.sys.call("/opt/lantiq/bin/config_onu.sh setip")
end

return m
