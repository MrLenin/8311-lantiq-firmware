--[[
LuCI - Lua Configuration Interface

Copyright 2011 Ralph Hempel <ralph.hempel@lantiq.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

]] --
require("luci.tools.gpon")

local m, s, v

m = Map("gpon", translate("Interoperability/Compatibility"))

local uci = require("luci.model.uci").cursor()
local onu_section = uci:get_all("gpon", "onu")

s = m:section(NamedSection, "onu", translate("ONU"), translate("Authentication"))
s.anonymous = true
s.addremove = false

v = s:option(Value, "nSerial", translate("GPON Serial Number"),
    translate("Gigabit Passive Optical Network Serial Number."))
v.addremove = true
v.rmempty = true

v = s:option(Value, "omci_loid", translate("LOID"), translate("Logical Identifier."))
v.addremove = true
v.rmempty = true

v = s:option(Value, "omci_lpwd", translate("LOID Check Code"), translate("Logical Identifier Check Code (password)."))
v.addremove = true
v.rmempty = true

v = s:option(Value, "ploam_password", translate("PLOAM Password/SLID"),
    translate("Physical Layer Operation, Administration, and Maintenance Password."))
v.addremove = true
v.rmempty = true

s = m:section(NamedSection, "onu", translate("ONU"), translate("VLANs"))

v = s:option(Flag, "iopmask", translate("Interoperability Mask"),
    translate("Compatible with the adaptation mode(?), takes effect after rebooting."))
v.addremove = true
v.rmempty = true

v = s:option(Value, "uvlan", translate("Upstream VLAN ID"),
    translate("Specifies the default upstream VLAN ID for the tagging operation, enter ‘u’ to use " ..
                  "untagged mode (VLAN range: 1-4094)."))
v.addremove = true
v.rmempty = true
v:depends("iopmask", "1")

v = s:option(Flag, "forceuvlan", translate("Force Upstream VLAN ID"),
    translate("Try enabling this if the Upstream VLAN ID setting isn't taking effect."))
v.addremove = true
v:depends("iopmask", "1")

v = s:option(Flag, "forcemerule", translate("Force MEs 47 and 171"),
    translate("Force creation of ‘MAC bridge port configuration data’ and ‘Extended VLAN tagging " ..
                  "operation configuration data’ managed entities. Try enabling this if O5 status " ..
                  "still isn't being obtained."))
v.addremove = true
v:depends("iopmask", "1")

v = s:option(Value, "mvlansource", translate("Upstream Multicast VLAN ID"),
    translate("Specifies the VLAN carrying the multicast group downstream (range: 1-4094)."))
v.addremove = true
v.rmempty = true
v.datatype = "and(uinteger,range(1,4094))"
v:depends("iopmask", "1")

v = s:option(Value, "mvlan", translate("Downstream Multicast TCI"),
    translate("Specify downstream multicast TCI in the form ‘A[@B]’ where ‘A’ is a VLAN and ‘B’ " ..
                  "is a priority. Controls the downstream tagging of both the IGMP/MLD and " ..
                  "multicast frames (Priority range: 0-7, VLAN range: 1-4094)."))
v.addremove = true
v.rmempty = true
v.datatype = "and(uinteger,range(1,4094))"
v:depends("iopmask", "1")

v = s:option(Value, "tvlan", translate("VLAN Tagging Operations"),
    translate("Specify VLAN tagging operations in the form ‘A[@B]:C[@D]’ where ‘A’ and ‘C’ is a " ..
                  "VLAN and ‘B’ and ‘D’ is a priority. Multiple comma-separated pairs can be " ..
                  "entered. For example, ‘2:41,3:43,4:u,5:44@5’ would bridge downstream VLANs: " ..
                  "2,3,4,5 to upstream VLANs: 41,43,untagged,44 respectively, where ‘@5’ specifies " ..
                  "VLAN priority. (Priority range: 0-7, VLAN range: 1-4094 and ‘u’ on the right hand side)"))
v.addremove = true
v.rmempty = true
v:depends("iopmask", "1")

v = s:option(Flag, "mtvlan", translate("Enable N:1 VLAN Mode"),
    translate("When enabled, multiple downstream VLANs can be bridged to a single upstream VLAN " ..
                  "(note: each downstream VLAN will be represented by a unique MAC address)."))
v.addremove = true
v:depends("iopmask", "1")

v = s:option(Flag, "vlandebug", translate("VLAN Script Logging"), translate("Enable VLAN script debug logging"))
v.addremove = true
v.rmempty = true
v:depends("iopmask", "1")

s = m:section(NamedSection, "onu", translate("ONU"), translate("Multicast"))

v = s:option(ListValue, "igmp_version", translate("IGMP Version"),
    translate("Configure the IGMP version reported in ‘multicast operations profile’ managed " ..
                  "entity. Try enabling this if IPoE-based multicast IPTV isn't working correctly."))
v.default = 3
v:value(3, translate("IGMP v3"))
v:value(2, translate("IGMP v2"))

v = s:option(Flag, "forceme309", translate("Force ME 309 creation"),
    translate("Force creation of ‘multicast operations profile’ managed entity. Try enabling " ..
                  "this if IPoE-based multicast IPTV isn't working correctly."))
v.addremove = true
v.rmempty = true

s = m:section(NamedSection, "onu", translate("ONU"), translate("Advanced"))

v = s:option(ListValue, "uni_type", translate("Custom UNI Type"),
    translate("Most SFU ONUs will be expected to be using ethernet PPTP UNI by the OLT, however " ..
                  "HGU ONUs may be expected to be using VEIP UNI. WARNING: Having the fibre " ..
                  "inserted for too long with the wrong UNI type active may cause the OLT to " ..
                  "de-register the GPON SN!!!!!"))
v.default = "pptp"
v:value("pptp", translate("Ethernet PPTP"))
v:value("veip", translate("VEIP"))

v = s:option(Flag, "mib_customized", translate("Custom MIB Profile"),
    translate("WARNING: Custom MIB profiles may result in infinite-reboot loop!!!!"))
v.addremove = true
v.rmempty = true

v = s:option(Value, "vendor_id", translate("Vendor ID"),
    translate("Typically the first four digits of the serial number."))
v.addremove = true
v.rmempty = true
v:depends("mib_customized", "1")

v = s:option(Value, "equipment_id", translate("Equipment ID"), translate("The equipment ID of the ONU."))
v.addremove = true
v.rmempty = true
v:depends("mib_customized", "1")

v = s:option(Value, "ont_version", translate("Hardware Version"), translate("The hardware version of the ONU."))
v.addremove = true
v.rmempty = true
v:depends("mib_customized", "1")

v = s:option(Flag, "mod_omcid", translate("Custom OMCID Software Version"),
    translate("Patch the OMCID binary so that it reports a custom software version. " ..
                  "WARNING: Patching OMCID software version may result in infinite-reboot loop!!!!"))
v.addremove = true
v.rmempty = true

v = s:option(Value, "omcid_version", translate("Software Version"), translate("The software version to report."))
v.addremove = true
v.rmempty = true
v:depends("mod_omcid", "1")

buttona = s:option(Button, "ButtonA", translate("Restore OMCID Software Version"))
buttona.inputtitle = translate("Restore")
buttona.inputstyle = "apply"
buttona:depends("mod_omcid", "1")

v = s:option(Flag, "mod_omcc", translate("Custom OMCC Version"),
    translate("WARNING: Custom OMCC version may result in infinite-reboot loop!!!!"))
v.addremove = true
v.rmempty = true

v = s:option(Value, "omcc_version", translate("OMCC Version"), translate("The default is 160"))
v.addremove = true
v.rmempty = true
v:depends("mod_omcc", "1")

v = s:option(Flag, "disable_sigstatus", translate("Disable Network Reset/Recovery"),
    translate("Disable network configuration reset of host and LCT on quick repeated " ..
                  "removals and reinsertions of the fibre cable."))
v.addremove = true
v.rmempty = true

v = s:option(Flag, "enable_txstatus", translate("Force Enable Optic TX"),
    translate("Re-enable optic TX on detction that TX status is disabled."))
v.addremove = true
v.rmempty = true

v = s:option(Flag, "disable_rx_los_status", translate("Disable RX_LOS Reporting"),
    translate("Patch the optic driver to disable RX_LOS status reporting."))
v.addremove = true
v.rmempty = true

v = s:option(Flag, "ignore_rx_loss", translate("Ignore RX_LOSS messages"),
    translate("Avoid dropouts due to ‘PLOAM Rx - message lost’ by making the ONU driver " ..
                  "ignore RX_LOSS messages (only enable if you have this problem)."))
v.addremove = true
v.rmempty = true

v = s:option(Flag, "asc", translate("Enable TTL Console (ASC0)"),
    translate("WARNING: Enabling the TTL console may cause TX_FAULTs to occur"))
v.addremove = true
v.rmempty = true

v = s:option(Flag, "omci_log_to_console", translate("Log OMCID to Console"), translate(
    "Output OMCID debug logs to /dev/console (requires enabling TTL console and adjusting OMCID log level)"))
v.addremove = true
v.rmempty = true
v:depends("asc", "1")

v = s:option(Flag, "mod_omci_log_level", translate("Configure OMCID Logging Level"),
    translate("Configure the OMCID logging level."))
v.addremove = true
v.rmempty = true

v = s:option(Value, "omci_log_level", translate("OMCID Logging Level"),
    translate("The OMCID logging level (1-7, default level 3)."))
v.addremove = true
v.rmempty = true
v:depends("mod_omci_log_level", "1")

buttonb = s:option(Button, "ButtonB", translate("Switch Boot Image"))
buttonb.inputtitle = translate("Switch")
buttonb.inputstyle = "apply"

s = m:section(NamedSection, "onu", translate("ONU"), translate("Reboot OpenWRT"))

v = s:option(Flag, "tryreboot", translate("Reboot OpenWrt on No-O5"), translate(
    "Reboot OpenWrt if no O5 state is reached with the fibre connected for a number of intervals of time."))
v.addremove = true
v.rmempty = true

v = s:option(Value, "totalrebootwait", translate("Number of Wait Intervals"),
    translate("Number of 5 or 15 second intervals to wait before rebooting, recommend around 5-10 intervals."))
v.addremove = true
v.rmempty = true
v:depends("tryreboot", "1")

v = s:option(Value, "totalreboottry", translate("Maximum Number of Reboots"),
    translate("Maximum number of reboots to attempt, recommend around 5-10 reboots."))
v.addremove = true
v.rmempty = true
v:depends("tryreboot", "1")

v = s:option(Flag, "lct_restart_try", translate("Restart LCT Interface"),
    translate("Attempts to restart the LCT interface when both monitor IPs are unreachable at the same time."))
v.addremove = true
v.rmempty = true

v = s:option(Value, "total_lct_try", translate("Maximum Number of Attempts"), translate(
    "Maximum number of attempts at restarting the LCT interface, about 5-10 attempts are recommended."))
v.addremove = true
v.rmempty = true
v:depends("lct_restart_try", "1")

v = s:option(Value, "total_lct_wait", translate("Number of Wait Intervals"),
    translate("Number of 5 or 15 second intervals to wait before restarting the LCT interface, " ..
                  "recommend around 5-10 intervals."))
v.addremove = true
v.rmempty = true
v:depends("lct_restart_try", "1")

v = s:option(Value, "trackip1", translate("Monitor IP 1"),
    translate("IP address to be monitored, a LAN IP address is recommended. Make sure that the " ..
                  "IP address entered is accessible, otherwise it may lead to infinite-reboot loop!!!!"))
v.addremove = true
v.rmempty = true
v.datatype = "ip4addr"
v:depends("lct_restart_try", "1")

v = s:option(Value, "trackip2", translate("Monitor IP 2"),
    translate("IP address to be monitored, a LAN IP address is recommended. Make sure that the " ..
                  "IP address entered is accessible, otherwise it may lead to infinite-reboot loop!!!!"))
v.addremove = true
v.rmempty = true
v.datatype = "ip4addr"
v:depends("lct_restart_try", "1")

v = s:option(Flag, "rebootlog", translate("Save Debug Log"),
    translate("Save the Debug Log to /root/ before rebooting OpenWrt."))
v.addremove = true
v.rmempty = true

v = s:option(Flag, "rebootdirect", translate("Reboot OpenWrt"),
    translate("Reboots OpenWrt immediately after the configured delay time has elapsed."))
v.addremove = true
v.rmempty = true

v = s:option(Value, "rebootwait", translate("Delay Time"),
    translate("Delay time before rebooting OpenWrt, recommended around 60-300 seconds."))
v.addremove = true
v.rmempty = true
v:depends("rebootdirect", "1")

function buttona.write(self, section, value)
    luci.sys.call("/opt/lantiq/bin/config_onu.sh restore")
end

function buttonb.write(self, section, value)
    luci.sys.call("/opt/lantiq/bin/config_onu.sh switch")
end

function m.on_after_commit(map)
    luci.sys.call("/opt/lantiq/bin/config_onu.sh set")
    luci.sys.call("/opt/lantiq/bin/config_onu.sh mod")
    luci.sys.call("/opt/lantiq/bin/config_onu.sh disable")
    luci.sys.call("/opt/lantiq/bin/config_onu.sh ignore")
    luci.sys.call("/opt/lantiq/bin/config_onu.sh reboot")
    luci.sys.call("/opt/lantiq/bin/config_onu.sh switchasc")
    luci.sys.call("/etc/init.d/iop.sh restart")
    luci.sys.call("/etc/init.d/monitomcid restart")
    luci.sys.call("/etc/init.d/monitoptic restart")
end

return m
