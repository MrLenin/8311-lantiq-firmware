--[[
LuCI - Lua Configuration Interface

Copyright 2011 Ralph Hempel <ralph.hempel@lantiq.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

]] --
require("luci.tools.gpon")

local tools = require "8311.tools"

local config_map = Map("8311")

config_map.template = "map"

local uci = require("luci.model.uci").cursor()
local config_section = uci:get_all("8311", "config")

function config_map.on_after_commit(configMap)
	luci.sys.call("/opt/lantiq/bin/config_onu.sh set")
	luci.sys.call("/opt/lantiq/bin/config_onu.sh mod")
	luci.sys.call("/opt/lantiq/bin/config_onu.sh disable")
	luci.sys.call("/opt/lantiq/bin/config_onu.sh ignore")
	luci.sys.call("/opt/lantiq/bin/config_onu.sh reboot")
	--luci.sys.call("/opt/lantiq/bin/config_onu.sh switch")
	luci.sys.call("/opt/lantiq/bin/config_onu.sh switchasc")
	luci.sys.call("/etc/init.d/vlan-svc.sh restart")
	luci.sys.call("/etc/init.d/monitomcid restart")
	luci.sys.call("/etc/init.d/monitoptic restart")
end

local function validate_bank(value)
	local pattern = "^[AB]?$"
	if not string.match(value, pattern) then return nil end
	return value
end

local config =
	config_map:section(NamedSection, "config", "cbi", translate("8311 Configuration"))

config:tab("pon", translate("PON"))
config:tab("vlan", translate("VLAN"))
config:tab("device", translate("Device"))
config:tab("advanced", translate("Advanced"))
config:tab("reboot", translate("Reboot"))

---------------------------------------
-- PON Tab Start
---------------------------------------

local gpon_sn =
	config:taboption("pon", Value, "gpon_sn", translate("PON Serial Number (ONT ID)"),
	translate("GPON Serial Number sent to the OLT in various MEs (4 alphanumeric " ..
	"characters, followed by 8 hex digits)."))

gpon_sn.datatype = "and(string, maxlength(12))"

function gpon_sn.validate(self, value)
	local pattern = "^%w%w%w%w%x%x%x%x%x%x%x%x$"
	if not string.match(value, pattern) then return nil end
	return value
end

local vendor_id =
	config:taboption("pon", Value, "vendor_id", translate("Vendor ID"),
	translate("PON Vendor ID sent in various MEs, automatically derived from the PON " ..
	"Serial Number if not set (4 alphanumeric characters)."))

vendor_id.datatype = "and(string, maxlength(4))"
vendor_id.rmempty = true

local equipment_id =
	config:taboption("pon", Value, "equipment_id", translate("Equipment ID"),
	translate("PON Equipment ID field in the ONU2-G ME [257] (up to 20 characters)."))

equipment_id.datatype = "and(string, maxlength(20))"
equipment_id.rmempty = true

local hw_ver = config:taboption("pon", Value, "hw_ver", translate("Hardware Version"),
	translate("Hardware version string sent in various MEs (up to 14 characters)."))

hw_ver.datatype = "and(string, maxlength(14))"
hw_ver.rmempty = true

local cp_hw_ver_sync =
	config:taboption("pon", Flag, "cp_hw_ver_sync", translate("Sync Circuit Pack " ..
	"Version"), translate("Modify the configured MIB file to set the Version field " ..
	"of any Circuit Pack MEs [6] to match the Hardware Version (if set)."))

cp_hw_ver_sync.datatype = "bool"
cp_hw_ver_sync.default = false

local sw_verA =
	config:taboption("pon", Value, "sw_verA", translate("Software Version A"),
	translate("Image specific software version sent in the Software image MEs [7] " ..
	"(up to 14 characters)."))

sw_verA.datatype = "and(string, maxlength(14))"
sw_verA.default = tools.fw_getenv { "image0_version" }

local sw_verB =
	config:taboption("pon", Value, "sw_verB", translate("Software Version B"),
	translate("Image specific software version sent in the Software image MEs [7] " ..
	"(up to 14 characters)."))

sw_verB.datatype = "and(string, maxlength(14))"
sw_verB.default = tools.fw_getenv { "image1_version" }

local fw_match_b64 =
	config:taboption("pon", Value, "fw_match_b64", translate("Firmware Version Match"),
	translate("PCRE pattern match for automatic updating of Software Versions when " ..
	"OLT uploads a firmware upgrade. Must contain a single sub-pattern match."))

fw_match_b64.datatype = "and(string, maxlength(14))"
fw_match_b64.rmempty = true

local fw_match_num =
	config:taboption("pon", Value, "fw_match_num", translate("Firmware Match Number"),
	translate("If there are multiple matches for the Firmware Version Match pattern, " ..
	"use this specific match number."))

fw_match_num.datatype = "and(uinteger,range(1,99))"
fw_match_num.default = "1"

local override_active =
	config:taboption("pon", ListValue, "override_active", translate("Override active " ..
	"firmware bank"), translate("Override which software bank is marked as active in " ..
	"the Software image MEs [7]."))

override_active.datatype = "and(string, maxlength(1))"
override_active.default = ""
override_active.rmempty = true

override_active:value("")
override_active:value("A")
override_active:value("B")

function override_active.validate(self, value)
	return validate_bank(value)
end

local override_commit =
	config:taboption("pon", ListValue, "override_commit", translate("Override " ..
	"committed firmware bank"), translate("Override which software bank is marked as " ..
	"committed in the Software image MEs [7]."))

override_commit.datatype = "and(string, maxlength(1))"
override_commit.default = ""
override_commit.rmempty = true

override_commit:value("")
override_commit:value("A")
override_commit:value("B")

function override_commit.validate(self, value)
	return validate_bank(value)
end

local omcc_version =
	config:taboption("pon", Value, "omcc_version", translate("OMCC Version"),
	translate("The OMCC version to use in hexadecimal format between 0x80 and 0xBF. " ..
	"Default is 0xA0 (160)."))

omcc_version.datatype = "and(uinteger,range(0x80,0xBF))"
omcc_version.default = "0xA0"

local iop_mask =
	config:taboption("pon", Value, "iop_mask", translate("OMCI Interoperability Mask"),
	translate("The OMCI Interoperability Mask is a bitmask of compatibility options " ..
	"for working with various OLTs. The options are:") .. "<br>&nbsp;&nbsp;" ..
	translate("1 - Force Unauthorized IGMP/MLD behavior") .. "<br>&nbsp;&nbsp;" ..
	translate("2 - Skip Alloc-IDs termination upon T-CONT deactivation") ..
	"<br>&nbsp;&nbsp;" ..
	translate("4 - Drop all packets on default Downstream Extended VLAN rules") ..
	"<br>&nbsp;&nbsp;" ..
	translate("8 - Ignore Downstream Extended VLAN rules priority matching") ..
	"<br>" ..
	translate("16 - Convert Traffic Descriptor PIR/CIR values from kbyte/s to kbit/s") ..
	"<br>" ..
	translate("32 - Force common IP handling - apply the IPv4 Ethertype 0x0800 to " ..
	"the Extended VLAN rule matching for IPv6 packets") .. "<br>" ..
	translate("64 - It is unknown what this option does but it appears to affect the " ..
	"message length in omci_msg_send."))

iop_mask.datatype = "and(uinteger,range(0,127))"
iop_mask.default = "18"
iop_mask.rmempty = true

local ploam_password =
	config:taboption("pon", Value, "ploam_password", translate("PLOAM Password"),
	translate("PLOAM password sent to the OLT, 10 characters."))

ploam_password.datatype = "and(string,maxlength(10))"
ploam_password.default = ""
ploam_password.rmempty = true

local omci_loid =
	config:taboption("pon", Value, "omci_loid", translate("Logical ONU ID"),
	translate("Logical ONU ID presented in the ONU-G ME [256] (up to 24 characters)."))

omci_loid.datatype = "and(string,maxlength(24))"
omci_loid.default = ""
omci_loid.rmempty = true

local omci_lpwd =
	config:taboption("pon", Value, "omci_lpwd", translate("Logical Password"),
	translate("Logical Password presented in the ONU-G ME [256] (up to 12 characters)."))

omci_lpwd.datatype = "and(string,maxlength(12))"
omci_lpwd.default = ""
omci_lpwd.rmempty = true

local mib_file =
	config:taboption("pon", Value, "mib_file", translate("MIB File"),
	translate("MIB file used by omcid. Defaults to /etc/mibs/prx300_1U.ini " ..
	"(U:SFU, V:HGU)"))

mib_file.datatype = "string"
mib_file.default = "auto.ini"

mib_file:value("auto.ini")
mib_file:value("data_1g_8q_us1280_ds512.ini")
mib_file:value("data_1v_8q.ini")

function mib_file.validate(self, value)
	-- TODO
	return value
end

local pon_slot =
	config:taboption("pon", Value, "pon_slot", translate("PON Slot"),
	translate("Change the slot number that the UNI port is presented on, needed on " ..
	"some ISPs."))

pon_slot.datatype = "and(uinteger,range(1,255))"
pon_slot.rmempty = true

local uni_type =
	config:taboption("pon", ListValue, "uni_type", translate("UNI Type"),
	translate("Most SFU ONUs will be expected to be using ethernet PPTP UNI by the " ..
	"OLT, however HGU ONUs may be expected to be using VEIP UNI. WARNING: Having the " ..
	"fibre inserted for too long with the wrong UNI type active may cause the OLT to " ..
	"de-register the GPON SN!!!!!"))

uni_type.datatype = "string"
uni_type.default = "pptp"

uni_type:value("pptp", translate("Ethernet PPTP"))
uni_type:value("veip", translate("VEIP"))

local iphost_hostname =
	config:taboption("pon", Value, "iphost_hostname", translate("IP Host Hostname"),
	translate("Hostname sent in the IP host config data ME [134] (up to 25 " ..
	"characters)."))

iphost_hostname.datatype = "and(hostname,maxlength(25))"
iphost_hostname.rmempty = true

local iphost_domain =
	config:taboption("pon", Value, "iphost_domain", translate("IP Host Domain Name"),
	translate("Domain name sent in the IP host config data ME [134] (up to 25 " ..
	"characters)."))

iphost_domain.datatype = "and(string, maxlength(25))"
iphost_domain.rmempty = true

---------------------------------------
-- PON Tab End
---------------------------------------


---------------------------------------
-- VLAN Tab Start
---------------------------------------
-- I'm actually pretty proud of how understandable this section now is, but I am sure 
-- there are as yet improvements to be made, particularly in making some bits clearer
-- and more consice.
local vlan_svc =
	config:taboption("vlan", Flag, "vlan_svc", translate("Enable VLAN Tagging Service"),
	translate("Allows for customization of the VLAN Tagging Operations between the " ..
	"downstream (ONT) and upstream (OLT). These features should be considered " ..
	"minimally tested and EXPERIMENTAL."))

vlan_svc.datatype = "bool"
vlan_svc.rmempty = true

local us_vlan_id =
	config:taboption("vlan", Value, "us_vlan_id", translate("Upstream VLAN ID"),
	translate("Specifies the default upstream VLAN ID for the tagging operation, " ..
	"enter 'u' to use untagged mode (VLAN range: 0-4094, or 'u')."))

us_vlan_id.datatype = "string"
us_vlan_id.rmempty = true

function us_vlan_id.validate(self, value)
	if value == "u" then return value end
	local n = tonumber(value)
	if n and n >= 0 and n <= 4094 and tostring(n) == value then return value end
	return nil
end

local force_us_vlan_id =
	config:taboption("vlan", Flag, "force_us_vlan_id", translate("Force Upstream VLAN ID"),
	translate("Try enabling this if the Upstream VLAN ID setting isn't taking effect."))

force_us_vlan_id.datatype = "bool"
force_us_vlan_id.rmempty = true

local force_me_create =
	config:taboption("vlan", Flag, "force_me_create", translate("Force MEs 47 and 171"),
	translate("Force creation of 'MAC bridge port configuration data' and 'Extended " ..
	"VLAN tagging operation configuration data' managed entities. Try enabling this " ..
	"if O5 status still isn't being obtained."))

force_me_create.datatype = "bool"
force_me_create.rmempty = true

local us_mc_vid =
	config:taboption("vlan", Value, "us_mc_vid", translate("Upstream Multicast " ..
	"VLAN ID"), translate("Specifies the VLAN carrying the multicast group " ..
	"downstream (range: 1-4094)."))

us_mc_vid.datatype = "and(uinteger,range(1,4094))"
us_mc_vid.rmempty = true

local ds_mc_tci =
	config:taboption("vlan", Value, "ds_mc_tci", translate("Downstream Multicast TCI"),
	translate("Specify downstream multicast TCI in the form 'A[@B]' where 'A' is a " ..
	"VLAN and 'B' is a priority. Controls the downstream tagging of both the " ..
	"IGMP/MLD and multicast frames (Priority range: 0-7, VLAN range: 1-4094)."))

ds_mc_tci.datatype = "string"
ds_mc_tci.rmempty = true

function ds_mc_tci.validate(self, value)
	-- TODO
	return value
end

local vlan_tag_ops =
	config:taboption("vlan", Value, "vlan_tag_ops", translate("VLAN Tagging Operations"),
	translate("Specify VLAN tagging operations in the form 'A[@B]:C[@D]' where 'A' " ..
	"and 'C' is a VLAN and 'B' and 'D' is a priority. Multiple comma-separated pairs " ..
	"can be entered. For example, '2:41,3:43,4:u,5:44@5' would bridge downstream " ..
	"VLANs: 2,3,4,5 to upstream VLANs: 41,43,untagged,44 respectively, where '@5' " ..
	"specifies VLAN priority. (Priority range: 0-7, VLAN range: 1-4094 and on the " ..
	"right side, 'u' )"))

vlan_tag_ops.datatype = "string"
vlan_tag_ops.rmempty = true

function vlan_tag_ops.validate(self, value)
	-- TODO
	return value
end

local n_to_1_vlan =
	config:taboption("vlan", Flag, "n_to_1_vlan", translate("Enable N:1 VLAN Mode"),
	translate("When enabled, multiple downstream VLANs can be bridged to a single " ..
	"upstream VLAN (note: each downstream VLAN will be represented by a unique MAC " ..
	"address)."))

n_to_1_vlan.datatype = "bool"
n_to_1_vlan.rmempty = true

local vlan_mapper_map =
	config:taboption("vlan", Value, "vlan_mapper_map", translate("VLAN Mapper Map"),
	translate("Override automatic VID-to-mapper assignment for dual-VLAN ISPs. " ..
	"Format: comma-separated VID:MAPPER_HEX pairs (e.g. '34:1102,35:1103'). " ..
	"Only needed when automatic conflict detection assigns VIDs to the wrong " ..
	"mapper ports."))

vlan_mapper_map.datatype = "string"
vlan_mapper_map.rmempty = true

function vlan_mapper_map.validate(self, value)
	if value == "" then return value end
	for pair in string.gmatch(value, "([^,]+)") do
		local vid, mapper = string.match(pair, "^(%d+):(%x+)$")
		if not vid or not mapper then return nil end
		local n = tonumber(vid)
		if not n or n < 1 or n > 4094 then return nil end
	end
	return value
end

local vlan_svc_log =
	config:taboption("vlan", Flag, "vlan_svc_log", translate("VLAN Service Logging"),
	translate("Enable VLAN script debug logging"))

vlan_svc_log.datatype = "bool"
vlan_svc_log.rmempty = true

local igmp_version =
	config:taboption("vlan", ListValue, "igmp_version", translate("IGMP Version"),
	translate("Configure the IGMP version reported in 'multicast operations profile' " ..
	"managed entity. Try enabling this if IPoE-based multicast IPTV isn't working " ..
	"correctly."))

igmp_version.datatype = "and(uinteger,range(2,3))"
igmp_version.default = 3

igmp_version:value(3, translate("IGMP v3"))
igmp_version:value(2, translate("IGMP v2"))

local force_me309_create =
	config:taboption("vlan", Flag, "force_me309_create", translate("Force ME 309 " ..
	"creation"), translate("Force creation of 'multicast operations profile' managed " ..
	"entity. Try enabling this if IPoE-based multicast IPTV isn't working correctly."))

force_me309_create.datatype = "bool"
force_me309_create.rmempty = true

---------------------------------------
-- VLAN Tab End
---------------------------------------


---------------------------------------
-- Device Tab Start
---------------------------------------

local bootdelay =
	config:taboption("device", ListValue, "bootdelay", translate("Boot Delay"),
	translate("Set the boot delay in seconds in which you can interupt the boot " ..
	"process over the serial console. Default: 3, Recommended: 1"))

bootdelay.datatype = "and(uinteger,range(0,3))"
bootdelay.default = "3"
bootdelay.rmempty = true

bootdelay:value("0", translate("0 (Fastest, not recommended)"))
bootdelay:value("1", translate("1 (Fast Boot)"))
bootdelay:value("2")
bootdelay:value("3", translate("3 (Default)"))

local console_en =
	config:taboption("device", Flag, "console_en", translate("Serial console"),
	translate("Enable the serial console. This will cause TX_FAULT to be asserted as " ..
	"it shares the same SFP pin."))

console_en.datatype = "bool"
console_en.default = false
console_en.rmempty = true

local dying_gasp_en =
	config:taboption("device", Flag, "dying_gasp_en", translate("Dying Gasp"),
	translate("Enable dying gasp. This will cause the serial console input to break " ..
	"as it shares the same SFP pin."))

dying_gasp_en.datatype = "bool"
dying_gasp_en.default = false
dying_gasp_en.rmempty = true

local rx_los =
	config:taboption("device", Flag, "rx_los", translate("RX Loss of Signal"),
	translate("Enable the RX_LOS pin. Disable to allow stick to be accessible " ..
	"without the fiber connected in all devices."))

rx_los.datatype = "bool"
rx_los.default = false
rx_los.rmempty = true

local failsafe_delay =
	config:taboption("device", Value, "failsafe_delay", translate("Failsafe Delay"),
	translate("Number of seconds that we will delay the startup of omcid for at " ..
	"bootup (10 to 300). Defaults to 15 seconds."))

failsafe_delay.datatype = "and(uinteger,range(10,300))"
failsafe_delay.default = "15"
failsafe_delay.rmempty = true

---------------------------------------
-- Device Tab End
---------------------------------------


---------------------------------------
-- Advanced Tab Start
---------------------------------------
-- This section's not bad, but could still have improved language
local mod_omcid =
	config:taboption("advanced", Flag, "mod_omcid", translate("Patch OMCID"),
	translate("Change the behavior of OMCID by patching the binary. WARNING: " ..
	"Patching OMCID may result in infinite-reboot loop!!!!"))

mod_omcid.datatype = "bool"
mod_omcid.default = false
mod_omcid.rmempty = true

local omcid_version =
	config:taboption("advanced", Value, "omcid_version", translate("Patch Software " ..
	"Version"), translate("Modify the software version OMCID reports on the command "..
	"line."))

omcid_version.datatype = "and(string, maxlength(14))"
omcid_version.rmempty = true
omcid_version:depends("mod_omcid", "1")

local restore_sw_ver =
	config:taboption("advanced", Button, "restore_sw_ver",
	translate("Restore Software Version"))

restore_sw_ver.inputtitle = translate("Restore")
restore_sw_ver.inputstyle = "apply"
restore_sw_ver:depends("mod_omcid", "1")

function restore_sw_ver.write(self, section, value)
	luci.sys.call("/opt/lantiq/bin/config_onu.sh restore_sw_ver")
end

local omcid_8021x =
	config:taboption("advanced", Flag, "omcid_8021x", translate("Patch 802.1x " ..
	"Enforcement"), translate("Disable enforcement of 802.1x by the ONU. May help in " ..
	"deployments where the ONU is erroneously dropping 802.1x traffic."))

omcid_8021x.datatype = "bool"
omcid_8021x.default = false
omcid_8021x.rmempty = true
omcid_8021x:depends("mod_omcid", "1")

local restore_8021x =
	config:taboption("advanced", Button, "restore_8021x",
	translate("Restore 802.1x Enforcement"))

restore_8021x.inputtitle = translate("Restore")
restore_8021x.inputstyle = "apply"
restore_8021x:depends("mod_omcid", "1")

function restore_8021x.write(self, section, value)
	luci.sys.call("/opt/lantiq/bin/config_onu.sh restore_8021x")
end

local disable_sigstatus =
	config:taboption("advanced", Flag, "disable_sigstatus", translate("Disable " ..
	"Network Reset/Recovery"), translate("Disable network configuration reset of " ..
	"host and LCT on quick repeated removals and reinsertions of the fibre cable."))

disable_sigstatus.datatype = "bool"
disable_sigstatus.default = false
disable_sigstatus.rmempty = true

local enable_txstatus =
	config:taboption("advanced", Flag, "enable_txstatus", translate("Force Enable " ..
	"Optic TX"), translate("Re-enable optic TX on detection that TX status is disabled."))

enable_txstatus.datatype = "bool"
enable_txstatus.default = false
enable_txstatus.rmempty = true

local ignore_rx_msg_lost =
	config:taboption("advanced", Flag, "ignore_rx_msg_lost", translate("Ignore PLOAM " ..
	"Rx - Message Lost"), translate("Avoid dropouts due to 'PLOAM Rx - message lost' " ..
	"by making the ONU driver ignore the messages (only enable if you have this " ..
	"problem)."))

ignore_rx_msg_lost.datatype = "bool"
ignore_rx_msg_lost.default = false
ignore_rx_msg_lost.rmempty = true

local omci_log_to_console =
	config:taboption("advanced", Flag, "omci_log_to_console", translate("Log OMCID " ..
	"to Console"), translate("Output OMCID debug logs to /dev/console (requires " ..
	"enabling the TTL console and adjusting OMCID log level)"))

omci_log_to_console.datatype = "bool"
omci_log_to_console.default = false
omci_log_to_console.rmempty = true

local omci_log_level =
	config:taboption("advanced",ListValue, "omci_log_level", translate("OMCID Logging " ..
	"Level"), translate("The OMCID logging level (1-7, default level 3)."))

omci_log_level.datatype = "and(uinteger,range(1,7))"
omci_log_level.default = "3"
omci_log_level.rmempty = true

omci_log_level:value("1")
omci_log_level:value("2")
omci_log_level:value("3")
omci_log_level:value("4")
omci_log_level:value("5")
omci_log_level:value("6")
omci_log_level:value("7")

---------------------------------------
-- Advanced Tab End
---------------------------------------


---------------------------------------
-- Reboot Tab Start
---------------------------------------
-- This whole section needs better naming and language
local tryreboot =
	config:taboption("reboot", Flag, "tryreboot", translate("Reboot OpenWrt on No-O5"),
	translate("Reboot OpenWrt if no O5 state is obtained while there is no Loss of Signal for" ..
	"a number of intervals of time."))

tryreboot.rmempty = true

local max_reboot_delay_intervals =
	config:taboption("reboot", Value, "max_reboot_delay_intervals", translate("Maximum " ..
	"number of delay intervals"), translate("Number of 5 or 15 second intervals to delay before " ..
	"rebooting, recommend around 5-10 intervals."))

max_reboot_delay_intervals.rmempty = true
max_reboot_delay_intervals:depends("tryreboot", "1")

local max_reboots =
	config:taboption("reboot", Value, "max_reboots", translate("Maximum Number of " ..
	"Reboots"), translate("Maximum number of reboots to attempt, recommend around " ..
	"5-10 reboots."))

max_reboots.rmempty = true
max_reboots:depends("tryreboot", "1")

local lct_restart_try =
	config:taboption("reboot", Flag, "lct_restart_try", translate("Restart LCT " ..
	"Interface"), translate("Attempts to restart the LCT interface when both " ..
	"monitor IPs are unreachable at the same time."))

lct_restart_try.rmempty = true

local total_lct_try =
	config:taboption("reboot", Value, "total_lct_try", translate("Maximum Number of " ..
	"Attempts"), translate("Maximum number of attempts at restarting the LCT " ..
	"interface, about 5-10 attempts are recommended."))

total_lct_try.rmempty = true
total_lct_try:depends("lct_restart_try", "1")

local total_lct_wait =
	config:taboption("reboot", Value, "total_lct_wait", translate("Number of Wait " ..
	"Intervals"), translate("Number of 5 or 15 second intervals to wait before " ..
	"restarting the LCT interface, recommend around 5-10 intervals."))

total_lct_wait.rmempty = true
total_lct_wait:depends("lct_restart_try", "1")

local trackip1 =
	config:taboption("reboot", Value, "trackip1", translate("Monitor IP 1"),
	translate("IP address to be monitored, a LAN IP address is recommended. Make " ..
	"sure that the IP address entered is accessible, otherwise it may lead to " ..
	"infinite-reboot loop!!!!"))

trackip1.rmempty = true
trackip1.datatype = "ip4addr"
trackip1:depends("lct_restart_try", "1")

local trackip2 =
	config:taboption("reboot", Value, "trackip2", translate("Monitor IP 2"),
	translate("IP address to be monitored, a LAN IP address is recommended. Make " ..
	"sure that the IP address entered is accessible, otherwise it may lead to " ..
	"infinite-reboot loop!!!!"))

trackip2.rmempty = true
trackip2.datatype = "ip4addr"
trackip2:depends("lct_restart_try", "1")

local persist_log_on_reboot =
	config:taboption("reboot", Flag, "persist_log_on_reboot", translate("Save Debug Log"),
	translate("Save the Debug Log to /root/ before rebooting OpenWrt."))

persist_log_on_reboot.rmempty = true

local rebootdirect =
	config:taboption("reboot", Flag, "rebootdirect", translate("Reboot OpenWrt"),
	translate("Reboots OpenWrt immediately after the configured delay time has " ..
	"elapsed."))

rebootdirect.rmempty = true

local rebootwait =
	config:taboption("reboot", Value, "rebootwait", translate("Delay Time"),
	translate("Delay time before rebooting OpenWrt, recommended around 60-300 seconds."))

rebootwait.rmempty = true
rebootwait:depends("rebootdirect", "1")

---------------------------------------
-- Reboot Tab End
---------------------------------------

return config_map
