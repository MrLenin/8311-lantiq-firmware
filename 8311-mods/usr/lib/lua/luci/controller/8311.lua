--[[
LuCI - Lua Configuration Interface

8311 Controller
===============
Main LuCI controller for the 8311 firmware mod. Defines the admin menu
structure and dispatches pages for:
  - Configuration (PON, VLAN, device, management settings via fwenv or CBI)
  - PON Status (proxies gtop/otop CLI output to the browser)
  - PON ME Explorer (OMCI managed-entity dump viewer)
  - VLAN Tables (extended VLAN rule decoder)
  - Module Information (optic/GTC info template)
  - Optic Calibration and Network Address CBI forms

Two parallel menu trees are registered:
  "admin/8311/*"  -- the original fwenv-based configuration UI
  "admin/gpon/*"  -- the newer UCI/CBI-based configuration UI

Copyright 2011 Ralph Hempel <ralph.hempel@lantiq.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

]]--
module("luci.controller.8311", package.seeall)

require("luci.tools.gpon")
require("luci.util")

local tools = require "8311.tools"
local util = require "luci.util"
local ltemplate = require "luci.template"
local http = require "luci.http"
local formvalue = http.formvalue
local dispatcher = require "luci.dispatcher"
local sys = require "luci.sys"
local i18n = require "luci.i18n"
local translate = i18n.translate
local base64 = require "base64"
local ltn12 = require "luci.ltn12"
local fs = require "nixio.fs"
local support_file = "/tmp/support.tar.gz"

function index()
	-----------------------------------------------------------------------
	-- Menu tree: admin/8311/* (fwenv-based configuration UI)
	-----------------------------------------------------------------------
	entry({"admin", "8311"}, firstchild(), _("8311"), 99).dependent=false
	entry({"admin", "8311", "config"}, call("action_config"), _("Configuration"), 1)
	entry({"admin", "8311", "pon_status"}, call("action_pon_status"), _("PON Status"), 2)
	entry({"admin", "8311", "pon_explorer"}, call("action_pon_explorer"), _("PON ME Explorer"), 3)
	entry({"admin", "8311", "vlans"}, call("action_vlans"), _("VLAN Tables"), 4)
--	entry({"admin", "8311", "support"}, post_on({ data = true }, "action_support"), _("Support"), 5)

	-- entry({"admin", "8311", "save"}, post_on({ data = true }, "action_save"))
	--entry({"admin", "8311", "get_hook_script"}, call("action_get_hook_script")).leaf=true
	--entry({"admin", "8311", "save_hook_script"}, call("action_save_hook_script")).leaf=true

	-- leaf=true allows the URL path to continue (e.g. /pontop/gtop_status)
	entry({"admin", "8311", "pontop"}, call("action_pontop")).leaf=true
	entry({"admin", "8311", "pon_dump"}, call("action_pon_dump")).leaf=true
	entry({"admin", "8311", "vlans", "extvlans"}, call("action_vlan_extvlans"))
--	entry({"admin", "8311", "support", "support.tar.gz"}, call("action_support_download"))

--	entry({"admin", "8311", "firmware"}, call("action_firmware"), _("Firmware"), 6);

	-----------------------------------------------------------------------
	-- Menu tree: admin/gpon/* (UCI/CBI-based configuration UI)
	-- These use standard LuCI CBI model files for form rendering.
	-----------------------------------------------------------------------
	entry({"admin", "gpon"}, alias("admin", "gpon", "config"), _("8311"), 80).index = true
	entry({"admin", "gpon", "config"}, cbi("8311-config"), _("Configuration"), 30).index = true
	entry({"admin", "gpon", "management"}, cbi("8311-management"), _("Network Addresses"), 40).index = true
	entry({"admin", "gpon", "optic-cal"}, cbi("8311-optic-cal"), _("Optic Calibration"), 50).index = true
	entry({"admin", "gpon", "mod-info"}, call("action_information"), _("Module Information"), 60).index = true
end

function action_information()
	luci.template.render("lantiq/gpon-gtc-info")
end

--[[
	pontop_page_details()
	Returns the full list of gtop/otop diagnostic pages.
	Each entry maps a short id (used in URLs) to the exact page name string
	expected by the gtop/otop CLI, plus a translatable label for the UI.
	Entries with otop=true are queried via /opt/lantiq/bin/otop instead of gtop.
]]--
function pontop_page_details()
	return {{
			id="gtop_status",
			page="Status",
			label=translate("gtop Status")
		},{
			id="gpe_cap",
			page="GPE capability",
			label=translate("GPE capability")
		},{
			id="gtop_config",
			page="Configuration",
			label=translate("gtop Configuration")
		},{
			id="gtc_alarms",
			page="GTC alarms",
			label=translate("GTC Alarms")
		},{
			id="gtc_counters",
			page="GTC counters",
			label=translate("GTC Counters")
		},{
			id="bwm_trace",
			page="BWM trace",
			label=translate("BWM Trace")
		},{
			id="gpe_info",
			page="GPE info",
			label=translate("GPE Info")
		},{
			id="gem_port",
			page="GEM port",
			label=translate("GEM Port")
		},{
			id="alloc_id",
			page="Alloc ID",
			label=translate("Alloc ID")
		},{
			id="br_port",
			page="Bridge port counter",
			label=translate("Bridge Port Counter"),
		},{
			id="us_flow",
			page="Upstream flow",
			label=translate("Upstream Flow")
		},{
			id="gpe_vlan_start_id",
			page="GPE VLAN Start ID",
			label=translate("GPE VLAN Start ID")
		},{
			id="gpe_ds_gem",
			page="GPE DS GEM port",
			label=translate("GPE DS GEM Port")
		},{
			id="gpe_us_gem",
			page="GPE US GEM port",
			label=translate("GPE US GEM Port")
		},{
			id="gpe_tag_filter",
			page="GPE tagging filter",
			label=translate("GPE Tagging Filter")
		},{
			id="gpe_fid_assign",
			page="GPE FID assignment",
			label=translate("GPE FID Assignment")
		},{
			id="gpe_vlan",
			page="GPE VLAN",
			label=translate("GPE VLAN")
		},{
			id="gpe_ext_vlan",
			page="GPE extended VLAN",
			label=translate("GPE Extended VLAN")
		},{
			id="gpe_vlan_rule",
			page="GPE VLAN rule",
			label=translate("GPE VLAN Rule")
		},{
			id="gpe_vlan_treat",
			page="GPE VLAN treatment",
			label=translate("GPE VLAN Treatment")
		},{
			id="gpe_lan_gen",
			page="GPE LAN port General",
			label=translate("GPE LAN Port General")
		},{
			id="gpe_lan_vlan",
			page="GPE LAN port VLAN",
			label=translate("GPE LAN Port VLAN")
		},{
			id="gpe_lan_acs",
			page="GPE LAN port Access Ctrl",
			label=translate("GPE LAN Port Access Ctrl")
		},{
			id="gpe_lan_traff_mgmt",
			page="GPE LAN port Traffic Mgmt",
			label=translate("GPE LAN Port Traffic Mgmt")
		},{
			id="gpe_lan_oam",
			page="GPE LAN port OAM",
			label=translate("GPE LAN Port OAM")
		},{
			id="gpe_br_port",
			page="GPE bridge port",
			label=translate("GPE Bridge Port")
		},{
			id="gpe_lan_port",
			page="GPE LAN port",
			label=translate("GPE LAN Port")
		},{
			id="gpe_policer",
			page="GPE policer",
			label=translate("GPE Policer")
		},{
			id="gpe_activity",
			page="GPE activity",
			label=translate("GPE Activity")
		},{
			id="gpe_bridge",
			page="GPE bridge",
			label=translate("GPE Bridge")
		},{
			id="gpe_arbiter",
			page="GPE arbiter dump",
			label=translate("GPE Arbiter Dump")
		},{
			id="gtop_version",
			page="Version",
			label=translate("gtop Version")
		},{
			id="otop_status",
			page="status (1)",
			label=translate("otop Status"),
			otop=true
		},{
			id="otop_config",
			page="configuration",
			label=translate("otop Configuration"),
			otop=true
		},{
			id="alarms",
			page="alarms",
			label=translate("Alarms"),
			otop=true
		},{
			id="range_set",
			page="range settings",
			label=translate("Range Settings"),
			otop=true
		},{
			id="mon_calib",
			page="monitor calibr.",
			label=translate("Monitor Calibration"),
			otop=true
		},{
			id="otop_version",
			page="Version",
			label=translate("otop Version"),
			otop=true
		}
	}
end

-- Build a lookup table from page id -> {page name, otop flag} for quick
-- dispatch in action_pontop(). Strips out the UI label since it isn't
-- needed at dispatch time.
function pontop_pages()
	local details = pontop_page_details()
	local pages = {}
	for _, page in pairs(details) do
		pages[page.id] = { page = page.page, otop = page.otop or false }
	end

	return pages
end

-- Callback invoked when the language option is changed in the fwenv config UI.
-- Persists the selection to UCI so LuCI picks it up on next page load.
function language_change(value)
	util.exec("uci set luci.main.lang=" .. util.shellquote(value) .. " && uci commit luci")
end

--[[
	fwenvs_8311()
	Builds the complete form definition for the fwenv-based configuration page
	(admin/8311/config). Returns a table of categories, each containing a list
	of option items with metadata (type, validation, defaults, etc.).

	This is the data model for the *original* config UI that reads/writes
	firmware environment variables directly (via fw_getenv/fw_setenv), as
	opposed to the newer CBI-based UI under admin/gpon/*.

	Categories: PON, ISP Fixes, Device, Management
]]--
function fwenvs_8311()
	local zones = util.trim(util.exec("grep -v '^#' /usr/share/zoneinfo/zone.tab  | awk '{print $3}' | sort -uV ; echo UTC"))
	local timezones = {}
	for zone in zones:gmatch("[^\r\n]+") do
		table.insert(timezones, zone)
	end

	local languages = {{
		name="auto",
		value="auto"
	}}
	local langs = util.trim(util.exec("uci show luci.languages | awk -F '[.=]' '/^luci\.languages\./ { print $3 }'"))
	for lang in langs:gmatch("[^\r\n]+") do
		table.insert(languages, {
			name=util.trim(util.exec("uci get luci.languages." .. util.shellquote(lang))),
			value=lang
		})
	end

	local ipv4_regex = "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$"

	return {{
			id="pon",
			category=translate("PON"),
			items={	{
					id="gpon_sn",
					name=translate("PON Serial Number (ONT ID)"),
					description=translate("GPON Serial Number sent to the OLT in various MEs (4 alphanumeric characters, followed by 8 hex digits)."),
					maxlength=12,
					pattern='^[A-Za-z0-9]{4}[A-F0-9]{8}$',
					type="text",
					required=true
				},{
					id="vendor_id",
					name=translate("Vendor ID"),
					description=translate("PON Vendor ID sent in various MEs, automatically derived from the PON Serial Number if not set (4 alphanumeric characters)."),
					maxlength=4,
					pattern='^[A-Za-z0-9]{4}$',
					type="text"
				},{
					id="equipment_id",
					name=translate("Equipment ID"),
					description=translate("PON Equipment ID field in the ONU2-G ME [257] (up to 20 characters)."),
					maxlength=20,
					type="text"
				},{
					id="hw_ver",
					name=translate("Hardware Version"),
					description=translate("Hardware version string sent in various MEs (up to 14 characters)."),
					maxlength=14,
					type="text"
				},{
					id="cp_hw_ver_sync",
					name=translate("Sync Circuit Pack Version"),
					description=translate("Modify the configured MIB file to set the Version field of any Circuit Pack MEs [6] to match the Hardware Version (if set)."),
					type="checkbox",
					default=false
				},{
					id="sw_verA",
					name=translate("Software Version A"),
					description=translate("Image specific software version sent in the Software image MEs [7] (up to 14 characters)."),
					maxlength=14,
					type="text",
					default=tools.fw_getenv{"img_versionA"}
				},{
					id="sw_verB",
					name=translate("Software Version B"),
					description=translate("Image specific software version sent in the Software image MEs [7] (up to 14 characters)."),
					maxlength=14,
					type="text",
					default=tools.fw_getenv{"img_versionB"}
				},{
					id="fw_match_b64",
					name=translate("Firmware Version Match"),
					description=translate("PCRE pattern match for automatic updating of Software Versions when OLT uploads a firmware upgrade. Must contain a single sub-pattern match."),
					type="text",
					maxlength="255",
					base64=true
				},{
					id="fw_match_num",
					name=translate("Firmware Match Number"),
					description=translate("If there are multiple matches for the Firmware Version Match pattern, use this specific match number."),
					type="number",
					min=1,
					max=99,
					default="1"
				},{
					id="override_active",
					name=translate("Override active firmware bank"),
					description=translate("Override which software bank is marked as active in the Software image MEs [7]."),
					type="select",
					default="",
					options={
						"",
						"A",
						"B"
					}
				},{
					id="override_commit",
					name=translate("Override committed firmware bank"),
					description=translate("Override which software bank is marked as committed in the Software image MEs [7]."),
					type="select",
					default="",
					options={
						"",
						"A",
						"B"
					}
				},{
					id="pon_mode",
					name=translate("PON Mode"),
					description=translate("PON mode of operation. This is where you can choose between XGS-PON (the default) or XG-PON."),
					type="select_named",
					default="xgspon",
					options={
						{
							name="XGS-PON",
							value="xgspon"
						},{
							name="XG-PON",
							value="xgpon"
						}
					}
				},{
					id="omcc_version",
					name=translate("OMCC Version"),
					description=translate("The OMCC version to use in hexadecimal format between 0x80 and 0xBF. Default is 0xA3"),
					type="text",
					default="0xA3",
					maxlength=4,
					pattern='^0x[89AB][0-9A-F]$'
				},{
					id="iop_mask",
					name=translate("OMCI Interoperability Mask"),
					description =
						translate("The OMCI Interoperability Mask is a bitmask of compatibility options for working with various OLTs. The options are:") .. "\n" ..
						translate("1 - Force Unauthorized IGMP/MLD behavior") .. "\n" ..
						translate("2 - Skip Alloc-IDs termination upon T-CONT deactivation") .. "\n" ..
						translate("4 - Drop all packets on default Downstream Extended VLAN rules") .. "\n" ..
						translate("8 - Ignore Downstream Extended VLAN rules priority matching") .. "\n" ..
						translate("16 - Convert Traffic Descriptor PIR/CIR values from kbyte/s to kbit/s") .. "\n" ..
						translate("32 - Force common IP handling - apply the IPv4 Ethertype 0x0800 to the Extended VLAN rule matching for IPv6 packets") .. "\n" ..
						translate("64 - It is unknown what this option does but it appears to affect the message length in omci_msg_send."),
					type="number",
					default="18",
					min=0,
					max=127
				},{
					id="reg_id_hex",
					name=translate("Registration ID (HEX)"),
					description=translate("Registration ID (up to 36 bytes) sent to the OLT, in hex format. This is where you would set a ploam password (which is contained in the last 12 bytes)."),
					maxlength=72,
					pattern='^([A-Fa-f0-9]{2})*$',
					type="text"
				},{
					id="loid",
					name=translate("Logical ONU ID"),
					description=translate("Logical ONU ID presented in the ONU-G ME [256] (up to 24 characters)."),
					maxlength=24,
					type="text"
				},{
					id="lpwd",
					name=translate("Logical Password"),
					description=translate("Logical Password presented in the ONU-G ME [256] (up to 12 characters)."),
					maxlength=12,
					type="text"
				},{
					id="mib_file",
					name=translate("MIB File"),
					description=translate("MIB file used by omcid. Defaults to /etc/mibs/prx300_1U.ini (U:SFU, V:HGU)"),
					type="select",
					default="/etc/mibs/prx300_1U.ini",
					options={
						"/etc/mibs/prx300_1U.ini",
						"/etc/mibs/prx300_1U_telus.ini",
						"/etc/mibs/prx300_1V.ini",
						"/etc/mibs/prx300_1V_bell.ini",
						"/etc/mibs/prx300_2U.ini",
						"/etc/mibs/prx300_2U_voip.ini",
						"/etc/mibs/urx800_1U.ini",
						"/etc/mibs/urx800_1V.ini"
					}
				},{
					id="pon_slot",
					name=translate("PON Slot"),
					description=translate("Change the slot number that the UNI port is presented on, needed on some ISPs."),
					type="number",
					min=1,
					max=255
				},{
					id="iphost_mac",
					name=translate("IP Host MAC Address"),
					description=translate("MAC address sent in the IP host config data ME [134] (XX:XX:XX:XX:XX:XX format)."),
					maxlength=17,
					pattern='^[A-Fa-f0-9]{2}(:[A-Fa-f0-9]{2}){5}$',
					type="text",
					default=util.trim(util.exec(". /lib/pon.sh && pon_mac_get host")):upper()
				},{
					id="iphost_hostname",
					name=translate("IP Host Hostname"),
					description=translate("Hostname sent in the IP host config data ME [134] (up to 25 characters)."),
					maxlength=25,
					type="text"
				},{
					id="iphost_domain",
					name=translate("IP Host Domain Name"),
					description=translate("Domain name sent in the IP host config data ME [134] (up to 25 characters)."),
					maxlength=25,
					type="text"
				}
			}
		},{
			id="isp",
			category=translate("ISP Fixes"),
			items={	{
					id="fix_vlans",
					name=translate("Fix VLANs"),
					description=translate("Apply automatic fixes to the VLAN configuration from the OLT."),
					type="select_named",
					default="1",
					options={
						{
							name=translate("Disabled"),
							value="0"
						},
						{
							name=translate("Enabled"),
							value="1"
						},
						{
							name=translate("Hook script only"),
							value="2"
						}
					}
				},{
					id="internet_vlan",
					name=translate("Internet VLAN"),
					description=translate("Set the local VLAN ID to use for the Internet or 0 to make the Internet untagged (and also remove VLAN 0) (0 to 4095). Defaults to 0 (untagged)."),
					type="number",
					min=0,
					max=4095,
					default="0"
				},{
					id="services_vlan",
					name=translate("Services VLAN"),
					description=translate("Set the local VLAN ID to use for Services (ie TV/Home Phone) (1 to 4095). This fixes multi-service on Bell."),
					type="number",
					min=1,
					max=4095,
					default="34|36"
				}
			}
		},{
			id="device",
			category=translate("Device"),
			items={ {
					id="lang",
					name=translate("Language"),
					description=translate("Set the language used in the WebUI"),
					type="select_named",
					default="auto",
					options=languages,
					change=language_change
				},{
					id="bootdelay",
					name=translate("Boot Delay"),
					description=translate("Set the boot delay in seconds in which you can interupt the boot process over the serial console. With the Azores U-Boot, this also controls the number of times multicast upgrade is attempted and thus can have a significant impact in boot time. Default: 3, Recommended: 1"),
					type="select_named",
					default="3",
					base=true,
					options={
						{
							name=translate("0 (Fastest, disables multicast upgrade, not recommended)"),
							value="0"
						},{
							name=translate("1 (Fast Boot)"),
							value="1"
						},{
							name="2",
							value="2"
						},{
							name=translate("3 (Default)"),
							value="3"
						}
					}
				},{
					id="console_en",
					name=translate("Serial console"),
					description=translate("Enable the serial console. This will cause TX_FAULT to be asserted as it shares the same SFP pin."),
					type="checkbox",
					default=false
				},{
					id="dying_gasp_en",
					name=translate("Dying Gasp"),
					description=translate("Enable dying gasp. This will cause the serial console input to break as it shares the same SFP pin."),
					type="checkbox",
					default=false
				},{
					id="rx_los",
					name=translate("RX Loss of Signal"),
					description=translate("Enable the RX_LOS pin. Disable to allow stick to be accessible without the fiber connected in all devices."),
					type="checkbox",
					default=false
				},{
					id="root_pwhash",
					name=translate("Root password hash"),
					description=translate("Custom password hash for the root user. This can be set from System > Administration"),
					maxlength=255,
					pattern="^\\$[0-9a-z]+\\$.+\\$[A-Za-z0-9.\\/]+\$",
					type="text"
				},{
					id="ethtool_speed",
					name=translate("Ethtool Speed Settings"),
					description=translate("Ethtool speed settings on the eth0_0 interface (ethtool -s)."),
					maxlength=100,
					type="text"
				},{
					id="failsafe_delay",
					name=translate("Failsafe Delay"),
					description=translate("Number of seconds that we will delay the startup of omcid for at bootup (10 to 300). Defaults to 15 seconds"),
					type="number",
					min=10,
					max=300,
					default="15"
				},{
					id="hostname",
					name=translate("System Hostname"),
					description=translate("Set the system hostname visible over SSH/Console/WebUI."),
					maxlength=100,
					type="text",
					default="prx126-sfp-pon"
				},{
					id="timezone",
					name=translate("Time Zone"),
					description=translate("System Time Zone"),
					type="select",
					default="UTC",
					options=timezones
				},{
					id="ntp_servers",
					name=translate("NTP Servers"),
					description=translate("NTP server(s) to sync time from (space separated)."),
					maxlength=255,
					type="text"
				},{
					id="persist_root",
					name=translate("Persist RootFS"),
					description=translate("Allow the root file system to stay persistent (would also require that you modify the bootcmd fwenv). This is not recommended and should only be used for debug/testing purposes."),
					type="checkbox",
					default=false
				}
			}
		},{
		id="manage",
		category=translate("Management"),
		items={	{
					id="lct_vlan",
					name=translate("Management VLAN"),
					description=translate("Set the management VLAN ID (0 to 4095). Defaults to 0 (untagged)."),
					type="number",
					min=0,
					max=4095,
					default="0"
				},{
					id="ipaddr",
					name=translate("IP Address"),
					description=translate("Management IP address. Defaults to 192.168.11.1"),
					maxlength=15,
					pattern=ipv4_regex,
					type="text",
					default="192.168.11.1"
				},{
					id="netmask",
					name=translate("Subnet Mask"),
					description=translate("Management subnet mask. Defaults to 255.255.255.0"),
					maxlength=15,
					pattern=ipv4_regex,
					type="text",
					default="255.255.255.0"
				},{
					id="gateway",
					name=translate("Gateway"),
					description=translate("Management gateway. Defaults to the IP address (ie. no default gateway)"),
					maxlength=15,
					pattern=ipv4_regex,
					type="text",
					default=util.trim(util.exec(". /lib/8311.sh && get_8311_ipaddr"))
				},{
					id="dns_server",
					name=translate("DNS Server"),
					description=translate("Management DNS server."),
					maxlength=15,
					pattern=ipv4_regex,
					type="text"
				},{
					id="ping_ip",
					name=translate("Ping IP"),
					description=translate("IP address to ping every 5 seconds, this can help with reaching the stick. Defaults to the 2nd IP address in the configured management network (ie. 192.168.11.2)."),
					maxlength=15,
					pattern=ipv4_regex,
					type="text",
					default=util.trim(util.exec(". /lib/8311.sh && get_8311_default_ping_host"))
				},{
					id="lct_mac",
					name=translate("LCT MAC Address"),
					description=translate("MAC address of the LCT management interface (XX:XX:XX:XX:XX:XX format)."),
					maxlength=17,
					pattern='^[A-Fa-f0-9]{2}(:[A-Fa-f0-9]{2}){5}$',
					type="text",
					default=util.trim(util.exec(". /lib/pon.sh && pon_mac_get lct")):upper()
				},{
					id="reverse_arp",
					name=translate("Reverse ARP Monitoring"),
					description=translate("Enables a reverse ARP monitoring daemon that will automatically add ARP entries from the MAC address of recieved packets." ..
						" This can help in reaching the management interface without using NAT."),
					type="checkbox",
					default=true
				},{
					id="https_redirect",
					name=translate("Redirect HTTP to HTTPs"),
					description=translate("Automatically redirect requests to the WebUI over HTTP to HTTPs. Defaults to on."),
					type="checkbox",
					default=true
				}
			}
		}
	}
end

-- Proxy handler for gtop/otop diagnostic pages. Called via XHR from the
-- PON Status page. The page_id comes from the URL path (leaf=true on the
-- route allows it to pass through). Runs the appropriate CLI tool with
-- "-b" (batch/non-interactive) and streams the text output back.
function action_pontop(page_id)
	local cmd

	page_id = page_id or "Status"

	local pages = pontop_pages()

	if not pages[page_id] then
		return false
	end

	-- Select gtop or otop based on the page's otop flag
	if not pages[page_id].otop then
		cmd = string.format("/opt/lantiq/bin/%s -g \"%s\" -b", "gtop", pages[page_id].page)
	else
		cmd = string.format("/opt/lantiq/bin/%s -g \"%s\" -b", "otop", pages[page_id].page)
	end

	luci.http.prepare_content("text/plain; charset=utf-8")

	local output = util.exec(cmd)
	luci.http.write(output)
end

function action_pon_status()
	local pages = pontop_page_details()

	ltemplate.render("8311/pon_status", {
		pages=pages,
	})
end

function action_vlans()
	ltemplate.render("8311/vlans", {})
end

-- Runs the extended VLAN decoder script twice: first with "-t" (table
-- summary), then without flags (full rule dump). Output is streamed as
-- plain text for display in the VLAN Tables page.
function action_vlan_extvlans()
	luci.http.prepare_content("text/plain; charset=utf-8")

	if luci.sys.process.exec({"/usr/sbin/8311-extvlan-decode.sh", "-t"}, luci.http.write, luci.http.write).code == 0 then
		luci.http.write("\n\n")
		luci.sys.process.exec({"/usr/sbin/8311-extvlan-decode.sh"}, luci.http.write, luci.http.write)
	end
end

function action_get_hook_script()
    local content = fs.readfile("/ptconf/8311/vlan_fixes_hook.sh") or ''
    luci.http.prepare_content("text/plain; charset=utf-8")
    luci.http.write(content)
end

function action_save_hook_script()
    local content = luci.http.formvalue('content') or ''
	if content == '' then
		fs.remove("/ptconf/8311/vlan_fixes_hook.sh")
	else
		fs.writefile("/ptconf/8311/vlan_fixes_hook.sh", content)
		fs.chmod("/ptconf/8311/vlan_fixes_hook.sh", 755)
	end
    luci.http.status(200, "OK")
    luci.http.prepare_content("application/json")
    luci.http.write_json({ success = true })
end

function action_support_download()
	local archive = ltn12.source.file(io.open(support_file))
	luci.http.prepare_content("application/x-targz")
	ltn12.pump.all(archive, luci.http.write)
end

-- Merge the form definition from fwenvs_8311() with current values read
-- from the firmware environment. Items flagged "base" are read from the
-- standard U-Boot env; everything else comes from the 8311 partition.
-- Base64-encoded items (e.g. fw_match_b64) are decoded for display.
function populate_8311_fwenvs()
	local fwenvs = fwenvs_8311()
	local fwenvs_values = tools.fw_getenvs_8311()

	for _, cat in ipairs(fwenvs) do
		for _, item in ipairs(cat.items) do
			local value
			if item.base then
				value = tools.fw_getenv{item.id}
			else
				value = fwenvs_values[item.id] or ''
			end
			if item.base64 and value ~= '' then
				value = base64.dec(value)
			end
			item.value = value
		end
	end

	return fwenvs
end

function action_config()
	local fwenvs = populate_8311_fwenvs()

	ltemplate.render("8311/config", {
		fwenvs=fwenvs
	})
end

-- POST handler for saving the fwenv-based configuration form.
-- Compares each submitted value against the current fwenv value and only
-- writes changes. Special handling:
--   - Checkboxes: avoid storing redundant default values
--   - base64 items: re-encode before writing
--   - "change" callbacks (e.g. language_change): invoked before write
--   - "base" items: written to the standard U-Boot env, not the 8311 partition
function action_save()
	local value = nil
	if http.getenv('REQUEST_METHOD') == 'POST' then
		local fwenvs = populate_8311_fwenvs()

		for catid, cat in pairs(fwenvs) do
			for itemid, item in pairs(cat.items) do
				value = formvalue(item.id) or ''

				-- Normalize checkbox values: don't persist if equal to default
				if item.type == 'checkbox' then
					if item.value == '' and ((item.default and value == '1') or (not item.default and (value == '0' or value == ''))) then
						value = ''
					elseif value == '' then
						value = '0'
					end
				elseif item.value == '' and item.default and value == item.default then
					-- Don't store value if it matches the default and was previously unset
					value = ''
				end

				if item.value ~= value then
					if item.change then
						item.change(value)
					end

					if item.base64 and value ~= '' then
						value = base64.enc(value)
					end

					if item.base then
						tools.fw_setenv{item.id, value}
					else
						tools.fw_setenv_8311{item.id, value}
					end
				end
			end
		end
	end

	http.redirect(dispatcher.build_url("admin/8311/config"))
end

function action_pon_explorer()
	local omci = util.exec("/usr/bin/luci-me-dump")

	ltemplate.render("8311/pon_me", {
		omci=omci
	})
end

-- Fetches a single OMCI managed entity instance via omci_pipe.sh.
-- Called from the PON ME Explorer to drill into a specific ME.
-- Both me_id and instance_id are validated as pure digit strings to
-- prevent shell injection.
function action_pon_dump(me_id, instance_id)
	if not me_id or not me_id:match("^%d+$") or
	   not instance_id or not instance_id:match("^%d+$") then
		luci.http.status(400, "Bad Request")
		return
	end

	local cmd = "/opt/lantiq/bin/omci_pipe.sh meg " .. me_id .. " " .. instance_id
	local output = util.exec(cmd)

	luci.http.prepare_content("text/plain; charset=utf-8")
	luci.http.write(output)
end

-- Firmware upgrade page handler. Manages the upload/validate/install
-- lifecycle for firmware .tar files. Supports actions: validate, install,
-- install_reboot, cancel, and reboot.
function action_firmware()
	local version = require "8311.version"
	local altversion = {
		variant="unknown",
		version="unknown",
		revision="unknown"
	}

	version.bank = util.trim(util.exec(". /lib/8311.sh && active_fwbank"))
	altversion.bank = util.trim(util.exec(". /lib/8311.sh && inactive_fwbank"))

	for k, v in string.gmatch(util.exec("/usr/sbin/alternate_firmware_info"), '([^\n=]+)=([^\n]+)') do
		if k == "FW_VARIANT" then
			altversion.variant=v
		elseif k == "FW_VERSION" then
			altversion.version=v
		elseif k == "FW_REVISION" then
			altversion.revision=v
		end
	end

	
	local input_field = "firmware_file"
	local location = "/tmp"
	local file_name = "8311-local-upgrade.tar"
	local firmware_file = location .. "/" .. file_name
	local values = luci.http.formvalue()

	if not file_exists(firmware_file) then
		local ul = values[input_field]
	
		if ul ~= '' and ul ~= nil then
			setFileHandler(location, input_field, file_name)
		end
	end

	local firmware_file_exists = file_exists(firmware_file)
	local firmware_exec = nil
	local action = "validate"
	local installed = false

	if firmware_file_exists then
		local cmd = {}
		action = values["action"] or "validate"

		if action == "cancel" then
			os.remove(firmware_file)
			firmware_file_exists = false
		elseif action == "install" then
			cmd = { "/usr/sbin/8311-firmware-upgrade.sh", "--yes", "--install", firmware_file }
			firmware_exec = luci.sys.process.exec(cmd, firmwareUpgradeOutput, firmwareUpgradeOutput)
			installed = true
		elseif action == "install_reboot" then
			cmd = { "/usr/sbin/8311-firmware-upgrade.sh", "--yes", "--install", "--reboot", firmware_file }	
			firmware_exec = luci.sys.process.exec(cmd, firmwareUpgradeOutput, firmwareUpgradeOutput)
			installed = true
		elseif action == "reboot" then
			sys.reboot()
		else
			-- validate
			cmd = { "/usr/sbin/8311-firmware-upgrade.sh", "--validate", firmware_file }
			firmware_exec = luci.sys.process.exec(cmd, firmwareUpgradeOutput, firmwareUpgradeOutput)
		end
	end

	local alt_firm_file = "/tmp/8311-alt-firmware"
	if installed and file_exists(alt_firm_file) then
		os.remove(alt_firm_file)
	end

	for k, v in string.gmatch(util.exec("/usr/sbin/alternate_firmware_info"), '([^\n=]+)=([^\n]+)') do
		if k == "FW_VARIANT" then
			altversion.variant=v
		elseif k == "FW_VERSION" then
			altversion.version=v
		elseif k == "FW_REVISION" then
			altversion.revision=v
		end
	end

	ltemplate.render("8311/firmware", {
		version=version,
		altversion=altversion,
		firmware_file_exists=firmware_file_exists,
		firmware_exec=firmware_exec,
		firmware_output=firmwareOutput,
		firmware_action=action
	})
end

function action_support()
	local values = luci.http.formvalue()
	local action = values["action"] or ""

	local support_file_exists = false
	local support_output = ""

	if action == "generate" then
		cmd = { "/usr/sbin/8311-support.sh" }
		luci.sys.process.exec(cmd, supportOut, supportOut)
	elseif action == "delete" then
		os.remove(support_file)
	end

	support_file_exists = file_exists(support_file)

	ltemplate.render("8311/support", {
		support_exec=support_exec,
		support_output=supportOutput,
		support_file_exists=support_file_exists
	})
end

function file_exists(filename)
	local fp = io.open(filename, "r")
	if fp ~= nil then
		io.close(fp)
		return true
	else
		return false
	end
end

function firmwareUpgradeOutput(data)
	data = data or ''
	firmwareOutput = (firmwareOutput or '') .. data
end

function supportOut(data)
	data = data or ''
	supportOutput = (supportOutput or '') .. data
end

-- Registers a chunked file upload handler with LuCI's HTTP layer.
-- location:   (string) Directory path to save the uploaded file into.
-- input_name: (string) HTML input field name to accept uploads from.
-- file_name:  (string, optional) Override filename; defaults to the
--             uploaded file's original name if not provided.
function setFileHandler(location, input_name, file_name)
	local fp

	luci.http.setfilehandler(
		function(meta, chunk, eof)
			if not fp then
				-- make sure the field name is the one we want
				if meta and meta.name == input_name then
					-- use the file name if specified
					file_name = file_name or meta.file

					fp = io.open(location .. "/" .. file_name, "w")
				end
			end

			-- actually write the uploaded file
			if chunk then
				fp:write(chunk)
			end

			if eof then
				fp:close()
			end
		end
	)
end
