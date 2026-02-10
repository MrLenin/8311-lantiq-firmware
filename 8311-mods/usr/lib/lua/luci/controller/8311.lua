--[[
LuCI - Lua Configuration Interface

8311 Controller
===============
Main LuCI controller for the 8311 firmware mod. Defines the admin menu
structure and dispatches pages for:
  - Configuration (UCI/CBI form for PON, VLAN, device settings)
  - Network Addresses (CBI form for management interface)
  - Optic Calibration (CBI form for optic TX/RX calibration)
  - PON Status (proxies gtop/otop CLI output to the browser)
  - PON ME Explorer (OMCI managed-entity dump viewer)
  - VLAN Tables (extended VLAN rule decoder)

All pages are under the "admin/8311/*" menu tree.

Copyright 2011 Ralph Hempel <ralph.hempel@lantiq.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

]]--
module("luci.controller.8311", package.seeall)

require("luci.tools.gpon")
require("luci.util")

local util = require "luci.util"
local ltemplate = require "luci.template"
local http = require "luci.http"
local dispatcher = require "luci.dispatcher"
local sys = require "luci.sys"
local i18n = require "luci.i18n"
local translate = i18n.translate
local ltn12 = require "luci.ltn12"
local fs = require "nixio.fs"
local support_file = "/tmp/support.tar.gz"

function index()
	-----------------------------------------------------------------------
	-- Menu tree: admin/8311/* (consolidated)
	-----------------------------------------------------------------------
	entry({"admin", "8311"}, alias("admin", "8311", "config"), _("8311"), 80).dependent=false
	entry({"admin", "8311", "config"}, cbi("8311-config"), _("Configuration"), 1)
	entry({"admin", "8311", "management"}, cbi("8311-management"), _("Network Addresses"), 2)
	entry({"admin", "8311", "optic-cal"}, cbi("8311-optic-cal"), _("Optic Calibration"), 3)
	entry({"admin", "8311", "pon_status"}, call("action_pon_status"), _("PON Status"), 4)
	entry({"admin", "8311", "pon_explorer"}, call("action_pon_explorer"), _("PON ME Explorer"), 5)
	entry({"admin", "8311", "vlans"}, call("action_vlans"), _("VLAN Tables"), 6)
	entry({"admin", "8311", "support"}, call("action_support"), _("Support"), 7)

	-- Hook script handlers (deferred — tc/flower not used on G-010S-P)
	--entry({"admin", "8311", "get_hook_script"}, call("action_get_hook_script")).leaf=true
	--entry({"admin", "8311", "save_hook_script"}, call("action_save_hook_script")).leaf=true

	-- XHR endpoints (leaf=true allows URL path continuation)
	entry({"admin", "8311", "pontop"}, call("action_pontop")).leaf=true
	entry({"admin", "8311", "pon_dump"}, call("action_pon_dump")).leaf=true
	entry({"admin", "8311", "vlans", "extvlans"}, call("action_vlan_extvlans"))
	entry({"admin", "8311", "support", "support.tar.gz"}, call("action_support_download"))

--	entry({"admin", "8311", "firmware"}, call("action_firmware"), _("Firmware"), 8);
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
		pages[page.id] = { page = page.page, otop = page.otop or false, custom = page.custom }
	end

	-- Non-tab XHR endpoint: system info summary
	pages["system_info"] = { custom = "/opt/lantiq/bin/system_info.sh summary" }

	return pages
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

	-- Custom command (e.g. system_info.sh), gtop, or otop
	if pages[page_id].custom then
		cmd = pages[page_id].custom
	elseif not pages[page_id].otop then
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

	local tables = util.exec("/usr/sbin/8311-extvlan-decode.sh -t 2>/dev/null")

	if tables and tables ~= "" then
		luci.http.write(tables)
		luci.http.write("\n\n")
		local rules = util.exec("/usr/sbin/8311-extvlan-decode.sh 2>/dev/null")
		luci.http.write(rules or "")
	else
		luci.http.write("No Extended VLAN Tables Detected")
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
	if not file_exists(support_file) then
		luci.http.status(404, "Not Found")
		return
	end

	luci.http.header("Content-Disposition", 'attachment; filename="support.tar.gz"')
	luci.http.prepare_content("application/x-targz")
	ltn12.pump.all(ltn12.source.file(io.open(support_file)), luci.http.write)
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
	local support_log = "/tmp/8311-support.log"
	local support_running = "/tmp/8311-support-running"

	local action = luci.http.formvalue("action") or ""

	if action == "generate" then
		os.remove(support_file)
		os.remove(support_log)
		os.execute(
			"(touch " .. support_running ..
			" && /usr/sbin/8311-support.sh >" .. support_log .. " 2>&1" ..
			"; rm -f " .. support_running ..
			") </dev/null >/dev/null 2>&1 &"
		)
		luci.http.redirect(dispatcher.build_url("admin", "8311", "support"))
		return
	elseif action == "delete" then
		os.remove(support_file)
		os.remove(support_log)
		luci.http.redirect(dispatcher.build_url("admin", "8311", "support"))
		return
	end

	local generating = file_exists(support_running)
	local support_file_exists = file_exists(support_file)
	local support_output = ""

	if file_exists(support_log) then
		local f = io.open(support_log, "r")
		if f then
			support_output = f:read("*a") or ""
			f:close()
		end
	end

	ltemplate.render("8311/support", {
		support_output=support_output,
		support_file_exists=support_file_exists,
		support_generating=generating
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
