--[[
LuCI - Lua Configuration Interface

Copyright 2011 Ralph Hempel <ralph.hempel@lantiq.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

]]--

require("luci.tools.gpon")
local fs = require "nixio.fs"
local sys = require 'luci.controller.admin.system'

local goi_exist =
	luci.util.exec("fw_printenv -n goi_config 2>&- && fw_printenv -n goi_config " ..
	">/tmp/goi_env")

local goi_env = "/tmp/goi_env"
local goi_len = string.len(goi_exist)

local warning_msg =
	"<b><font color=\"red\">" .. translate("WARNING: Please enter the correct " ..
	"calibration information or damage to the laser assembly may result!!!!") ..
	"</font></b>"

-- UCI config file /etc/config/gpon
local gpon_map = Map("gpon", translate("Optic Calibration"))

-- 'goi' - section
local goi_section = gpon_map:section(NamedSection, "goi", "GOI")

-- 'goi' - option
local overwrite
if ( goi_len ~= 0 ) then
		overwrite =
			goi_section:option(Flag, "overwrite", translate("Confirm Overwrite"),
			translate("ENV calibration information already exists and it is highly " ..
			"recommended not to overwrite it!!!!"))

		-- don't let the user add/remove this option
		overwrite.addremove = false
		overwrite.default = "0"

		-- don't let the user to remove entry from config file if it is empty
		overwrite.rmempty = false
else
		overwrite =
			goi_section:option(Flag, "overwrite", translate("Enter Calibration " ..
			"Information"), translate("No ENV calibration information found, enter " ..
			"the calibration information in the text box below."))

		-- don't let the user add/remove this option
		overwrite.addremove = false
		overwrite.default = "1"

		-- don't let the user to remove entry from config file if it is empty
		overwrite.rmempty = false
end

function gpon_map.on_after_commit(map)
	local ow = overwrite:formvalue("goi") or "0"
	if ow == "1" then
		luci.sys.call("/opt/lantiq/bin/config_onu.sh update 2>&-")
	end
end

local goi_value =
	goi_section:option(TextValue, "goivalue", translate("ENV Calibration Value " ..
	"(base64)"), warning_msg)

-- don't let the user add/remove this option
goi_value.addremove = false
goi_value.datatype = "minlength(1000)"

-- don't let the user to remove entry from config file if it is empty
goi_value.rmempty = true
goi_value.rows = 15

goi_value:depends("overwrite","1")

function goi_value.cfgvalue()
	return fs.readfile(goi_env) or ""
end

local save_button =
	goi_section:option(Button, "Button", translate("Save Optic Calibration to ENV"))

save_button.inputtitle = translate("save")
save_button.inputstyle = "apply"

save_button:depends("overwrite","1")

function save_button.write(self, section, value)
	if ( goi_len == 0 ) then
		luci.sys.call("/opt/lantiq/bin/goi_store_uboot.sh 2>&-")
	end
end  

return gpon_map
