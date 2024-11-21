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

local goi_exist = luci.util.exec("fw_printenv -n goi_config 2>&- && fw_printenv -n goi_config > /tmp/goi_env")
local goi_env = "/tmp/goi_env"
local goi_len = string.len(goi_exist)
local warning_msg = "<b><font color=\"red\">" .. translate("WARNING: Please enter the correct calibration information or damage to the laser assembly may result!!!!") .. "</font></b>"

-- UCI config file /etc/config/gpon
local gpon_map = Map("gpon", translate("Optic Calibration"))
-- 'goi' - section
local goi_section = gpon_map:section(NamedSection, "goi", "GOI")

-- 'goi' - option

if ( goi_len ~= 0 ) then
		overwrite = goi_section:option(Flag, "overwrite", translate("Confirm Overwrite"), translate("ENV calibration information already exists and it is highly recommended not to overwrite it!!!!"))
		overwrite.addremove = false -- don't let the user add/remove this option
		overwrite.rmempty = false -- don't let the user to remove entry from config file if it is empty
		overwrite.default = "0"
else
		--sys.fork_exec("uci set gpon.goi.overwrite=1 2>&-; uci commit gpon.goi.overwrite=1 2>&-")
		overwrite = goi_section:option(Flag, "overwrite", translate("Enter Calibration Information"), translate("No ENV calibration information found, enter the calibration information in the text box below."))
		overwrite.addremove = false -- don't let the user add/remove this option
		overwrite.rmempty = false -- don't let the user to remove entry from config file if it is empty
		overwrite.default = "1"
end

local goi_value = goi_section:option(TextValue, "goivalue", translate("ENV Calibration Value (base64)"), warning_msg)
goi_value.addremove = false -- don't let the user add/remove this option
goi_value.rmempty = true -- don't let the user to remove entry from config file if it is empty
goi_value.rows = 15
goi_value.datatype = "minlength(1000)"
goi_value:depends("overwrite","1")

function goi_value.cfgvalue()
	return fs.readfile(goi_env) or ""
end

local save_button = goi_section:option(Button, "Button", translate("Save Optic Calibration to ENV"))
save_button.inputtitle = translate("save")
save_button.inputstyle = "apply"
save_button:depends("overwrite","")

function save_button.write(self, section, value)
	if ( goi_len == 0 ) then
		luci.sys.call("/opt/lantiq/bin/goi_store_uboot.sh 2>&-")
	end
end  

function gpon_map.on_after_commit(map)
	if ( overwrite ~= "" ) then
		luci.sys.call("/opt/lantiq/bin/config_onu.sh update 2>&-")
	end
end

return gpon_map
