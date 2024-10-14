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
m = Map("gpon", translate("Optic Calibration"))
-- 'goi' - section
s = m:section(NamedSection, "goi", "GOI")

-- 'goi' - option

if ( goi_len ~= 0 ) then
		v = s:option(Flag, "overwrite", translate("Confirm Overwrite"), translate("ENV calibration information already exists and it is highly recommended not to overwrite it!!!!"))
		v.addremove = false -- don't let the user add/remove this option
		v.rmempty = false -- don't let the user to remove entry from config file if it is empty
		v.default = "0"
else
		--sys.fork_exec("uci set gpon.goi.overwrite=1 2>&-; uci commit gpon.goi.overwrite=1 2>&-")
		v = s:option(Flag, "overwrite", translate("Enter Calibration Information"), translate("No ENV calibration information found, enter the calibration information in the text box below."))
		v.addremove = false -- don't let the user add/remove this option
		v.rmempty = false -- don't let the user to remove entry from config file if it is empty
		v.default = "1"
end

v = s:option(TextValue, "goivalue", translate("ENV Calibration Value (base64)"), warning_msg)
v.addremove = false -- don't let the user add/remove this option
v.rmempty = true -- don't let the user to remove entry from config file if it is empty
v.rows = 15
v.datatype = "minlength(1000)"
v:depends("overwrite","1")
function v.cfgvalue()
	return fs.readfile(goi_env) or ""
end

button = s:option(Button, "Button", translate("Save Optic Calibration to ENV"))
button.inputtitle = translate("save")
button.inputstyle = "apply"
button:depends("overwrite","")

function button.write(self, section, value)
	if ( goi_len == 0 ) then
		luci.sys.call("/opt/lantiq/bin/goi_store_uboot.sh 2>&-")
	end
end  

function m.on_after_commit(map)
	if ( overwrite ~= "" ) then
		luci.sys.call("/opt/lantiq/bin/config_onu.sh update 2>&-")
	end
end

return m
