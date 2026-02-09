-- 8311.tools -- Lua helper library for the 8311 firmware mod LuCI interface
--
-- Provides convenience wrappers around the firmware environment (fwenv) shell
-- commands and basic HTML escaping utilities.  Used by the LuCI CBI models
-- and controller to read/write EEPROM-backed firmware variables.
--
-- The fw_getenv / fw_setenv family accept a table argument so callers can
-- use either positional ({key, default}) or named ({key=..., base64=true})
-- style.  The _8311 variants automatically prepend the "8311_" prefix.
--
-- Dependencies:
--   luci.util          -- shellquote(), exec()
--   /usr/sbin/fwenv_get, fwenv_set  -- shell helpers (from 8311 mod)
--   /usr/sbin/fw_printenv            -- U-Boot env tool

local require = require
local string = string
local setmetatable = setmetatable

module "8311.tools"

local util = require "luci.util"

-- html_escape(text) -- Replace HTML-significant characters with entities.
-- Note: the gsub pattern uses %S+ (non-whitespace runs) which means only
-- whole whitespace-delimited tokens that exactly match a key are replaced.
function html_escape(text)
	if text == nil then text = "" end
	text = "" .. text

	return text:gsub("%S+", {
		["&"] = "&amp;",
		["<"] = "&lt;",
		[">"] = "&gt;",
		['"'] = "&quot;",
		["'"] = "&#039;"
	})
end

-- nl2br(text) -- Convert newlines to HTML <br /> tags for display.
function nl2br(text)
	if text == nil then text = "" end
	return string.gsub("" .. text, "\n", "<br />\n")
end

-- fw_getenv(t) -- Read a firmware environment variable (generic, no prefix).
--   t = {key, [default], [base64=bool]}  or  {key=..., default=..., base64=...}
-- Returns the variable's value as a string, or default if unset.
function fw_getenv(t)
	setmetatable(t, {__index={key=nil, default=nil, base64=false}})

	return fwenv_get(
		t[1] or t.key,
		t[2] or t.default,
		false,
		t[3] or t.base64
	)
end

-- fw_getenv_8311(t) -- Read an 8311-prefixed firmware environment variable.
-- Same interface as fw_getenv but passes --8311 flag so the shell helper
-- automatically prepends "8311_" to the key name.
function fw_getenv_8311(t)
	setmetatable(t, {__index={key=nil, default=nil, base64=false}})

	return fwenv_get(
		t[1] or t.key,
		t[2] or t.default,
		true,
		t[3] or t.base64
	)
end

-- fwenv_get(key, default, _8311, base64) -- Low-level firmware env reader.
-- Shells out to the fwenv_get helper script, building the command line from:
--   key     : environment variable name
--   default : fallback value if the variable is not set
--   _8311   : if true, passes --8311 to auto-prefix the key with "8311_"
--   base64  : if true, passes --base64 to base64-decode the stored value
-- Returns the value with trailing newlines stripped, or false if no key.
function fwenv_get(key, default, _8311, base64)
	if not key then return false end

	local _8311_arg, base64_arg, default_arg = "", "", ""
	if _8311 then _8311_arg = "--8311 " end
	if base64 then base64_arg = "--base64 " end
	if default then default_arg = " " .. util.shellquote(default) end

	return string.gsub(util.exec("fwenv_get " .. _8311_arg .. base64_arg .. util.shellquote(key) .. default_arg), '[\r\n]+$', "")
end

-- fw_getenvs_8311() -- Bulk-read all 8311-prefixed firmware env vars.
-- Calls fw_printenv, filters lines starting with "8311_", and returns a
-- table keyed by the variable name (with the "8311_" prefix stripped).
-- The leading "echo ;" ensures the first match starts after a newline.
function fw_getenvs_8311()
	local fwenvs = {}
	for k, v in string.gmatch(util.exec('echo ; fw_printenv | grep "^8311_"'), '\n8311_([^\n=]+)=([^\r\n]+)') do
		fwenvs[k] = v
	end

	return fwenvs
end

-- fw_setenv(t) -- Write a firmware environment variable (generic, no prefix).
--   t = {key, value, [base64=bool]}  or  {key=..., value=..., base64=...}
function fw_setenv(t)
	setmetatable(t, {__index={key=nil, value=nil, base64=false}})

	return fwenv_set(
		t[1] or t.key,
		t[2] or t.value,
		false,
		t[3] or t.base64
	)
end

-- fw_setenv_8311(t) -- Write an 8311-prefixed firmware environment variable.
-- Same interface as fw_setenv but passes --8311 flag.
function fw_setenv_8311(t)
	setmetatable(t, {__index={key=nil, value=nil, base64=false}})

	return fwenv_set(
		t[1] or t.key,
		t[2] or t.value,
		true,
		t[3] or t.base64
	)
end

-- fwenv_set(key, value, _8311, base64) -- Low-level firmware env writer.
-- Shells out to the fwenv_set helper script.  Arguments mirror fwenv_get.
-- Returns nothing; the write is fire-and-forget from Lua's perspective.
function fwenv_set(key, value, _8311, base64)
	if not key then return false end

	local _8311_arg, base64_arg = "", ""
	if _8311 then _8311_arg = "--8311 " end
	if base64 then base64_arg = "--base64 " end

	util.exec("fwenv_set " .. _8311_arg .. base64_arg .. util.shellquote(key) .. " " .. util.shellquote(value))
end
