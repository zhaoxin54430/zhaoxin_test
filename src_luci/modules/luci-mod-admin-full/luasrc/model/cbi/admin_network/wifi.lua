-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Licensed to the public under the Apache License 2.0.

local wa = require "luci.tools.webadmin"
local nw = require "luci.model.network"
local ut = require "luci.util"
local nt = require "luci.sys".net
local fs = require "nixio.fs"

arg[1] = arg[1] or ""



m = Map("wireless", "",
	translate("Wifi configuration page"))

m:chain("network")
m:chain("firewall")
m.redirect = luci.dispatcher.build_url("admin/network/wireless")

local ifsection

function m.on_commit(map)
	local wnet = nw:get_wifinet(arg[1])
	if ifsection and wnet then
		ifsection.section = wnet.sid
--		m.title = luci.util.pcdata(wnet:get_i18n())
	end
end

m.on_after_commit = function(self)
    if self.changed then    -- changes ?
        os.execute("/sbin/notify_uhttpd &")
    end
end

nw.init(m.uci)

local wnet = nw:get_wifinet(arg[1])
local wdev = wnet and wnet:get_device()

-- redirect to overview page if network does not exist anymore (e.g. after a revert)
if not wnet or not wdev then
	luci.http.redirect(luci.dispatcher.build_url("admin/network/wireless"))
	return
end

-- wireless toggle was requested, commit and reload page
function m.parse(map)
	if m:formvalue("cbid.wireless.%s.__toggle" % wdev:name()) then
		if wdev:get("disabled") == "1" or wnet:get("disabled") == "1" then
			wnet:set("disabled", nil)
		else
			wnet:set("disabled", "1")
		end
		wdev:set("disabled", nil)

		nw:commit("wireless")
		luci.sys.call("(env -i /bin/ubus call network reload) >/dev/null 2>/dev/null")

		luci.http.redirect(luci.dispatcher.build_url("admin/network/wireless", arg[1]))
		return
	end
	Map.parse(map)
end

--m.title = luci.util.pcdata(wnet:get_i18n())


local iw = luci.sys.wifi.getiwinfo(arg[1])
--local hw_modes      = iw.hwmodelist or { }



----------------------- Interface -----------------------

s = m:section(NamedSection, wnet.sid, "wifi-iface", translate("Interface Configuration"))
ifsection = s
s.addremove = false
s.anonymous = true
s.defaults.device = wdev:name()

--s:tab("general", translate("General Setup"))
--s:tab("encryption", translate("Wireless Security"))
--s:taboption("general", Value, "ssid", translate("<abbr title=\"Extended Service Set Identifier\">ESSID</abbr>"))
ssid_name = s:option(Value, "ssid", translate("Wifi ssid, The length is (3-30), One chinese length is 3"))
ssid_name.rmempty = false

if arg[1] == "radio0.network2" then
	wpakey = s:option(Value, "key", translate("Wifi password, The length is (8-63)"))
--	wpakey:depends("encryption", "psk")
--	wpakey:depends("encryption", "psk2")
--	wpakey:depends("encryption", "psk+psk2")
--	wpakey:depends("encryption", "psk-mixed")
	wpakey.datatype = "wpakey"
	wpakey.rmempty = false
	wpakey.password = true
--[[	
	function wpakey.validate(self, value, section)
		local length = string.len(value)
		local err_str = translate("The length should be (8-63)characters, current is ") .. length
		if length < 8 or length > 63 then
			return nil, err_str
		end
		return value
	end
]]--
end

function ssid_name.validate(self, value, section)
    local length = string.len(value)
	local err_str = translate("The length should be (3-30)characters, current is ") .. length
    if length < 3 or length > 30 then
        return nil, err_str
    end
    return value
end

return m
