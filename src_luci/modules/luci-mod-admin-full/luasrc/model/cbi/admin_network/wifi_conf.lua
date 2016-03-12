-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Licensed to the public under the Apache License 2.0.

local nw = require "luci.model.network"

m = Map("wireless", "", translate("Wifi configuration page"))

s = m:section(TypedSection, "wifi-iface", translate("Interface Configuration"))
s.addremove = false
s.anonymous = true

ssid_name = s:option(Value, "ssid", translate("Wifi ssid (3-30)characters, One chinese as 3 characters"))
--ssid_name.datatype = "rangelength(8, 28)"
ssid_name.rmempty = false

function ssid_name.validate(self, value, section)
    local length = string.len(value)
	local err_str = translate("The length should be (3-30)characters, current is ") .. length
    if length < 3 or length > 30 then
        return nil, err_str
    end
    return value
end

return m
