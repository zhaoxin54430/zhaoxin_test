-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Licensed to the public under the Apache License 2.0.

local nw = require "luci.model.network"

m = Map("wireless", "", translate("The Configuration page of the wifi, The first is the master wifi interface"))

s = m:section(TypedSection, "wifi-iface", translate("Interface Configuration"))
s.addremove = false
s.anonymous = true

ssid_name = s:option(Value, "ssid", translate("wifi ssid"))
ssid_name.maxlength = 28
ssid_name.size = 28
ssid_name.rmempty = true

function ssid_name.validate(self, value)
    if value == nil or value == false then
        return nil, translate("ssid can't empty!")
    end 
    return value
end

return m
