-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Licensed to the public under the Apache License 2.0.


m = Map("shopInfo", "", translate("Shop information"))

s = m:section(TypedSection, "shopInfo", translate("Shop information"))
s.addremove = false
s.anonymous = true

id_alue = s:option(Value, "idValue", "ShopId")
id_alue.rmempty = false

key_alue = s:option(Value, "keyValue", "SecretKey")
key_alue.rmempty = false

m.on_after_commit = function(self)
--    if self.changed then    -- changes ?
        os.execute("cp -rf /etc/config/shopInfo /www/connect/res/")
        os.execute("/sbin/notify_uhttpd &")
--    end
end

function id_alue.write(self, section, value)
    Value.write(self, section, value)
    magic_value=luci.util.exec("/bin/genShopMagic " .. value)
    m:set(section, "magic", magic_value)
end

return m
