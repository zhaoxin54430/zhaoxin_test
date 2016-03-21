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

return m
