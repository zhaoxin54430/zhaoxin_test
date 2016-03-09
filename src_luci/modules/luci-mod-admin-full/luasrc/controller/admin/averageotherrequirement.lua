-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Copyright 2008-2011 Jo-Philipp Wich <jow@openwrt.org>
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.admin.averageotherrequirement", package.seeall)

local fs = require "nixio.fs"

function index()

	entry({"admin", "averageotherrequirement"}, alias("admin", "averageotherrequirement", "essentialfiles"), _("hide1"), 70).index = true
	entry({"admin", "averageotherrequirement", "essentialfiles"}, call("action_requirement"), _("hide2"), 1)
end

function upgradeReadFile(file)
    if fs.access(file) then 
        return fs.readfile(file)
    else 
        return false
    end  
end

function action_requirement()
	local sys = require "luci.sys"
	local fs  = require "nixio.fs"
	local resource_dir   = "/tmp/others_res/"
	local resource_tmp   = resource_dir .. "res.tar.gz"
	local resource_res   = resource_dir .. "res/*"
	local pass_file = "/etc/upgrade_o_pass"
	local result = false
	local local_pass = nil

	local function file_supported()         
		return (os.execute("tar -zxvf %s -C %s >/dev/null" %{resource_tmp , resource_dir}) == 0)        
	end
	local fp
	luci.http.setfilehandler(
		function(meta, chunk, eof)
			if not fp then
				if meta and meta.name == "resource" then
					fp = io.open(resource_tmp, "w")
				end
			end
			if chunk then
				fp:write(chunk)
			end
			if eof and fp then
				fp:close()
				fp = nil
			end
		end
	)

	if luci.http.formvalue("resource") then
		local_pass = upgradeReadFile(pass_file)
		local luci_pass = luci.http.formvalue("up_password")
		if local_pass and luci_pass and luci_pass == local_pass and file_supported() then
			os.execute("rm -rf %s >/dev/null" % resource_tmp)
			if os.execute("cp -rf %s /www/connect/res/ >/dev/null" % resource_res) == 0 then
				result = true
			end
		end

		if result then
			luci.template.render("admin_averageotherrequirement/stevenmidlinksession", {
				upgrade_avail = true ,
				success = true
			})
		else
			luci.template.render("admin_averageotherrequirement/stevenmidlinksession", {
				upgrade_avail = true ,
				image_invalid = true
			})
		end
	else
		--
		-- Overview
		--
		luci.template.render("admin_averageotherrequirement/stevenmidlinksession", {
				upgrade_avail = true
		})
	end
end
