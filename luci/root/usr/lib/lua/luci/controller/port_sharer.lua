module("luci.controller.port_sharer", package.seeall)

function index()
    if not nixio.fs.access("/etc/config/httpportreuse") then
        return
    end

    entry({"admin", "services", "port_sharer"},
          cbi("port_sharer/instances"),
          _("Port Sharer"), 10).dependent = true
end
