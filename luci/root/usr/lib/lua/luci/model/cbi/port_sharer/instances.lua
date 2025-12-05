local m = Map("httpportreuse", translate("Port Sharer"),
    translate("Configure port-sharer instances, each with its own listen port, routes and fallback backends."))

local function add_instance_values(opt)
    m.uci:foreach("httpportreuse", "instance", function(s)
        if s[".name"] then opt:value(s[".name"]) end
    end)
end

-- Instance list (one per mixed port)
local inst = m:section(TypedSection, "instance", translate("Instances"))
inst.addremove = true
inst.anonymous = false
inst.template = "cbi/tblsection"

local enabled = inst:option(Flag, "enabled", translate("Enable"))
enabled.rmempty = false
enabled.default = enabled.enabled

local addr = inst:option(Value, "listen_addr", translate("Listen Address"))
addr.datatype = "ipaddr"
addr.placeholder = "0.0.0.0"

local port = inst:option(Value, "listen_port", translate("Listen Port"))
port.datatype = "port"
port.placeholder = "8888"

local peek = inst:option(Value, "peek_size", translate("Peek Size"),
    translate("Bytes to peek for protocol detection (64-4096)."))
peek.datatype = "range(64,4096)"
peek.placeholder = "512"

local prefer_zc = inst:option(Flag, "prefer_zero_copy", translate("Prefer Zero Copy"))
prefer_zc.rmempty = false
prefer_zc.default = prefer_zc.enabled

local prefer_dnat = inst:option(Flag, "prefer_kernel_dnat", translate("Prefer Kernel DNAT"))
prefer_dnat.rmempty = false
prefer_dnat.default = prefer_dnat.enabled

local metrics_en = inst:option(Flag, "metrics_enable", translate("Prometheus Metrics"))
metrics_en.default = metrics_en.disabled
metrics_en.rmempty = false

local metrics_port = inst:option(Value, "metrics_port", translate("Metrics Port"))
metrics_port.datatype = "port"
metrics_port.placeholder = "9100"
metrics_port:depends("metrics_enable", "1")

-- Fallback backend per instance
local fb = m:section(TypedSection, "fallback", translate("Fallback"))
fb.addremove = true
fb.anonymous = false
fb.template = "cbi/tblsection"

local fb_inst = fb:option(ListValue, "instance", translate("Instance"))
fb_inst.rmempty = false
add_instance_values(fb_inst)

local fb_host = fb:option(Value, "host", translate("Host"))
fb_host.datatype = "host"
fb_host.placeholder = "127.0.0.1"

local fb_port = fb:option(Value, "port", translate("Port"))
fb_port.datatype = "port"
fb_port.placeholder = "22"

local fb_pp = fb:option(Flag, "proxy_protocol", translate("Proxy Protocol v2"))
fb_pp.rmempty = false

-- Routing rules
local rt = m:section(TypedSection, "route", translate("Routes"))
rt.addremove = true
rt.anonymous = false
rt.template = "cbi/tblsection"

local rt_inst = rt:option(ListValue, "instance", translate("Instance"))
rt_inst.rmempty = false
add_instance_values(rt_inst)

local rname = rt:option(Value, "name", translate("Rule Name"))
rname.placeholder = "web"
rname.rmempty = false

local det = rt:option(ListValue, "detector", translate("Detector"))
det:value("http_or_tls", translate("HTTP or TLS"))
det:value("http", translate("HTTP"))
det:value("tls_client_hello", translate("TLS ClientHello"))
det:value("prefix", translate("Prefix Match"))
det:value("ssh_banner", translate("SSH Banner"))
det:value("always", translate("Always"))

local prefix = rt:option(Value, "prefix", translate("Prefix Bytes"),
    translate("Hex or plain prefix matched at stream start when detector is 'prefix'."))
prefix:depends("detector", "prefix")

local bk_host = rt:option(Value, "host", translate("Backend Host"))
bk_host.datatype = "host"
bk_host.placeholder = "127.0.0.1"

local bk_port = rt:option(Value, "port", translate("Backend Port"))
bk_port.datatype = "port"
bk_port.placeholder = "443"

local bk_pp = rt:option(Flag, "proxy_protocol", translate("Proxy Protocol v2"))
bk_pp.rmempty = false

local httpf = rt:option(Flag, "http_forward", translate("Inject HTTP Forward Headers"))
httpf.rmempty = false

local xri = rt:option(Flag, "x_real_ip", translate("X-Real-IP"))
xri:depends("http_forward", "1")
xri.default = xri.enabled
xri.rmempty = false

local xff = rt:option(Flag, "x_forwarded_for", translate("X-Forwarded-For"))
xff:depends("http_forward", "1")
xff.default = xff.enabled
xff.rmempty = false

local xfp = rt:option(Flag, "x_forwarded_proto", translate("X-Forwarded-Proto"))
xfp:depends("http_forward", "1")
xfp.default = xfp.enabled
xfp.rmempty = false

local xport = rt:option(Flag, "x_forwarded_port", translate("X-Forwarded-Port"))
xport:depends("http_forward", "1")
xport.default = xport.enabled
xport.rmempty = false

local forwarded = rt:option(Flag, "forwarded", translate("Forwarded (RFC 7239)"))
forwarded:depends("http_forward", "1")
forwarded.rmempty = false

local headers = rt:option(DynamicList, "headers", translate("Extra Headers"),
    translate("Format: Header-Name: value"))
headers:depends("http_forward", "1")

return m
