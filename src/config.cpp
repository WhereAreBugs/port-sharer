#include "config.hpp"

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <string_view>
#ifdef OPENWRT
#include <uci.h>
#endif

namespace pt = boost::property_tree;

namespace port_sharer {

namespace {

DetectorKind parse_detector(std::string_view value) {
    if (value == "http") return DetectorKind::Http;
    if (value == "tls" || value == "tls_client_hello") return DetectorKind::TlsClientHello;
    if (value == "http_or_tls" || value == "https") return DetectorKind::HttpOrTls;
    if (value == "prefix") return DetectorKind::Prefix;
    if (value == "ssh" || value == "ssh_banner") return DetectorKind::SshBanner;
    if (value == "always") return DetectorKind::Always;
    return DetectorKind::HttpOrTls;
}

Backend parse_backend(const pt::ptree& node, const Backend& fallback) {
    Backend backend = fallback;
    backend.host = node.get<std::string>("host", backend.host);
    backend.port = node.get<uint16_t>("port", backend.port);
    backend.proxy_protocol = node.get<bool>("proxy_protocol", backend.proxy_protocol);
    return backend;
}

HttpForward parse_http_forward(const pt::ptree& node, const HttpForward& fallback) {
    HttpForward hf = fallback;
    hf.enable = node.get<bool>("enable", hf.enable);
    hf.add_x_real_ip = node.get<bool>("x_real_ip", hf.add_x_real_ip);
    hf.add_x_forwarded_for = node.get<bool>("x_forwarded_for", hf.add_x_forwarded_for);
    hf.add_x_forwarded_proto = node.get<bool>("x_forwarded_proto", hf.add_x_forwarded_proto);
    hf.add_x_forwarded_port = node.get<bool>("x_forwarded_port", hf.add_x_forwarded_port);
    hf.add_forwarded = node.get<bool>("forwarded", hf.add_forwarded);
    hf.extra_headers.clear();
    if (auto extras = node.get_child_optional("headers")) {
        for (const auto& item : *extras) {
            HeaderKV kv;
            kv.name = item.second.get<std::string>("name", "");
            kv.value = item.second.get<std::string>("value", "");
            if (!kv.name.empty()) hf.extra_headers.push_back(std::move(kv));
        }
    }
    return hf;
}

} // namespace

AppConfig make_default_config() {
    AppConfig config;
    config.listener = {"0.0.0.0", 8888};
    config.fallback = {"127.0.0.1", 22, false};
    config.routes = {
        RouteRule{
            "http-https",
            DetectorKind::HttpOrTls,
            {},
            Backend{"127.0.0.1", 443, false},
            HttpForward{true, true, true, true, true, false, {}}
        },
        RouteRule{
            "ssh",
            DetectorKind::SshBanner,
            {},
            Backend{"127.0.0.1", 22, false},
            HttpForward{}
        }
    };
    config.peek_size = 512;
    return config;
}

#ifdef OPENWRT
// Minimal UCI loader: package "httpportreuse"
std::vector<InstanceConfig> load_configs_from_uci(std::ostream& log) {
    std::vector<InstanceConfig> instances;
    uci_context* ctx = uci_alloc_context();
    if (!ctx) {
        log << "[config] UCI alloc failed, use defaults.\n";
        return {InstanceConfig{"default", true, make_default_config()}};
    }

    uci_package* pkg = nullptr;
    if (uci_load(ctx, "httpportreuse", &pkg) != UCI_OK) {
        log << "[config] UCI package 'httpportreuse' not found, use defaults.\n";
        uci_free_context(ctx);
        return {InstanceConfig{"default", true, make_default_config()}};
    }

    auto read_bool = [](uci_option* opt, bool def) {
        if (!opt || opt->type != UCI_TYPE_STRING) return def;
        return std::string(opt->v.string) == "1" || std::string(opt->v.string) == "true";
    };
    auto read_str = [](uci_option* opt, const std::string& def) {
        if (!opt || opt->type != UCI_TYPE_STRING) return def;
        return std::string(opt->v.string);
    };
    auto clamp_peek = [](std::size_t v) { return std::max<std::size_t>(64, std::min<std::size_t>(v, 4096)); };
    auto parse_headers = [](uci_option* opt) {
        std::vector<HeaderKV> list;
        if (!opt || opt->type != UCI_TYPE_LIST) return list;
        for (uci_element* e = opt->v.list.head; e; e = e->next) {
            if (!e->name) continue;
            std::string item = e->name;
            auto pos = item.find(':');
            if (pos == std::string::npos) continue;
            HeaderKV kv;
            kv.name = std::string(item.substr(0, pos));
            // trim leading spaces
            std::string val = item.substr(pos + 1);
            while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.erase(val.begin());
            kv.value = val;
            if (!kv.name.empty()) list.push_back(std::move(kv));
        }
        return list;
    };

    // First pass: load instances
    for (uci_element* e = pkg->sections.head; e; e = e->next) {
        uci_section* sec = uci_to_section(e);
        if (!sec || sec->type == nullptr || std::string(sec->type) != "instance") continue;
        InstanceConfig inst;
        inst.name = sec->e.name ? sec->e.name : "instance";
        inst.app = make_default_config();
        inst.app.routes.clear(); // will be filled by route sections
        inst.enabled = read_bool(uci_lookup_option(ctx, sec, "enabled"), true);
        inst.app.listener.address = read_str(uci_lookup_option(ctx, sec, "listen_addr"), inst.app.listener.address);
        inst.app.listener.port = static_cast<uint16_t>(std::stoi(read_str(uci_lookup_option(ctx, sec, "listen_port"), std::to_string(inst.app.listener.port))));
        inst.app.peek_size = clamp_peek(static_cast<std::size_t>(std::stoul(read_str(uci_lookup_option(ctx, sec, "peek_size"), std::to_string(inst.app.peek_size)))));
        inst.app.performance.prefer_zero_copy = read_bool(uci_lookup_option(ctx, sec, "prefer_zero_copy"), inst.app.performance.prefer_zero_copy);
        inst.app.performance.prefer_kernel_dnat = read_bool(uci_lookup_option(ctx, sec, "prefer_kernel_dnat"), inst.app.performance.prefer_kernel_dnat);
        inst.app.metrics.enable = read_bool(uci_lookup_option(ctx, sec, "metrics_enable"), inst.app.metrics.enable);
        inst.app.metrics.port = static_cast<uint16_t>(std::stoi(read_str(uci_lookup_option(ctx, sec, "metrics_port"), std::to_string(inst.app.metrics.port))));
        instances.push_back(std::move(inst));
    }

    if (instances.empty()) {
        // Backward compatibility: prepare a default instance to accept legacy sections.
        InstanceConfig inst;
        inst.name = "default";
        inst.enabled = true;
        inst.app = make_default_config();
        inst.app.routes.clear();
        instances.push_back(std::move(inst));
    }

    auto find_instance = [&](const std::string& name) -> InstanceConfig* {
        for (auto& inst : instances) {
            if (inst.name == name) return &inst;
        }
        return nullptr;
    };

    // Second pass: routes/fallbacks
    for (uci_element* e = pkg->sections.head; e; e = e->next) {
        uci_section* sec = uci_to_section(e);
        if (!sec) continue;
        std::string stype = sec->type;
        if (stype == "route") {
            std::string inst_name = read_str(uci_lookup_option(ctx, sec, "instance"), "");
            auto* inst = inst_name.empty() ? &instances.front() : find_instance(inst_name);
            if (!inst) inst = &instances.front();
            RouteRule rule;
            rule.name = sec->e.name ? sec->e.name : "";
            auto detector = read_str(uci_lookup_option(ctx, sec, "detector"), "http_or_tls");
            rule.detector = parse_detector(detector);
            rule.prefix = read_str(uci_lookup_option(ctx, sec, "prefix"), "");
            rule.backend.host = read_str(uci_lookup_option(ctx, sec, "host"), inst->app.fallback.host);
            rule.backend.port = static_cast<uint16_t>(std::stoi(read_str(uci_lookup_option(ctx, sec, "port"), std::to_string(inst->app.fallback.port))));
            rule.backend.proxy_protocol = read_bool(uci_lookup_option(ctx, sec, "proxy_protocol"), false);
            rule.http_forward.enable = read_bool(uci_lookup_option(ctx, sec, "http_forward"), rule.http_forward.enable);
            rule.http_forward.add_x_real_ip = read_bool(uci_lookup_option(ctx, sec, "x_real_ip"), rule.http_forward.add_x_real_ip);
            rule.http_forward.add_x_forwarded_for = read_bool(uci_lookup_option(ctx, sec, "x_forwarded_for"), rule.http_forward.add_x_forwarded_for);
            rule.http_forward.add_x_forwarded_proto = read_bool(uci_lookup_option(ctx, sec, "x_forwarded_proto"), rule.http_forward.add_x_forwarded_proto);
            rule.http_forward.add_x_forwarded_port = read_bool(uci_lookup_option(ctx, sec, "x_forwarded_port"), rule.http_forward.add_x_forwarded_port);
            rule.http_forward.add_forwarded = read_bool(uci_lookup_option(ctx, sec, "forwarded"), rule.http_forward.add_forwarded);
            rule.http_forward.extra_headers = parse_headers(uci_lookup_option(ctx, sec, "headers"));
            if (rule.backend.port == 0) continue;
            inst->app.routes.push_back(rule);
        } else if (stype == "server") {
            // Legacy single-instance keys map to the first instance
            auto& inst = instances.front();
            inst.app.listener.address = read_str(uci_lookup_option(ctx, sec, "listen_addr"), inst.app.listener.address);
            inst.app.listener.port = static_cast<uint16_t>(std::stoi(read_str(uci_lookup_option(ctx, sec, "listen_port"), std::to_string(inst.app.listener.port))));
            inst.app.peek_size = clamp_peek(static_cast<std::size_t>(std::stoul(read_str(uci_lookup_option(ctx, sec, "peek_size"), std::to_string(inst.app.peek_size)))));
        } else if (stype == "performance") {
            auto& inst = instances.front();
            inst.app.performance.prefer_zero_copy = read_bool(uci_lookup_option(ctx, sec, "prefer_zero_copy"), inst.app.performance.prefer_zero_copy);
            inst.app.performance.prefer_kernel_dnat = read_bool(uci_lookup_option(ctx, sec, "prefer_kernel_dnat"), inst.app.performance.prefer_kernel_dnat);
        } else if (stype == "metrics") {
            auto& inst = instances.front();
            inst.app.metrics.enable = read_bool(uci_lookup_option(ctx, sec, "enable"), inst.app.metrics.enable);
            inst.app.metrics.port = static_cast<uint16_t>(std::stoi(read_str(uci_lookup_option(ctx, sec, "port"), std::to_string(inst.app.metrics.port))));
        } else if (stype == "fallback") {
            std::string inst_name = read_str(uci_lookup_option(ctx, sec, "instance"), "");
            auto* inst = inst_name.empty() ? &instances.front() : find_instance(inst_name);
            if (!inst) inst = &instances.front();
            inst->app.fallback.host = read_str(uci_lookup_option(ctx, sec, "host"), inst->app.fallback.host);
            inst->app.fallback.port = static_cast<uint16_t>(std::stoi(read_str(uci_lookup_option(ctx, sec, "port"), std::to_string(inst->app.fallback.port))));
            inst->app.fallback.proxy_protocol = read_bool(uci_lookup_option(ctx, sec, "proxy_protocol"), inst->app.fallback.proxy_protocol);
        }
    }

    uci_unload(ctx, pkg);
    uci_free_context(ctx);

    if (instances.empty()) {
        log << "[config] No instance defined in UCI, use defaults.\n";
        instances.push_back(InstanceConfig{"default", true, make_default_config()});
    }

    for (auto& inst : instances) {
        if (inst.app.routes.empty()) {
            log << "[config] No route defined for instance '" << inst.name << "', use defaults.\n";
            inst.app.routes = make_default_config().routes;
        }
    }
    return instances;
}
#endif

AppConfig load_config(const std::string& config_path, std::ostream& log) {
    if (config_path.empty()) {
#ifdef OPENWRT
        return load_configs_from_uci(log).front().app;
#else
        log << "[config] No config path provided. Using defaults.\n";
        return make_default_config();
#endif
    }

    std::ifstream in(config_path);
    if (!in) {
        log << "[config] Cannot open config file at " << config_path << ". Using defaults.\n";
        return make_default_config();
    }

    pt::ptree tree;
    try {
        pt::read_json(in, tree);
    } catch (const std::exception& ex) {
        log << "[config] Failed to parse JSON: " << ex.what() << ". Using defaults.\n";
        return make_default_config();
    }

    AppConfig config = make_default_config();
    config.listener.address = tree.get<std::string>("listen.address", config.listener.address);
    config.listener.port = tree.get<uint16_t>("listen.port", config.listener.port);
    config.peek_size = tree.get<std::size_t>("peek_size", config.peek_size);
    config.peek_size = std::max<std::size_t>(64, std::min<std::size_t>(config.peek_size, 4096));

    config.metrics.enable = tree.get<bool>("metrics.enable", config.metrics.enable);
    config.metrics.port = tree.get<uint16_t>("metrics.port", config.metrics.port);
    config.performance.prefer_zero_copy = tree.get<bool>("performance.prefer_zero_copy", config.performance.prefer_zero_copy);
    config.performance.prefer_kernel_dnat = tree.get<bool>("performance.prefer_kernel_dnat", config.performance.prefer_kernel_dnat);

    if (auto fallback_node = tree.get_child_optional("fallback")) {
        config.fallback = parse_backend(*fallback_node, config.fallback);
    }

    config.routes.clear();
    std::size_t unnamed_index = 0;
    if (auto routes_child = tree.get_child_optional("routes")) {
        for (const auto& entry : *routes_child) {
            const auto& node = entry.second;
            RouteRule rule;
            rule.name = node.get<std::string>("name", "rule-" + std::to_string(++unnamed_index));
            rule.detector = parse_detector(node.get<std::string>("detector", "http_or_tls"));
            rule.prefix = node.get<std::string>("prefix", "");
            if (auto backend_node = node.get_child_optional("backend")) {
                rule.backend = parse_backend(*backend_node, config.fallback);
            }
            if (auto httpf_node = node.get_child_optional("http_forward")) {
                rule.http_forward = parse_http_forward(*httpf_node, rule.http_forward);
            }
            if (rule.backend.port == 0) {
                log << "[config] Skip rule '" << rule.name << "' due to invalid port.\n";
                continue;
            }
            config.routes.push_back(rule);
        }
    }

    if (config.routes.empty()) {
        log << "[config] No valid routes defined. Using default route.\n";
        config.routes = make_default_config().routes;
    }

    return config;
}

std::vector<InstanceConfig> load_all_configs(const std::string& config_path, std::ostream& log) {
#ifdef OPENWRT
    if (config_path.empty()) {
        return load_configs_from_uci(log);
    }
#endif
    // Non-UCI path: reuse JSON loader and wrap as a single instance
    std::vector<InstanceConfig> list;
    InstanceConfig inst;
    inst.name = "default";
    inst.enabled = true;
    inst.app = load_config(config_path, log);
    list.push_back(inst);
    return list;
}

} // namespace port_sharer
