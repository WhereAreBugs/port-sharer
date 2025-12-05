#pragma once

#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

namespace port_sharer {

struct Backend {
    std::string host;
    uint16_t port = 0;
    bool proxy_protocol = false;
};

struct HeaderKV {
    std::string name;
    std::string value;
};

struct Listener {
    std::string address = "0.0.0.0";
    uint16_t port = 8888;
};

enum class DetectorKind {
    Http,
    TlsClientHello,
    HttpOrTls,
    Prefix,
    SshBanner,
    Always
};

struct HttpForward {
    bool enable = false;
    bool add_x_real_ip = true;
    bool add_x_forwarded_for = true;
    bool add_x_forwarded_proto = true;
    bool add_x_forwarded_port = true;
    bool add_forwarded = false;
    std::vector<HeaderKV> extra_headers;
};

struct RouteRule {
    std::string name;
    DetectorKind detector = DetectorKind::HttpOrTls;
    std::string prefix; // only used by Prefix detector
    Backend backend;
    HttpForward http_forward;
};

struct AppConfig {
    Listener listener;
    std::vector<RouteRule> routes;
    Backend fallback;
    std::size_t peek_size = 512;
    struct Performance {
#ifdef __linux__
        bool prefer_zero_copy = true;
        bool prefer_kernel_dnat = true;
#else
        bool prefer_zero_copy = false;
        bool prefer_kernel_dnat = false;
#endif
    } performance;
    struct Metrics {
        bool enable = false;
        uint16_t port = 0; // 0 means disabled
    } metrics;
};

struct InstanceConfig {
    std::string name;
    bool enabled = true;
    AppConfig app;
};

// Load configuration from JSON (default) or return defaults when file is missing/invalid.
AppConfig load_config(const std::string& config_path, std::ostream& log);

// Load all instance configs (multi-instance aware). For non-OpenWrt/JSON inputs,
// this returns a single enabled instance.
std::vector<InstanceConfig> load_all_configs(const std::string& config_path, std::ostream& log);

// Provide a built-in default that mirrors the original behavior.
AppConfig make_default_config();

} // namespace port_sharer
