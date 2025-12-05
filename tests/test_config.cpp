#include "config.hpp"
#include "test_common.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

using namespace port_sharer;

int main() {
    auto test_default_config = [] {
        auto cfg = make_default_config();
        EXPECT_EQ(cfg.listener.address, "0.0.0.0");
        EXPECT_EQ(cfg.listener.port, 8888);
        EXPECT_EQ(cfg.routes.size(), 2u);
        EXPECT_EQ(cfg.fallback.host, "127.0.0.1");
        EXPECT_EQ(cfg.peek_size, 512u);
        EXPECT_TRUE(cfg.routes[0].http_forward.enable);
    };

    auto test_load_config_missing = [] {
        std::stringstream log;
        auto cfg = load_config("this_file_does_not_exist.json", log);
        EXPECT_TRUE(log.str().find("Cannot open config") != std::string::npos);
        auto def = make_default_config();
        EXPECT_EQ(cfg.listener.port, def.listener.port);
        EXPECT_EQ(cfg.routes.size(), def.routes.size());
    };

    auto test_load_config_json = [] {
        namespace fs = std::filesystem;
        fs::path tmp = fs::temp_directory_path() / "port_sharer_config_test.json";
        std::ofstream out(tmp);
        out << R"({
            "listen": {"address": "127.0.0.1", "port": 9090},
            "peek_size": 32,
            "metrics": {"enable": true, "port": 10001},
            "performance": {"prefer_zero_copy": false, "prefer_kernel_dnat": false},
            "fallback": {"host": "10.0.0.1", "port": 8080, "proxy_protocol": true},
            "routes": [
                {"name": "skip-me", "backend": {"host": "1.2.3.4", "port": 0}},
                {"name": "pref", "detector": "prefix", "prefix": "SSH",
                 "backend": {"host": "2.2.2.2", "port": 2222, "proxy_protocol": true},
                 "http_forward": {"enable": true, "x_real_ip": false, "forwarded": true,
                                  "headers": [{"name": "Extra", "value": "A"}]}
                }
            ]
        })";
        out.close();

        std::stringstream log;
        auto cfg = load_config(tmp.string(), log);
        EXPECT_EQ(cfg.listener.address, "127.0.0.1");
        EXPECT_EQ(cfg.listener.port, 9090);
        EXPECT_EQ(cfg.peek_size, 64u); // clamped minimum
        EXPECT_TRUE(cfg.metrics.enable);
        EXPECT_EQ(cfg.metrics.port, 10001);
        EXPECT_FALSE(cfg.performance.prefer_zero_copy);
        EXPECT_FALSE(cfg.performance.prefer_kernel_dnat);
        EXPECT_EQ(cfg.fallback.host, "10.0.0.1");
        EXPECT_EQ(cfg.fallback.port, 8080);
        EXPECT_TRUE(cfg.fallback.proxy_protocol);
        EXPECT_EQ(cfg.routes.size(), 1u); // skipped invalid port
        EXPECT_EQ(cfg.routes[0].name, "pref");
        EXPECT_EQ(cfg.routes[0].detector, DetectorKind::Prefix);
        EXPECT_EQ(cfg.routes[0].prefix, "SSH");
        EXPECT_TRUE(cfg.routes[0].http_forward.enable);
        EXPECT_FALSE(cfg.routes[0].http_forward.add_x_real_ip);
        EXPECT_TRUE(cfg.routes[0].http_forward.add_forwarded);
        EXPECT_EQ(cfg.routes[0].http_forward.extra_headers.size(), 1u);
    };

    return run_tests({
        {"default_config", test_default_config},
        {"load_config_missing", test_load_config_missing},
        {"load_config_json", test_load_config_json},
    });
}
