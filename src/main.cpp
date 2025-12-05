#include "config.hpp"
#include "metrics.hpp"
#include "router.hpp"
#include "server.hpp"

#include <boost/asio.hpp>

#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace port_sharer;

int main(int argc, char* argv[]) {
    try {
        std::string config_path;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
                config_path = argv[++i];
            } else if (arg == "-h" || arg == "--help") {
                std::cout << "Usage: " << argv[0] << " [-c|--config path]\n";
                return 0;
            }
        }

        auto instances = load_all_configs(config_path, std::cerr);
        if (instances.empty()) {
            std::cerr << "[fatal] no configuration instances available\n";
            return 1;
        }

        boost::asio::io_context io;
        std::vector<std::unique_ptr<Server>> servers;
        std::vector<std::unique_ptr<MetricsServer>> metrics_servers;
        servers.reserve(instances.size());
        metrics_servers.reserve(instances.size());

        for (const auto& inst : instances) {
            if (!inst.enabled) continue;
            auto router = std::make_shared<Router>(inst.app.routes, inst.app.fallback);
            auto srv = std::make_unique<Server>(io, inst.app, router);
            srv->start();
            if (inst.app.metrics.enable && inst.app.metrics.port != 0) {
                auto m = std::make_unique<MetricsServer>(io, srv->metrics(), inst.app.metrics.port);
                m->start();
                metrics_servers.push_back(std::move(m));
            }
            servers.push_back(std::move(srv));
        }

        if (servers.empty()) {
            std::cerr << "[fatal] all instances are disabled or invalid\n";
            return 1;
        }

        const auto workers = std::max(2u, std::thread::hardware_concurrency());
        std::vector<std::thread> threads;
        threads.reserve(workers);
        for (unsigned int i = 0; i < workers; ++i) {
            threads.emplace_back([&io]() { io.run(); });
        }

        for (auto& t : threads) {
            if (t.joinable()) t.join();
        }
    } catch (const std::exception& ex) {
        std::cerr << "[fatal] " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
