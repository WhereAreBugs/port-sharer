#include "metrics.hpp"
#include "test_common.hpp"

#include <array>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/system/system_error.hpp>

using namespace port_sharer;
using boost::asio::ip::tcp;

int main() {
    auto test_metrics_server = [] {
        boost::asio::io_context io;
        auto metrics = make_metrics();
        metrics->total_connections = 5;
        metrics->active_sessions = 2;
        metrics->bytes_upstream = 42;
        metrics->bytes_downstream = 21;

        try {
            MetricsServer server(io, metrics, 0);
            server.start();
            const auto port = server.bound_port();
            EXPECT_NE(port, 0u);

            std::thread runner([&]() { io.run(); });

            tcp::socket sock(io);
            sock.connect(tcp::endpoint(tcp::v4(), port));

            std::string response;
            std::array<char, 512> buf{};
            boost::system::error_code ec;
            do {
                auto n = sock.read_some(boost::asio::buffer(buf), ec);
                if (n > 0) response.append(buf.data(), buf.data() + n);
            } while (!ec);

            io.stop();
            runner.join();

            if (response.find("port_sharer_total_connections 5") == std::string::npos) {
                throw TestFailure("Metrics response missing totals. Response: " + response);
            }
            EXPECT_TRUE(response.find("port_sharer_bytes_upstream 42") != std::string::npos);
        } catch (const boost::system::system_error& ex) {
            if (ex.code().value() == EPERM) {
                std::cerr << "[SKIP] metrics_server: " << ex.code().message() << "\n";
                return;
            }
            throw;
        }
    };

    return run_tests({
        {"metrics_server", test_metrics_server},
    });
}
