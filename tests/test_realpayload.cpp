#include "router.hpp"
#include "session.hpp"
#include "test_common.hpp"

#include <array>
#include <chrono>
#include <future>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/system_error.hpp>
#include <boost/asio/detail/socket_option.hpp>

using namespace port_sharer;
using boost::asio::ip::tcp;

namespace {

struct Summary {
    bool skipped = false;
    std::string skip_reason;
    double server_read_ms = 0.0;
    double client_rtt_ms = 0.0;
    double throughput_mb_per_sec = 0.0;
    std::size_t payload_bytes = 0;
    uint64_t bytes_upstream = 0;
    uint64_t bytes_downstream = 0;
};

struct ReusePort : public boost::asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT> {
    using boolean::boolean;
};

bool is_permission_error(const boost::system::system_error& ex) {
    return ex.code().value() == EPERM;
}

template <class SockLike>
void enable_reuse(SockLike& sock) {
    boost::system::error_code ec;
    sock.set_option(boost::asio::socket_base::reuse_address(true), ec);
#ifdef SO_REUSEPORT
    sock.set_option(ReusePort(true), ec);
#endif
}

Summary run_realpayload_case() {
    Summary result;

    boost::asio::io_context io;

    tcp::acceptor backend_acceptor(io);
    tcp::acceptor front_acceptor(io);
    try {
        backend_acceptor = tcp::acceptor(io, tcp::endpoint(tcp::v4(), 0));
        enable_reuse(backend_acceptor);
        front_acceptor = tcp::acceptor(io, tcp::endpoint(tcp::v4(), 0));
        enable_reuse(front_acceptor);
    } catch (const boost::system::system_error& ex) {
        if (is_permission_error(ex)) {
            result.skipped = true;
            result.skip_reason = ex.code().message();
            return result;
        }
        throw;
    }

    const auto backend_port = backend_acceptor.local_endpoint().port();
    const auto front_port = front_acceptor.local_endpoint().port();

    RouteRule rule{
        "mock-heavy",
        DetectorKind::Prefix,
        "MOCK",
        {},
        Backend{"127.0.0.1", backend_port, false},
        HttpForward{}
    };
    auto router = std::make_shared<Router>(
        std::vector<RouteRule>{rule},
        Backend{"127.0.0.1", backend_port, false});

    auto metrics = make_metrics();

    std::function<void()> accept_front;
    accept_front = [&]() {
        front_acceptor.async_accept([&](auto ec, auto socket) {
            if (!ec) {
                auto session = std::make_shared<Session>(std::move(socket), router, 1024, metrics, false, false);
                session->start();
            }
            if (ec != boost::asio::error::operation_aborted) {
                accept_front();
            }
        });
    };

    struct PayloadResult {
        std::vector<char> data;
        double server_ms = 0.0;
    };
    std::promise<PayloadResult> payload_promise;
    auto payload_future = payload_promise.get_future();

    const std::size_t payload_size = 512 * 1024; // 512KiB payload to simulate heavy traffic
    std::string payload;
    payload.reserve(payload_size + 4);
    payload.append("MOCK");
    for (std::size_t i = 0; i < payload_size; ++i) {
        payload.push_back(static_cast<char>('A' + (i % 26)));
    }
    const auto expected_size = payload.size();

    auto send_start = std::make_shared<std::chrono::steady_clock::time_point>();

    auto accept_backend = [&]() {
        backend_acceptor.async_accept([&](auto ec, auto socket) {
            if (ec) {
                payload_promise.set_value({});
                return;
            }
            auto buf = std::make_shared<std::vector<char>>(expected_size);
            auto sock_ptr = std::make_shared<tcp::socket>(std::move(socket));
            boost::asio::async_read(
                *sock_ptr,
                boost::asio::buffer(*buf),
                boost::asio::transfer_exactly(expected_size),
                [buf, sock_ptr, send_start, &payload_promise](auto read_ec, auto len) mutable {
                    if (read_ec || len != buf->size()) {
                        payload_promise.set_value({});
                        return;
                    }
                    const double server_ms = std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - *send_start).count();
                    boost::asio::async_write(
                        *sock_ptr,
                        boost::asio::buffer("ACK"),
                        [sock_ptr](auto, auto) mutable {
                            boost::system::error_code ignored;
                            sock_ptr->shutdown(tcp::socket::shutdown_both, ignored);
                            sock_ptr->close(ignored);
                        });
                    payload_promise.set_value({*buf, server_ms});
                });
        });
    };

    accept_front();
    accept_backend();

    std::thread runner([&]() { io.run(); });

    tcp::socket client(io);
    client.connect(tcp::endpoint(tcp::v4(), front_port));
    *send_start = std::chrono::steady_clock::now();
    boost::asio::write(client, boost::asio::buffer(payload));

    std::array<char, 3> ack{};
    boost::system::error_code ack_ec;
    boost::asio::read(client, boost::asio::buffer(ack), ack_ec);
    const double client_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - *send_start).count();

    boost::system::error_code ignored;
    client.shutdown(tcp::socket::shutdown_both, ignored);
    client.close(ignored);

    if (payload_future.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
        io.stop();
        runner.join();
        throw TestFailure("Timeout waiting for backend payload");
    }
    auto backend_result = payload_future.get();

    // Allow the session to drain and close before stopping the io_context so metrics are updated.
    for (int i = 0; i < 80 && metrics->active_sessions.load() != 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    front_acceptor.close(ignored);
    backend_acceptor.close(ignored);
    io.stop();
    runner.join();

    if (result.skipped) return result; // Should not happen here but keep symmetry
    EXPECT_FALSE(backend_result.data.empty());
    EXPECT_EQ(backend_result.data.size(), payload.size());
    EXPECT_TRUE(std::equal(payload.begin(), payload.end(), backend_result.data.begin()));
    EXPECT_TRUE(!ack_ec);

    for (int i = 0; i < 40 && metrics->active_sessions.load() != 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    EXPECT_EQ(metrics->total_connections.load(), 1u);
    EXPECT_EQ(metrics->active_sessions.load(), 0u);
    EXPECT_TRUE(metrics->bytes_upstream.load() >= payload.size());

    result.server_read_ms = backend_result.server_ms;
    result.client_rtt_ms = client_ms;
    const double seconds = client_ms / 1000.0;
    result.throughput_mb_per_sec = (seconds > 0.0)
        ? (static_cast<double>(payload.size()) / (1024.0 * 1024.0)) / seconds
        : 0.0;
    result.payload_bytes = payload.size();
    result.bytes_upstream = metrics->bytes_upstream.load();
    result.bytes_downstream = metrics->bytes_downstream.load();
    return result;
}

} // namespace

int main() {
    return run_tests({
        {"realpayload_test", [] {
            auto summary = run_realpayload_case();
            if (summary.skipped) {
                std::cout << "[SKIP] realpayload_test: " << summary.skip_reason << "\n";
                return;
            }
            std::cout << "[realpayload_test] payload_bytes=" << summary.payload_bytes
                      << " server_read_ms=" << summary.server_read_ms
                      << " client_rtt_ms=" << summary.client_rtt_ms
                      << " throughput_MBps=" << summary.throughput_mb_per_sec
                      << " upstream_bytes=" << summary.bytes_upstream
                      << " downstream_bytes=" << summary.bytes_downstream
                      << "\n";
        }},
    });
}
