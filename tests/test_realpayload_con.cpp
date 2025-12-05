#include "router.hpp"
#include "session.hpp"
#include "test_common.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <sys/resource.h>
#include <sys/time.h>

#include <boost/asio.hpp>
#include <boost/asio/detail/socket_option.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/system_error.hpp>

using namespace port_sharer;
using boost::asio::ip::tcp;

namespace {

struct ReusePort : public boost::asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT> {
    using boolean::boolean;
};

template <class SockLike>
void enable_reuse(SockLike& sock) {
    boost::system::error_code ec;
    sock.set_option(boost::asio::socket_base::reuse_address(true), ec);
#ifdef SO_REUSEPORT
    sock.set_option(ReusePort(true), ec);
#endif
}

bool is_permission_error(const boost::system::system_error& ex) {
    return ex.code().value() == EPERM;
}

struct ClientStat {
    double rtt_ms = 0.0;
    double throughput_mb_s = 0.0;
    bool ok = false;
    std::string error;
};

struct Summary {
    bool skipped = false;
    std::string skip_reason;
    std::vector<ClientStat> clients;
    uint64_t payload_bytes_per_client = 0;
    uint64_t total_payload_bytes = 0;
    uint64_t server_ok = 0;
    uint64_t server_fail = 0;
    uint64_t server_bytes = 0;
    double server_avg_ms = 0.0;
    double server_max_ms = 0.0;
    uint64_t metrics_total_connections = 0;
    uint64_t metrics_active_sessions = 0;
    uint64_t metrics_bytes_up = 0;
    uint64_t metrics_bytes_down = 0;
    uint64_t peak_rss_bytes = 0;
};

uint64_t read_peak_rss_bytes() {
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) != 0) return 0;
#if defined(__APPLE__)
    return static_cast<uint64_t>(usage.ru_maxrss);
#else
    // ru_maxrss is kilobytes on Linux.
    return static_cast<uint64_t>(usage.ru_maxrss) * 1024ULL;
#endif
}

Summary run_concurrent_payload(std::size_t threads) {
    Summary summary;
    summary.clients.resize(threads);

    boost::asio::io_context io;

    tcp::acceptor backend_acceptor(io);
    tcp::acceptor front_acceptor(io);
    try {
        backend_acceptor = tcp::acceptor(io, tcp::endpoint(tcp::v4(), 0));
        enable_reuse(backend_acceptor);
        front_acceptor = tcp::acceptor(io, tcp::endpoint(tcp::v4(), 0));
        enable_reuse(front_acceptor);
        backend_acceptor.listen(1024);
        front_acceptor.listen(1024);
    } catch (const boost::system::system_error& ex) {
        if (is_permission_error(ex)) {
            summary.skipped = true;
            summary.skip_reason = ex.code().message();
            return summary;
        }
        throw;
    }

    const auto backend_port = backend_acceptor.local_endpoint().port();
    const auto front_port = front_acceptor.local_endpoint().port();

    RouteRule rule{
        "mock-heavy-concurrent",
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

    const std::size_t payload_size = 4 * 1024 * 1024; // 4 MiB per client
    summary.payload_bytes_per_client = payload_size;
    summary.total_payload_bytes = static_cast<uint64_t>(payload_size) * static_cast<uint64_t>(threads);
    std::string payload;
    payload.reserve(payload_size + 4);
    payload.append("MOCK");
    for (std::size_t i = 0; i < payload_size; ++i) {
        payload.push_back(static_cast<char>('A' + (i % 26)));
    }

    std::atomic<uint64_t> server_ok{0};
    std::atomic<uint64_t> server_fail{0};
    std::atomic<uint64_t> server_bytes{0};
    std::atomic<uint64_t> server_total_us{0};
    std::atomic<uint64_t> server_max_us{0};

    std::function<void()> accept_front;
    accept_front = [&]() {
        front_acceptor.async_accept([&](auto ec, auto socket) {
            if (ec == boost::asio::error::operation_aborted) return;
            if (!ec) {
                auto session = std::make_shared<Session>(std::move(socket), router, 1024, metrics, false, false);
                session->start();
            }
            accept_front();
        });
    };

    std::function<void()> accept_backend;
    accept_backend = [&]() {
        backend_acceptor.async_accept([&](auto ec, auto socket) {
            if (ec == boost::asio::error::operation_aborted) return;
            if (!ec) {
                auto sock = std::make_shared<tcp::socket>(std::move(socket));
                auto buf = std::make_shared<std::vector<char>>(payload.size());
                auto start = std::make_shared<std::chrono::steady_clock::time_point>(std::chrono::steady_clock::now());
                boost::asio::async_read(
                    *sock,
                    boost::asio::buffer(*buf),
                    boost::asio::transfer_exactly(payload.size()),
                    [sock, buf, start, &payload, &server_ok, &server_fail, &server_bytes, &server_total_us, &server_max_us](auto read_ec, auto len) mutable {
                        if (!read_ec && len == buf->size() && std::equal(payload.begin(), payload.end(), buf->begin())) {
                            server_ok.fetch_add(1, std::memory_order_relaxed);
                            server_bytes.fetch_add(len, std::memory_order_relaxed);
                            const auto us = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::steady_clock::now() - *start).count());
                            server_total_us.fetch_add(us, std::memory_order_relaxed);
                            uint64_t cur = server_max_us.load(std::memory_order_relaxed);
                            while (us > cur && !server_max_us.compare_exchange_weak(cur, us, std::memory_order_relaxed)) {
                            }
                            boost::asio::async_write(*sock, boost::asio::buffer("ACK"), [sock](auto, auto) mutable {
                                boost::system::error_code ignored;
                                sock->shutdown(tcp::socket::shutdown_both, ignored);
                                sock->close(ignored);
                            });
                        } else {
                            server_fail.fetch_add(1, std::memory_order_relaxed);
                        }
                    });
            }
            accept_backend();
        });
    };

    accept_front();
    accept_backend();

    std::thread io_runner([&]() { io.run(); });

    std::vector<std::thread> clients;
    clients.reserve(threads);
    for (std::size_t i = 0; i < threads; ++i) {
        clients.emplace_back([&, idx = i]() {
            ClientStat stat;
            for (int attempt = 0; attempt < 3; ++attempt) {
                boost::asio::io_context cli_io;
                tcp::socket sock(cli_io);
                boost::system::error_code ec;
                sock.open(tcp::v4(), ec);
                if (ec) { stat.error = ec.message(); continue; }
                enable_reuse(sock);
                sock.connect(tcp::endpoint(tcp::v4(), front_port), ec);
                if (ec) { stat.error = ec.message(); continue; }
                const auto start = std::chrono::steady_clock::now();
                boost::asio::write(sock, boost::asio::buffer(payload), ec);
                if (ec) { stat.error = ec.message(); continue; }
                std::array<char, 3> ack{};
                boost::asio::read(sock, boost::asio::buffer(ack), ec);
                const auto end = std::chrono::steady_clock::now();
                if (ec) { stat.error = ec.message(); continue; }
                const double ms = std::chrono::duration<double, std::milli>(end - start).count();
                stat.rtt_ms = ms;
                const double seconds = ms / 1000.0;
                stat.throughput_mb_s = (seconds > 0.0)
                    ? (static_cast<double>(payload.size()) / (1024.0 * 1024.0)) / seconds
                    : 0.0;
                stat.ok = true;
                summary.clients[idx] = stat;
                sock.shutdown(tcp::socket::shutdown_both, ec);
                sock.close(ec);
                break;
            }
            if (!stat.ok) {
                summary.clients[idx] = stat;
            }
        });
    }

    for (auto& t : clients) {
        if (t.joinable()) t.join();
    }

    boost::system::error_code ignored;
    front_acceptor.close(ignored);
    backend_acceptor.close(ignored);
    io.stop();
    io_runner.join();

    for (int i = 0; i < 160 && metrics->active_sessions.load() != 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    const auto successes = std::count_if(summary.clients.begin(), summary.clients.end(), [](const ClientStat& s) { return s.ok; });
    EXPECT_EQ(successes, threads);
    EXPECT_EQ(server_ok.load(), threads);
    EXPECT_EQ(server_fail.load(), 0u);
    EXPECT_TRUE(metrics->active_sessions.load() == 0u);
    EXPECT_EQ(metrics->total_connections.load(), threads);
    EXPECT_TRUE(metrics->bytes_upstream.load() >= payload.size());

    summary.server_ok = server_ok.load();
    summary.server_fail = server_fail.load();
    summary.server_bytes = server_bytes.load();
    if (server_ok.load() > 0) {
        const double avg_us = static_cast<double>(server_total_us.load()) / static_cast<double>(server_ok.load());
        summary.server_avg_ms = avg_us / 1000.0;
        summary.server_max_ms = static_cast<double>(server_max_us.load()) / 1000.0;
    }
    summary.metrics_total_connections = metrics->total_connections.load();
    summary.metrics_active_sessions = metrics->active_sessions.load();
    summary.metrics_bytes_up = metrics->bytes_upstream.load();
    summary.metrics_bytes_down = metrics->bytes_downstream.load();
    summary.peak_rss_bytes = read_peak_rss_bytes();
    return summary;
}

} // namespace

int main() {
    constexpr std::size_t kThreads = 256;
    return run_tests({
        {"realpayload_concurrent", [] {
            auto summary = run_concurrent_payload(kThreads);
            if (summary.skipped) {
                std::cout << "[SKIP] realpayload_concurrent: " << summary.skip_reason << "\n";
                return;
            }
            double total_rtt = 0.0;
            double max_rtt = 0.0;
            double min_rtt = std::numeric_limits<double>::max();
            double total_tp = 0.0;
            for (const auto& s : summary.clients) {
                total_rtt += s.rtt_ms;
                total_tp += s.throughput_mb_s;
                if (s.rtt_ms > max_rtt) max_rtt = s.rtt_ms;
                if (s.rtt_ms < min_rtt) min_rtt = s.rtt_ms;
            }
            const double avg_rtt = total_rtt / summary.clients.size();
            const double avg_tp = total_tp / summary.clients.size();
            const double payload_mib = static_cast<double>(summary.payload_bytes_per_client) / (1024.0 * 1024.0);
            const double total_payload_mib = static_cast<double>(summary.total_payload_bytes) / (1024.0 * 1024.0);
            const double server_bytes_mib = static_cast<double>(summary.server_bytes) / (1024.0 * 1024.0);
            const double metrics_up_mib = static_cast<double>(summary.metrics_bytes_up) / (1024.0 * 1024.0);
            const double metrics_down_mib = static_cast<double>(summary.metrics_bytes_down) / (1024.0 * 1024.0);
            const double peak_rss_mb = static_cast<double>(summary.peak_rss_bytes) / (1024.0 * 1024.0);

            std::cout << "[realpayload_concurrent]\n"
                      << "  threads: " << summary.clients.size() << "\n"
                      << "  payload per client: " << payload_mib << " MiB\n"
                      << "  total payload: " << total_payload_mib << " MiB\n"
                      << "  client RTT: avg " << avg_rtt << " ms, min " << min_rtt << " ms, max " << max_rtt << " ms\n"
                      << "  client throughput: avg " << avg_tp << " MB/s\n"
                      << "  server latency: avg " << summary.server_avg_ms << " ms, max " << summary.server_max_ms << " ms\n"
                      << "  server results: ok " << summary.server_ok << ", fail " << summary.server_fail << ", bytes " << server_bytes_mib << " MiB\n"
                      << "  metrics: total_conn " << summary.metrics_total_connections
                      << ", bytes_up " << metrics_up_mib << " MiB, bytes_down " << metrics_down_mib << " MiB\n"
                      << "  peak RSS: " << peak_rss_mb << " MiB\n";
        }},
    });
}
