#pragma once

#include "router.hpp"
#include "session.hpp"
#include "test_common.hpp"

#include <atomic>
#include <array>
#include <chrono>
#include <functional>
#include <future>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>
#include <boost/system/system_error.hpp>
#include <boost/asio/detail/socket_option.hpp>

namespace stress_shared {

using namespace port_sharer;
using boost::asio::ip::tcp;

inline constexpr std::array<unsigned char, 12> kProxySig = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
};

struct ReusePort : public boost::asio::detail::socket_option::boolean<SOL_SOCKET, SO_REUSEPORT> {
    using boolean::boolean;
};

template <class SockLike>
inline void enable_reuse(SockLike& s) {
    boost::system::error_code ec;
    s.set_option(boost::asio::socket_base::reuse_address(true), ec);
#ifdef SO_REUSEPORT
    s.set_option(ReusePort(true), ec);
#endif
}

enum class ProxyMode { Mixed, AllOn, AllOff };

struct StressConfig {
    std::size_t concurrency;
    const char* name;
    ProxyMode proxy_mode = ProxyMode::Mixed;
};

inline bool is_permission_error(const boost::system::system_error& ex) {
    return ex.code().value() == EPERM;
}

inline void stress_run(const StressConfig& cfg) {
    boost::asio::io_context io;

    struct BackendContext {
        std::string name;
        tcp::acceptor acceptor;
        std::atomic<std::size_t> hits{0};
        std::function<void()> accept_loop;
        bool expect_proxy_header{true};

        BackendContext(boost::asio::io_context& io, std::string n)
            : name(std::move(n)), acceptor(io) {
            acceptor.open(tcp::v4());
            enable_reuse(acceptor);
            acceptor.bind(tcp::endpoint(tcp::v4(), 0));
            acceptor.listen();
            std::cout << "[stress] backend " << name << " on "
                      << acceptor.local_endpoint().address().to_string() << ":"
                      << acceptor.local_endpoint().port() << "\n";
        }

        BackendContext(const BackendContext&) = delete;
        BackendContext& operator=(const BackendContext&) = delete;
    };

    std::vector<std::shared_ptr<BackendContext>> backends;

    auto add_backend = [&](const std::string& name) {
        backends.push_back(std::make_shared<BackendContext>(io, name));
    };

    add_backend("http");
    add_backend("tls");
    add_backend("http_or_tls");
    add_backend("prefix");
    add_backend("ssh");
    add_backend("always");

    tcp::acceptor front_acceptor(io);
    try {
        front_acceptor = tcp::acceptor(io, tcp::endpoint(tcp::v4(), 0));
        enable_reuse(front_acceptor);
    } catch (const boost::system::system_error& ex) {
        if (is_permission_error(ex)) {
            std::cerr << "[SKIP] stress_" << cfg.name << ": " << ex.code().message() << "\n";
            return;
        }
        throw;
    }
    const auto front_port = front_acceptor.local_endpoint().port();

    auto find_backend = [&](const std::string& name) -> BackendContext& {
        for (auto& b : backends) {
            if (b->name == name) return *b;
        }
        return *backends.front();
    };

    auto select_proxy = [&](bool def) {
        switch (cfg.proxy_mode) {
            case ProxyMode::AllOn: return true;
            case ProxyMode::AllOff: return false;
            default: return def;
        }
    };

    std::vector<RouteRule> rules = {
        {"http", DetectorKind::Http, "", {}, Backend{"127.0.0.1", find_backend("http").acceptor.local_endpoint().port(), select_proxy(true)}, HttpForward{true, true, true, true, true, true, {}}},
        {"tls", DetectorKind::TlsClientHello, "", {}, Backend{"127.0.0.1", find_backend("tls").acceptor.local_endpoint().port(), select_proxy(true)}, HttpForward{}},
        {"http_or_tls", DetectorKind::HttpOrTls, "", {}, Backend{"127.0.0.1", find_backend("http_or_tls").acceptor.local_endpoint().port(), select_proxy(false)}, HttpForward{}},
        {"prefix", DetectorKind::Prefix, "HELLO", {}, Backend{"127.0.0.1", find_backend("prefix").acceptor.local_endpoint().port(), select_proxy(true)}, HttpForward{}},
        {"ssh", DetectorKind::SshBanner, "", {}, Backend{"127.0.0.1", find_backend("ssh").acceptor.local_endpoint().port(), select_proxy(true)}, HttpForward{}},
    };
    find_backend("http").expect_proxy_header = rules[0].backend.proxy_protocol;
    find_backend("tls").expect_proxy_header = rules[1].backend.proxy_protocol;
    find_backend("http_or_tls").expect_proxy_header = rules[2].backend.proxy_protocol;
    find_backend("prefix").expect_proxy_header = rules[3].backend.proxy_protocol;
    find_backend("ssh").expect_proxy_header = rules[4].backend.proxy_protocol;
    const bool fallback_proxy = select_proxy(true);
    auto router = std::make_shared<Router>(
        rules,
        Backend{"127.0.0.1", find_backend("always").acceptor.local_endpoint().port(), fallback_proxy});
    find_backend("always").expect_proxy_header = fallback_proxy;
    std::cout << "[stress] router ready, front port " << front_port << "\n";

    auto metrics = make_metrics();

    std::atomic<std::size_t> received{0};
    std::promise<void> done_promise;
    auto done_future = done_promise.get_future();
    std::atomic<bool> done_set{false};

    std::function<void()> accept_front;
    accept_front = [&]() {
        front_acceptor.async_accept([&](auto ec, auto socket) {
            if (!ec) {
                auto session = std::make_shared<Session>(std::move(socket), router, 512, metrics, false, false);
                session->start();
            } else if (ec != boost::asio::error::operation_aborted) {
                std::cerr << "[stress] front accept error: " << ec.message() << "\n";
            }
            accept_front();
        });
    };

    auto make_accept_loop = [&](BackendContext& ctx) {
        ctx.accept_loop = [&]() {
            ctx.acceptor.async_accept([&](auto ec, auto socket) {
                if (!ec) {
                    auto buf = std::make_shared<std::vector<char>>(4096);
                    socket.async_read_some(
                        boost::asio::buffer(*buf),
                        [buf,
                         sock = std::move(socket),
                         &ctx,
                         &received,
                         &done_promise,
                         &done_set,
                         &cfg](auto read_ec, auto len) mutable {
                            if (!read_ec && len > 0) {
                                const bool has_proxy = len >= kProxySig.size() &&
                                                       std::equal(kProxySig.begin(), kProxySig.end(), buf->begin());
                                if (has_proxy != ctx.expect_proxy_header) {
                                    std::stringstream ss;
                                    ss << "proxy header mismatch on backend " << ctx.name
                                       << " expected=" << ctx.expect_proxy_header << " got=" << has_proxy;
                                    if (!done_set.exchange(true)) {
                                        done_promise.set_exception(std::make_exception_ptr(TestFailure(ss.str())));
                                    }
                                    return;
                                }
                                ctx.hits.fetch_add(1, std::memory_order_relaxed);
                                auto count = ++received;
                                boost::asio::async_write(sock, boost::asio::buffer("OK"), [](auto, auto) {});
                                if (count >= cfg.concurrency && !done_set.exchange(true)) {
                                    done_promise.set_value();
                                }
                            } else {
                                if (read_ec) {
                                    std::cerr << "[stress] backend read error on " << ctx.name << ": " << read_ec.message() << "\n";
                                }
                                if (!done_set.exchange(true)) {
                                    done_promise.set_value();
                                }
                            }
                        });
                } else if (ec == boost::asio::error::operation_aborted) {
                    return; // shutting down
                } else {
                    std::cerr << "[stress] backend accept error on " << ctx.name << ": " << ec.message() << "\n";
                    if (!done_set.exchange(true)) {
                        done_promise.set_value();
                    }
                }
                ctx.accept_loop();
            });
        };
        ctx.accept_loop();
    };

    accept_front();
    for (auto& b : backends) {
        make_accept_loop(*b);
    }

    std::thread runner([&]() { io.run(); });

    struct Case {
        DetectorKind kind;
        std::string payload;
        const char* backend_name;
    };
    std::vector<Case> cases = {
        {DetectorKind::Http, "GET /path HTTP/1.1\r\nHost: example\r\n\r\n", "http"},
        {DetectorKind::TlsClientHello, std::string("\x16\x03\x01", 3) + "XYZ", "tls"},
        {DetectorKind::HttpOrTls, "POST /x HTTP/1.1\r\nHost: h\r\n\r\n", "http_or_tls"},
        {DetectorKind::Prefix, "HELLO WORLD", "prefix"},
        {DetectorKind::SshBanner, "SSH-2.0-OpenSSH", "ssh"},
        {DetectorKind::Always, "RANDOM", "always"},
    };
    std::vector<std::thread> clients;
    clients.reserve(cfg.concurrency);
    for (std::size_t i = 0; i < cfg.concurrency; ++i) {
        clients.emplace_back([front_port, i, &cases]() {
            boost::asio::io_context cli_io;
            tcp::socket sock(cli_io);
            boost::system::error_code ec;
            sock.open(tcp::v4(), ec);
            if (ec) return;
            enable_reuse(sock);
            sock.connect(tcp::endpoint(tcp::v4(), front_port), ec);
            if (ec) return;
            std::mt19937 rng(static_cast<unsigned int>(12345 + i));
            std::uniform_int_distribution<std::size_t> pick(0, cases.size() - 1);
            auto idx = pick(rng);
            const auto& c = cases[idx];
            std::string req = c.payload;
            if (c.kind == DetectorKind::Http || c.kind == DetectorKind::HttpOrTls) {
                req += "X-ID: " + std::to_string(i) + "\r\n\r\n";
            }
            sock.write_some(boost::asio::buffer(req));
            std::array<char, 8> resp{};
            sock.read_some(boost::asio::buffer(resp), ec); // ignore content
            sock.shutdown(tcp::socket::shutdown_both, ec);
            sock.close(ec);
        });
    }

    done_future.get();

    for (auto& t : clients) {
        if (t.joinable()) t.join();
    }

    io.stop();
    runner.join();

    if (received.load() > 0) {
        EXPECT_EQ(received.load(), cfg.concurrency);
        EXPECT_EQ(metrics->total_connections.load(), cfg.concurrency);
        EXPECT_EQ(metrics->active_sessions.load(), 0u);
        for (const auto& c : cases) {
            if (cfg.concurrency >= cases.size()) {
                auto hits = find_backend(c.backend_name).hits.load();
                if (!(hits > 0)) {
                    std::cerr << "[stress] backend " << c.backend_name << " had zero hits\n";
                    EXPECT_TRUE(false);
                }
            }
        }
    }
}

inline void stress_run_extreme() {
    // 5 minutes of sustained mixed traffic with proxy headers on, 10 client threads.
    boost::asio::io_context io;

    struct BackendContext {
        std::string name;
        tcp::acceptor acceptor;
        bool expect_proxy_header{true};
        std::function<void()> accept_loop;

        BackendContext(boost::asio::io_context& io, std::string n)
            : name(std::move(n)), acceptor(io) {
            acceptor.open(tcp::v4());
            acceptor.set_option(tcp::acceptor::reuse_address(true));
            acceptor.bind(tcp::endpoint(tcp::v4(), 0));
            acceptor.listen();
            std::cout << "[extreme] backend " << name << " on "
                      << acceptor.local_endpoint().address().to_string() << ":"
                      << acceptor.local_endpoint().port() << "\n";
        }

        BackendContext(const BackendContext&) = delete;
        BackendContext& operator=(const BackendContext&) = delete;
    };

    std::vector<std::shared_ptr<BackendContext>> backends;
    auto add_backend = [&](const std::string& name) {
        backends.push_back(std::make_shared<BackendContext>(io, name));
    };
    add_backend("http");
    add_backend("tls");
    add_backend("http_or_tls");
    add_backend("prefix");
    add_backend("ssh");
    add_backend("always");

    tcp::acceptor front_acceptor(io);
    try {
        front_acceptor = tcp::acceptor(io, tcp::endpoint(tcp::v4(), 0));
        enable_reuse(front_acceptor);
    } catch (const boost::system::system_error& ex) {
        if (is_permission_error(ex)) {
            std::cerr << "[SKIP] stress_extreme: " << ex.code().message() << "\n";
            return;
        }
        throw;
    }
    const auto front_port = front_acceptor.local_endpoint().port();

    auto find_backend = [&](const std::string& name) -> BackendContext& {
        for (auto& b : backends) {
            if (b->name == name) return *b;
        }
        return *backends.front();
    };

    std::vector<RouteRule> rules = {
        {"http", DetectorKind::Http, "", {}, Backend{"127.0.0.1", find_backend("http").acceptor.local_endpoint().port(), true}, HttpForward{true, true, true, true, true, true, {}}},
        {"tls", DetectorKind::TlsClientHello, "", {}, Backend{"127.0.0.1", find_backend("tls").acceptor.local_endpoint().port(), true}, HttpForward{}},
        {"http_or_tls", DetectorKind::HttpOrTls, "", {}, Backend{"127.0.0.1", find_backend("http_or_tls").acceptor.local_endpoint().port(), false}, HttpForward{}},
        {"prefix", DetectorKind::Prefix, "HELLO", {}, Backend{"127.0.0.1", find_backend("prefix").acceptor.local_endpoint().port(), true}, HttpForward{}},
        {"ssh", DetectorKind::SshBanner, "", {}, Backend{"127.0.0.1", find_backend("ssh").acceptor.local_endpoint().port(), true}, HttpForward{}},
    };
    find_backend("http").expect_proxy_header = true;
    find_backend("tls").expect_proxy_header = true;
    find_backend("http_or_tls").expect_proxy_header = false;
    find_backend("prefix").expect_proxy_header = true;
    find_backend("ssh").expect_proxy_header = true;
    auto router = std::make_shared<Router>(
        rules,
        Backend{"127.0.0.1", find_backend("always").acceptor.local_endpoint().port(), true});
    find_backend("always").expect_proxy_header = true;
    std::cout << "[extreme] router ready, front port " << front_port << "\n";

    auto metrics = make_metrics();
    std::atomic<bool> stop{false};
    std::atomic<int> connect_errors{0};

    std::function<void()> accept_front;
    accept_front = [&]() {
        front_acceptor.async_accept([&](auto ec, auto socket) {
            if (stop) return;
            if (!ec) {
                auto session = std::make_shared<Session>(std::move(socket), router, 512, metrics, false, false);
                session->start();
            }
            accept_front();
        });
    };

    auto make_accept_loop = [&](BackendContext& ctx) {
        ctx.accept_loop = [&]() {
            ctx.acceptor.async_accept([&](auto ec, auto socket) {
                if (stop || ec == boost::asio::error::operation_aborted) return;
                if (!ec) {
                    auto buf = std::make_shared<std::vector<char>>(4096);
                    socket.async_read_some(
                        boost::asio::buffer(*buf),
                        [buf,
                         sock = std::move(socket),
                         &ctx](auto read_ec, auto len) mutable {
                            if (!read_ec && len > 0) {
                                const bool has_proxy = len >= kProxySig.size() &&
                                                       std::equal(kProxySig.begin(), kProxySig.end(), buf->begin());
                                if (has_proxy != ctx.expect_proxy_header) {
                                    std::cerr << "[extreme] proxy header mismatch on backend " << ctx.name
                                              << " expected=" << ctx.expect_proxy_header << " got=" << has_proxy << "\n";
                                    return;
                                }
                            }
                            boost::asio::async_write(sock, boost::asio::buffer("OK"), [](auto, auto) {});
                        });
                }
                if (!stop) ctx.accept_loop();
            });
        };
        ctx.accept_loop();
    };

    accept_front();
    for (auto& b : backends) {
        make_accept_loop(*b);
    }

    std::thread runner([&]() { io.run(); });

    struct Case {
        DetectorKind kind;
        std::string payload;
        const char* backend;
        bool partial_send = false;
    };
    std::vector<Case> cases = {
        {DetectorKind::Http, "GET /ok HTTP/1.1\r\nHost: example\r\n\r\n", "http"},
        {DetectorKind::Http, "GET /weird HTTP/1.1\r\nHost:\r\nX-Long: " + std::string(1024, 'a') + "\r\n", "http", true},
        {DetectorKind::HttpOrTls, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "http_or_tls"},
        {DetectorKind::TlsClientHello, std::string("\x16\x03\x01", 3) + "HELLO", "tls"},
        {DetectorKind::TlsClientHello, std::string("\x16\x03", 2), "tls", true}, // truncated TLS
        {DetectorKind::Prefix, "HELLO THERE", "prefix"},
        {DetectorKind::Prefix, std::string("HEL") + std::string("\x00\x01", 2), "prefix", true},
        {DetectorKind::SshBanner, "SSH-2.0-sshscan\r\n", "ssh"},
        {DetectorKind::SshBanner, "SSH-1.99-OpenSSH_7.4\r\nUSER root\r\n", "ssh"},
        {DetectorKind::Always, std::string("\x00\xFF\xAA\xBBJUNK", 9), "always"},
    };

    const auto start = std::chrono::steady_clock::now();
    std::chrono::minutes duration{5};
    if (const char* env = std::getenv("STRESS_EXTREME_MINUTES")) {
        try {
            int mins = std::stoi(env);
            if (mins > 0) duration = std::chrono::minutes(mins);
        } catch (...) {
        }
    }
    const auto deadline = start + duration;
    const std::size_t client_threads = 10;
    std::vector<std::thread> clients;
    clients.reserve(client_threads);
    for (std::size_t i = 0; i < client_threads; ++i) {
        clients.emplace_back([&, i]() {
            std::mt19937 rng(static_cast<unsigned int>(1234 + i));
            std::uniform_int_distribution<std::size_t> pick(0, cases.size() - 1);
            std::uniform_int_distribution<int> pause_ms(10, 25);
            while (!stop && std::chrono::steady_clock::now() < deadline) {
                const auto& c = cases[pick(rng)];
                boost::asio::io_context cli_io;
                tcp::socket sock(cli_io);
                boost::system::error_code ec;
                sock.open(tcp::v4(), ec);
                if (ec) { ++connect_errors; continue; }
                enable_reuse(sock);
                sock.connect(tcp::endpoint(tcp::v4(), front_port), ec);
                if (ec) { ++connect_errors; continue; }
                auto send_payload = c.payload;
                sock.write_some(boost::asio::buffer(send_payload.substr(0, c.partial_send ? send_payload.size() / 2 : send_payload.size())), ec);
                if (ec) {
                    sock.close();
                    ++connect_errors;
                    continue;
                }
                if (!c.partial_send) {
                    std::array<char, 8> resp{};
                    sock.read_some(boost::asio::buffer(resp), ec);
                }
                sock.shutdown(tcp::socket::shutdown_both, ec);
                sock.close(ec);
            }
        });
    }

    while (std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    stop = true;
    boost::system::error_code ignored;
    front_acceptor.close(ignored);
    for (auto& b : backends) {
        b->acceptor.close(ignored);
    }

    for (auto& t : clients) {
        if (t.joinable()) t.join();
    }

    io.stop();
    runner.join();

    for (int i = 0; i < 40 && metrics->active_sessions.load() != 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    EXPECT_EQ(metrics->active_sessions.load(), 0u);
    if (connect_errors.load() > 0) {
        throw TestFailure("stress_extreme encountered connect failures: " + std::to_string(connect_errors.load()));
    }
}

} // namespace stress_shared
