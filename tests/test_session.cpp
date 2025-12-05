#include "config.hpp"
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
#include <boost/system/system_error.hpp>

using namespace port_sharer;
using boost::asio::ip::tcp;

namespace {

struct SessionCase {
    DetectorKind detector;
    std::string peek_data;
    bool enable_http_forward = false;
    bool expect_forward_headers = false;
    bool proxy_protocol = true;
    bool expect_proxy_header = true;
    std::string name;
};

std::vector<char> run_session_case(const SessionCase& c) {
    boost::asio::io_context io;

    tcp::acceptor backend_acceptor(io);
    tcp::acceptor front_acceptor(io);
    try {
        backend_acceptor = tcp::acceptor(io, tcp::endpoint(tcp::v4(), 0));
        front_acceptor = tcp::acceptor(io, tcp::endpoint(tcp::v4(), 0));
    } catch (const boost::system::system_error& ex) {
        if (ex.code().value() == EPERM) {
            std::cerr << "[SKIP] session_" << c.name << ": " << ex.code().message() << "\n";
            return {};
        }
        throw;
    }
    const auto backend_port = backend_acceptor.local_endpoint().port();
    const auto front_port = front_acceptor.local_endpoint().port();

    RouteRule rule{
        c.name,
        c.detector,
        c.detector == DetectorKind::Prefix ? std::string("HELLO") : std::string{},
        Backend{"127.0.0.1", backend_port, c.proxy_protocol},
        HttpForward{c.enable_http_forward, true, true, true, true, true, {HeaderKV{"X-Test", "1"}}}
    };
    auto router = std::make_shared<Router>(
        std::vector<RouteRule>{rule},
        Backend{"127.0.0.1", backend_port, false});

    auto metrics = make_metrics();

    tcp::socket client(io);
    client.connect(tcp::endpoint(tcp::v4(), front_port));

    tcp::socket incoming(io);
    front_acceptor.accept(incoming);

    auto session = std::make_shared<Session>(std::move(incoming), router, 512, metrics, false, false);
    session->start();

    auto backend_socket = std::make_shared<tcp::socket>(io);
    std::promise<std::vector<char>> backend_data_promise;
    backend_acceptor.async_accept(*backend_socket, [backend_socket, &backend_data_promise](const boost::system::error_code& ec) {
        if (ec) {
            backend_data_promise.set_value({});
            return;
        }
        auto buf = std::make_shared<std::vector<char>>(4096);
        backend_socket->async_read_some(boost::asio::buffer(*buf), [buf, backend_socket, &backend_data_promise](auto read_ec, auto len) {
            if (!read_ec) {
                buf->resize(len);
                backend_data_promise.set_value(*buf);
            } else {
                backend_data_promise.set_value({});
            }
            boost::asio::async_write(*backend_socket, boost::asio::buffer("OK"), [](auto, auto) {});
        });
    });

    std::thread runner([&]() { io.run(); });

    client.write_some(boost::asio::buffer(c.peek_data));

    auto future = backend_data_promise.get_future();
    if (future.wait_for(std::chrono::seconds(2)) != std::future_status::ready) {
        throw TestFailure("Timeout waiting for backend data");
    }
    auto data = future.get();

    boost::system::error_code ignored;
    client.shutdown(tcp::socket::shutdown_both, ignored);
    client.close(ignored);
    if (backend_socket && backend_socket->is_open()) {
        backend_socket->shutdown(tcp::socket::shutdown_both, ignored);
        backend_socket->close(ignored);
    }

    for (int i = 0; i < 80 && metrics->active_sessions.load() != 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    io.stop();
    runner.join();

    if (!data.empty()) {
        EXPECT_EQ(metrics->total_connections.load(), 1u);
        EXPECT_EQ(metrics->active_sessions.load(), 0u);
    }
    return data;
}

void validate_case_output(const SessionCase& c, const std::vector<char>& data) {
    if (data.empty()) return; // skipped in restricted env

    std::size_t offset = 0;
    static const std::array<unsigned char, 12> sig = {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
    };
    const bool has_proxy_header = data.size() >= sig.size() &&
                                  std::equal(sig.begin(), sig.end(), data.begin());
    if (c.expect_proxy_header) {
        EXPECT_TRUE(has_proxy_header);
        offset = 28; // IPv4 length in this setup
    } else {
        EXPECT_FALSE(has_proxy_header);
    }
    EXPECT_TRUE(data.size() >= offset);
    const std::string payload(data.begin() + offset, data.end());

    if (c.expect_forward_headers) {
        EXPECT_TRUE(payload.find("X-Test: 1") != std::string::npos);
        EXPECT_TRUE(payload.find("X-Real-IP:") != std::string::npos);
    } else {
        EXPECT_TRUE(payload.find("X-Real-IP:") == std::string::npos);
        EXPECT_TRUE(payload.find(c.peek_data) != std::string::npos);
    }
}

} // namespace

int main() {
    auto test_sessions = [] {
        std::vector<SessionCase> cases = {
            {DetectorKind::Http, "GET /path HTTP/1.1\r\nHost: example\r\n\r\n", true, true, true, true, "http"},
            {DetectorKind::TlsClientHello, std::string("\x16\x03\x01", 3) + "XYZ", false, false, true, true, "tls"},
            {DetectorKind::HttpOrTls, "POST /x HTTP/1.1\r\nHost: h\r\n\r\n", true, true, false, false, "http_or_tls"},
            {DetectorKind::Prefix, "HELLO WORLD", false, false, true, true, "prefix"},
            {DetectorKind::SshBanner, "SSH-2.0-OpenSSH", false, false, true, true, "ssh"},
            {DetectorKind::Always, "RANDOM", false, false, false, false, "always"},
            // Edge cases
            {DetectorKind::TlsClientHello, std::string("\x16\x03", 2), false, false, true, false, "truncated_tls"},
            {DetectorKind::Http, "GET /path HTTP/1.1\r\nHost: example\r\n", true, false, true, true, "malformed_http_headers"},
            {DetectorKind::Prefix, std::string("\xFF\x00\x01" "BAD", 6), false, false, true, false, "garbage_fallback"},
        };

        for (const auto& c : cases) {
            auto data = run_session_case(c);
            validate_case_output(c, data);
        }
    };

    auto test_abrupt_disconnect = [] {
        boost::asio::io_context io;

        tcp::acceptor backend_acceptor(io);
        tcp::acceptor front_acceptor(io);
        try {
            backend_acceptor = tcp::acceptor(io, tcp::endpoint(tcp::v4(), 0));
            front_acceptor = tcp::acceptor(io, tcp::endpoint(tcp::v4(), 0));
        } catch (const boost::system::system_error& ex) {
            if (ex.code().value() == EPERM) {
                std::cerr << "[SKIP] session_abrupt_disconnect: " << ex.code().message() << "\n";
                return;
            }
            throw;
        }

        auto metrics = make_metrics();

        RouteRule rule{
            "always",
            DetectorKind::Always,
            {},
            Backend{"127.0.0.1", backend_acceptor.local_endpoint().port(), false},
            HttpForward{}
        };
        auto router = std::make_shared<Router>(
            std::vector<RouteRule>{rule},
            Backend{"127.0.0.1", backend_acceptor.local_endpoint().port(), false});

        tcp::socket client(io);
        client.connect(tcp::endpoint(tcp::v4(), front_acceptor.local_endpoint().port()));

        tcp::socket incoming(io);
        front_acceptor.accept(incoming);

        auto session = std::make_shared<Session>(std::move(incoming), router, 128, metrics, false, false);
        session->start();

        boost::system::error_code ignored;
        client.shutdown(tcp::socket::shutdown_both, ignored);
        client.close(ignored);

        std::thread runner([&]() { io.run(); });

        for (int i = 0; i < 40 && metrics->active_sessions.load() != 0; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        io.stop();
        runner.join();

        EXPECT_EQ(metrics->total_connections.load(), 1u);
        EXPECT_EQ(metrics->active_sessions.load(), 0u);
    };

    return run_tests({
        {"session_routes", test_sessions},
        {"session_abrupt_disconnect", test_abrupt_disconnect},
    });
}
