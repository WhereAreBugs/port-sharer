#include "server.hpp"

#include "session.hpp"

#include <boost/asio/ip/address.hpp>

#include <iostream>

namespace port_sharer {

Server::Server(boost::asio::io_context& io, AppConfig config, std::shared_ptr<Router> router)
    : acceptor_(io, boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address(config.listener.address), config.listener.port)),
      config_(std::move(config)),
      router_(std::move(router)),
      metrics_(make_metrics()),
      access_(config_.access) {
    std::cout << "[server] Listening on " << config_.listener.address << ":" << config_.listener.port << "\n";
    for (const auto& r : config_.routes) {
        std::cout << "[server] Rule '" << r.name << "' -> " << r.backend.host << ":" << r.backend.port
                  << " detector=";
        switch (r.detector) {
            case DetectorKind::Http: std::cout << "http"; break;
            case DetectorKind::TlsClientHello: std::cout << "tls"; break;
            case DetectorKind::HttpOrTls: std::cout << "http_or_tls"; break;
            case DetectorKind::Prefix: std::cout << "prefix"; break;
            case DetectorKind::SshBanner: std::cout << "ssh"; break;
            case DetectorKind::SshUsername: std::cout << "ssh_username"; break;
            case DetectorKind::Always: std::cout << "always"; break;
        }
        std::cout
                  << " proxy_protocol=" << (r.backend.proxy_protocol ? "on" : "off") << "\n";
    }
    std::cout << "[server] Fallback -> " << config_.fallback.host << ":" << config_.fallback.port
              << (config_.fallback.proxy_protocol ? " (proxy_protocol)" : "") << "\n";
    if (access_.enabled()) {
        std::cout << "[server] Access control enabled (whitelist=" << config_.access.whitelist.size()
                  << ", blacklist=" << config_.access.blacklist.size() << ")";
        if (config_.access.syn_limit.enable && config_.access.syn_limit.max_attempts > 0) {
            std::cout << " syn_rate=" << config_.access.syn_limit.max_attempts
                      << "/" << config_.access.syn_limit.interval_ms << "ms"
                      << " ban=" << config_.access.syn_limit.ban_seconds << "s";
        }
        std::cout << "\n";
    } else {
        std::cout << "[server] Access control disabled\n";
    }
}

void Server::start() {
    do_accept();
}

void Server::do_accept() {
    acceptor_.async_accept([this](auto ec, auto socket) {
        if (!ec) {
            bool allowed = true;
            boost::system::error_code ep_ec;
            auto remote_ep = socket.remote_endpoint(ep_ec);
            if (!ep_ec && access_.enabled()) {
                auto verdict = access_.check(remote_ep.address());
                if (verdict.result != AccessResult::Allowed) {
                    allowed = false;
                    std::string reason;
                    switch (verdict.result) {
                        case AccessResult::Blacklisted: reason = "blacklist"; break;
                        case AccessResult::NotWhitelisted: reason = "not whitelisted"; break;
                        case AccessResult::RateLimited: reason = "syn-rate-limit"; break;
                        default: break;
                    }
                    std::cerr << "[server] Drop connection from " << remote_ep.address().to_string()
                              << (reason.empty() ? "" : " due to " + reason);
                    if (verdict.result == AccessResult::RateLimited && verdict.retry_after.count() > 0) {
                        std::cerr << " retry_after=" << verdict.retry_after.count() << "ms";
                    }
                    std::cerr << "\n";
                }
            }

            if (allowed) {
                std::make_shared<Session>(std::move(socket), router_, config_.peek_size, config_.metrics.enable ? metrics_ : nullptr, config_.performance.prefer_zero_copy, config_.performance.prefer_kernel_dnat)->start();
            } else {
                boost::system::error_code close_ec;
                socket.close(close_ec);
            }
        } else {
            std::cerr << "[server] Accept error: " << ec.message() << "\n";
        }
        do_accept();
    });
}

} // namespace port_sharer
