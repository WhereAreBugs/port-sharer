#include "server.hpp"

#include "session.hpp"

#include <boost/asio/ip/address.hpp>

#include <iostream>

namespace port_sharer {

Server::Server(boost::asio::io_context& io, AppConfig config, std::shared_ptr<Router> router)
    : acceptor_(io, boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address(config.listener.address), config.listener.port)),
      config_(std::move(config)),
      router_(std::move(router)),
      metrics_(make_metrics()) {
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
            case DetectorKind::Always: std::cout << "always"; break;
        }
        std::cout
                  << " proxy_protocol=" << (r.backend.proxy_protocol ? "on" : "off") << "\n";
    }
    std::cout << "[server] Fallback -> " << config_.fallback.host << ":" << config_.fallback.port
              << (config_.fallback.proxy_protocol ? " (proxy_protocol)" : "") << "\n";
}

void Server::start() {
    do_accept();
}

void Server::do_accept() {
    acceptor_.async_accept([this](auto ec, auto socket) {
        if (!ec) {
            std::make_shared<Session>(std::move(socket), router_, config_.peek_size, config_.metrics.enable ? metrics_ : nullptr, config_.performance.prefer_zero_copy, config_.performance.prefer_kernel_dnat)->start();
        } else {
            std::cerr << "[server] Accept error: " << ec.message() << "\n";
        }
        do_accept();
    });
}

} // namespace port_sharer
