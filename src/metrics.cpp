#include "metrics.hpp"

#include <boost/asio/write.hpp>

#include <iostream>
#include <sstream>

namespace port_sharer {

MetricsPtr make_metrics() {
    return std::make_shared<MetricsRegistry>();
}

MetricsServer::MetricsServer(boost::asio::io_context& io, MetricsPtr metrics, uint16_t port)
    : acceptor_(io, tcp::endpoint(tcp::v4(), port)),
      metrics_(std::move(metrics)) {
    std::cout << "[metrics] Exposing metrics on 0.0.0.0:" << port << "\n";
}

void MetricsServer::start() {
    do_accept();
}

uint16_t MetricsServer::bound_port() const {
    return acceptor_.local_endpoint().port();
}

void MetricsServer::do_accept() {
    acceptor_.async_accept([this](auto ec, auto socket) {
        if (!ec) {
            serve_connection(std::move(socket));
        }
        do_accept();
    });
}

void MetricsServer::serve_connection(tcp::socket socket) {
    // Keep socket alive for the async write; avoid using a moved-from socket due to
    // unspecified argument evaluation order.
    auto socket_ptr = std::make_shared<tcp::socket>(std::move(socket));

    const auto body = render();
    std::ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\n"
        << "Content-Type: text/plain; version=0.0.4\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    auto response = oss.str();
    auto buffer = std::make_shared<std::string>(std::move(response));
    boost::asio::async_write(
        *socket_ptr,
        boost::asio::buffer(*buffer),
        [buffer, socket_ptr](auto, auto) mutable {
            boost::system::error_code ignored;
            socket_ptr->shutdown(tcp::socket::shutdown_both, ignored);
            socket_ptr->close(ignored);
        });
}

std::string MetricsServer::render() const {
    std::ostringstream os;
    os << "port_sharer_total_connections " << metrics_->total_connections.load() << "\n";
    os << "port_sharer_active_sessions " << metrics_->active_sessions.load() << "\n";
    os << "port_sharer_bytes_upstream " << metrics_->bytes_upstream.load() << "\n";
    os << "port_sharer_bytes_downstream " << metrics_->bytes_downstream.load() << "\n";
    return os.str();
}

} // namespace port_sharer
