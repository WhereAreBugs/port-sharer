#pragma once

#include <atomic>
#include <memory>
#include <string>

#include <boost/asio.hpp>

namespace port_sharer {

struct MetricsRegistry {
    std::atomic<uint64_t> total_connections{0};
    std::atomic<uint64_t> active_sessions{0};
    std::atomic<uint64_t> bytes_upstream{0};
    std::atomic<uint64_t> bytes_downstream{0};
};

using MetricsPtr = std::shared_ptr<MetricsRegistry>;

MetricsPtr make_metrics();

class MetricsServer {
public:
    MetricsServer(boost::asio::io_context& io, MetricsPtr metrics, uint16_t port);
    void start();
    uint16_t bound_port() const;

private:
    using tcp = boost::asio::ip::tcp;
    void do_accept();
    void serve_connection(tcp::socket socket);
    std::string render() const;

    tcp::acceptor acceptor_;
    MetricsPtr metrics_;
};

} // namespace port_sharer
