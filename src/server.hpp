#pragma once

#include "config.hpp"
#include "access_control.hpp"
#include "metrics.hpp"
#include "router.hpp"

#include <memory>

#include <boost/asio.hpp>

namespace port_sharer {

class Server {
public:
    Server(boost::asio::io_context& io, AppConfig config, std::shared_ptr<Router> router);
    void start();
    MetricsPtr metrics() const { return metrics_; }

private:
    void do_accept();

    using tcp = boost::asio::ip::tcp;

    tcp::acceptor acceptor_;
    AppConfig config_;
    std::shared_ptr<Router> router_;
    MetricsPtr metrics_;
    AccessController access_;
};

} // namespace port_sharer
