#pragma once

#include <vector>

#include <boost/asio/ip/tcp.hpp>

namespace port_sharer {

std::vector<char> build_proxy_protocol_v2(const boost::asio::ip::tcp::endpoint& client,
                                          const boost::asio::ip::tcp::endpoint& local);

} // namespace port_sharer
