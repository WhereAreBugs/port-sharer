#pragma once

#include "config.hpp"

#include <string>
#include <string_view>

#include <boost/asio/ip/tcp.hpp>

namespace port_sharer {

struct DetectionContext {
    std::string_view data;
    boost::asio::ip::tcp::endpoint remote;
    boost::asio::ip::tcp::endpoint local;
};

class ProtocolDetector {
public:
    virtual ~ProtocolDetector() = default;
    virtual std::string name() const = 0;
    virtual bool match(const DetectionContext& ctx) const = 0;
};

// Factory helpers
std::shared_ptr<ProtocolDetector> make_detector(const RouteRule& rule);

} // namespace port_sharer
