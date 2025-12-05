#pragma once

#include "config.hpp"
#include "detector.hpp"

#include <memory>
#include <optional>
#include <vector>

namespace port_sharer {

struct RouteDecision {
    const Backend* backend = nullptr;
    const RouteRule* rule = nullptr;
};

class Router {
public:
    Router(std::vector<RouteRule> rules, Backend fallback);

    RouteDecision select(const DetectionContext& ctx) const;

private:
    struct CompiledRule {
        RouteRule rule;
        std::shared_ptr<ProtocolDetector> detector;
    };

    std::vector<CompiledRule> rules_;
    Backend fallback_;
};

} // namespace port_sharer
