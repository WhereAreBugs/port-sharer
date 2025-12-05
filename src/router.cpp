#include "router.hpp"

#include <iostream>

namespace port_sharer {

Router::Router(std::vector<RouteRule> rules, Backend fallback)
    : fallback_(std::move(fallback)) {
    rules_.reserve(rules.size());
    for (auto& r : rules) {
        CompiledRule compiled;
        compiled.rule = std::move(r);
        compiled.detector = make_detector(compiled.rule);
        rules_.push_back(std::move(compiled));
    }
}

RouteDecision Router::select(const DetectionContext& ctx) const {
    for (const auto& compiled : rules_) {
        if (compiled.detector && compiled.detector->match(ctx)) {
            return RouteDecision{&compiled.rule.backend, &compiled.rule};
        }
    }
    return RouteDecision{&fallback_, nullptr};
}

} // namespace port_sharer
