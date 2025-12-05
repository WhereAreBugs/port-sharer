#pragma once

#include "config.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <boost/asio/ip/address.hpp>

namespace port_sharer {

enum class AccessResult {
    Allowed,
    Blacklisted,
    NotWhitelisted,
    RateLimited
};

struct AccessCheckResult {
    AccessResult result = AccessResult::Allowed;
    std::chrono::milliseconds retry_after{0};
};

class AccessController {
public:
    explicit AccessController(const AccessControl& cfg);

    AccessCheckResult check(const boost::asio::ip::address& addr);
    bool enabled() const { return enabled_; }

private:
    struct CidrEntry {
        std::array<std::uint8_t, 16> network{};
        std::array<std::uint8_t, 16> mask{};
        bool is_v6 = false;
    };

    struct IpKey {
        std::uint64_t hi = 0;
        std::uint64_t lo = 0;
        bool operator==(const IpKey& other) const noexcept {
            return hi == other.hi && lo == other.lo;
        }
    };

    struct IpKeyHash {
        std::size_t operator()(const IpKey& k) const noexcept {
            std::size_t h1 = std::hash<std::uint64_t>{}(k.hi);
            std::size_t h2 = std::hash<std::uint64_t>{}(k.lo);
            return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
        }
    };

    struct RateEntry {
        std::uint64_t window_start_ms = 0;
        std::uint32_t count = 0;
        std::uint64_t ban_until_ms = 0;
        std::uint64_t last_seen_ms = 0;
    };

    struct Bucket {
        std::mutex mu;
        std::unordered_map<IpKey, RateEntry, IpKeyHash> entries;
        std::uint64_t next_cleanup_ms = 0;
    };

    bool match_list(const std::vector<CidrEntry>& list, const boost::asio::ip::address& addr) const;
    AccessCheckResult check_rate_limit(const boost::asio::ip::address& addr);

    static std::array<std::uint8_t, 16> address_bytes(const boost::asio::ip::address& addr);
    static CidrEntry make_cidr(const std::string& text, bool& ok);
    static std::array<std::uint8_t, 16> make_mask(unsigned prefix, bool is_v6);
    static std::uint64_t now_ms();

    std::vector<CidrEntry> whitelist_;
    std::vector<CidrEntry> blacklist_;
    AccessControl::SynLimit syn_limit_;
    bool enabled_ = false;
    bool has_whitelist_ = false;
    std::array<Bucket, 64> buckets_;
    std::uint64_t cleanup_interval_ms_ = 5000;
    std::uint64_t cleanup_horizon_ms_ = 120000;
};

} // namespace port_sharer
