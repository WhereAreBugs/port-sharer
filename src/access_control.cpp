#include "access_control.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <limits>

namespace port_sharer {

namespace {

std::uint64_t clamp_add(std::uint64_t base, std::uint64_t delta) {
    const std::uint64_t limit = std::numeric_limits<std::uint64_t>::max();
    if (base > limit - delta) return limit;
    return base + delta;
}

} // namespace

AccessController::AccessController(const AccessControl& cfg)
    : syn_limit_(cfg.syn_limit) {
    whitelist_.reserve(cfg.whitelist.size());
    blacklist_.reserve(cfg.blacklist.size());

    auto load_list = [](const std::vector<std::string>& raw, std::vector<CidrEntry>& dst) {
        for (const auto& item : raw) {
            bool ok = false;
            auto cidr = make_cidr(item, ok);
            if (ok) {
                dst.push_back(std::move(cidr));
            } else {
                std::cerr << "[access] skip invalid cidr '" << item << "'\n";
            }
        }
    };

    load_list(cfg.whitelist, whitelist_);
    load_list(cfg.blacklist, blacklist_);

    has_whitelist_ = !whitelist_.empty();
    enabled_ = has_whitelist_ || !blacklist_.empty() || syn_limit_.enable;
    if (syn_limit_.interval_ms == 0) syn_limit_.interval_ms = 1000;
    cleanup_horizon_ms_ = std::max<std::uint64_t>(
        syn_limit_.ban_seconds * 1000ULL + syn_limit_.interval_ms * 4ULL,
        60000ULL);
}

AccessCheckResult AccessController::check(const boost::asio::ip::address& addr) {
    if (!enabled_) return {};

    if (!blacklist_.empty() && match_list(blacklist_, addr)) {
        return {AccessResult::Blacklisted, std::chrono::milliseconds(0)};
    }
    if (has_whitelist_ && !match_list(whitelist_, addr)) {
        return {AccessResult::NotWhitelisted, std::chrono::milliseconds(0)};
    }
    if (syn_limit_.enable && syn_limit_.max_attempts > 0) {
        auto rate_res = check_rate_limit(addr);
        if (rate_res.result != AccessResult::Allowed) return rate_res;
    }
    return {};
}

bool AccessController::match_list(const std::vector<CidrEntry>& list, const boost::asio::ip::address& addr) const {
    const bool is_v6 = addr.is_v6();
    auto bytes = address_bytes(addr);
    for (const auto& entry : list) {
        if (entry.is_v6 != is_v6) continue;
        bool match = true;
        for (std::size_t i = 0; i < entry.network.size(); ++i) {
            if ((bytes[i] & entry.mask[i]) != entry.network[i]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

AccessCheckResult AccessController::check_rate_limit(const boost::asio::ip::address& addr) {
    AccessCheckResult res;
    const auto bytes = address_bytes(addr);
    IpKey key;
    std::memcpy(&key.hi, bytes.data(), sizeof(std::uint64_t));
    std::memcpy(&key.lo, bytes.data() + sizeof(std::uint64_t), sizeof(std::uint64_t));

    const std::size_t bucket_idx = static_cast<std::size_t>((key.hi ^ key.lo) % buckets_.size());
    auto now = now_ms();
    auto& bucket = buckets_[bucket_idx];
    std::lock_guard<std::mutex> lk(bucket.mu);

    if (bucket.entries.empty()) {
        bucket.next_cleanup_ms = now + cleanup_interval_ms_;
    } else if (bucket.next_cleanup_ms <= now) {
        for (auto it = bucket.entries.begin(); it != bucket.entries.end();) {
            if (now > cleanup_horizon_ms_ + it->second.last_seen_ms &&
                it->second.ban_until_ms <= now) {
                it = bucket.entries.erase(it);
            } else {
                ++it;
            }
        }
        bucket.next_cleanup_ms = now + cleanup_interval_ms_;
    }

    auto& entry = bucket.entries[key];
    entry.last_seen_ms = now;

    if (entry.ban_until_ms > now) {
        res.result = AccessResult::RateLimited;
        res.retry_after = std::chrono::milliseconds(entry.ban_until_ms - now);
        return res;
    }

    if (entry.window_start_ms == 0 || now - entry.window_start_ms >= syn_limit_.interval_ms) {
        entry.window_start_ms = now;
        entry.count = 0;
    }
    ++entry.count;
    if (entry.count > syn_limit_.max_attempts) {
        const auto ban_ms = syn_limit_.ban_seconds * 1000ULL;
        entry.ban_until_ms = clamp_add(now, ban_ms);
        res.result = AccessResult::RateLimited;
        res.retry_after = std::chrono::milliseconds(entry.ban_until_ms > now ? entry.ban_until_ms - now : 0);
    }
    return res;
}

std::array<std::uint8_t, 16> AccessController::address_bytes(const boost::asio::ip::address& addr) {
    std::array<std::uint8_t, 16> bytes{};
    if (addr.is_v4()) {
        auto b4 = addr.to_v4().to_bytes();
        std::copy(b4.begin(), b4.end(), bytes.begin() + 12);
    } else {
        auto b6 = addr.to_v6().to_bytes();
        std::copy(b6.begin(), b6.end(), bytes.begin());
    }
    return bytes;
}

AccessController::CidrEntry AccessController::make_cidr(const std::string& text, bool& ok) {
    ok = false;
    CidrEntry entry;
    auto pos = text.find('/');
    std::string addr_str = text.substr(0, pos);
    unsigned prefix = 0;
    try {
        auto addr = boost::asio::ip::make_address(addr_str);
        const bool is_v6 = addr.is_v6();
        const unsigned max_pref = is_v6 ? 128 : 32;
        if (pos == std::string::npos) {
            prefix = max_pref;
        } else {
            prefix = static_cast<unsigned>(std::stoul(text.substr(pos + 1)));
        }
        if (prefix > max_pref) return entry;

        entry.mask = make_mask(prefix, is_v6);
        auto bytes = address_bytes(addr);
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            entry.network[i] = bytes[i] & entry.mask[i];
        }
        entry.is_v6 = is_v6;
        ok = true;
    } catch (const std::exception&) {
    }
    return entry;
}

std::array<std::uint8_t, 16> AccessController::make_mask(unsigned prefix, bool is_v6) {
    std::array<std::uint8_t, 16> mask{};
    const std::size_t offset = is_v6 ? 0 : 12;
    const std::size_t bytes = is_v6 ? mask.size() : 4;
    for (std::size_t i = 0; i < bytes && prefix > 0; ++i) {
        if (prefix >= 8) {
            mask[offset + i] = 0xFF;
            prefix -= 8;
        } else {
            mask[offset + i] = static_cast<std::uint8_t>(0xFF << (8 - prefix));
            prefix = 0;
        }
    }
    return mask;
}

std::uint64_t AccessController::now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

} // namespace port_sharer
