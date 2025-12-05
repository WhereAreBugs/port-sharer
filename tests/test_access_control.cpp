#include "access_control.hpp"
#include "test_common.hpp"

#include <boost/asio/ip/address.hpp>

#include <chrono>
#include <thread>

using namespace port_sharer;

int main() {
    auto test_whitelist_blacklist = [] {
        AccessControl cfg;
        cfg.whitelist = {"192.0.2.0/24"};
        cfg.blacklist = {"198.51.100.1"};
        AccessController ac(cfg);

        auto allow = ac.check(boost::asio::ip::make_address("192.0.2.5"));
        EXPECT_EQ(allow.result, AccessResult::Allowed);

        auto deny = ac.check(boost::asio::ip::make_address("203.0.113.5"));
        EXPECT_EQ(deny.result, AccessResult::NotWhitelisted);

        auto block = ac.check(boost::asio::ip::make_address("198.51.100.1"));
        EXPECT_EQ(block.result, AccessResult::Blacklisted);
    };

    auto test_rate_limit = [] {
        AccessControl cfg;
        cfg.syn_limit.enable = true;
        cfg.syn_limit.max_attempts = 2;
        cfg.syn_limit.interval_ms = 50;
        cfg.syn_limit.ban_seconds = 1;
        AccessController ac(cfg);
        auto ip = boost::asio::ip::make_address("203.0.113.10");

        EXPECT_EQ(ac.check(ip).result, AccessResult::Allowed);
        EXPECT_EQ(ac.check(ip).result, AccessResult::Allowed);
        auto limited = ac.check(ip);
        EXPECT_EQ(limited.result, AccessResult::RateLimited);
        EXPECT_TRUE(limited.retry_after.count() > 0);

        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        EXPECT_EQ(ac.check(ip).result, AccessResult::Allowed);
    };

    return run_tests({
        {"whitelist_blacklist", test_whitelist_blacklist},
        {"rate_limit", test_rate_limit},
    });
}
