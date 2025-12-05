#include "proxy_protocol.hpp"
#include "test_common.hpp"

#include <array>
#include <cstring>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

using namespace port_sharer;
using boost::asio::ip::tcp;

int main() {
    auto test_proxy_protocol_builder = [] {
        tcp::endpoint client(boost::asio::ip::make_address_v4("192.0.2.1"), 12345);
        tcp::endpoint local(boost::asio::ip::make_address_v4("198.51.100.2"), 8080);
        auto buf = build_proxy_protocol_v2(client, local);
        EXPECT_EQ(buf.size(), 28u);
        static const std::array<unsigned char, 12> sig = {
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
        };
        EXPECT_TRUE(std::equal(sig.begin(), sig.end(), buf.begin()));
        uint16_t len = 0;
        std::memcpy(&len, &buf[14], sizeof(uint16_t));
        EXPECT_EQ(ntohs(len), 12u);
        // Check client port bytes are present near the end
        uint16_t port_net = 0;
        std::memcpy(&port_net, &buf[buf.size() - 4], sizeof(uint16_t));
        EXPECT_EQ(ntohs(port_net), 12345u);

        tcp::endpoint client6(boost::asio::ip::make_address_v6("2001:db8::1"), 23456);
        tcp::endpoint local6(boost::asio::ip::make_address_v6("2001:db8::2"), 8443);
        auto buf6 = build_proxy_protocol_v2(client6, local6);
        EXPECT_TRUE(buf6.size() > 40);
        std::memcpy(&len, &buf6[14], sizeof(uint16_t));
        EXPECT_EQ(ntohs(len), 36u);
    };

    return run_tests({
        {"proxy_protocol_builder", test_proxy_protocol_builder},
    });
}
