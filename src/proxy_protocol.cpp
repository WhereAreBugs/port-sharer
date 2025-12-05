#include "proxy_protocol.hpp"

#include <array>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace port_sharer {

using boost::asio::ip::tcp;

namespace {
constexpr unsigned char kProxyV2VersionAndCommand = 0x21;
constexpr unsigned char kProxyV2FamilyProtocolTCPv4 = 0x11;
constexpr unsigned char kProxyV2FamilyProtocolTCPv6 = 0x21;
constexpr std::array<unsigned char, 12> kSignature = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
    0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
};

template <class Container, class Value>
void append_bytes(Container& out, const Value& value) {
    const auto* bytes = reinterpret_cast<const char*>(&value);
    out.insert(out.end(), bytes, bytes + sizeof(Value));
}

} // namespace

std::vector<char> build_proxy_protocol_v2(const tcp::endpoint& client,
                                          const tcp::endpoint& local) {
    std::vector<char> buffer;
    buffer.reserve(56);
    buffer.insert(buffer.end(), kSignature.begin(), kSignature.end());
    buffer.push_back(static_cast<char>(kProxyV2VersionAndCommand));

    if (client.protocol() == tcp::v4()) {
        buffer.push_back(static_cast<char>(kProxyV2FamilyProtocolTCPv4));
        const uint16_t len_net = htons(static_cast<uint16_t>(12));
        append_bytes(buffer, len_net);
        append_bytes(buffer, client.address().to_v4().to_bytes());
        append_bytes(buffer, local.address().to_v4().to_bytes());
        append_bytes(buffer, htons(client.port()));
        append_bytes(buffer, htons(local.port()));
    } else {
        buffer.push_back(static_cast<char>(kProxyV2FamilyProtocolTCPv6));
        const uint16_t len_net = htons(static_cast<uint16_t>(36));
        append_bytes(buffer, len_net);
        append_bytes(buffer, client.address().to_v6().to_bytes());
        append_bytes(buffer, local.address().to_v6().to_bytes());
        append_bytes(buffer, htons(client.port()));
        append_bytes(buffer, htons(local.port()));
    }

    return buffer;
}

} // namespace port_sharer
