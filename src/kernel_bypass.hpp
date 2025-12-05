#pragma once

#include "config.hpp"

#include <cstdint>
#include <string>
#include <boost/asio/ip/tcp.hpp>

namespace port_sharer {

struct KernelBypassResult {
    bool engaged = false;
    std::uint64_t client_cookie = 0;
    std::uint64_t backend_cookie = 0;
};

// eBPF-based DNAT/redirect using sockmap.
// When engaged, the kernel forwards data between client/backend sockets without
// further user-space copies. Requires Linux >= 5.8 with BPF/sockmap support.
class KernelBypass {
public:
    KernelBypass() = default;

    // Try to install a sockmap redirection for the given sockets.
    // Returns {false, ...} on any failure; caller should fall back to user-space path.
    KernelBypassResult attempt_dnat(boost::asio::ip::tcp::socket& client_socket,
                                    boost::asio::ip::tcp::socket& backend_socket,
                                    const Backend& backend,
                                    const std::string& session_label);

    // Remove sockmap state for a pair of cookies (no-op on non-Linux).
    void teardown(std::uint64_t client_cookie, std::uint64_t backend_cookie);
};

} // namespace port_sharer
