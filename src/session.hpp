#pragma once

#include "config.hpp"
#include "kernel_bypass.hpp"
#include "metrics.hpp"
#include "router.hpp"

#include <array>
#include <atomic>
#include <memory>
#include <optional>
#include <vector>

#include <boost/asio.hpp>

namespace port_sharer {

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(boost::asio::ip::tcp::socket client_socket,
            std::shared_ptr<Router> router,
            std::size_t peek_size,
            MetricsPtr metrics,
            bool prefer_zero_copy,
            bool prefer_kernel_dnat);

    void start();

private:
    using tcp = boost::asio::ip::tcp;
    using Strand = boost::asio::strand<boost::asio::any_io_executor>;

    void do_peek();
    void on_peek(const boost::system::error_code& ec, std::size_t length);
    void resolve_and_connect(const Backend& backend);
    void on_resolve(const boost::system::error_code& ec,
                    const tcp::resolver::results_type& endpoints,
                    Backend backend);
    void on_connect(const boost::system::error_code& ec);

    void do_read_from_client();
    void do_write_to_backend(std::size_t length);
    void do_read_from_backend();
    void do_write_to_client(std::size_t length);

    void start_kernel_bypass_watch(std::uint64_t client_cookie, std::uint64_t backend_cookie);
    bool start_zero_copy_splice();
#if defined(PORT_SHARER_HAS_IO_URING)
    bool start_zero_copy_io_uring();
#endif
    void close_sockets(const boost::system::error_code& ec);

    std::shared_ptr<Router> router_;
    Backend selected_backend_;
    RouteRule selected_rule_;
    bool is_http_traffic_ = false;
    std::shared_ptr<Strand> strand_;
    MetricsPtr metrics_;
    bool prefer_zero_copy_;
    bool prefer_kernel_dnat_;

    tcp::socket client_socket_;
    tcp::socket backend_socket_;
    tcp::endpoint local_endpoint_;

    std::vector<char> peek_buffer_;
    std::size_t peek_size_;
    std::size_t peek_length_ = 0;
    std::vector<char> proxy_header_;

    std::array<char, 4096> client_buffer_{};
    std::array<char, 4096> backend_buffer_{};
    std::string remote_label_;
    std::atomic<bool> closed_{false};
    KernelBypass kernel_bypass_;
    std::optional<std::pair<std::uint64_t, std::uint64_t>> bypass_cookies_;

    bool is_local_backend(const Backend& backend) const;
    bool start_zero_copy();
};

} // namespace port_sharer
